# 0018 — `INV.access_token_hash`, and the HTC/INV signing input

Gate G-11 builds the HTC and INV objects, so two byte layouts §F.2 leaves open have to be fixed
before the mutation suite can mean anything. Both are recorded here.

## Context

**The field.** §F.2 gives `access_token_hash: H(AT@aud)` and names no construction. ADR 0009
classified it **category (c)** — *"fixed when INV/HTC are built and mutation-tested (**G-11**)"* —
and `smoke/g4/DESIGN.md` §9 **C2** carried a proposal while explicitly forbidding any code from
treating it as settled. G-4 Phase 2 honoured that: it adjudicated the AS-side **precondition** only
(the presented token is observable, ASCII-stable and swap-detectable) and left limb **L4** open, so
G-4's PASS was recorded as *"not a full four-limb closure"*. This ADR is the adjudication.

**The trap, confirmed against the text.** Three digests are taken over the same access token in this
project, and two of them consume **the same input bytes**:

| Digest | Input | Rendering | Owner |
|---|---|---|---|
| `ath` | ASCII **token string** | base64url, unpadded | RFC 9449 §4.2, `src/sut/dpop.py` |
| `H_JCS` | RFC 8785 canonical bytes of a **JSON object** | lowercase hex | ADR 0009 |
| `access_token_hash` | ASCII **token string** | lowercase hex | this ADR |

`ath` and `access_token_hash` differ **only** by domain tag and output encoding. That is precisely
why the tag is load-bearing rather than decorative, and why STEP 1 item 3 forbade reusing `ath`,
`H_JCS` or the §A.0.1 capability tag for this field.

**The signing input.** §F.2 mandates that every signature is over a byte string prefixed with a
fixed domain tag and schema version, and fixes the tags `"AASC-HTC-v1"` / `"AASC-INV-v1"`. It does
**not** specify how the rest of the payload is serialized — an underspecification that has to be
resolved to sign anything at all, and one that the domain-tag-confusion mutation depends on.

## Decision

### 1. `access_token_hash` — the §9 C2 proposal is **adopted**, unchanged

`[DESIGN]`

```
TAG      = b"AASC-AT-DIGEST"   # 14 bytes; distinct from every tag in use
VERSION  = 0x01                # one byte; any other value fails closed
t        = the access token exactly as presented at the boundary — its compact
           serialization, ASCII bytes

access_token_hash = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(t)) || t ) )
```

Same tagged, versioned, length-delimited family as ADR 0003 `commitment.py`, ADR 0009
`jcs_digest.py` and ADR 0016 `frozen_config.py`; **no algorithm byte** (a hash change is a new
VERSION, not a parameter), lowercase hex per ADR 0011, fail-closed on an unsupported version.

Adopted rather than replaced because the proposal already satisfied every constraint the task set,
and inventing an alternative would have created a fourth layout to keep distinct for no gain.

**The input, precisely.** The bytes hashed are the token **as presented** — the compact
serialization the boundary received, not a re-serialization, not a parsed-and-re-encoded form. A
JWS compact serialization is base64url characters and dots by construction, so:

- **a non-ASCII byte fails closed** (`NonAsciiTokenError`). Encoding it as UTF-8 instead would let
  two different byte strings collide onto one digest, and a non-ASCII input is not a well-formed
  presented token in any case.

**Worked example**, with `ath` and `H_JCS` over the *same* token as non-vacuity evidence:

```
t (85 bytes):  eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ1c2VyLXlpeGlhbiJ9.c2lnbmF0dXJl
preimage:      b"AASC-AT-DIGEST" || 0x01 || 0x00000055 || t

access_token_hash:  600b4e6e581a15b4b3e847e093120ba87c6126851fd347f18994020c40010e13
ath (base64url):    qIcA6_GtjNdrUMTlUqgSAHevgGRlm8kqfAl7Nx-UUgw
H_JCS({"token":t}): 3b8b26a9c023f073f713af06ef67858ea2f22b89d087f95d0ce6a378c6a4f095
bare SHA-256(t):    a88700ebf1ad8cd76b50c4e552a8120077af8064659bc92a7c097b371f94520c
```

All four differ. The comparison against the bare digest is the domain-separation evidence; the
comparison against `ath` is the one that matters most, because it consumes the identical input bytes.

### 2. The HTC/INV signing input

`[DESIGN]` Every HTC and INV signature is Ed25519 over

```
signing_input = TAG || VERSION || u32be(len(C)) || C
    TAG     = b"AASC-HTC-v1"  or  b"AASC-INV-v1"      (§F.2, unchanged)
    VERSION = the object's `schema_version` (1), one byte, fail-closed otherwise
    C       = RFC 8785 canonical UTF-8 bytes of the payload object
```

and the wire form is the canonical JSON of `{"payload": …, "signature": base64url(sig)}`.

RFC 8785 canonical bytes with a big-endian length prefix is chosen for consistency with every other
frozen layout in the project, and because canonicalization makes the signed bytes independent of
member order and insignificant whitespace — so a re-serialized payload still verifies, while any
change of content does not.

**Why this makes the tag load-bearing.** The tag is *inside* the signed bytes, so a payload signed
in the HTC domain cannot verify in the INV domain even if it is structurally a valid INV. That is
the property the domain-tag-confusion mutation tests, and it holds in both directions.

**Public keys on the wire** are base64url unpadded raw Ed25519 (32 bytes → 43 characters), matching
the JWK `x` encoding already used at G-5 and G-4.

## Status

accepted — 2026-07-29

## Consequences

- **ADR 0009's category (c) is closed for `access_token_hash`.** The remaining category-(c) fields
  that ADR 0009 nominally assigned to G-11 — `label_assertions_digest` and `authz_context_hash` —
  are **not** closed here and could not honestly be: both depend on the F4 label vocabulary and
  allowed-sink policy (`docs/frozen_parameters.md` rows 4 and 6, both **UNSET**), their verification
  is **G-15**'s, and the approval-artifact arm is out of scope for this gate. The INV signature
  covers `label_assertions_digest`, so it is tamper-evident, but the verifier does not recompute it
  and claims nothing about its construction.
- **`smoke/g4/DESIGN.md` §9 C2 is closed**, recorded there as a dated update note rather than a
  rewrite, and G-4's limb **L4** becomes adjudicable — run at G-11 through the real verifier, with a
  swapped token rejected as `inv_access_token_hash`.
- **A design constant, not a seal-time parameter.** TAG and VERSION are fixed here and carried in
  the verifier code, which the v0.5 candidate manifest already hashes (Part H step 3). **No
  `frozen_parameters` row is added**, exactly as ADR 0009 concluded for `H_JCS`.
- **D21 obligation.** `src/harness/verifier/` is instrument-side and recomputes every digest it
  checks from raw evidence. The B3 arm's **SUT-side** INV signer must compute `access_token_hash`
  and the signing input with an **independent** implementation; that obligation is still owed and is
  discharged when the arm is built.
- The regression suite pins the layout (known answer), the three-way distinctness against `ath` and
  `H_JCS`, the non-ASCII rejection, the version fail-closed, and that the new tag collides with no
  tag in use.
