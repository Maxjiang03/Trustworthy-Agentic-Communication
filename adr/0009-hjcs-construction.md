# 0009 — Frozen `H_JCS` construction: tagged, versioned, length-delimited SHA-256 over RFC 8785 canonical bytes, lowercase hex

## Context

Gate G-8 verified RFC 8785 canonicalisation (`rfc8785==0.1.4`, ADR 0005) but recorded, per the
no-invention rule, that the architecture document **underspecifies the digest construction over
it** (`smoke/g8/REPORT.md` §9): §F.2 (`canonical_request_digest: H_JCS(raw_arguments)`) and
Part I (`oracle_digest = H_JCS(obs.raw_arguments)`) name no hash function — SHA-256 appears only
in §A.0.1, which scopes itself to capability-state commitments; no domain tag is stated for
digests (§F.2's domain-tag MUST covers HTC/INV **signatures**); and the string encoding of
`intended_request_digest`/`effect_request_digest` (hex vs base64url) is unspecified. This ADR
records the Commander's adjudication closing that gap.

## Decision

[DESIGN] `H_JCS` is frozen as **SHA-256 over a versioned, domain-separated, length-delimited
encoding of the RFC 8785 canonical bytes, rendered as a lowercase hexadecimal string** —
deliberately the same construction family as the capability commitment (ADR 0003,
`src/harness/oracle/commitment.py`), with a distinct tag, so the two constructions cannot be
confused with one another or with a bare digest.

### Normative byte layout (two independent implementations must agree byte-for-byte)

```
TAG      = b"AASC-JCS-DIGEST"      # fixed ASCII, 15 bytes; distinct from b"AASC-CAP-COMMIT"
VERSION  = 0x01                    # one byte; any other value fails closed
C        = RFC 8785 canonical UTF-8 bytes of the arguments object
           (the JCS output of rfc8785==0.1.4, ADR 0005 — including its fail-closed
            rejections: NaN/Infinity, lone surrogates, non-string keys, |int| >= 2^53)

H_JCS(x) = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
```

Conventions match `commitment.py` exactly: fixed ASCII tag as a module constant, one version
byte, big-endian 4-byte length prefix on the variable-length item, SHA-256, fail-closed on any
unsupported version. **Deliberate difference, documented:** there is **no algorithm byte** —
unlike the capability commitment, `H_JCS` has no algorithm registry; the hash function is fixed
by the version (a future hash change is a new VERSION, not an alg parameter). The output is the
64-character lowercase hexadecimal encoding of the 32-byte digest (Python `hexdigest()`), which
settles the `intended_request_digest`/`effect_request_digest` string-encoding question: **hex,
lowercase**, everywhere `H_JCS` governs.

**Worked example** (the G-8 suite's pilot object):

```
input (any member order):  {"tool":"calendar.read","query":{"user":"A","day":"2026-07-25"},"limit":10}
C (canonical, 75 bytes):   {"limit":10,"query":{"day":"2026-07-25","user":"A"},"tool":"calendar.read"}
preimage:                  b"AASC-JCS-DIGEST" || 0x01 || 0x0000004B || C
H_JCS:                     67e50bfea620578e4d8f5b765204c5d5ce18688a71fdeb794c24f731d4931f56
bare SHA-256(C) (differs): 1892de68e8ea76aeebd3293846b1911471c7efbb53d501021f4ada6e6840648e
```

(The bare digest is the G-8 spike's evidence value — the domain separation is visibly
non-vacuous against exactly the previously recorded test-local digest.)

### Digest-field classification (every digest field in `src/harness/schema.py`; none unclassified)

Dispositions: **(a)** governed by `H_JCS`; **(b)** governed by a different construction, with a
pointer; **(c)** deferred, naming the gate or decision that settles it.

| Field | Where | Disposition |
|---|---|---|
| `canonical_request_digest` | INV template, §F.2 (signed object, not a `schema.py` class) | **(a)** — the defining occurrence: `INV.canonical_request_digest = H_JCS(raw_arguments)` (§F.2). |
| `intended_request_digest` | `IntendedInvocation` | **(a)** — the sealed expected value; `realized_harm_F3` compares it for **equality** against `effect_request_digest` and the oracle's `H_JCS(obs.raw_arguments)` (Part I), which forces the same construction. |
| `effect_request_digest` | `EffectEvent` | **(a)** — same Part I equality comparisons; computed **ledger-side over what the tool actually acted on**, as an independent implementation (D21). |
| `ingress_request_digest` | `ToolIngressEvent` | **(c) deferred to G-7.** The architecture document names no construction and no Part I predicate compares it; the field is built with the `ToolIngressEvent` recorder at G-7. Constraint recorded now: **if** any oracle check compares it against an `H_JCS`-governed digest, it MUST be `H_JCS`-governed — G-7 settles this; nothing is invented here. |
| `request_digest` | `DeclassificationArtifact` | **(c) deferred.** F4/F5 machinery; the document gives no formula for how the artifact binds "the request". Settled by the F4 label-plumbing decision (the ADR fixing `docs/frozen_parameters.md` items 4/6) and verified at **G-15**. |
| `payload_digest` | `LabelAssertion` | **(c) deferred.** §A.6 resolves label assertions **by payload digest**, but the payload domain is a data **value** (not necessarily a JSON object), so `H_JCS` MUST NOT be assumed; the construction is settled by the same F4 label-plumbing decision (frozen-parameters items 4/6 ADR; exercised at G-15). |
| `payload_digest` | `DeclassificationArtifact` | **(c) deferred** — same disposition; it is a join key against `LabelAssertion.payload_digest` and MUST share that construction. |
| `payload_digest` | `ToolIngressEvent` | **(c) deferred** — same disposition and same join-key constraint. |
| `payload_digest` | `EffectEvent` | **(c) deferred** — same disposition and same join-key constraint. |

Adjacent digests **not** in `schema.py`, for completeness: `capability_hash` /
`prefix_hash` / `child_block_hash` are **(b)** — the §A.0.1 BlockID commitment (ADR 0003);
`access_token_hash = H(AT@aud)` and `label_assertions_digest` (INV fields, §F.2) and
`authz_context_hash` (approval artifact, §F.2) are **(c)** — fixed when INV/HTC are built and
mutation-tested (**G-11**).
*(Update, 2026-07-29: at G-11, **`access_token_hash` was fixed by ADR 0018** — the same tagged,
versioned, length-delimited family under the new tag `b"AASC-AT-DIGEST"`, over the presented token's
ASCII bytes, rendered lowercase hex, with a test pinning it distinct from both `ath` and `H_JCS`.
`label_assertions_digest` and `authz_context_hash` **remain (c)**: both depend on the F4 label
vocabulary and allowed-sink policy (`frozen_parameters` rows 4/6, still UNSET) and are verified at
**G-15**, so G-11 could not honestly close them and did not. This row's classification stands; only
the first of the three fields has been settled.)*

### D21 obligation (explicit)

`src/harness/oracle/jcs_digest.py` is **oracle-side**. The SUT-side computation must be written
**independently later** (when the B3 arm's INV signer is built); the oracle must **never**
consume a SUT-computed digest (§F.1; PROJECT_RULES.md red line 4). The Part I F3 predicate always
recomputes `H_JCS(obs.raw_arguments)` from raw bytes.

## Status

accepted — 2026-07-26

## Consequences

- Unblocks the `INV.canonical_request_digest == H_JCS(raw_arguments)` check (§F.2) and the
  Part I `realized_harm_F3` predicate: both now have a byte-precise, independently
  reimplementable definition.
- `H_JCS` is a **design constant, not a seal-time parameter**: TAG and VERSION are fixed by
  this ADR and carried in the architecture document and the oracle code, both of which the
  v0.5 candidate manifest already hashes (Part H step 3). No genuine seal-time dependency was
  found, so **no row is added** to `docs/frozen_parameters.md`.
- Fixture authors inherit ADR 0005's constraint through `H_JCS`: integer arguments stay within
  `±(2^53 − 1)`; out-of-model input fails closed at canonicalisation.
- §F.2 and Part I point at this construction; `schema.py` field comments carry the
  classification; `smoke/g8/REPORT.md` §9 records the gap as closed (dated line; the gate's
  findings and PASS record unchanged) — same pass.
- The regression suite computes digests through `h_jcs` (module, not test-local code) and adds
  construction tests: layout known-answer + domain-separation non-vacuity, version fail-closed,
  output shape, cross-process determinism.
