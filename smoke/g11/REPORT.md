# Gate G-11 Report — the HTC/INV verifier and the mutation suite

**Outcome: PASS.** All fourteen named mutations are rejected, each for the condition it targets, and
both positive arms pass — including the `n = 0` zero-hop case. Run 2026-07-29 on Windows;
`smoke/g11/spike.py` exit 0, six mandatory checks; regression suite `tests/test_holder_binding.py`,
57 tests.

The pass also closes two G-4 residuals: **L4** (`INV.access_token_hash`, ADR 0018) and **L3**
(`actor→holder` against the **frozen** registry, ADR 0019). G-4's PASS was recorded as *"not a full
four-limb closure"*; it is now complete.

**IA-3 is untouched and remains `[UNVERIFIED-IA]` for G-3.** This gate establishes holder-binding
**correctness**, not that verification fits under the equivalence margin.

## 1. Gate

The Part G G-11 row, reproduced exactly, not paraphrased:

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-11** | HTC mutations: wrong-signer, parent-swap, child-swap, depth-rollback, capability-swap, terminal-key-mismatch, domain-tag confusion (HTC bytes replayed as INV), expired/`nbf`-violating cert; **plus the commitment-layer mutations: block reordering, truncation, container re-encoding, missing HTC coverage, unsupported commitment version, unsupported algorithm** | Each **rejected**; the valid chain (including the `n=0` zero-hop case) passes. Commitment-layer status: reordering, truncation, re-encoding, coverage, version, and algorithm rejection are already **[VERIFIED]** at the commitment layer by the ADR 0003 regression suite (tests 1–8); G-11 proper re-tests them through the full HTC/INV verifier once implemented | IA (HTC correctness); H4a |

What rides on it, in the row's own words: **IA (HTC correctness); H4a.** If a mutation that should be
rejected is accepted, the holder-binding claim has no floor.

## 2. The specification read, and what was underspecified

§F.2 was read in full — the `HTC_0`/`HTC_i`/`INV` templates field by field, the domain tags
`"AASC-HTC-v1"`/`"AASC-INV-v1"`, the `H_JCS` paragraph, the **zero-hop rule**, the complete
**Verification (MUST all hold)** list including `check_htc_coverage` and the
HTC-count-equals-block-count rule, and *"Why HTC is separate from Biscuit"* `[VERIFIED]`. Then
§F.2.1, §F.3, §A.0.1 / ADR 0003, ADR 0009 (the digest family, the tag rules, the category-(c)
classification), ADR 0002, the Part G G-11 row verbatim, and `smoke/g4/DESIGN.md` §9 C2/C3 with §10
rows L3/L4.

**Five points were underspecified or in tension.** None was filled by assumption.

1. **§F.2 fixes the signature's tag and version prefix but not the serialization of the rest.**
   Nothing can be signed without resolving it. Resolved as `TAG ‖ VERSION ‖ u32be(len(C)) ‖ C` with
   `C` the RFC 8785 canonical payload bytes — consistent with every other frozen layout in the
   project — and recorded in **ADR 0018 §2**. The choice is load-bearing, not cosmetic: because the
   tag is inside the signed bytes, a payload signed in the HTC domain cannot verify in the INV
   domain, which is the property the domain-tag-confusion mutation tests.

2. **`access_token_hash` had no construction.** ADR 0009 category (c), with a §9 C2 proposal that
   code was forbidden to treat as settled. **Adjudicated in ADR 0018 §1** — the proposal adopted
   unchanged, with the input defined as the token *as presented* and a non-ASCII byte failing closed.

3. **ADR 0009 assigns three category-(c) fields to G-11, and only one of them can honestly be fixed
   here.** `label_assertions_digest` and `authz_context_hash` both depend on the F4 label vocabulary
   and allowed-sink policy (`frozen_parameters` rows 4 and 6, both **UNSET**), their verification is
   **G-15**'s, and the approval-artifact arm is out of scope (STEP 1 item 6). They stay deferred and
   are named as such. `label_assertions_digest` is therefore **bound by the INV signature but not
   recomputed** — tampering with it is caught as `inv_signature`, while the verifier claims nothing
   about its construction. The `ApprovalArtifact` is likewise out of scope: it appears in §F.2 as a
   template, and **no condition in §F.2's verification paragraph refers to it** (`approval_artifact_ok`
   is a separate §A.5 conjunct).

4. **The registry cannot be frozen *and* contain per-campaign key bytes.** §F.2.1 requires it frozen
   and hashed before sealing, yet holder keys derive from sealed seeds (ADR 0007). Resolved in
   **ADR 0019 §1**: the artifact fixes structure and derivation labels, `bind()` resolves them to
   keys at campaign start, and `H(R)` covers the structure and **not** the key values — the same line
   ADR 0016 drew for `Γ` and `κ`. A test asserts the artifact holds no key material.

5. **`HTC_0.prefix_hash` breaks the pattern of every later hop.** The template gives it as
   `commit_prefix(BlockID_0..BlockID_0)` — the commitment over block 0 *itself* — while hop `i ≥ 1`
   commits to the prefix ending at `i − 1`. Implemented as `max(index − 1, 0)`, a **formula rather
   than a branch**, so the zero-hop rule's "no separate code path" is not weakened by an index
   special case.

**A sixth point is a tension in the Part G row itself, not in §F.2 — see §5.**

**One field-shape note.** §F.1's `CapabilityEvidence.signed_blocks: list[bytes]` cannot support
ADR 0003's "recompute from raw bytes with independent chain verification" rule on its own, since
signature-chain verification needs the container. §F.2's verification paragraph settles it —
`INV.capability_hash == capability_commitment(**presented token**)`, "recomputed from raw bytes" — so
the verifier takes raw token bytes. Recorded because the two field descriptions read differently.

## 3. The `access_token_hash` adjudication

The §9 C2 proposal is **adopted unchanged** (ADR 0018): it already satisfied every constraint, and
inventing an alternative would have created a fourth layout to keep distinct for no gain.

```
TAG      = b"AASC-AT-DIGEST"   # 14 bytes; distinct from every tag in use
VERSION  = 0x01                # fail-closed on any other value; no algorithm byte
t        = the token as presented — its compact serialization, ASCII bytes

access_token_hash = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(t)) || t ) )
```

A **non-ASCII byte fails closed** (`NonAsciiTokenError`): a JWS compact serialization is base64url
and dots by construction, and encoding otherwise as UTF-8 would let two different byte strings
collide onto one digest.

**Worked example, with the three-way non-vacuity evidence:**

```
t (85 bytes):  eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ1c2VyLXlpeGlhbiJ9.c2lnbmF0dXJl
preimage:      b"AASC-AT-DIGEST" || 0x01 || 0x00000055 || t

access_token_hash:  600b4e6e581a15b4b3e847e093120ba87c6126851fd347f18994020c40010e13
ath (base64url):    qIcA6_GtjNdrUMTlUqgSAHevgGRlm8kqfAl7Nx-UUgw
H_JCS({"token":t}): 3b8b26a9c023f073f713af06ef67858ea2f22b89d087f95d0ce6a378c6a4f095
bare SHA-256(t):    a88700ebf1ad8cd76b50c4e552a8120077af8064659bc92a7c097b371f94520c
```

All four differ. The comparison against `ath` is the one that matters: it consumes the **identical
input bytes**, so only the domain tag and the output encoding keep them apart. That is why §9 C2
called the conflation a trap, and why a test pins the three-way distinctness rather than only the
separation from a bare digest.

## 4. The verifier

**Placement: `src/harness/verifier/`** — the instrument. `at_digest.py` (ADR 0018),
`registry.py` (ADR 0019), `holder_binding.py` (the §F.2 verification), and the frozen
`identity_registry_v1.json`.

**How D21 independence holds.** The verifier recomputes **every** digest it checks from raw evidence:
`capability_commitment` and `commit_prefix` from the raw token bytes via ADR 0003's
`commitment.py` (which independently verifies the signature chain before extracting any identifier,
and refuses third-party blocks and non-Ed25519 keys), `H_JCS` from the raw arguments, and
`access_token_hash` from the presented token. It compares those against the values *inside* the
signed objects and never consumes a SUT-computed digest. **Commitments are reused, not reinvented:**
there is no second notion of "the prefix" anywhere in the package. The obligation still owed is
recorded plainly — the B3 arm's **SUT-side** INV signer must be an independent implementation, and
`build_htc_chain`/`build_inv` here are **fixture** constructors, not that signer.

**The named checks.** Every §F.2 condition is a separate check with its own reason code, so a
rejection is attributable: `capability_chain_invalid`, `commitment_unsupported_version`,
`commitment_unsupported_algorithm`, `htc_chain_empty`, `htc_schema`, `htc_coverage_count`,
`htc_unsupported_schema_version`, `htc0_signer_is_root`, `htc0_root_signature`, `htc_chain_linkage`,
`htc_signature`, `htc_task_invariant`, `htc_audience_invariant`, `htc_depth_contiguous`,
`htc_exp_non_increasing`, `htc_validity_window`, `htc_prefix_hash`, `htc_child_block_hash`,
`registry_unmapped`, `registry_key_mismatch`, `inv_schema`, `inv_unsupported_schema_version`,
`inv_terminal_holder`, `inv_signature`, `inv_capability_hash`, `inv_access_token_hash`,
`inv_request_digest`, `inv_task_binding`, `inv_audience_binding`, `inv_method_binding`,
`inv_tool_binding`, `inv_validity_window`. Verification is fail-closed: the first failing condition
raises.

**The zero-hop rule, and the test that no branch keys on `n == 0`.** Two independent assertions,
because the obvious formulation of the first one turned out to be wrong:

- **Behavioural.** The invariant is **not** "the same checks run at `n = 0` and `n = 2`" — five
  conditions (`htc_chain_linkage`, `htc_signature`, `htc_task_invariant`, `htc_audience_invariant`,
  `htc_exp_non_increasing`) are inherently about a hop `i ≥ 1`, and a one-element chain has no such
  hop to compare against. The real invariant is that **no check runs only in the zero-hop case**:
  measured as **∅**, with the difference being exactly those five. At `n = 0`, 25 distinct checks
  run, so the case is substantively verified rather than waved through.
- **Structural.** An AST scan of `holder_binding.py` finds **no** branch whose test compares a chain
  length against 0 or 1, and no `n == 0`. Two constructs are deliberately permitted and are distinct
  from a zero-hop path: `if not evidence.htc_chain` rejects an **empty** chain (zero HTCs, whereas
  `n = 0` means **one**), and six branches key on the **hop index** (`index == 0`), which the template
  requires because `HTC_0` is signed by `κ` and carries `depth: 0`.

## 5. The fourteen mutations

Thirteen HTC constructions over the eight named families (three families are tested in more than one
form, for reasons given below), plus the six commitment-layer mutations.

### The eight HTC families

| Mutation | Reason code | Would-have-failed world |
|---|---|---|
| wrong-signer — unauthorized key signs, `signer_pubkey` untouched | `htc_signature` | an agent that never held the capability could mint a hop and be treated as its holder |
| wrong-signer — `signer_pubkey` rewritten so the attacker's signature verifies | `registry_key_mismatch` | a self-consistent hop spliced in by a key the previous holder never named |
| wrong-signer — a **registered** holder signs out of turn | `htc_chain_linkage` | an earlier hop's holder could insert itself mid-chain, so the chain no longer reflects who held the capability at each step |
| parent-swap — `HTC_2.prefix_hash` replaced | `htc_prefix_hash` | a hop could be re-parented onto a different capability prefix than the one presented |
| child-swap — `HTC_1.child_block_hash` points at another block | `htc_child_block_hash` | an HTC could cover a different attenuation block than the one it was issued for |
| depth-rollback — `HTC_2.depth` set to 1 | `htc_depth_contiguous` | a deeper chain could masquerade as a shallower one, hiding an intermediate hop |
| capability-swap — a different token presented | `htc_prefix_hash` | the holder chain could be replayed over a capability it was never issued against |
| capability-swap — HTCs match the token, INV binds another | `inv_capability_hash` | an INV issued for one capability could authorize a call carrying another |
| terminal-key-mismatch — INV signed by a non-terminal holder | `inv_terminal_holder` | a spent hop's holder could sign invocations after delegating onward |
| domain-tag confusion — valid INV payload signed in the **HTC** domain | `inv_signature` | a signature made for one object type would authenticate the other, collapsing the HTC/INV distinction §F.2's domain separation exists to enforce |
| domain-tag confusion — literal HTC bytes in the INV slot | `inv_schema` | an HTC accepted as an INV would bind no request at all |
| expired cert | `htc_validity_window` | a delegation could be exercised indefinitely after its certificate lapsed |
| `nbf`-violating cert | `htc_validity_window` | a certificate could be used before it became valid |

**Two of these expectations were wrong on the first run, and one revealed a masked check.** Recorded
because the correction is the substance:

- **`wrong-signer` with `signer_pubkey` rewritten** rejects as `registry_key_mismatch`, not
  `htc_chain_linkage` as first expected. The identity plane catches it one condition **earlier**: the
  key presented is not the registered holder key for the `kid` claimed, and an attacker key is in no
  registry entry at all (§F.2.1's "unmapped keys are rejected"). That is a correct and more specific
  rejection — but it meant **`htc_chain_linkage` was never genuinely exercised**, because the registry
  always fired first. A third construction was added to isolate it: a **registered** holder signing
  out of turn, with `kid` and `signer_pubkey` mutually consistent so the registry check passes and
  only linkage can catch it. Without that case the linkage condition would have been masked, and a
  masked check is not a pass.
- **`capability-swap` with a different token** rejects as `htc_prefix_hash`, not
  `htc_child_block_hash`: the prefix commitment is checked first. The second form was already in the
  suite to isolate `inv_capability_hash`, so both conditions are exercised.

### The six commitment-layer mutations

Two facts, kept distinct as the row requires: these are **already `[VERIFIED]` at the commitment
layer** by the ADR 0003 regression suite (tests 1–8), and G-11 **re-tests** them through the full
HTC/INV verifier. Nothing here is presented as a first verification.

| Mutation | Through the verifier | Already established by ADR 0003 |
|---|---|---|
| block reordering | `capability_chain_invalid` | `test_block_reordering_fails_closed` |
| truncation | `capability_chain_invalid` | `test_truncation_fails_closed` |
| container re-encoding — **content changed** | `capability_chain_invalid` | `test_mutation_fails_closed` |
| container re-encoding — **semantically equivalent** | **ACCEPTED**, commitment unchanged | `test_commitment_is_encoding_independent` |
| missing HTC coverage | `htc_coverage_count` | `test_missing_htc_coverage_fails_closed` |
| unsupported commitment version | `UnsupportedVersionError` | `test_unsupported_version_fails_closed` |
| unsupported algorithm (real Secp256r1 token) | `commitment_unsupported_algorithm` | `test_unsupported_algorithm_fails_closed` |

**A tension in the Part G row, reported rather than fudged.** The row lists "container re-encoding"
among mutations that must "each be **rejected**". For a **semantically equivalent** re-encoding that
is the opposite of what the design requires: ADR 0003's central verified property is that such a
re-encoding yields the **same** commitment and must be **accepted**, because rejecting it is exactly
the false-rejection bug ADR 0003 was written to fix ("a semantically equivalent re-encoding by any
intermediary would change the bytes, mismatch `H(P_n)`, and **falsely reject a legitimate
request**"). In ADR 0003's own suite the re-encoding test is an *accept* case, so the row's blanket
phrase is imprecise for that one member of the list, and ADR 0003 is authoritative on the correct
behaviour.

Resolved by testing both halves: an equivalent re-encoding is **accepted** with the commitment
**unchanged**, and a re-encoding that changes a block's **content** is **rejected** at chain
verification. **The Part G row was not edited** (STEP 1 item 1 forbids it). This does not block the
PASS: the verifier behaves correctly, and every mutation that genuinely must be rejected is rejected.

**On the unsupported-algorithm case:** the Secp256r1 token is **accepted by the library** and refused
by the commitment layer, so the Ed25519 mandate (D8) is project-enforced rather than inherited — the
same load-bearing pattern G-4 found for third-party blocks. **On the version case:** the verifier
pins commitment version 1 and threads **no** version from input, so it cannot be talked down to
another; a test asserts that by inspecting its `commit_prefix` call sites.

### Both positive arms

The valid chain verifies at **`n = 2`** (51 checks, 30 distinct) and at **`n = 0`** (25 checks, 25
distinct) — the zero-hop case the row names explicitly. Without these the suite would prove only
that the verifier rejects things.

## 6. The frozen identity-plane registry

Artifact `src/harness/verifier/identity_registry_v1.json` (ADR 0019),
`H(R) = d1bfc5ffcb22e2ded736f5248b99b9f019ba314b93ddd808e50ea522b3fb4cbe` over 2302 canonical bytes.

| Entry | `kid` | Necessity |
|---|---|---|
| AS root | `kid-as-root` | §F.2: `HTC_0` is signed by `κ` and carries `kid_AS`; §F.2's verification resolves **every** `kid` through the registry |
| supervisor | `kid-holder-supervisor` | the first delegating hop of the golden thread; a chain of depth ≥ 1 cannot exist without it |
| specialist | `kid-holder-specialist` | the delegate and the terminal holder at two hops, so it is the key INV must be signed by; also the second principal F2 needs to distinguish from |
| worker | `kid-holder-worker` | a third principal, so depth-2 chains have a real nested `act` history and `depth` contiguity is exercised over more than one increment |

The loader **rejects** an entry whose `necessity` is missing, so the column cannot rot. Encoding is
fixed (US-ASCII lowercase principals; `agent-` prefixed actor claims; `kid`s unique across the whole
registry, since `kid` is a key selector and a duplicate would make it ambiguous; base64url unpadded
raw Ed25519 on the wire; byte-exact comparison). `H(R)` is non-vacuous — it differs from the bare
SHA-256 of the same canonical bytes **and** from `H_JCS` of the same document — is invariant to member
reordering, and changes when a principal, an actor mapping or a resource owner is added.

Verified behaviour: three principals with **exactly one** holder key each; an unmapped actor
**rejected**; an unmapped holder **key** rejected (§F.2.1 requires both, so the reverse lookup is a
first-class operation); `binding` refused when two principals would share a key; resource owners
recorded and absent from the holder mapping.

**The line I did not cross.** This registry is the **actor→holder mapping only**. It is **not** the
`task_authorization_policy` (task → authorized actor principals), which is `frozen_parameters` **row
5** and stays **UNSET** — so the F2 `wrong_principal` family stays **unscored** and G-4's `may_act`
stand-in stays a stand-in. The artifact carries that boundary in a `scope_boundary` field, and a test
asserts the document mentions no task policy, contains no `may_act`, and that row 5 is still UNSET.

**Only its own row was set:** row **11**. Rows 1–7, 9 and 10 are untouched, and row 8 with the
`Ω`/`Γ` artifact is byte-unchanged.

## 7. G-4's residuals closed

- **L4.** `INV.access_token_hash == H(presented AT@aud)` verified **through the real verifier**, and a
  swapped token rejected as `inv_access_token_hash`. G-4 Phase 2 could only show that the presented
  byte string was observable and stable, because no construction existed (§9 C2) and INV did not
  exist; both now do.
- **L3.** The `actor→holder` limb re-run against the **frozen** registry rather than the C3 stand-in:
  `actor_of("agent-specialist")` → `specialist` → exactly one holder key. The negative test still
  holds — no resource owner is a holder or an actor (§A.5.1 MUST NOT). The outcome is unchanged, which
  is the useful result: it confirms the stand-in had not flattered the finding.

The record shows the **sequence** rather than back-dating the closure: G-4's report keeps its original
L4 and L3 text and carries a dated update note naming G-11 as the closing gate, its board row and the
§F.4 IA-4 cell say the limb was open and is now closed **by G-11**, and `smoke/g4/DESIGN.md` §9 C2/C3
each carry a dated closure note rather than a rewrite.

## 8. Outcome and grades

**G-11 PASSES.**

`[VERIFIED]` for **this verifier** (`src/harness/verifier/`, Ed25519 via `cryptography`,
`rfc8785==0.1.4`, `biscuit-python==0.4.0`): the §F.2 HTC chain and INV assertion verify as specified
with every MUST as a separately named check; all fourteen named mutations are rejected for the
condition each targets; domain separation is load-bearing in **both** directions; the zero-hop case
flows through the same code as a two-hop chain with no branch on the chain length; the frozen registry
resolves actors and keys to exactly one principal and rejects unmapped ones; and
`access_token_hash` is distinct from `ath`, from `H_JCS` and from a bare digest.

**The IA for HTC correctness is verified by gate G-11**, scoped to this build and these frozen
artifacts.

**IA-3 remains `[UNVERIFIED-IA]`, for G-3.** Correctness is not cost: nothing here measures whether
verification fits under the equivalence margin, and no timing figure appears in this report.

What remains `[DESIGN]`: the constructions this gate fixed are project decisions (ADR 0018/0019), and
everything §9 lists.

## 9. Residual risks

- **`label_assertions_digest` and `authz_context_hash` are still category (c)** — deferred to the F4
  label-plumbing decision (rows 4/6) and **G-15**. The INV signature covers the former, so it is
  tamper-evident, but its construction is unfixed and the verifier claims nothing about it.
- **The `ApprovalArtifact` is unbuilt.** It is a §F.2 template with no condition in that section's
  verification paragraph; `approval_artifact_ok` is a separate §A.5 conjunct owned by the approval arm
  and G-15.
- **Row 5 is UNSET**, so F2 `wrong_principal` stays unscored.
- **The SUT-side signer is owed** (D21). This gate delivers the instrument-side verifier only; the B3
  arm's INV signer must be independent, and G-13 checks the two layers agree.
- **`H(R)` does not cover key values**, deliberately — holder keys are per-campaign material sealed at
  Part H step 3 (ADR 0007). Substituting a key set is caught by the seal, not by `H(R)`.
- **Amendment re-triggers.** Amending the registry re-triggers G-11 and G-4's `actor→holder` limb;
  amending `Ω`/`Γ` re-triggers G-2 and G-4's effective-authority limb (ADR 0016).
- **Exact pins.** A `biscuit-python` bump re-triggers G-1/G-2 and the commitment analysis; an
  `rfc8785` bump re-triggers G-8. The Biscuit format remains **not formally audited** (ADR 0002).
- **No revocation.** Nothing here consults a revocation list; `BlockID_i` *is* the Biscuit revocation
  identifier, but revocation semantics are not part of this design.
- **Replay.** The INV carries `invocation_id` (jti) and a window, and the verifier enforces the
  window — but the **jti cache** that makes single-use meaningful is B3⁺ and **G-9**.

## 10. What this gate does NOT establish

- **Not timing.** IA-3 and the equivalence margin are **G-3**, whose threshold must be fixed
  externally first. No figure here is a measurement.
- **Not `Allowed(AT_i) = C_i`** across baselines, nor matched per-hop authority — **G-13**.
- **Not the four-way DPoP taxonomy** — **G-14**. §F.2's INV binds method/tool/arguments; DPoP binds
  method and URI only, and the two must not be conflated.
- **Not the F4/F5 reference monitor** — **G-15**, which also settles the two deferred digests.
- **Not the arms, agents, protocol adapters, fixtures, or the oracle predicates** (Part I).
- **Not `holder_proof_ok` at a live boundary**: this gate verifies presented evidence; wiring it into
  the arms' enforcement path belongs to the arm build and G-13.
- **No `frozen_parameters` row other than 11** was set; rows 1–7, 9 and 10 remain UNSET.

## 11. Reproduction

```
uv sync --frozen
uv run python smoke/g11/spike.py            # exit 0; six mandatory checks
uv run pytest -q tests/test_holder_binding.py   # 57 tests
```

The regression suite is the durable form of this gate and is **platform-independent** — pure signing
and hashing, so unlike the Windows-only effect-ledger tests (ADR 0014) it must pass on Linux CI too.
**The spike is also run by CI** (`Gate G-11 spike (cross-platform)`), the way G-4's was added, so the
claim is confirmed rather than assumed.
