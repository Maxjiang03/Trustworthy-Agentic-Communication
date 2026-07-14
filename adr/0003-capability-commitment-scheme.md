# 0003 — Capability commitment scheme: versioned commitment over signature-derived BlockIDs

## Context

Gate G-1's PASS (ADR 0002) rested on an `H(P_i)` computed over the **raw protobuf bytes** of the
Biscuit container (fields 2 + 3, excluding the proof field 4). **Protobuf is not a canonical
encoding**: the same semantic message admits multiple valid byte encodings — fields may appear in
any order on the wire, varints may be non-minimal, length-delimited fields may be re-emitted
differently. The commitment therefore bound an **encoding**, when the property the design needs
is a commitment to **which blocks are present and in what order**. A semantically equivalent
re-encoding by any intermediary would change the bytes, mismatch `H(P_n)`, and **falsely reject a
legitimate request**. The spike's `re-serialization byte-identical=True` was a property of this
library's encoder, not a guarantee of the format.

**Falsification, demonstrated (test 1 of the regression suite):** for one token, three
semantically equivalent re-encodings (top-level field reorder; SignedBlock-internal field
reorder; non-minimal inner varint) were built by a test-local re-encoder. The library parsed and
verified **all three**; the BlockID commitment was **identical** across all four encodings
(`0f31ccf3299f2bb0cb60cf940ee8bae93a2fea8f2cb9a0a36c1d6e7520950245`); and the superseded raw-byte
hash **differed** for the two re-encodings that touch committed bytes
(`1d2b8af6…` → `09daddc9…` / `65a6c702…`). The unsoundness is real, not theoretical: the pinned
decoder accepts re-encoded containers.

## Decision

[DESIGN] Replace the raw-byte commitment with a **versioned, domain-separated, length-delimited
commitment over the ordered signature-derived block identifiers**, implemented oracle-side in
`src/harness/oracle/commitment.py`:

```
TAG      = b"AASC-CAP-COMMIT"   VERSION = 0x01   ALG = 0x01 (Ed25519 only)
commit(BlockIDs[0..i]) = SHA-256( TAG || VERSION || ALG || u32be(i+1)
                                  || u32be(len(BlockID_0)) || BlockID_0 || … )
H(P_i)                 := commit_prefix(BlockID_0..BlockID_i)
H(SignedBlock_i)       := BlockID_i          (HTC child_block_hash)
INV.capability_hash    := capability_commitment(P_n)
```

Unsupported version or algorithm values **fail closed** (raise; no commitment computed). The
extractor `block_ids_from_raw` starts from **raw token bytes + the root public key**, performs
independent chain verification, rejects non-Ed25519 keys (root key by serialized length — raw
Ed25519 keys are 32 bytes, SEC1-compressed P-256 is 33; every carried `nextKey` by its wire
algorithm enum) and rejects third-party/external-signature blocks (out of the MSc profile,
§A.6.1). It never accepts a parsed object or a caller-supplied digest.

**What `BlockID_i` is** [VERIFIED, Biscuit SPECIFICATIONS.md]:

- `BlockID_i` is block `i`'s **signature** — the Biscuit **revocation identifier**: *"The
  revocation identifier for a block is its signature (as it uniquely identifies it)"*
  (SPECIFICATIONS.md, "Revocation identifiers"). Confirmed empirically: the library's
  `revocation_ids` equal the wire `SignedBlock.signature` bytes, byte-for-byte (64-byte Ed25519
  signatures).
- Under **block signature payload v0** (what biscuit-rust 6.0.0 emits — the `SignedBlock.version`
  field is absent), the signature covers `data_i ‖ pk_{i+1} ‖ alg_{i+1}`: the block's serialized
  Datalog, the carried next public key, and its algorithm. Payload **v1** additionally covers
  domain-separation tags and `sig_{i−1}` (`\0PREVSIG\0`), strengthening position binding in the
  payload itself; a library upgrade re-triggers G-1 (0.x pin) and re-verifies this analysis.

**Properties (1)–(4), and which test verifies each:**

| # | Property | Verified by |
|---|---|---|
| 1 | Derived from the block signature → block content + carried next key (+ `sig_{i−1}` under payload v1) | spec citation above; `revocation_ids` ≡ wire signatures (probe + suite) |
| 2 | Stable under append: `BlockID_i` (i < n) unchanged when block n+1 is appended | `test_append_preserves_all_prior_prefix_commitments` (depth 3) |
| 3 | Binding to content: mutating a block fails verification closed, no commitment produced | `test_mutation_fails_closed` |
| 4 | Binding to position: reordering blocks breaks signature-chain verification (block i verifies under the key carried in block i−1) | `test_block_reordering_fails_closed` |

Encoding-independence is verified by `test_commitment_is_encoding_independent`; fail-closed
version/algorithm handling by `test_unsupported_version_fails_closed` /
`test_unsupported_algorithm_fails_closed` (including a real Secp256r1-minted token, which the
library verifies but the commitment layer rejects); truncation and HTC-coverage by
`test_truncation_fails_closed` / `test_missing_htc_coverage_fails_closed`; process-separated
verification by `test_signer_and_verifier_are_separate_processes`; non-vacuity by
`test_no_assertion_passes_vacuously`.

## Status

accepted — 2026-07-14; **supersedes the commitment definition adopted in ADR 0002 on that point
only** (ADR 0002's library selection and seal decision stand).

## Consequences

- `§A.0.1` (commitment rule), `§F.2` (HTC/INV field definitions + `check_htc_coverage`
  cross-reference), Part B.2 D22 wording, and the Part G G-1 / G-2 / G-11 rows are updated in the
  same pass — never silently.
- **Forward commitment (open obligation, D21):** at implementation time the **SUT-side** and
  **oracle-side** commitment computations must be **independent implementations**; the oracle
  must never consume a SUT-computed commitment. This pass delivers the oracle-side implementation
  plus a subprocess-separated verifier path (test 9); the independent SUT-side implementation is
  due when the SUT is built.
- G-1 is **CONDITIONAL PASS** from the moment the unsoundness was recognised and returns to
  **PASS** only with every corrective test green (the flip is a separate commit).
- Residuals unchanged from ADR 0002: the 0.x pin re-triggers G-1 on any bump; the Biscuit format
  is not formally audited (disclosed limitation).
- A related, non-blocking observation for Part H planning (no repository change in this pass):
  token bytes are not reproducible across builds even with a seeded root key, because block-level
  single-use keys are generated inside the library. Evidence and analysis live in the corrective
  pass report only.
