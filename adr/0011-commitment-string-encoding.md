# 0011 — Commitment-family string encoding is lowercase hex; `P_hashes` classified

## Context

Two gaps surfaced in the ADR 0009 review, both in how the ADR 0003 commitment family meets the
string-typed schema fields of `src/harness/schema.py`. First, the ADR 0009 classification table
covered every digest field except `IntendedInvocation.P_hashes: list[str]`, which carries
`H(P_0)..H(P_n)`. Second, `commitment.py` returns **raw bytes** (`digest.digest()`), while every
schema field that carries one of these values is typed `str` — the byte→string rendering was
never fixed anywhere. This ADR closes both; it **extends** ADR 0003/0009 and re-opens neither.

## Decision

[DESIGN] **1. `P_hashes` classification.** `IntendedInvocation.P_hashes` is disposition **(b)**
in the ADR 0009 scheme: governed by a different construction — the §A.0.1 **BlockID prefix
commitment** (ADR 0003, `commit_prefix(BlockID_0..BlockID_i)`), not `H_JCS`. Each list element
is the commitment for one prefix, rendered per item 2 below.

**Field-by-field re-check of `schema.py`** (everything the ADR 0009 table did not classify):
`P_hashes` was the **only** missed hash-bearing field. All remaining unclassified fields carry
no digest: `correlation_id`/`effect_id`/`value_id`/`jti` are minted identifiers,
`issuer_kid`/`approver_kid`/`htc_holder_kid` are key identifiers, `raw_key_ref`/`approval_ref`
are references, `signature` fields are signatures, and `raw_at`/`signed_blocks`/`htc_chain`/
`invocation_assertion`/`inv_only`/`raw_arguments`/`approval_artifact`/`dpop_proof` are raw
evidence bytes (kept as bytes by design — the oracle recomputes digests from them, §F.1).

[DESIGN] **2. Commitment-family string encoding.** Wherever a commitment-family value — a
`commit_prefix`/`commit_ids`/`capability_commitment` output, or a `BlockID` — is rendered as a
string, the rendering is **lowercase hexadecimal**, matching `H_JCS` (ADR 0009) so the whole
digest surface uses one rendering. This covers `P_hashes` now and, when they are built at G-11,
the string carriage of `INV.capability_hash`, HTC `prefix_hash`, and HTC `child_block_hash`
(`BlockID`s already surface as lowercase hex via the pinned library's `revocation_ids`
**[VERIFIED, gate G-1: the spike and suite parse them with `bytes.fromhex`]**).

**Failure prevented** (why this must be frozen rather than left to convention): if the SUT side
rendered base64url while the oracle rendered hex, the `INV.capability_hash` equality check
(§F.2) would fail **on correct inputs** and reject honest requests — the same class of
false-rejection defect the G-1 corrective pass removed when it replaced the encoding-sensitive
raw-byte commitment **[VERIFIED, ADR 0003: a semantically equivalent re-encoding changed the
committed bytes and would have falsely rejected a legitimate request]**.

**No helper is added.** Nothing in the current codebase consumes a hex-rendered commitment
(the comparisons built so far are bytes-to-bytes); a rendering helper would be dead code. When
G-11 builds the HTC/INV verifier, the rendering is one expression (`.hex()`) governed by this
ADR. `commitment.py`'s byte-returning surface is unchanged.

## Status

accepted — 2026-07-26

## Consequences

- The ADR 0009 classification is complete over `schema.py`: every digest field has exactly one
  disposition; `P_hashes` is (b) → ADR 0003, hex-rendered.
- One digest-rendering rule project-wide: lowercase hex (H_JCS by ADR 0009; the commitment
  family by this ADR). No base64url anywhere on the digest surface.
- `schema.py` comment on `P_hashes` updated; registered in Part B.2 (same commit).
- G-11's HTC/INV verifier and the corpus generator inherit the rule; a mismatch found there is
  a defect, not a convention choice.
