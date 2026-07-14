# SMOKE_G1_CORRECTIVE_TASK — G-1 corrective pass (commitment scheme)

**Read this file completely, then execute it exactly. Stop at the end and wait for Commander review.**

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`. **Working rules:** `CLAUDE.md`.

---

## STEP 0 — Why this pass exists, and the immediate status change

The G-1 PASS granted in the previous session rests on an **unsound commitment**. `H(P_i)` was implemented as a hash over the **raw protobuf bytes** of the Biscuit container (fields 2 + 3, excluding the proof field 4). Protobuf is **not a canonical encoding**: the same semantic message admits multiple valid byte encodings (fields may appear in any order on the wire; varints may be non-minimal; length-delimited fields may be re-emitted differently). Consequently:

- a **semantically equivalent re-encoding** by any intermediary yields **different bytes** → `H(P_n)` mismatch → a **legitimate request is falsely rejected**; and
- more fundamentally, the commitment binds an **encoding**, when the property the design needs is a commitment to **which blocks are present and in what order**.

The spike's observation that `re-serialization byte-identical=True` is a property of **this library's encoder**, not a guarantee of the **format**, and it does not bind a component elsewhere in the path that re-encodes.

**Action, immediately and before any other work:** set G-1 to **`CONDITIONAL PASS`** on the status board and in `smoke/g1/REPORT.md`, reason: *commitment scheme unsound (raw protobuf bytes); corrective pass in progress; ADR 0003*. G-1 returns to **PASS only when every corrective test in STEP 4 passes.**

---

## STEP 1 — Strict boundaries

| Forbidden                                                    |
| ------------------------------------------------------------ |
| Do **not** edit Part H or any confirmatory-corpus rule       |
| Do **not** generate or inspect confirmatory fixtures         |
| Do **not** define or freeze `Ω` or `Γ`                       |
| Do **not** run G-2, G-4, G-5, G-8, or any later gate         |
| Do **not** reorder the gate DAG                              |
| Do **not** open an upstream PR                               |
| Do **not** implement HTC signing/verification, INV, baselines, mediation, or the OAuth arms. The coverage check in this pass is a **count check over BlockIDs against a supplied HTC count**; it does not sign or verify HTCs. |
| Do **not** `git push --force`                                |

**On Part H:** you may **not** change the repository. If you judge the token-non-reproducibility issue to be independently blocking, include **only an evidence appendix** in your final report (STEP 10): the exact reproducer, raw command and output, and a **seed-visibility / secret-exposure analysis**. No files, no commits, no doc edits for Part H.

---

## STEP 2 — Establish what `BlockID_i` actually is (verify; do not assume)

Determine from the **Biscuit specification** (biscuitsec.org / the format spec / `schema.proto`) and from the library what a per-block identifier is derived from. Record the answer with a citation in ADR 0003.

You must establish, for the identifier you choose:

1. **What it is derived from** — the block signature, and hence the block content, the previous block's signature (chain position), and the carried next public key?
2. **Stability under append** — `BlockID_i` for `i < n` is unchanged when block `n+1` is appended.
3. **Binding to content** — mutating a block changes its `BlockID`.
4. **Binding to position** — reordering blocks changes the identifiers, or breaks verification outright.

Candidates, in order of preference:

- the library's per-block **revocation identifiers** (`revocation_ids`), if the specification confirms they are signature-derived and satisfy (1)–(4);
- otherwise, a value **derived directly from the block signature** extracted from the verified token.

**If neither satisfies (1)–(4), stop and report.** Do not invent an identifier.

---

## STEP 3 — Implement the commitment (oracle-side, from raw evidence)

Create **`src/harness/oracle/commitment.py`**. It must take **raw token bytes** and the root public key and do everything itself. It must **never** accept a parsed object, a digest, or any value computed by a system under test.

**Scheme (project-owned; versioned, domain-separated, length-delimited):**

```
TAG      = b"AASC-CAP-COMMIT"     # fixed ASCII domain-separation tag
VERSION  = 0x01                    # any other value => FAIL CLOSED (raise)
ALG      = 0x01                    # 0x01 = Ed25519 only; any other value => FAIL CLOSED (raise)

commit(BlockIDs[0..i]) = SHA-256(
      TAG
   || VERSION
   || ALG
   || u32be(i + 1)                            # number of BlockIDs committed
   || u32be(len(BlockID_0)) || BlockID_0
   || u32be(len(BlockID_1)) || BlockID_1
   || ...
   || u32be(len(BlockID_i)) || BlockID_i
)
```

Public API (names indicative; keep them explicit):

```python
def block_ids_from_raw(token_bytes: bytes, root_pub) -> list[bytes]:
    """Independently verify the chain against root_pub, then extract the ordered
    BlockID_0..BlockID_n. Raises on any verification failure. NEVER trusts a
    caller-supplied parse or digest."""

def commit_prefix(block_ids: list[bytes], upto: int, *, version: int = 1, alg: int = 1) -> bytes:
    """Commitment over BlockID_0..BlockID_upto. Raises on unsupported version or alg."""

def capability_commitment(token_bytes: bytes, root_pub) -> bytes:
    """Terminal commitment: commit over all BlockIDs. This is H(P_n)."""

def check_htc_coverage(block_ids: list[bytes], htc_count: int) -> None:
    """Fail closed unless htc_count == len(block_ids). Count check only — this
    function does NOT sign or verify HTCs."""
```

**Replaces, in the design:**

- `H(P_i)` → `commit_prefix(block_ids, i)`
- `H(SignedBlock_i)` (the HTC `child_block_hash`) → `BlockID_i`
- `INV.capability_hash` → `capability_commitment(...)`

Reject the algorithm at extraction time: the design mandates Ed25519 (D8). The library also supports Secp256r1 — a token under any non-Ed25519 algorithm must **fail closed**, not be committed to.

---

## STEP 4 — Real pytest tests (`tests/test_capability_commitment.py`)

**Permanent regression tests**, not a spike. Every test carries a **positive arm and a negative arm** so no assertion can pass vacuously. Report the exact test count.

| #    | Test                                                 | Must prove                                                   |
| ---- | ---------------------------------------------------- | ------------------------------------------------------------ |
| 1    | `test_commitment_is_encoding_independent`            | Take a valid token. Produce a **semantically equivalent alternative encoding** of the outer container (re-emit top-level protobuf fields in a different order; and, separately, with a non-minimal varint). Assert the library still parses/verifies both and that the **commitment is identical**. **Also assert the old raw-protobuf-byte hash would have differed** — the demonstration that the correction was necessary. If the library **rejects** a re-encoding, report it as a finding (it reduces but does not eliminate the risk, since another component in a path need not use a strict decoder). *Negative arm:* a token with a genuinely different block yields a **different** commitment. |
| 2    | `test_append_preserves_all_prior_prefix_commitments` | Build a chain of depth **≥ 3** (`P_0 … P_3`). After each append, assert **every** prior prefix commitment `commit(P_0) … commit(P_{k-1})` is **unchanged**, and the **new terminal** commitment differs from the previous terminal. *Negative arm:* `commit(P_0) ≠ commit(P_1)`, so "unchanged" is not vacuous. |
| 3    | `test_mutation_fails_closed`                         | Flip a byte inside a block → independent verification **must fail**; no commitment produced. *Positive arm:* the unmutated token verifies and commits. |
| 4    | `test_truncation_fails_closed`                       | Remove the terminal block → verification fails **or** the commitment changes **and** `check_htc_coverage` fails against the original HTC count. *Positive arm:* the intact token passes both. |
| 5    | `test_block_reordering_fails_closed`                 | Reorder blocks in the container → verification **must fail** (the chain is signature-linked). If the library **accepts** a reordering, that is a **major finding** — stop and report. *Positive arm:* the correctly ordered token verifies. |
| 6    | `test_missing_htc_coverage_fails_closed`             | `n+1` BlockIDs with only `n` HTC entries → `check_htc_coverage` raises. *Positive arm:* `n+1` entries passes. |
| 7    | `test_unsupported_version_fails_closed`              | `commit_prefix(..., version=2)` raises; no commitment computed. *Positive arm:* `version=1` works. |
| 8    | `test_unsupported_algorithm_fails_closed`            | A token minted under **Secp256r1** (the library supports it) must be **rejected** at extraction — the design mandates Ed25519. *Positive arm:* an Ed25519 token is accepted. |
| 9    | `test_signer_and_verifier_are_separate_processes`    | The **signer** computes the terminal commitment in-process from the token it built. The **verifier** runs in a **separate Python process** (`subprocess`), receiving **only** the raw token bytes and the root public key (hex), and independently parses, verifies, extracts BlockIDs, and commits. Assert the two commitments are **equal**. *Negative arm:* hand the subprocess a **tampered** token → it must fail or produce a different commitment. |
| 10   | `test_no_assertion_passes_vacuously`                 | Guard against a degenerate `commit()` (e.g. one returning a constant): commitments over different BlockID sequences differ; an empty sequence differs from a one-element sequence; order matters (`[A,B]` ≠ `[B,A]`). |

**Do not weaken any test to make it pass.** If a property does not hold, stop and report it; that is the gate doing its job.

---

## STEP 5 — CI in the locked environment

- Ensure the new tests run under `pytest` in CI **with the locked environment** (`uv sync --frozen`), not an ad-hoc install.
- Confirm `biscuit-python==0.4.0` resolves from `uv.lock` (already pinned; this pass changes no pin).
- Run locally: `make lint` and `make test`. Both must be green.
- Record the exact commands, their **exit codes**, the **test count**, and the **raw relevant output** (do not paraphrase it).

---

## STEP 6 — ADR 0003

Create `adr/0003-capability-commitment-scheme.md` (status `accepted`).

- **Context** — G-1's PASS rested on a raw-protobuf-byte `H(P_i)`. Protobuf is not canonical; a semantically equivalent re-encoding changes the bytes, so the commitment was bound to an encoding rather than to the ordered set of blocks. State the falsification plainly, with the test-1 evidence.
- **Decision** — `[DESIGN]` Replace the raw-byte commitment with the **versioned, domain-separated, length-delimited commitment over ordered `BlockID_i`** of STEP 3. Record what `BlockID_i` is derived from, with the specification citation from STEP 2, and which of properties (1)–(4) are `[VERIFIED]` by which test.
- **Status** — `accepted — <date>`; **supersedes the commitment definition adopted in ADR 0002** (leave ADR 0002 in place, marked superseded **on that point only**; its library selection stands).
- **Consequences** —
  - `§A.0.1`, `§F.2`, Part G G-1, G-2 and G-11 are updated (STEP 7).
  - **Forward commitment:** at implementation time the **SUT-side** and **oracle-side** commitments must be **independent implementations**; the oracle must never consume a SUT-computed commitment (D21). This pass delivers the oracle-side implementation and a subprocess-separated verifier path; the independent SUT-side implementation is due when the SUT is built. Record as an open obligation.
  - Residuals unchanged from ADR 0002 (0.x pin re-triggers G-1; Biscuit not formally audited).

---

## STEP 7 — Documentation corrections

Quote each existing passage before editing so the diff is reviewable. Correct **every** place that still claims raw-protobuf canonical hashing, seal terminality, or a guarantee stronger than the evidence supports.

1. **`§A.0.1`.** Replace the hashing rule. `P_i` remains the *concept* (the ordered signed-block prefix), but its **commitment** is now `commit_prefix(BlockID_0..BlockID_i)` per STEP 3 — **not** a hash over raw container bytes. State explicitly: *protobuf is not a canonical encoding; commitments are taken over signature-derived block identifiers so that a semantically equivalent re-encoding yields the same commitment.*
2. **`§F.2`.** `HTC.prefix_hash := commit_prefix(BlockIDs, i−1)`; `HTC.child_block_hash := BlockID_i`; `INV.capability_hash := capability_commitment(...)`. Keep the HTC-count-coverage conjunct added previously and cross-reference `check_htc_coverage`.
3. **D22 (Part B.2).** The inline entry still reads `seal-only-terminal **[VERIFIED]**`. That overstates the evidence: sealing is a property of the **format**, it is **not exposed by the chosen binding**, and **this design never seals**. Reword so the entry claims only what is supported — Biscuit appends per hop; the format defines sealing as a terminal operation; **this binding does not expose it and this design does not use it** (see the D22 note and ADR 0002). Remove the bare `[VERIFIED]` where it attaches to terminality-as-used.
4. **Part G, the G-1 row.** The pass criterion must reference the **commitment scheme**, not raw prefix bytes: prefix commitments stable under append; terminal commitment changes under append; **commitment is encoding-independent**; fail-closed on unsupported version/algorithm. Note G-1 is **CONDITIONAL PASS until the STEP 4 tests pass**.
5. **Part G, the G-2 row.** It references `Γ` and `Allowed(P_i)`. Add a pointer that block identity and prefix commitments are defined by ADR 0003 / `§A.0.1`, so G-2's authority computation and G-1's commitment scheme cannot drift apart. **Do not otherwise change G-2, and do not run it.**
6. **Part G, the G-11 row.** Extend the mutation list to include the commitment-layer mutations now covered: **block reordering, truncation, container re-encoding, missing HTC coverage, unsupported version, unsupported algorithm.** State which are already `[VERIFIED]` by the STEP 4 tests and which remain for G-11 proper.

---

## STEP 8 — Archive the task specifications

Create `docs/tasks/archive/g1/` and place **byte-for-byte, unmodified** copies of:

- `SMOKE_G1_TASK.md`
- `SMOKE_G1_RESOLUTION_TASK.md`
- this file, `SMOKE_G1_CORRECTIVE_TASK.md`

Record the **SHA-256 of each** in `docs/tasks/archive/g1/MANIFEST.md`, with this header at the top of that file:

> **Retrospective records — NOT pre-registration evidence.** These task specifications were authored during the work they describe. They document what was asked and when, for provenance and audit. They are **not** pre-registered commitments, they were **not** sealed before the work, and they must **never** be cited as pre-registration evidence. The pre-registration is authored and sealed only per Part H, after the smoke gates pass.

Do **not** alter the archived bytes to fix typos or formatting. If a file was modified locally, archive the version that was actually executed and say so.

---

## STEP 9 — Verify, commit, push

`make lint` and `make test` must be green. Commit in logical groups:

1. `fix: replace raw-protobuf commitment with versioned BlockID commitment (ADR 0003)` — `src/harness/oracle/commitment.py`
2. `test: add capability-commitment regression suite (encoding-independence, prefix, fail-closed, process separation)` — `tests/test_capability_commitment.py`
3. `docs: add ADR 0003; set G-1 to CONDITIONAL PASS pending corrective tests` — ADR, `smoke/g1/REPORT.md`, `smoke/README.md`
4. `docs: correct §A.0.1, §F.2, D22, G-1, G-2, G-11 to the BlockID commitment; remove overstated terminality` — architecture document
5. `docs: archive g1 task specifications as retrospective records` — `docs/tasks/archive/g1/` + `MANIFEST.md`

Only after **all** STEP 4 tests pass may you flip G-1 from **CONDITIONAL PASS** to **PASS**, in a **separate, final commit**: `docs: G-1 corrective tests pass; G-1 -> PASS (ADR 0003)`.

Then `git push origin main`. Never force-push. If push fails on authentication, STOP and say what to configure; do not enter, store, or generate any credential.

---

## STEP 10 — Report to the Commander, then stop

Provide, without paraphrasing:

1. **G-1 status** — `CONDITIONAL PASS` or `PASS`, and the precise reason.
2. **`BlockID_i`** — what it is derived from, with the specification citation, and which of properties (1)–(4) are verified by which test.
3. **Commands and exit codes** — `make lint`, `make test`, and the CI run.
4. **Test count** and the **raw relevant pytest output** (verbatim).
5. **Test-1 evidence** — the alternative-encoding raw bytes differ; the **BlockID commitment is identical**; the **old raw-byte hash would have differed**. Show the actual values.
6. **Test-9 evidence** — the subprocess verifier's commitment equals the signer's; the tampered negative arm fails.
7. **Commit hashes** and push result.
8. **Archive** — the three SHA-256 values and confirmation the bytes are unmodified.
9. **Documentation diffs** — the six edits from STEP 7, with surrounding context.
10. **Scope-guard confirmation** — no Part H change; no confirmatory fixture generated or inspected; `Ω`/`Γ` untouched; no later gate run; no DAG reorder; no upstream PR.
11. **Part H evidence appendix** *(only if you judge it independently blocking)* — the exact reproducer, raw command and output, and a **seed-visibility / secret-exposure analysis** covering: whether deterministic key derivation from a published corpus seed makes every private key in the corpus public by construction; whether that is acceptable for a testbed holding no real credentials; and what warning the code must carry so the derivation is never reused outside the testbed. **No repository changes.**

**Then stop and wait for Commander review. Do not begin any other gate.**