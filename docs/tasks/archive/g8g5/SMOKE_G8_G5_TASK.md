# SMOKE_G8_G5_TASK — ADR 0004 (build-vs-reuse) + gates G-8 (RFC 8785 JCS) and G-5 (DPoP)

**Read this file completely, then execute it exactly, in order. Stop at the end and wait for Commander review.**

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` (Parts A–J). **Working rules:** `PROJECT_RULES.md`. If anything in this spec conflicts with either, STOP and report the conflict with the primary-source citation; do not improvise a resolution.

---

## STEP 0 — Self-check and context

1. Print `wc -l SMOKE_G8_G5_TASK.md` and `sha256sum SMOKE_G8_G5_TASK.md`. Compare both against the values given in the launch prompt. On mismatch: STOP and report truncation — do not proceed.
2. Confirm the working tree is clean and on `main`, at or after commit `b385e6d` (G-1 = PASS). If G-1 is not PASS on the status board, STOP.
3. Read, in this order: `PROJECT_RULES.md`; `smoke/README.md` (status board + DAG); `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part B (decision register), Part F §F.2 and §F.4 (IA table), Part G rows G-5 and G-8; `adr/0002` and `adr/0003` (style precedent for library-choice ADRs); `smoke/g1/REPORT.md` (report format precedent).
4. Evidence grades are mandatory throughout: `[VERIFIED]` (checked against a primary source, cite it), `[DESIGN]` (project decision, cite the ADR), `[UNVERIFIED-IA]` (assumption awaiting its gate). **Never state an `[UNVERIFIED-IA]` as fact.** Verify every RFC claim against the RFC text itself and cite section numbers; several load-bearing "facts" in earlier passes turned out wrong until checked against primary sources.

---

## STEP 1 — Strict boundaries

| Forbidden |
| --- |
| Do **not** edit Part H or any confirmatory-corpus rule (the token-non-reproducibility amendment is a pending Commander decision — out of scope) |
| Do **not** generate or inspect confirmatory fixtures; `fixtures/confirmatory/` stays README-only |
| Do **not** define or freeze `Ω` or `Γ`; `docs/frozen_parameters.md` stays UNSET |
| Do **not** run G-2, G-3, G-4, G-6, G-7, G-9–G-15, or any gate other than G-8 and G-5 |
| Do **not** reorder the gate DAG. In particular, do **not** start the G-4 spike: parallelising G-4 is a pending Commander decision that requires its own ADR — merely record it as an open decision in the final report |
| Do **not** pin `a2a-python`, the MCP Python SDK, or `authlib` (their gates have not run); the `# PENDING GATE` line for authlib → G-4 stays |
| Do **not** implement HTC signing/verification, INV assembly, baselines, mediation, the effect ledger, or any OAuth AS. G-5 in this pass simulates issuance locally; the real AS is G-4 |
| Do **not** modify anything under `src/sut/` (skeleton only; zero harness imports) |
| Do **not** touch `docs/PRE_REGISTRATION.md` (stays a stub) or resurrect any earlier draft of anything |
| Do **not** fork, vendor, or copy code from AIP (`github.com/sunilp/aip`) or any other repository — build-vs-reuse (STEP 2) pins dependencies, it never forks |
| Do **not** open upstream PRs or issues; do **not** `git push --force` |

**Gate-failure policy:** run G-8 first (cheapest). If G-8 FAILs: write its FAIL report, set the board row to FAIL with the reason, commit the docs, **STOP the whole pass** (do not start G-5), and report. Same policy if G-5 FAILs after a G-8 PASS. A FAIL that stops for a decision is worth more than a green light built on a broken assumption — never rationalise a failing check into a pass.

---

## STEP 2 — ADR 0004: build-vs-reuse (documentation only)

Write `adr/0004-build-vs-reuse.md` using `adr/template.md`, status **Accepted**. It records the already-concluded investigation; do not re-open it. Content, in the established ADR voice:

- **Decision:** fork **zero** repositories. Reuse as **pinned dependencies only**, each pinned exactly and only after its gate passes: `a2a-python` (official A2A SDK — gate not yet run), the official MCP Python SDK (gate not yet run; G-6/G-7 exercise its mediation surface), `biscuit-python==0.4.0` (done, G-1/ADR 0002–0003), a JCS library (this pass, gate G-8), a DPoP/JOSE library (this pass, gate G-5), an OAuth stack for the AS if viable (gate G-4).
- **Build from scratch:** HTC/INV constructs, the nine-arm orchestration, the independent effect ledger + oracle, the attack-family fixtures, and (most likely, per the external investigation: no off-the-shelf Python AS supports both RFC 8693 down-scoped exchange and RFC 9396 RAR) a behaviourally faithful OAuth 2.1 AS.
- **AIP is explicitly not forked** `[DESIGN]`: reusing its code would violate oracle independence (the oracle must share no implementation with anything it judges); AIP's role is (a) the citation anchoring the "measurement, not novel mechanism" positioning, and (b) a comparator (feature-matched table, or a P3 comparator arm) — its own paper names "a controlled comparison against a real OAuth 2.1 baseline" as future work, which is exactly this study's contribution.
- **Consequences:** the pin-only-after-gate rule stays binding; each future pin gets its own library-choice ADR (precedent: ADR 0002); this ADR does **not** change the DAG order.

Add the corresponding entry to the Part B decision register in `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` **in the same commit** (never diverge silently from the source of truth).

**Commit:** `docs: add ADR 0004 (build-vs-reuse); register it in Part B`

---

## STEP 3 — Gate G-8: RFC 8785 JCS canonicalisation

**Assumption under test:** IA-8 — "RFC 8785 JCS canonicalization agrees across signer and verifier" (§F.4). **Pass criterion (Part G):** canonicalise identical arguments on signer and verifier; digests **byte-identical**. This underwrites `INV.canonical_request_digest = H_JCS(raw_arguments)` (§F.2) — the T-args defence.

### 3a. Primary source first

Fetch RFC 8785 and read enough to verify, with section numbers: the property it guarantees; string serialisation and the sort order for object member names; number serialisation (the ES6 rule) and its edge cases; what inputs are outside the JSON/I-JSON model (e.g. NaN/Infinity). Record each claim you rely on as `[VERIFIED, RFC 8785 §x.y]`. Take test vectors **from the RFC's own text/appendices** — do not invent vectors and do not trust remembered ones.

### 3b. Library discovery (G-1 §2 discipline)

Candidate leads, all `[UNVERIFIED]` until you check PyPI/GitHub/runtime yourself: `rfc8785`; `jcs`; `canonicaljson` (**warning:** Matrix canonical JSON is a different algorithm — verify RFC 8785 conformance explicitly before considering it). Evaluate: exists and maintained; licence; typing; pure-Python or wheels for cp311 (no new toolchain in local/CI/Docker); conformance against the RFC vectors. Hand-rolling JCS is the fallback of last resort (ES6 number serialisation is the hard part) and would need its own justification — prefer a conformant library. Record the discovery table in the report exactly as G-1 §2 did.

### 3c. Spike — `smoke/g8/spike.py`

Runnable via `make gate GATE=g8` (the Makefile target already handles `smoke/$(GATE)/spike.py`; run inside the synced venv). Exit 0 only if every mandatory check passes; print evidence values (canonical bytes as hex where short, digests) for the report. Checks:

- **G-8.A** semantically identical objects with different member order (nested), different insignificant whitespace, and equivalent string escapes canonicalise to **byte-identical** output; SHA-256 digests identical.
- **G-8.B** signer and verifier in **separate processes** (subprocess receiving only the JSON text on stdin) produce byte-identical canonical output and equal digests — mirrors the G-1 test-9 discipline.
- **G-8.C** RFC-provided vectors reproduce exactly (numbers, strings, sorting).
- **G-8.D** a genuine value difference yields a different digest (non-vacuity: the identity is neither always-equal nor always-different).
- **G-8.E** out-of-model inputs (NaN/Infinity, non-string keys, non-JSON types) **fail closed** with a clear exception — no silent coercion.

### 3d. Permanent regression suite — `tests/test_jcs_canonicalization.py`

Eight tests, each with a positive and a negative arm where meaningful, mirroring the corrective-suite style: (1) member-order invariance; (2) whitespace invariance; (3) string-escape equivalence and member-name sort order per the RFC rule you verified in 3a, including one non-ASCII case; (4) RFC number vectors as known-answer tests; (5) value-difference sensitivity; (6) separate-process signer/verifier agreement; (7) fail-closed on out-of-model input; (8) determinism/non-vacuity. No test may pass vacuously.

### 3e. Conditional graduation — `src/harness/oracle/jcs_digest.py`

§F.2 defines `canonical_request_digest: H_JCS(raw_arguments)`. Locate the definition of the `H`/`H_JCS` notation in the doc (grep Part A/§F). **If and only if** the doc fully determines the construction (hash function; whether any domain tag applies), implement the thin oracle-side module `canonicalize(obj) -> bytes` + `h_jcs(obj) -> str` on the pinned library, exercised by the suite in 3d. If anything is underspecified, do **not** invent: deliver spike + tests only and list the exact gap under "open decisions" in the report. Either way, the SUT-side computation is **not** built now, and when it is built it must be an independent implementation (D21 obligation, as in ADR 0003).

### 3f. Pin, ADR 0005, report, docs

On PASS: pin the chosen library **exactly** in `pyproject.toml` with a comment naming ADR 0005 and gate G-8; regenerate `uv.lock`; confirm `uv sync --frozen` still works. Write `adr/0005-jcs-library.md` (ADR 0002 as the template: decision, alternatives rejected, residuals — e.g. a 0.x pin re-triggers G-8 on any bump). Write `smoke/g8/REPORT.md` with the G-1 section structure (gate; discovery; API mapping; results table with per-check evidence; outcome; consequences; reproduction; residual risks; what this gate does NOT establish — e.g. it does not establish the full INV binding, which is G-11). Update, same pass: §F.4 IA-8 → verified-by-gate with residuals; the smoke board row G-8 (status, report link, ADR link).

**Suggested commits:** `build: pin <lib>==<ver> (ADR 0005, gate G-8)` · `feat: add G-8 JCS canonicalisation spike` · `test: add JCS canonicalisation regression suite` · `docs: record G-8 gate report; G-8 -> PASS (ADR 0005)`

---

## STEP 4 — Gate G-5: DPoP-bound token issuance and verification

**Assumption under test:** IA-5 — "A DPoP-bound (cnf/jkt) access token can be issued/verified in the local AS" (§F.4). **Pass criterion (Part G):** issue/verify a DPoP-bound (`cnf`/`jkt`) token; proof over method+URI; reject a wrong-holder proof. In this pass "the local AS" is **simulated locally** (a minting function inside the spike); the real AS integration is re-exercised at G-4. The doc's standing `[VERIFIED, RFC 9449]` claim — the DPoP proof covers **method+URI only**, not tool or body — must not be contradicted; if you mention `ath` or nonces, cite the RFC section and mark them optional.

### 4a. Primary sources first

Fetch and verify against: RFC 9449 (DPoP proof JWT structure: `typ`, `jwk` header, `htm`, `htu`, `iat`, `jti`; what the proof binds; server-side validation steps), RFC 7800 (`cnf`), RFC 7638 (JWK thumbprint computation), RFC 8037 (Ed25519/OKP in JOSE; check whether its appendix provides a known-answer OKP thumbprint — if yes, use it as a known-answer test; if not, say so and construct the vector per RFC 7638 with the computation shown in the report). Cite section numbers for every claim.

### 4b. Library discovery

Candidate leads, all `[UNVERIFIED]` until checked: `joserfc`, `jwcrypto`, `PyJWT` (+`cryptography`, already a dependency), `authlib`'s JOSE surface. Selection rule: the **minimal** JOSE library sufficient to construct and verify DPoP proof JWTs; prefer EdDSA/Ed25519 support (project-wide signature choice) — if the best candidate lacks EdDSA, ES256 is acceptable with the trade-off recorded. The DPoP-specific validation logic itself is written in the spike/tests this pass (it is a small profile over JWS); the pinned dependency is the JOSE library. If the winner is `authlib`, pin it for **exactly the G-5-verified JOSE/DPoP surface** and state in the ADR that the RFC 8693 + RFC 9396 surface remains `[UNVERIFIED-IA]` pending G-4 — a pin never asserts more than its gate verified.

### 4c. Spike — `smoke/g5/spike.py`

Runnable via `make gate GATE=g5`; exit 0 only if all mandatory checks pass; print evidence values. Checks:

- **G-5.A** holder keypair generated; `jkt` computed per RFC 7638 over the required members for the key type; known-answer vector reproduced if 4a yielded one.
- **G-5.B** a local mint function issues a signed access token whose `cnf.jkt` equals the holder's thumbprint (issuer key ≠ holder key; the issuer's private key never leaves the minting function's frame — the G-1 structural discipline).
- **G-5.C** a DPoP proof JWT for a given `htm`+`htu` verifies: proof signature under the `jwk` in its own header; `typ` correct; `htm`/`htu` match the presented request; thumbprint of the proof's `jwk` equals the token's `cnf.jkt`; `iat` within an explicit acceptance window; `jti` present.
- **G-5.D** wrong-holder proof — signed by a **different** keypair over the same `htm`/`htu` — is **rejected**, specifically at the `cnf.jkt` ↔ proof-`jwk` thumbprint comparison.
- **G-5.E** `htm` mismatch rejected; `htu` mismatch rejected (each independently).
- **G-5.F** negative control: the valid proof still verifies after G-5.D/E (rejection logic is not rejecting everything).

### 4d. Permanent regression suite — `tests/test_dpop_binding.py`

At most six tests, positive+negative arms, using test-local helpers only (no `src/` module this pass — the production verifier is built with the B2-DPoP arm and re-tested at G-11/G-14): valid-proof verify; wrong-holder reject; `htm` reject; `htu` reject; `cnf.jkt` mismatch reject; thumbprint known-answer/determinism. The four-way DPoP taxonomy (Part D) is **G-14, not this pass** — state that in the report's "does NOT establish" section.

### 4e. Pin, ADR 0006, report, docs

On PASS: pin the chosen JOSE library exactly (comment: ADR 0006, gate G-5); **remove the `DPoP / JOSE library -> gate G-5` line from the `# PENDING GATE` block** (the authlib → G-4 line stays unless authlib itself was pinned in 4b, in which case reword that line to say the 8693/9396 surface still awaits G-4); regenerate `uv.lock`; `uv sync --frozen` must still work. Write `adr/0006-dpop-jose-library.md`. Write `smoke/g5/REPORT.md` (same section structure; "does NOT establish": the real AS (G-4), the four-way taxonomy (G-14), replay semantics (G-9), any claim beyond method+URI binding). Update §F.4 IA-5 → verified-by-gate with residuals; smoke board row G-5.

**Suggested commits:** `build: pin <lib>==<ver> (ADR 0006, gate G-5)` · `feat: add G-5 DPoP binding spike` · `test: add DPoP binding regression suite` · `docs: record G-5 gate report; G-5 -> PASS (ADR 0006)`

---

## STEP 5 — Full verification in the locked environment

1. `uv sync --frozen` from clean; `make gate GATE=g8`; `make gate GATE=g5`; full `pytest -q` — **all** tests green (the pre-existing eleven plus the new suites). Paste the raw tail of the pytest output into the final report.
2. `pre-commit run --all-files` (ruff) clean.
3. Confirm the red lines still hold: `fixtures/confirmatory/` README-only; `src/sut/` unchanged; `git grep -n "harness" src/sut/` empty; `docs/frozen_parameters.md` untouched; Part H untouched (`git diff` shows no Part H hunk).

---

## STEP 6 — Archive this task specification

Create `docs/tasks/archive/g8g5/`, copy this file into it byte-for-byte, add a `MANIFEST.md` with its SHA-256 and the exact label used for g1: **"retrospective records — NOT pre-registration evidence."** Remove the working copy from the repo root in the same commit.

**Commit:** `docs: archive g8/g5 task specification as retrospective record`

---

## STEP 7 — Report to the Commander, then stop

Report, in this order: (1) G-8 and G-5 statuses with the decisive evidence line for each check; (2) libraries pinned with exact versions and ADR numbers (0004/0005/0006); (3) test counts and the raw pytest tail; (4) all commit hashes in order; (5) a summary of every doc diff (Part B entry, §F.4 rows, board rows, pyproject/uv.lock); (6) residual risks per gate; (7) **open decisions restated for the Commander** — (a) the Part H token-non-reproducibility amendment (still pending; untouched per STEP 1), (b) whether to parallelise the G-4 spike ahead of G-6/G-7 (requires its own ADR; not started), (c) any `H_JCS` specification gap found in STEP 3e. Then **STOP and wait**. Do not start G-6, G-7, or any other gate.
