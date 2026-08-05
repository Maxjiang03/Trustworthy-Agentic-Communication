# LEDGER_PLATFORM_TASK — ADR 0014: the ledger platform decision, CI restored, and the G-4 spike opened

**Context.** Gate G-7 PASSed on the measurement box, but the enforcement mechanism is Win32 share-mode locking and `LedgerWriter.__init__` raises on any other platform. On Linux this makes six tests in `tests/test_effect_ledger.py` **fail hard** and `smoke/g7/spike.py` exit 1, so the `ubuntu-latest` CI workflow is red and no third party can independently re-verify G-7 by cloning the repository — the project's standard verification practice. The Commander's decision (option **丙**) is: **accept Windows as the measurement platform now, record it as a first-class architectural decision rather than a report footnote, restore CI, and defer the POSIX variant to after submission.** This pass implements that decision and opens the G-4 construction spike; it runs **no gate**.

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`. **Working rules:** `PROJECT_RULES.md`. Evidence grades mandatory on load-bearing statements.

---

## STEP 0 — Self-check and context

2. Confirm a clean tree on `main` at or after `ab0c0fb` (G-1/G-5/G-6/G-7/G-8 PASS; ADRs 0001–0013 present).
3. Read: `PROJECT_RULES.md`; `adr/template.md`; `adr/0008` (the precedent for a decision that changes scheduling without changing criteria); `smoke/g7/REPORT.md` in full; `src/harness/effect_ledger.py`; `tests/test_effect_ledger.py`; `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part H, §F.4 row IA-7, §J (validity threats); `docs/frozen_parameters.md`; `.github/workflows/ci.yml`.

---

## STEP 1 — Strict boundaries

| Forbidden |
| --- |
| Do **not** write the POSIX ledger variant, or any `O_APPEND` / `chattr` / bind-mount / permission-based fallback. The decision is to **defer** it — implementing it here contradicts the decision |
| Do **not** weaken `LedgerWriter`: the non-Windows path must keep **raising**. A silent degradation to an unenforced ledger would leave every downstream conclusion resting on a file any SUT code could rewrite — the one outcome worse than a red CI |
| Do **not** re-run, re-adjudicate, or amend G-6 or G-7; their PASS records, reports, and criteria stand unchanged |
| Do **not** edit `smoke/g7/spike.py`'s checks. STEP 3 may add a **guard** that reports the platform and exits non-zero with a clear message on non-Windows; the five checks themselves are untouched |
| Do **not** change the CI workflow's runner, steps, or Python version — STEP 3 makes the tests platform-aware, not the CI |
| Do **not** start G-2, G-11, or any gate. STEP 5 opens the G-4 **construction spike** only, which ADR 0008 already authorised; it does **not** adjudicate G-4 |
| Do **not** touch `src/sut/`, `docs/PRE_REGISTRATION.md`, or `fixtures/confirmatory/`; do **not** pin new dependencies |
| Do **not** set any `docs/frozen_parameters.md` value. STEP 4 may add a **row** if the platform belongs in the seal manifest; the value stays UNSET with the fixing ADR named |

---

## STEP 2 — ADR 0014: Windows is the sealed measurement platform

Write `adr/0014-ledger-platform-decision.md`, status **Accepted**. It must record, in the established voice:

- **The mechanism and why it is platform-bound** `[VERIFIED, gate G-7]`: enforcement is a `CreateFileW` handle opened with `FILE_SHARE_READ` only, held by a separate ledger process; while that handle lives, every other open for write, append, truncate, or delete fails at the OS level, from any process, immune to attribute and `chmod` changes. This is a Win32 sharing-semantics property with no direct POSIX equivalent — POSIX advisory locks do not bind uncooperative writers.
- **The decision**: the confirmatory campaign runs on Windows; the sealed environment therefore **includes the operating system**. This is a scope statement, not a claim that the design requires Windows.
- **Why the alternative was rejected** `[DESIGN]`: a POSIX fallback with weaker enforcement would make the independence property differ by platform, so results would not be comparable across environments; a silent fallback is prohibited outright (see the boundary above).
- **The three costs, stated plainly**: third parties cannot re-verify G-7 by cloning on Linux or macOS; artifact evaluation for a future conference submission will most likely run on Linux; the seal is bound to one OS. Each is accepted knowingly for schedule reasons (11 September), not overlooked.
- **The deferred obligation**: a POSIX variant is planned **after submission and before any artifact-evaluated conference version**, and re-running the five G-7 checks under it is a precondition for claiming cross-platform independence. Until then, **no cross-platform claim may appear anywhere** in the dissertation, the repository, or a paper.
- **The live-handle limitation, promoted from footnote to decision** `[VERIFIED, gate G-7 report]`: immutability holds only while the writer process holds the handle; after `writer.close()` the file is ordinary. Post-campaign tamper-evidence therefore rests on the Part H seal — content hashes, the split manifest, and the public timestamp anchor — **not** on the ledger mechanism. State explicitly that the campaign-time property and the post-campaign property have different guarantors, so neither is mistaken for the other.

Register the decision in Part B.2, same commit.

**Commit:** `docs: add ADR 0014 (Windows as the sealed measurement platform)`

---

## STEP 3 — Restore CI without weakening anything

1. **Tests.** Add a module-level `pytest.mark.skipif(sys.platform != "win32", ...)` to `tests/test_effect_ledger.py`. The reason string must name ADR 0014 and say the enforcement mechanism is Win32-only — a reader seeing a skip must be able to tell it is a **recorded decision**, not an unexplained gap. Do not weaken, split, or platform-branch any assertion inside the six tests; they must still run and pass on Windows exactly as they do now.
2. **Spike guard.** In `smoke/g7/spike.py`, before `build_stack`, print an unmistakable platform line and exit non-zero on non-Windows with a message naming ADR 0014. The gate must not appear to pass where its mechanism does not exist.
3. **Visibility.** Add a short line to `README.md` (or the smoke board, whichever is the natural home) stating that the ledger suite is Windows-only per ADR 0014 and that the remaining suites are cross-platform — someone reading a green CI badge must not conclude the ledger was verified on Linux.
4. **Verify on both readings.** Run the full suite and report the counts: on Windows all tests run and pass; on a non-Windows reading the six are **skipped, not failed**. If a Windows box is the only environment available, say so and state the expected Linux behaviour as a prediction rather than an observation — do not report an unobserved result as fact.

**Commit:** `test: make the ledger suite Windows-only per ADR 0014; restore CI`

---

## STEP 4 — Carry the platform into the seal and the validity discussion

1. **Part H.** Add the operating system and its version to the sealed environment description, so the seal manifest records the OS alongside the pinned dependencies and lockfile. Point at ADR 0014. Keep the edit minimal and additive — no other Part H rule changes.
2. **`docs/frozen_parameters.md`.** Add a row for the sealed measurement platform, value **UNSET** with the fixing ADR named, following the existing row format. The exact Windows build is fixed at seal time, not now.
3. **Validity threats (§J).** Add a short entry under the appropriate threat class recording the platform dependency, the deferred POSIX variant, and the different guarantors of the campaign-time and post-campaign tamper-evidence properties. This is the sentence the dissertation will draw on, so it must be accurate and free of any cross-platform implication.
4. **§F.4 IA-7 row.** The Windows-only residual is already recorded; extend it with a pointer to ADR 0014 so the row's residual and the decision are linked. Do **not** alter the verified-by-gate status or the rest of the row.

**Commit:** `docs: record the sealed platform in Part H, frozen parameters, and the validity threats`

---

## STEP 5 — Open the G-4 construction spike (scoping only, no adjudication)

ADR 0008 already authorises the G-4 AS construction spike to start ahead of its adjudication. Open it as a **scoping artifact only** — this pass writes no AS code.

Create `smoke/g4/SCOPE.md` recording: the pass criteria copied verbatim from the Part G G-4 row (do not paraphrase them); the concluded finding that no off-the-shelf Python AS supports both RFC 8693 down-scoped exchange and RFC 9396 `authorization_details` `[DESIGN, ADR 0004]`, so a behaviourally faithful AS most likely has to be built; the two items G-5 handed forward — `ath` (RFC 9449 §4.2, required when a DPoP proof accompanies an access token to a protected resource) and DPoP nonce handling — both `[UNVERIFIED-IA]`; that `authlib` stays unpinned with its `# PENDING GATE` line until G-4 adjudicates; that **adjudication stays after G-6/G-7 with unchanged criteria** (ADR 0008); and an explicit list of the RFC sections that must be read against primary sources before any AS code is written. Update the `smoke/README.md` G-4 row to point at the scope file. **Write no AS code, no endpoint, no token-exchange logic.**

**Commit:** `docs: open the G-4 construction spike scope (ADR 0008; no adjudication)`

---

## STEP 6 — Verification, archive, report

1. `uv sync --frozen` from clean; full `pytest -q`; every gate spike that is runnable on the current platform exits 0 — run `g1`, `g6`, `g8`, `g5` and report each exit code, plus `g7` with its platform result. `pre-commit run --all-files` clean.
2. Red lines: `src/sut/` zero diff; `fixtures/confirmatory/` README-only; `PRE_REGISTRATION.md` unchanged; no new dependency; `frozen_parameters.md` values still UNSET (the new row included); G-6/G-7 reports and PASS records unchanged; `git diff --stat ab0c0fb..HEAD` reviewed hunk by hunk.
3. Archive this file byte-for-byte to `docs/workplan/archive/ledger-platform/` with a `MANIFEST.md` carrying its SHA-256 and the standard label **"retrospective records — NOT pre-registration evidence."** Remove the root copy in the same commit.
4. Report: ADR 0014's decisive content; the test counts on the platform you actually ran, with the other platform's behaviour clearly labelled as observed or predicted; every gate spike exit code; the document diffs; every commit hash in order; push confirmed by pasting `git ls-remote origin main` verbatim; and — if CI has completed on GitHub — its result, or a statement that it had not completed when you stopped. Then **STOP and wait.** Do not begin AS implementation.
