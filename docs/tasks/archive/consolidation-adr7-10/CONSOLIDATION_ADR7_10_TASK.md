# CONSOLIDATION_ADR7_10_TASK — Commander decisions: Part H amendment, G-4 parallelisation, frozen `H_JCS`, §K demo scope

**Read this file completely, then execute it exactly, in order. Stop at the end and wait for Commander review.**

This is a **decisions-and-consolidation pass**, not a gate pass. It converts four adjudicated Commander decisions into ADRs, one small oracle-side module, and same-commit document updates. **No gate is run.** The four decisions below are **given**: record and implement them, do not re-open, re-derive, or re-litigate them. If executing one reveals a factual contradiction with a primary source or the architecture document, STOP and report with the citation rather than adapting the decision.

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` (Parts A–J). **Working rules:** `PROJECT_RULES.md`. Evidence grades (`[VERIFIED]` / `[DESIGN]` / `[UNVERIFIED-IA]`) are mandatory on load-bearing statements, as in ADRs 0002–0006.

---

## STEP 0 — Self-check and context

1. Print `wc -l CONSOLIDATION_ADR7_10_TASK.md` and `sha256sum CONSOLIDATION_ADR7_10_TASK.md`; compare both with the launch prompt. On mismatch: STOP and report truncation.
2. Confirm a clean tree on `main` at or after `9541407` (G-8 and G-5 both PASS on the board). If either is not PASS, STOP.
3. Read: `PROJECT_RULES.md`; `adr/template.md`; `adr/0003` (corrective-pass precedent) and `adr/0005`/`adr/0006` (recent style); `src/harness/oracle/commitment.py` in full (the new module must match its conventions); `smoke/g8/REPORT.md` §9 (the recorded `H_JCS` gap); `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §A.0.1, §F.2, §F.4, Part G, Part H, Part I; `docs/frozen_parameters.md`.

---

## STEP 1 — Strict boundaries

| Forbidden |
| --- |
| Do **not** run, start, or prepare any gate — no G-4 spike, no G-6, no G-7, no re-run of G-1/G-5/G-8 beyond the verification in STEP 6 |
| Do **not** create, generate, or populate any fixture. `fixtures/confirmatory/` stays **README-only**; STEP 2 edits that README's text and adds nothing else |
| Do **not** write the corpus generator, key-seed derivation, or any minting code — STEP 2 amends the **rule**, not the implementation |
| Do **not** define, freeze, or fill `Ω` or `Γ`; `docs/frozen_parameters.md` values stay UNSET (STEP 4 may add a row only if the decision genuinely requires a seal-time value — justify it, do not fill it) |
| Do **not** implement the SUT-side digest. STEP 4 builds the **oracle-side** module only; the D21 independent-implementation obligation stands |
| Do **not** implement, scaffold, or stub the §K LLM demonstration — STEP 5 records a scope decision only |
| Do **not** touch `docs/PRE_REGISTRATION.md`; do **not** modify `src/sut/`; do **not** pin new dependencies |
| Do **not** alter any existing ADR's Decision or Status; supersession, if ever needed, is a separate Commander decision |
| Do **not** reorder the gate DAG beyond the single G-4 amendment in STEP 3 |

---

## STEP 2 — ADR 0007: confirmatory corpus stores generators, not minted tokens

**Commander decision (given).** Biscuit tokens are **not byte-reproducible across mints** — the format uses a single-use ephemeral block key per append, so two mints of the same logical capability differ in bytes `[VERIFIED, gate G-1 corrective pass]`. Part H step 3 therefore may not be read as sealing pre-minted token bytes. The sealed confirmatory corpus consists of **scenario specifications plus deterministic key seeds**; Biscuit tokens are **minted at campaign runtime** from those sealed inputs.

Write `adr/0007-corpus-generators-not-tokens.md`, status **Accepted**, recording:

- **Why determinism is unaffected** `[DESIGN]`: every oracle verdict is a function of the authority set `C_n = Allowed(P_n; Γ, κ, Ω)` and the sealed scenario, **never** of token bytes (§A.0.1, §F.1, Part I). The `INV.capability_hash` binding is computed over the presented token's BlockID commitment at runtime and compared against the runtime-presented token, so it remains exact (§F.2, ADR 0003).
- **Why runtime minting is required anyway** `[DESIGN]`: per-hop append is the measured operation — sealing post-append bytes would make `delegation_cost` unmeasurable (§E two-phase, Part H latency decomposition).
- **What the seal therefore covers** `[DESIGN]`: scenario specifications; the deterministic key-seed material for every principal; the corpus generator code; the derivation rule from seed to keypair. What it does **not** cover: minted token bytes, ephemeral block keys, or any per-mint randomness.
- **Disjointness under the amendment** `[DESIGN]`: Part H step 5 asserts on **scenario-specification and seed content hashes**, not token bytes — state this explicitly so the step stays executable.
- **Seed-disclosure warning** `[DESIGN]`: publishing the corpus seeds publishes every private key derived from them. The corpus is a **testbed artifact only**; its keys MUST NOT be reused in any deployment. This warning is a **binding obligation on the generator when it is written** — record it here and in the two document locations below; do not write the generator now.

**Same-commit document updates:** amend Part H step 3 so the sealed item reads as the corpus generator plus seeds and scenario specifications rather than as reproducible token bytes; amend step 5 so disjointness is asserted on specification and seed hashes; add a short note under Part H carrying the non-reproducibility fact, its `[VERIFIED, G-1]` grade, and the seed-disclosure warning. Add the same warning to `fixtures/confirmatory/README.md` (text only — the directory stays otherwise empty). Register the decision in Part B.2 as with ADR 0004.

**Commit:** `docs: add ADR 0007 (corpus stores generators and seeds, not minted tokens); amend Part H`

---

## STEP 3 — ADR 0008: the G-4 spike may start early; its adjudication does not move

**Commander decision (given).** The G-4 authorization-server work is the schedule's long pole: the concluded external investigation found **no off-the-shelf Python AS supporting both RFC 8693 down-scoped exchange and RFC 9396 `authorization_details`** `[DESIGN, ADR 0004]`, so a behaviourally faithful AS most likely has to be built. The **construction spike** is authorised to start ahead of G-6/G-7. The **G-4 PASS adjudication remains where the DAG puts it**, after G-6/G-7, with its pass criteria unchanged.

Write `adr/0008-g4-spike-parallelisation.md`, status **Accepted**, recording: the split between *spike start* (moved earlier) and *gate adjudication* (unmoved); that no G-4 pass criterion, dependency, or `[UNVERIFIED-IA]` grade changes (IA-4 stays `[UNVERIFIED-IA]`); that nothing may be pinned on spike progress alone — `authlib`'s `# PENDING GATE` line stays until G-4 adjudicates; that the spike additionally inherits the two items G-5 handed forward, namely `ath` (RFC 9449 §4.2 — required when a DPoP proof accompanies an access token to a protected resource) and DPoP nonce handling, both still `[UNVERIFIED-IA]`; and the schedule rationale (11 September submission).

**Same-commit document update:** the `smoke/README.md` G-4 row keeps its dependency column but records that the construction spike is authorised to start, with adjudication still gated on G-6/G-7. Do not change any other row. Register in Part B.2.

**Commit:** `docs: add ADR 0008 (G-4 spike may start early; adjudication unmoved)`

---

## STEP 4 — ADR 0009 and the oracle-side `H_JCS` module

**Commander decision (given).** `H_JCS` is frozen as **SHA-256 over a versioned, domain-separated, length-delimited encoding of the RFC 8785 canonical bytes**, rendered as a **lowercase hexadecimal** string. It is deliberately the same family as the capability commitment (ADR 0003) so that the two constructions cannot be confused with one another or with a bare digest.

### 4a. Write the ADR

`adr/0009-hjcs-construction.md`, status **Accepted**. It must:

- State the construction normatively and completely enough that **two independent implementations agree byte-for-byte**: the domain tag (a fixed ASCII string, distinct from `AASC-CAP-COMMIT`), the version byte, the length-delimiting convention, the input (RFC 8785 canonical bytes of the arguments object), the hash (SHA-256), and the output encoding (lowercase hex). Read `commitment.py` first and **match its existing conventions exactly**; document the resulting byte layout in the ADR.
- **Classify every digest field in `src/harness/schema.py`.** Enumerate them all — `canonical_request_digest`, `intended_request_digest`, `effect_request_digest`, `ingress_request_digest`, `request_digest`, and every `payload_digest` occurrence — and give each exactly one disposition: (a) governed by `H_JCS`; (b) governed by a different construction, with a pointer to where that is defined; or (c) deferred, naming the gate or decision that will settle it. **No field may be left unclassified**; if the architecture document does not determine one, choose (c) and say so — do not invent.
- Record the **D21 obligation** explicitly: this module is oracle-side; the SUT-side computation must be written independently later and the oracle must never consume a SUT-computed digest.
- Record consequences: it unblocks the `INV.canonical_request_digest == H_JCS(raw_arguments)` check (§F.2) and the Part I `realized_harm_F3` predicate; it is a **design constant, not a seal-time parameter**, so it belongs in the architecture document rather than `docs/frozen_parameters.md` — add a row there only if you find a genuine seal-time dependency, and justify it if you do.

### 4b. Build `src/harness/oracle/jcs_digest.py`

Mirror `commitment.py` in structure and discipline: module-level `TAG` and `VERSION` constants; a typed exception hierarchy; **fail-closed** on unsupported version, on out-of-model input (propagate the pinned library's typed errors rather than swallowing them), and on any ambiguity. Public surface: `canonicalize(obj) -> bytes` and `h_jcs(obj) -> str`. No I/O, no logging, no global state, no SUT imports.

### 4c. Extend the regression suite

Rewire the eight existing tests in `tests/test_jcs_canonicalization.py` so digest comparisons go through `h_jcs` instead of the test-local `sha256`; the canonical-bytes assertions and all RFC vectors stay exactly as they are. Add **at most four** tests for the construction itself: (1) **domain separation is non-vacuous** — `h_jcs(x)` must differ from a bare `sha256(canonical_bytes(x))` hex digest; (2) tag/version fail-closed on an unsupported version; (3) output shape — 64 lowercase hex characters; (4) cross-process determinism, in the style of the existing separate-process test. Every test keeps a positive and a negative arm; none may pass vacuously.

### 4d. Document updates, same pass

Update §F.2 and Part I so `H_JCS` points at the frozen construction and ADR 0009; update the `schema.py` field comments to match the STEP 4a classification; register the decision in Part B.2; note in `smoke/g8/REPORT.md` §9 that the recorded gap is now **closed by ADR 0009** (append a dated line — do **not** rewrite the gate's findings or its PASS record).

**Suggested commits:** `docs: add ADR 0009 (frozen H_JCS construction)` · `feat: add oracle-side H_JCS digest module` · `test: rewire JCS suite to the H_JCS module; add construction tests` · `docs: point F.2/Part I/schema at ADR 0009; close the G-8 open decision`

---

## STEP 5 — ADR 0010: the §K LLM-in-the-loop demonstration is retained, outside the seal

**Commander decision (given).** The research proposal (§K) promised a single qualitative demonstration placing a real LLM agent and a poisoned MCP tool into the golden-thread example, and §M cited it as partially narrowing the external-validity gap. It is **retained**, but strictly **outside the sealed campaign**.

Write `adr/0010-llm-demonstration-scope.md`, status **Accepted**, recording: that the demonstration is qualitative and produces **no counts, no rates, and no statistics** — it may never enter a results table; that it is **not** part of the sealed corpus or the single confirmatory campaign, and running it can never trigger an unseal; that its scope is the golden thread under B0 and B3 only; that the deterministic-mock design remains the sole basis for every measured result, for the pre-registered reason that it removes LLM sampling as a confound; that it is reported with explicit limitations under external validity; and that **if the schedule does not permit it before 11 September, it is dropped and the dissertation records the scope change and its reason** — never silently omitted. Add a matching note to the architecture document stating that the demonstration exists outside Parts A–J and outside the seal. Register in Part B.2. **Implement nothing.**

**Commit:** `docs: add ADR 0010 (LLM-in-the-loop demonstration retained outside the seal)`

---

## STEP 6 — Verification in the locked environment

1. `uv sync --frozen` from clean; full `pytest -q` green; paste the raw tail. Re-run `smoke/g8/spike.py` and `smoke/g5/spike.py` — **both must still exit 0** (the module must not have perturbed them).
2. `pre-commit run --all-files` clean. If the formatter rewrites anything, commit that separately as `chore:` and re-run both spikes and the suite afterwards, exactly as the G-8/G-5 pass did.
3. Confirm the red lines: `fixtures/confirmatory/` still README-only (README text changed, nothing added); `src/sut/` unchanged; `git grep -n "src.sut\|from sut" src/harness/` empty; `docs/PRE_REGISTRATION.md` unchanged; `docs/frozen_parameters.md` values still UNSET; no new dependency in `pyproject.toml`; `git diff --stat 9541407..HEAD` reviewed hunk by hunk against this spec.

---

## STEP 7 — Archive this specification

Create `docs/tasks/archive/consolidation-adr7-10/`, copy this file byte-for-byte, add `MANIFEST.md` with its SHA-256 and the standard label **"retrospective records — NOT pre-registration evidence."** Remove the root working copy in the same commit.

**Commit:** `docs: archive the ADR 0007-0010 consolidation task specification`

---

## STEP 8 — Report, then stop

Report: (1) the four ADRs with their decisive content in one line each; (2) the complete STEP 4a field classification table — every digest field and its disposition; (3) the exact `H_JCS` byte layout as implemented, with one worked example (input, canonical bytes, output hex); (4) test count and the raw pytest tail, plus both spike exit codes; (5) every commit hash in order, and confirmation that the push reached `origin/main` — **verify with `git ls-remote origin main` and paste the output**, do not infer it from the push command's exit status; (6) a summary of every document diff; (7) anything you had to classify as deferred in STEP 4a, with the gate that will settle it; (8) the two passes now unblocked and **not** started here — G-6/G-7 (complete mediation and the independent effect ledger, the construct-validity pair) and the G-4 AS construction spike, now authorised to run in parallel. Then **STOP and wait.**
