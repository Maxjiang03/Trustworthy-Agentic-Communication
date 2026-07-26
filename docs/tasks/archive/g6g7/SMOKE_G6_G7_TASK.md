# SMOKE_G6_G7_TASK — tidy-ups + gates G-6 (complete mediation) and G-7 (independent effect ledger)

**Read this file completely, then execute it exactly, in order. Stop at the end and wait for Commander review.**

**These are the construct-validity gates.** Part G is explicit: if G-6 or G-7 fails, the construct validity of the whole study is at risk and interposition must be re-architected before any confirmatory work — highest priority. A FAIL here is a **valuable result delivered on time**, not a setback. Do not soften a partial result into a pass, do not narrow a check until it passes, and do not re-architect on the fly to rescue a failing gate: write the FAIL report with the evidence, stop, and let the Commander decide.

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` (Parts A–J). **Working rules:** `CLAUDE.md`. Evidence grades (`[VERIFIED]` / `[DESIGN]` / `[UNVERIFIED-IA]`) mandatory on load-bearing statements. If this spec conflicts with either document, STOP and report with the citation.

---

## STEP 0 — Self-check and context

1. Print `wc -l SMOKE_G6_G7_TASK.md` and `sha256sum SMOKE_G6_G7_TASK.md`; compare with the launch prompt. On mismatch: STOP and report truncation.
2. Confirm a clean tree on `main` at or after `da1c9c9` (G-1/G-5/G-8 all PASS; ADRs 0001–0010 present).
3. Read: `CLAUDE.md`; `smoke/README.md`; `adr/0003`, `adr/0004`, `adr/0009`; `src/harness/schema.py` in full; `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §A.0.1, §F.1, §F.2, §F.4, Part G (rows G-6/G-7 and the failure-policy paragraph), Part I; `smoke/g1/REPORT.md` and `smoke/g8/REPORT.md` as report-format precedent.

---

## STEP 1 — Strict boundaries

| Forbidden |
| --- |
| Do **not** build any baseline arm, agent, A2A hop, capability logic, HTC/INV construct, or OAuth AS. This pass builds **instrumentation only** |
| Do **not** start, prepare, or reference-implement G-4; do **not** run G-2, G-9–G-15 |
| Do **not** modify `src/sut/`. The toy tool server for this pass lives under `smoke/`, not in `src/sut/` |
| Do **not** create or populate fixtures; `fixtures/confirmatory/` stays README-only |
| Do **not** define or freeze `Ω`, `Γ`, or a `reason_code` vocabulary. Use a **pilot** reason-code set inside the spike, label it as such, and record that the frozen vocabulary is deferred to arm implementation — exactly as G-1 used a pilot vocabulary that was never `Ω` |
| Do **not** send real email, write outside the repo working tree, or open a network socket to anything but localhost. The sensitive tool is a **sandboxed stub**: it records an effect and returns; it never performs one |
| Do **not** alter any existing ADR's Decision or Status; STEP 2 and STEP 5 **extend** ADR 0009's classification with new ADRs |
| Do **not** touch Part H, `docs/PRE_REGISTRATION.md`, or `docs/frozen_parameters.md` values |
| Do **not** pin `a2a-python` (its surface is not exercised here). The MCP SDK is pinned only in STEP 6, only after both gates pass, and only for the surface the gates verified |

**Failure policy.** Run G-6 first. If G-6 FAILs: write `smoke/g6/REPORT.md` including the **full call-path enumeration** from STEP 3a (that enumeration is the input to any re-architecture, so it must be complete even in failure), set the board row to FAIL with the reason, commit the docs, **do not start G-7**, and report re-architecture options without choosing one. Same policy if G-7 FAILs after a G-6 PASS.

---

## STEP 2 — Two tidy-ups carried over from the ADR 0009 review

Write `adr/0011-commitment-string-encoding.md`, status **Accepted**, closing two gaps found in review:

1. **`P_hashes` classification.** `IntendedInvocation.P_hashes: list[str]` (`schema.py`) holds `H(P_0)..H(P_n)` and was not classified in the ADR 0009 table. It is disposition **(b)** — the §A.0.1 BlockID prefix commitment (ADR 0003, `commit_prefix`). Record it, and check `schema.py` field-by-field for any other hash-bearing field the ADR 0009 table missed; classify anything found or state that none was.
2. **Byte→string encoding for the commitment family.** `commitment.py` returns **raw bytes** (`digest.digest()`), but every schema field that carries one of these values is typed `str` — the rendering was never fixed. Freeze it as **lowercase hexadecimal**, matching `H_JCS` (ADR 0009), and state the failure it prevents: if the SUT side rendered base64url while the oracle rendered hex, the `INV.capability_hash` equality check would fail on correct inputs and reject honest requests — the same class of false-rejection defect the G-1 corrective pass removed `[VERIFIED, ADR 0003]`.

Add a helper only if it is trivial and used (for example a `hex()` rendering function beside `commitment.py`'s existing surface); otherwise ADR + comments suffice. Update the `schema.py` comments on the affected fields and register the decision in Part B.2, same commit. **Do not** re-open ADR 0003 or ADR 0009.

**Commit:** `docs: add ADR 0011 (commitment-family hex encoding; P_hashes classified)`

---

## STEP 3 — Gate G-6: complete mediation in the MCP SDK tool-call path

**Assumption under test:** IA-6 — the MCP Python SDK exposes tool-call handling where the boundary can mediate **every** call and emit a `MediationEvent` (§F.4). **Pass criterion (Part G):** no tool call executes without passing the boundary and emitting a `MediationEvent`.

The word carrying the weight is **every**. A spike showing "calls routed through my wrapper produce an event" proves nothing about completeness; the gate asks whether a path exists that **skips** the boundary. Design every check around that question.

### 3a. Enumerate the SDK's tool-invocation paths — the load-bearing evidence

Install the official MCP Python SDK (unpinned for now) and **inspect its source**, not its README. Produce an explicit enumeration of every path by which a tool function can be reached: the documented request-handling path; decorator or registry-based registration; any direct-dispatch, internal, or convenience API; streaming or batched variants if present; and error/retry paths that might re-enter dispatch. For each path, record whether the chosen interposition point dominates it. Cite file and symbol names, with version, as `[VERIFIED, mcp-sdk <ver>, <file>:<symbol>]`. **This enumeration is the gate's central evidence and belongs in the report in full, PASS or FAIL.**

### 3b. Spike — `smoke/g6/spike.py`, runnable via `make gate GATE=g6`

Build a minimal MCP server exposing two tools: `calendar.read` (benign) and `mail.send` (**sandboxed stub** — records an intent to act and returns; never sends). Interpose the boundary at the point chosen in 3a. Exit 0 only if every mandatory check passes; print evidence values.

- **G-6.A** a normal call through the documented path executes and emits exactly one `MediationEvent` carrying the harness-minted `correlation_id`, `admitted`, a pilot `reason_code`, and `boundary_ts_ns`.
- **G-6.B** a **denied** call emits a `MediationEvent` with `admitted=false` **and the tool function does not run** — assert on a tool-side execution witness (a counter or marker the boundary cannot write), not on the boundary's own claim.
- **G-6.C** **bypass attempts**, one per path enumerated in 3a that is not the documented one: attempt to reach the tool through it. Each attempt must either be blocked or be shown to still pass the boundary. Report each attempt and its outcome individually — an unenumerated path is an untested path.
- **G-6.D** non-vacuity: with the interposition **removed**, the same bypass attempt reaches the tool and no event is emitted. This proves the checks are detecting mediation rather than an unrelated failure.
- **G-6.E** exceptions and error paths: a tool that raises still produces exactly one `MediationEvent`; no path emits zero or two events for one call.

### 3c. Graduate the permanent module

On PASS, move the interposition layer into `src/harness/` (mirror the existing package layout; the layer is **harness-side and trusted**, so `src/sut/` must never import it — verify with `git grep`). Public surface only: install the boundary, mediate a call, emit a `MediationEvent`. No policy logic, no capability checks, no verdicts — those belong to the arms and the oracle.

### 3d. Permanent regression suite — `tests/test_complete_mediation.py`

At most eight tests, each with positive and negative arms: admitted call emits one event; denied call emits an event **and** leaves the tool-side witness untouched; one test per enumerated bypass path; error-path single-event; non-vacuity (interposition removed → tool reached, no event). No test may pass vacuously.

---

## STEP 4 — Gate G-7: independent effect ledger and ingress recorder

**Assumption under test:** IA-7 — an immutable external effect ledger plus a `ToolIngressEvent` recorder can be interposed at the tool, **independent of agent self-report** (§F.4). **Pass criterion (Part G):** both recorded independently of any SUT self-report; `correlation_id` matches the harness-minted value.

The word carrying the weight is **independent**. There is a real architectural tension to resolve here and report explicitly: the recorder must sit at the tool, yet `src/sut/` may not import harness code (`CLAUDE.md` red line). Determine a mechanism that satisfies both — external process, wrapper installed by the harness, append-only channel, or another approach — and **document the mechanism and its trust argument in the report**. Do not invent a design the architecture document forbids; if no mechanism satisfies both constraints, that is a FAIL and a finding.

### 4a. Spike — `smoke/g7/spike.py`, runnable via `make gate GATE=g7`

- **G-7.A** one call through the G-6 boundary produces a `ToolIngressEvent` and an `EffectEvent`, both carrying the harness-minted `correlation_id` unchanged.
- **G-7.B** **independence**: the SUT-side code path can neither write, amend, nor delete a ledger entry. Demonstrate by attempting it and showing the attempt fails; state the enforcement mechanism (file permissions, separate process, append-only handle) rather than asserting independence.
- **G-7.C** **immutability**: an existing entry cannot be modified in place; show what an attempted modification produces.
- **G-7.D** **records survive SUT lying**: with the SUT self-reporting "blocked" while the tool actually executed, the ledger still shows the effect. This is the property the whole independent-oracle design rests on; G-12 will stress it further, but a first demonstration belongs here.
- **G-7.E** non-vacuity: a call that does **not** reach the tool produces **no** `EffectEvent`.

### 4b. Settle `ingress_request_digest`

ADR 0009 deferred this field's construction to G-7. Settle it now: write `adr/0012-ingress-digest-construction.md`, status **Accepted**, either adopting `H_JCS` (required if any oracle predicate compares it against an `H_JCS`-governed digest) or fixing a different construction with a stated reason. Update the `schema.py` comment and the ADR 0009 pointer, and say explicitly whether the ingress digest is computed over the same object as `intended_request_digest`. The ingress computation is **recorder-side and independent** of the SUT's (D21).

### 4c. Graduate and test

Move the ledger and recorder into `src/harness/` (same discipline as 3c). Permanent suite `tests/test_effect_ledger.py`, at most eight tests, positive and negative arms: correlation-ID propagation; SUT write attempt rejected; in-place modification rejected; effect recorded despite a false SUT self-report; no effect recorded when the tool is not reached; ingress digest matches the STEP 4b construction.

---

## STEP 5 — Pin, ADRs, reports, documents

On both gates PASS: pin the MCP Python SDK **exactly**, with a comment naming the ADR and gates G-6/G-7; regenerate `uv.lock`; confirm `uv sync --frozen`. Write `adr/0013-mcp-sdk-pin.md` scoping the pin to **only** the surface these gates verified — the tool-call handling path and the interposition point — and stating that A2A integration, transports not exercised, and every other SDK surface remain `[UNVERIFIED-IA]`. A pin never asserts more than its gate verified (ADR 0006 precedent).

Write `smoke/g6/REPORT.md` and `smoke/g7/REPORT.md` in the established section structure, with the 3a enumeration in full and, for G-7, the interposition mechanism and its trust argument. Each report's "what this gate does NOT establish" must be honest: G-6 does not establish that the boundary's **policy** is correct, only that it is unavoidable; G-7 does not establish oracle correctness (Part I), fault detection under adversarial swap/drop/duplicate (G-12), or anything about the arms. Update §F.4 rows IA-6 and IA-7 to verified-by-gate **with residuals**, and the `smoke/README.md` rows for G-6 and G-7.

---

## STEP 6 — Verification, archive, report

1. `uv sync --frozen` from clean; `make gate` for `g1`, `g6`, `g7` and both earlier gates (`g8`, `g5`) — **all exit 0**; full `pytest -q` green; paste the raw tail. `pre-commit run --all-files` clean.
2. Red lines: `src/sut/` zero diff; `git grep -n "harness" src/sut/` shows nothing but the pre-existing rule-stating docstring; `fixtures/confirmatory/` README-only; `frozen_parameters.md` values still UNSET; Part H untouched; `git diff --stat da1c9c9..HEAD` reviewed hunk by hunk.
3. Archive this file byte-for-byte to `docs/tasks/archive/g6g7/` with a `MANIFEST.md` carrying its SHA-256 and the standard label **"retrospective records — NOT pre-registration evidence."** Remove the root copy in the same commit.
4. Report: gate statuses with the decisive evidence line per check; **the full 3a call-path enumeration**; the G-7 interposition mechanism and trust argument; the MCP SDK version pinned and what the pin does **not** cover; test counts and the raw pytest tail; every commit hash in order; push confirmed by pasting `git ls-remote origin main` verbatim; every document diff; residual risks per gate; and what is now unblocked but **not** started — G-2 (still blocked on `Γ`), G-11, and the G-4 spike. Then **STOP and wait.**
