# TASK — Experimental body, block 5: process separation, and gates G-12, G-9 and G-14

Ten gates pass. The three that remain before G-10 all rest on one thing the apparatus does **not**
yet have: **the SUT and the harness run in the same process.**

That is not a detail. Two gate records already carry it as a standing residual —
G-6's *"in-process raw-reference/introspection paths excluded by SUT process separation (stressed at
G-12)"* and G-7's *"in-process reachability inside the harness process excluded by SUT process
separation and stressed at G-12"*. Both defer to **G-12**, and G-12 is in this block. Until it runs,
complete mediation and ledger immutability are established only for a co-resident SUT that could, in
principle, reach past both by holding a Python reference.

Three gates, in dependency order (Part G's DAG: `G-12/G-13 → G-9/G-14`):

- **G-12** — a fault-injected SUT reporting a **wrong** self-verdict while the ledger records the
  true effect, plus correlation-ID swap/drop/duplicate/concurrency injection. Its stake, in Part G's
  own words: **oracle independence; every security result.** If the oracle can be fooled, nothing
  else in the study survives.
- **G-9** — N concurrent bit-identical requests at the replay cache **across processes**, plus an
  induced backend error. `B3⁺`'s cache is single-process today and says so; this is where that
  changes.
- **G-14** — the same authenticated-ID cache on `B2-DPoP` and on `B3`, running §D's four-way DPoP
  taxonomy, so the DPoP/INV attribution rests on measurement rather than on argument.

Four phases. **A** (STEP 3–5) is process separation. **B** (STEP 6–8) is G-12. **C** (STEP 9–10) is
G-9. **D** (STEP 11–12) is G-14. Each ends green and committed; report between phases.

---

## STEP 0 — Self-check, and the machine

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the launch
prompt**. If either differs, **STOP and report**.

Confirm the `pre-commit` git hook is installed. And carry forward your own process note from block 4:
**`pytest` green is not `main` green** — CI runs the gate spikes too, and this block adds one more.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | **Measuring, benchmarking or reporting any latency number** | G-3 owns timing, needs the row 9 sealed platform, and is **not** in this block. Process separation will change costs; **that is G-3's to measure, not yours to mention** |
| 2 | Running, preparing or marking G-3 or G-10; editing any Part G row, pass criterion, dependency edge or evidence grade | Three gates are adjudicated here and only three |
| 3 | **Weakening a fault injection so a gate passes** | The faults are the instrument. A swap the oracle cannot detect is a **finding**, not a fixture to soften |
| 4 | Amending any frozen row, `Ω`/`Γ`, the registry, the policy document, or any `H(·)` | ADR 0016/0019/0022/0023/0025/0026/0027/0030 |
| 5 | Setting row 5 or row 9 | Row 5 is deferred by decision (ADR 0028); row 9 is read at seal time |
| 6 | Changing `Δ` or the `2^16` capacity to make a concurrency test convenient | ADR 0027 froze both. If a test needs a different value, **the test is wrong** |
| 7 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/` | Red line 6, ADR 0015. Process separation makes these **easier** to honour, not optional |
| 8 | Letting a SUT process read `τ_gt`, `IntendedInvocation`, or any sealed object — including over the new IPC channel | §A.3, red line 5. A new channel is a new way to leak; STEP 4 tests it |
| 9 | Drafting `PRE_REGISTRATION.md`, populating `fixtures/confirmatory/`, sealing, or running a campaign | Red lines 1–2 |
| 10 | Secrets or minted tokens on disk, in the repository, or in `results/`; `git push --force`; history rewrite | Red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read what you are implementing

**Part G's G-12, G-9 and G-14 rows verbatim.** Then **Part I in full** — `admission_breach`,
`realized_harm_*`, `log_integrity_failure`, `observed_forwarded`, and the **no-/partial-/multi-effect
MUST**; **§F.1's unforgeable `correlation_id` paragraph**, which names swap/drop/duplicate/concurrency
as G-12's injections; **§D's four-way DPoP taxonomy** with each row's predicted outcome; **§F.5**
(replay ordering) and **D37** (`B3⁺` jti semantics); **ADR 0027** (`Δ`, the `2^16` budget,
fail-closed overflow, the injectable clock, no real waiting); **ADR 0014** (the ledger is Win32-only
and does **not** degrade); and the **IA-6 and IA-7 residuals in §F.4** that name process separation
and defer to G-12.

Then the code: `src/harness/mediation/boundary.py`, `src/harness/effect_ledger.py`,
`src/harness/runner.py`, `src/harness/as_process.py` (the **existing** out-of-process pattern —
spawn, start-up JSON line, runner-held pipe), `src/sut/authz/jti_cache.py` and its honest
single-process note, `src/sut/dpop.py`, and `smoke/g6/`, `smoke/g7/` and `smoke/g13/`.

**Report what turns out underspecified for implementation, and what you did.** Every block has found
some. Do not invent to cover one.

---

# PHASE A — process separation

## STEP 3 — Put the SUT in its own process

Follow the pattern that already works: `src/harness/as_process.py` spawns the AS, reads a start-up
JSON line, and holds the pipe. **Spawn, never import.** Do the same for the SUT: the agents, the
arms and the boundary run in a child process; the harness — runner, mediation record, ledger writer,
oracle, sealed truth — stays in the parent.

Three things this must achieve, and each needs a test that would fail without it:

1. **No shared object graph.** The SUT process holds no Python reference into harness memory, so
   the raw-reference and introspection paths G-6 and G-7 excluded are now excluded **by
   construction** rather than by assumption. This is the residual both gates deferred here.
2. **The ledger writer stays in the parent.** ADR 0014's Win32 exclusive-share handle is what makes
   the ledger unforgeable; a child holding it would defeat the property G-7 established.
3. **The channel carries data, not capability.** The SUT sends requests and self-reports; it
   receives no handle, no callable and no sealed object.

Keep the in-process path working and selectable. G-12 needs both: the fault-injected comparison is
sharper when the same scenario can run either way, and every earlier gate was adjudicated
in-process — **do not silently invalidate ten passed gates.** Say in the report which mode each
existing gate spike runs in after this change, and confirm each still passes.

## STEP 4 — Test the new channel as an attack surface

A new IPC channel is a new way to leak. Write the tests that assume it will be attacked:

- a SUT process asking for `τ_gt`, `IntendedInvocation`, `C_sets`, or any sealed field gets
  **nothing**, and the request is recorded;
- a SUT process cannot open, append to, truncate or delete the ledger — the **same five checks G-7
  ran**, now from a genuinely separate process rather than a same-process caller;
- a malformed, oversized or unparseable message from the child **fails closed** and never crashes
  the harness or admits a call;
- the child dying mid-invocation produces a recorded outcome, not a hang and not a silent pass.

## STEP 5 — Phase A checkpoint

`pre-commit` and `pytest` green, **plus every gate spike CI runs** — name each and its result.
Report the Linux count as **measured or derived**, and say which. Scoped commits; push; verify with
`git ls-remote origin main`. **Report before Phase B.**

---

# PHASE B — gate G-12

## STEP 6 — The lying SUT

Build a fault-injection harness that makes the SUT report a **wrong self-verdict**: it claims
*blocked* while the tool executes, and claims *admitted* while nothing runs. Both directions —
one hides a breach, the other manufactures a false negative, and a gate that only tests the first
has tested half of it.

The criterion is exact and its second half matters as much as its first: the oracle detects every
discrepancy **without reading any SUT verdict or SUT digest.** Assert that structurally — the
oracle's inputs are the sealed intent, the trusted mediation record and the ledger, and a test
should fail if a SUT-supplied verdict or digest can reach a predicate. Block 1's red-line AST scan
is the model.

`log_integrity_failure` is the predicate that catches the first direction: the boundary reported
blocked and an effect occurred anyway. Show it firing on a real lie, and **not** firing on an honest
block — otherwise it is an alarm that is always on.

## STEP 7 — Correlation-ID injection: swap, drop, duplicate, concurrency

§F.1 makes the `correlation_id` harness-minted, unforgeable and bound into the sealed intent, the
`MediationEvent`, the `ToolIngressEvent` and the INV `jti`. Inject all four fault classes and show
the oracle flags each:

| fault | what it simulates | what must be detected |
|---|---|---|
| **swap** | two invocations' records crossed | the effect correlated to the wrong intent |
| **drop** | a record vanishes | a missing linkage, **not** silently "no effect, no harm" |
| **duplicate** | one invocation recorded twice | one intent, two effects |
| **concurrency** | N invocations in flight together | no interleaving produces a mis-correlation |

**Drop is the dangerous one and deserves its own attention.** Part I says zero effects means no
harm — correctly, because an unreached tool produces no entries. But a *dropped record* also
produces zero effects, and if the two are indistinguishable then deleting evidence looks exactly
like behaving well. Show how the oracle tells them apart, or **report that it cannot** — that would
be a finding about the instrument, and a serious one.

Concurrency must be **real** concurrency at the process boundary, not simulated interleaving in one
thread. That is what the fault class means now that Phase A exists.

## STEP 8 — Adjudicate G-12

`smoke/g12/spike.py`, `smoke/g12/REPORT.md`, `make gate GATE=g12`, wired into CI. **Every check shown
able to fail**, judged by the gate's own predicate. Mark **PASS** only if every discrepancy is
detected and the oracle is structurally incapable of reading a SUT verdict or digest. If any cannot
be honestly adjudicated, say which, why, and the smallest correction.

Then close what G-12 owed: **update the IA-6 and IA-7 residuals** — dated notes, not rewrites —
recording that process separation is now real and what that does and does **not** establish.

`obs.raw_arguments` (§J.5 item 20) is G-12's to settle: with a genuine process boundary there are
now bytes crossing it. State whether `raw_arguments` is the bytes as received or still a
re-serialization, and if the latter, whether Part I's three-digest `realized_harm_F3` is still
meaningful. **Report the answer; do not quietly assume it is fine.**

**Report before Phase C.**

---

# PHASE C — gate G-9

## STEP 9 — The multi-process replay cache

`B3⁺`'s cache is `threading.Lock` over a dict — atomic within one process, and its own note says so.
G-9 needs atomic check-and-insert **across processes**, with ADR 0027's parameters unchanged: TTL
exactly `Δ = 60 s`, capacity exactly `2^16`, key `(mechanism_tag, jti)`, **fail-closed on overflow**.

Pick a mechanism and justify it against the alternatives — the AS process pattern, an OS-level
primitive, a single-writer arbiter. Whatever you choose, the **frozen parameters do not move to suit
it** (forbidden action 6). Record the choice in an ADR.

The clock stays **injectable** and **no test sleeps**: sixty seconds of real waiting per repetition,
at ≥ 200 repetitions per configuration, would cost hours and make the suite's runtime a function of
`Δ`.

## STEP 10 — Run G-9, and adjudicate

The criterion: N concurrent bit-identical requests **across processes**; induce a backend error.
Exactly one proceeds; no double-admission; fail-closed observed; the frozen budget respected.

- **Exactly one** — assert the count, not "at least one blocked". A cache admitting two of five has
  failed even though four were blocked.
- **The induced backend error must produce a denial**, never an admission and never a silent
  eviction of an unexpired entry.
- **Overflow must be reachable and tested.** The budget exists so the fail-closed path can be
  exercised, not so the campaign approaches it.
- **Show the world in which it fails**: the same N requests against a cache with the lock removed
  must double-admit, so the passing result is a measurement rather than a race that happened not to
  occur.

`smoke/g9/spike.py`, `smoke/g9/REPORT.md`, CI. `IA-9` moves to verified **only** if all of this
holds. **Report before Phase D.**

---

# PHASE D — gate G-14

## STEP 11 — The same cache on both arms, and §D's four rows

Attach the **same** authenticated-ID cache to `B2-DPoP` and to `B3`. Same object or same class,
asserted structurally — the discipline G-15 established for the monitor. A cache that is merely
equivalent is not the same cache, and the whole gate is an attribution claim.

Run §D's four-way taxonomy. The criterion names three outcomes, and each is a **separate** claim:

1. **Both block `captured-proof-replay` identically** — the shared cache is what blocks it, on both
   arms, and neither does better than the other.
2. **INV-only blocks `first-use-body-mutation` while the replay cache alone does not** — DPoP binds
   method and URI, not the body; this is the cell where invocation binding earns its place, and
   block 3 already made that limitation observable on `B2-DPoP`.
3. **A bare bearer cannot carry the cache** — an authenticated request ID needs something
   authenticating it, so the cache is not a free upgrade for an unbound token. Show *why* it cannot,
   not merely that this configuration was not built.

## STEP 12 — Adjudicate G-14, and say what it attributes

**PASS** only if all three hold. The attribution this gate delivers is worth stating plainly in the
report and belongs in the results chapter: **DPoP and invocation binding block different things, and
the difference is measured here rather than argued.** If the taxonomy disagrees with §D anywhere,
that is a finding — report it; adjust neither the code nor §D.

Board and IA cells at their true values, dated notes rather than rewrites. `IA-3` stays
`[UNVERIFIED-IA]` — none of these three gates establishes cost.

---

## STEP 13 — The standing check

Five blocks, five instances of one hazard: a check that made an existing capability unobservable,
dormant at first and load-bearing later, failing **toward** the hypothesis every time.

This block adds a process boundary, a cross-process cache and four fault injectors. Before
reporting, ask of **each** arm: *does it still distinguish itself where §E.4 says it does?* In
particular — does every arm behave identically across the process boundary, or did separation change
an outcome? Does `B3⁺` still uniquely block the F3 replay now that the cache is cross-process? Do
the ten passed gates still pass? **Report the answer per arm, and per gate.**

---

## STEP 14 — Commit, push, archive

Scoped Conventional Commits, ADRs referenced in bodies. Archive this spec under
`docs/tasks/archive/exp5-process-separation/` with the standing note that task specs are
**retrospective records, NOT pre-registration evidence**, and remove the working copy in the same
commit. Push; verify with `git ls-remote origin main`.

---

## STEP 15 — Stop and report

1. STEP 0 self-check and the hook confirmation.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did.
3. **Phase A:** the separation mechanism, the three properties with the test that would fail without
   each, and the four channel-attack tests. Which mode each existing gate spike runs in, and
   confirmation that each still passes.
4. **Phase B:** the lying SUT in **both** directions. The structural proof that no SUT verdict or
   digest reaches the oracle. The four correlation-ID faults — and specifically **how drop is
   distinguished from an unreached tool**, or that it is not. G-12's adjudication, the IA-6/IA-7
   residual updates, and the `raw_arguments` answer.
5. **Phase C:** the cross-process mechanism and why, over the alternatives. Exactly-one under
   concurrency, the induced backend error, overflow reached, and the lock-removed world that
   double-admits. Whether `IA-9` moves.
6. **Phase D:** the shared cache asserted structurally, and each of the three claims separately.
   Any disagreement with §D, unadjusted.
7. **STEP 13's answer, per arm and per gate.**
8. Confirmation that no timing number was produced, no test sleeps, no frozen parameter moved, and
   no secret reached disk, the repository or `results/`.
9. Commits, push verification, counts on both platforms **stated as measured or derived**, every
   gate spike's result, and anything you could **not** verify.
10. Any point where you were tempted to soften a fault injection, to move a frozen parameter to suit
    a test, to describe the cache as more G-9-ready than it is, or to build past this specification
    — and what you did instead.
