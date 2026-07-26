# 0010 — The §K LLM-in-the-loop demonstration is retained, strictly outside the seal

## Context

The research proposal (§K) promised a single qualitative demonstration placing a **real LLM
agent and a poisoned MCP tool** into the golden-thread example, and §M cited it as partially
narrowing the external-validity gap (the measured benchmark uses deterministic mock agents).
The architecture document (Parts A–J) defines the sealed, measured campaign and does not
mention the demonstration. This ADR records the Commander's adjudication of its scope.

## Decision

[DESIGN] The demonstration is **retained**, strictly **outside the sealed campaign**:

- It is **qualitative** and produces **no counts, no rates, and no statistics** — its output
  may never enter a results table. It is narrative evidence that the golden-thread scenario is
  realizable with a real LLM agent, nothing more.
- It is **not** part of the sealed corpus or the single confirmatory campaign, and running it
  — before, during, or after the campaign — **can never trigger an unseal** (Part H's unseal
  rule covers sealed design/oracle/config/corpus; the demonstration touches none of them).
- Its scope is the **golden thread under B0 and B3 only** — one benign-plus-attack narrative
  under the no-protection arm and the full control layer, no other baseline, no sweep.
- The **deterministic-mock design remains the sole basis for every measured result**, for the
  pre-registered reason: it removes LLM sampling as a confound (verdicts must be functions of
  the sealed scenario and frozen configuration, §F.1/Part I — an LLM in the loop would make
  them functions of sampling noise).
- It is reported with **explicit limitations under external validity**: one scenario, one
  model, qualitative only; it narrows the mock-vs-real gap anecdotally, not statistically.
- **Schedule rule:** if the schedule does not permit it before the **11 September 2026**
  submission, it is **dropped**, and the dissertation records the scope change and its reason
  — never silently omitted.

**Implement nothing now.** No scaffold, no stub, no fixture, no prompt file; this ADR is a
scope record only.

## Status

accepted — 2026-07-26

## Consequences

- A note in the architecture document states that the demonstration exists **outside Parts
  A–J and outside the seal** (same pass); registered in Part B.2. Parts A–J themselves are
  unchanged — no baseline, gate, predicate, or corpus definition refers to the demonstration.
- The seal-loop invariants are unaffected: the demonstration cannot contaminate the frozen
  benchmark, cannot force a reseal, and cannot generate a measured claim.
- The write-up gains either one qualitative subsection under external validity or one recorded
  scope-change paragraph — never an unexplained absence.
