# 0025 — The reference LLM-turn denominators and the G-3 latency threshold (`frozen_parameters` rows 7 and 2)

## Context

Part H step 2 and §J.2 item 9 impose an ordering that exists to prevent a specific failure:
**the G-3 threshold and the equivalence margin must be fixed from external engineering need,
before any timing measurement**, and the G-3 threshold first. A threshold chosen after seeing the
data is not a threshold; it is a description of the data wearing a threshold's clothes.

Two rows are fixed here, in one ADR, because the second is derived from the first:

- **Row 7** — the reference LLM-turn denominators. §E.5 makes absolute overhead the **primary**
  result and the fraction-of-one-LLM-turn a **secondary interpretive aid**, reported against both
  a full-turn and a conservative TTFT denominator.
- **Row 2** — the G-3 latency smoke threshold, which is a **gate** criterion (does boundary
  verification cost anything like a plausible per-step budget?) and is deliberately separate from,
  and set before, row 1's equivalence margin (ADR 0026).

Neither value may be derived from this experiment's own measurements. Both are therefore anchored
to published third-party figures and to the runtime-guard operating point already established in
the project's literature review.

## Decision

### Row 7 — reference denominators

`[DESIGN]` **`T_full = 2000 ms`** (primary denominator) and **`T_ttft = 250 ms`** (conservative
secondary denominator). Both are **fixed constants for interpretation**, not measurements, and
neither is ever re-fitted to observed data.

**Why these values, and why the direction of the choice matters.** A denominator that is too
*large* would make any overhead look negligible. Both values are therefore taken at or below the
**low end** of the published ranges, so the reported fraction is **larger** than a generous choice
would give, and the "lightweight" framing is held to a stricter standard rather than flattered.

- `T_full = 2000 ms`. Published 2026 practitioner figures put agent planning at roughly one to
  five seconds per reasoning step, and a representative tier-2 support agent at about 2.7 s
  median turn time. 2000 ms sits at the bottom of that range.
- `T_ttft = 250 ms`. Published 2026 TTFT figures for the fastest tier straddle this value:
  specialised inference silicon is reported near 0.18 s, a mainstream low-latency proprietary
  model near 0.35 s, and a frontier non-reasoning model in the 0.4–0.8 s band. 250 ms is at or
  below the mainstream fastest tier, so it is the conservative choice in the direction that
  penalises this work's own result.

**Sourcing obligation, and it is not optional.** Each figure is recorded in
`docs/frozen_parameters.md` row 7 with an **exact source, URL and retrieval date**, snapshotted at
seal time. The primary anchor is the independent benchmark that publishes per-model TTFT and total
response time on a fixed methodology and is cited as such in vendor technical reports; trade-press
aggregations may corroborate but **must not** be the sole citation for a number that appears in the
dissertation. If a figure cannot be sourced to a dated, retrievable publication, the value stays
but the claim that rests on it is reported as unanchored rather than the value being changed to
whatever happens to be citable.

**Scope.** Row 7 governs a **secondary interpretive aid only**. No hypothesis, no gate criterion
and no retraction rule depends on it except through row 2 below. Its precision therefore matters
far less than its being fixed and disclosed **in advance**, which is what this ADR accomplishes.

### Row 2 — the G-3 latency smoke threshold

`[DESIGN]` **G-3 passes iff the median single boundary-verification cost is `≤ 5 ms`** on the
row 9 sealed measurement platform.

Three independent arguments converge on this value, and the ADR records all three because a
threshold justified one way is a threshold that moves when that way is questioned:

1. **A per-step budget argument.** 5 ms is 2% of `T_ttft` and 0.25% of `T_full`. A per-invocation
   authorization cost at 2% of the most optimistic first-token budget is not a deployment
   obstacle; one substantially above it would be.
2. **A comparison to the published operating point.** Runtime agent-guard work already reports an
   operating point of roughly **20 ms per step**. A gate threshold four times tighter than an
   operating point the literature treats as deployable is defensible as a *smoke* criterion.
3. **Headroom against the real cost, in both directions.** Ed25519 signing and verification plus
   RFC 8785 canonicalization over the golden-thread payloads sit well below 5 ms on commodity
   hardware, so the threshold leaves roughly three-to-tenfold headroom. **Both outcomes are
   therefore informative**: passing is not automatic, and failing would indicate a real defect in
   the implementation rather than an impossible bar. A threshold that could not fail would not be
   a gate.

**Where G-3 may be adjudicated.** A G-3 run that counts toward the gate **MUST** execute on the
row 9 sealed measurement platform. The Linux CI runs the spike for **regression protection only**
and its numbers are never adjudicative — a cross-platform latency claim would need the five G-7
checks that ADR 0014 defers.

## Rejected alternatives

**Setting row 2 after a pilot timing run.** Rejected: it inverts Part H step 2 and makes the
threshold a restatement of the measurement. The whole point of fixing it first is that it can fail.

**A single denominator.** Rejected: §E.5 already requires both, and the two answer different
questions — whether the cost is material against a whole turn, and whether it is material against
the moment the user first sees output. Reporting only the larger would be the flattering choice.

**Deriving row 2 from row 1.** Rejected and inverted: Part H step 2 fixes the G-3 threshold
**first**, separately. ADR 0026 sets row 1 afterwards and does not re-open this value.

## Status

accepted — 2026-07-31 (rows 7 and 2 of `docs/frozen_parameters.md`; amendable by a later ADR until
Part H step 3)

## Consequences

- `docs/frozen_parameters.md` rows 7 and 2 are set, each with its justification line and, for row 7,
  its dated sources. `src/harness/frozen_parameters.py` gains both, and any run that would compare
  a measured value against either **fails closed** if the row is unset.
- **`IA-3` stays `[UNVERIFIED-IA]` until G-3 actually runs.** Fixing the threshold is not verifying
  the assumption, and this ADR must never be cited as if it were.
- No timing number is produced by this ADR. It fixes the bar; it measures nothing.
- **Re-triggered by:** any change to the sealed measurement platform (row 9), which would invalidate
  a G-3 adjudication run on the previous one; and any change to `Ω`/`Γ` large enough to change what
  boundary verification does.
