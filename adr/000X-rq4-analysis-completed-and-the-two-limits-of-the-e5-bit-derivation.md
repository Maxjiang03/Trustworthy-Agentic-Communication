# 000X — RQ4's analysis layer completed, and the two limits of the §E.5 bit derivation

## Context

**RQ4 asks** for the absolute added latency of each mechanism, separated into **setup, delegation,
boundary-verification and end-to-end** components, cold and warm, and for the
security-versus-overhead trade-off. The instrumentation for that has been complete since ADR 0026:
`GoldenThreadRunner` records five spans per run (`setup`, `delegation`, `presentation`,
`boundary_verification`, `end_to_end`) as monotonic-clock intervals correlated by
`correlation_id`, and the campaign carries the seams as **names, never durations**.

**The analysis layer was not.** `analysis/latency.py` implemented exactly the frozen row 1
machinery — the equivalence decision over the measured segment
(`presentation + boundary_verification`, warm) — and its own comment inside `_segment_values`
said `setup`, `delegation` and `end_to_end` *"are reported separately"*. **No code reported
them.** Found while preparing the pre-registration, which must seal the full pre-registered
statistical procedure (Part H step 3): RQ4 was roughly one quarter answered, and the dissertation
supervisor has separately asked for exactly the missing parts — end-to-end latency and the
per-mechanism overhead of the individual security constructions.

The obvious route to "per-mechanism overhead" — difference two adjacent arms — runs through
§E.5's ten-column bitmask, and **the bitmask does not support it as widely as it appears to.**
That is the finding this ADR exists to record.

## Decision

`[DESIGN]` Three functions complete the RQ4 layer, in `analysis/latency.py` only — no change to
`src/`, to any existing analysis function, or to any frozen row. All three produce
**descriptives**; the only equivalence decision in this study remains row 1's (ADR 0026), and
nothing added returns a `Decision`, accepts a margin, or compares anything to one (asserted
structurally in `tests/test_analysis_rq4.py`).

1. **`span_descriptives`** — `Descriptives` (median, p95, IQR — §E.5's shape) for every runner
   span, every arm and every phase present, cold and warm never pooled, warm-up discarded through
   the one existing `discard_warmup`. The chain-tamper exclusion (ADR 0026, §J.3 item 12) is
   re-applied **per span**, and it binds harder here than on the measured segment: on
   `gt-f1-chain-tamper` the exchange arms' **failed AS round trip lands in `delegation`**, so the
   refusal path is reported under its own `refusal_path` series and a chain-tamper sample
   reaching a benign span series raises. A repetition missing a requested span — or a span
   missing from every repetition, the shape a campaign result would have if it stopped carrying a
   seam the runner records — **refuses the report** rather than averaging over what is present.
   The five span names are a **transcription** (`RQ4_SPANS`): `analysis/` may import nothing from
   `src`, so a test pins the tuple against the runner's `timing.mark(...)` sites read as source
   text, and a seam added or renamed there re-triggers it.

2. **`arm_pair_delta`** — `median(treatment) − median(control)` for one span (or for ADR 0026's
   measured segment, built by the same `benign_series` the row 1 estimand uses), with a 95%
   percentile-bootstrap CI from the one existing `bootstrap_median_difference`, seed required.
   The pair is labelled by `e5_bit_difference` **before any arithmetic**, from a cell-for-cell
   **transcription of §E.5's bitmask table** (`E5_BITMASK`, row labels and cell tokens exactly as
   the document writes them — `dpop-cnf`, `(scope in token)` and `root-only` stay opaque tokens
   compared for equality only). A test pins the transcription against the design document's own
   table, so **an amendment to §E.5 re-triggers it**; no invented column, no invented cell.
   Labels, by what the derivation can actually support:
   * **exactly one cell differs** → `mechanism-increment`, naming the bit;
   * **more than one differs** → `composite-delta`, naming every differing bit, `mechanism = None`
     — it must never carry a single mechanism's name;
   * **zero differ, or the pair involves `B1`** → **refused**, because the bitmask is known not
     to describe the difference (the two limits below).

3. **`llm_turn_fraction`** — `frozen_parameters` row 7's framing: a span's median as a fraction
   of `T_full_ms` and of `T_ttft_ms`. **A secondary interpretive aid only** (ADR 0025): both
   denominators are fixed constants for interpretation, never measurements, never re-fitted to
   observed data, and no hypothesis, gate criterion or retraction rule depends on this framing.
   The values are read from their single reader,
   `src.harness.frozen_parameters.llm_turn_denominators()`, by the **caller and the committed
   tests** — `analysis/` cannot import `src` (the no-measurement guarantee is structural), so the
   function takes the pair as parameters exactly as `lightweight_claim` takes the row 1 margin,
   and a test derives the forbidden literals **from the frozen readers themselves** and scans the
   module and the test file to refuse a hardcoded `2000`, `250` or `20`.

### The two limits of the bit derivation — findings about the design, not defects repaired

Verified against §E.5 and pinned by the transcription tests. **Both constrain what the
dissertation may claim about per-mechanism cost**, and neither is repaired here: inventing a bit
for either would make `E5_BITMASK` stop being a transcription, and what to do about them is the
Commander's decision.

1. **§E.5 carries no bit for the RFC 8693 exchange.** `B2-broad-noexchange` and
   `B2-exchange-broad` have **byte-identical rows** (`1 0 0 0 0 0 0 0 0 1`), yet one performs an
   exchange round trip on every delegation and the other never talks to the AS. Any pair with
   identical rows is therefore refused. The consequence reaches further than the refused pair: a
   delta between an arm that exchanges and one that does not (e.g. `B2-broad-noexchange` →
   `B2-exchange-task`, one cell apart via `contain`) **carries the unmodelled round trip inside a
   bit-labelled result**, so a `mechanism-increment` label names the bit, never everything that
   changed. The honest per-mechanism cost of *the exchange itself* is not derivable from the
   bitmask at all.

2. **§E.5 carries no bit for `B1`'s static shared secret** (ADR 0035: `B1`'s row is `0…0 1`,
   `audit` alone). The one authentication mechanism `B1` has is invisible to the bitmask, so
   *every* pair involving `B1` is refused with the ADR 0035 reason — including `B0 → B1`, which
   differs only in `audit` and would otherwise be labelled as if audit logging were the only
   thing `B1` adds. This is the third abstraction found to drop `B1`'s secret plane (after the
   bitmask reading corrected by ADR 0035 and the fault vocabulary), consistent with ADR 0035's
   standing obligation: any mechanism that enumerates credentials must ask what `B1` carries.

What remains derivable, stated positively: the bitmask supports **exactly two clean
single-mechanism increments on the built ladder** — `B2-exchange-task → B2-exchange-task-DPoP`
(`htc/holder`: DPoP holder binding) and `B3 → B3⁺` (`jti`: the replay cache) — plus the six
matched ablations, each a single bit off `B3` by construction (confirmed mechanically from the
transcription). `B-cap → B3` differs in **four** bits (`htc/holder`, `invoke`, `context`,
`approval`) and is reported only as a composite; it is **not** "the cost of invocation binding".

## Addition, 2026-08-05 — limit 1's reach, enforced by the exchange-partition guard

The Decision above enforced limit 1 only where the bit difference already fell to a refusal
(identical rows) and left its **reach** — a single-bit pair straddling the unmodelled exchange —
as prose. The Commander's decision: **close it in code, not in prose.**

**The finding, verified by enumerating all 15 rows.** Exactly one unordered pair (both ordered
directions) was returned as a clean `mechanism-increment` while straddling the exchange:
`B2-broad-noexchange ↔ B2-exchange-task`, one cell apart via `contain`. The bit is named
correctly; what is not named is the **online AS round trip that only one of the two arms
performs** — on a localhost AS plausibly the dominant term, so "the cost of task-scoping is
X ms" would be wrong by a round trip. The error direction matters: it **inflates an OAuth arm's
apparent mechanism cost and makes the capability arms look relatively cheaper** — it fails
toward this project's own hypothesis, the pattern the standing bias check exists for. Every
other increment is safe: `B2-exchange-broad → B2-exchange-task` and
`B2-exchange-task → B2-exchange-task-DPoP` are exchange-to-exchange, and `B3 → B3⁺` plus the
six ablations are non-exchange throughout. (The third exchange-to-exchange pair,
`B2-exchange-broad ↔ B2-exchange-task-DPoP`, was already a two-bit composite and is untouched.)

`[DESIGN]` **The guard.** `PERFORMS_AS_EXCHANGE` in `analysis/latency.py` declares the exchange
partition explicitly: a **total** classification of every §E.5 row — `B2-exchange-broad`,
`B2-exchange-task` and `B2-exchange-task-DPoP` perform an online AS exchange per delegation;
every other row does not. It is **transcribed from §E.1/§E.2** and **deliberately not derived
from §E.5**, because §E.5 having no bit for the exchange *is* limit 1; it lives beside the
bitmask, never as an invented column in it, and the existing test asserting no exchange column
exists keeps passing. When exactly one arm of a single-bit pair is in the partition,
`e5_bit_difference` **downgrades the label to `composite-delta`** (`mechanism = None`,
`differing_bits` keeps §E.5's truth) and **names the unmodelled round trip on the record
itself** — a new `unmodelled` field carried by `BitDifference` and `ArmPairDelta`, empty for
every pair the bitmask fully describes. **Downgraded, not refused**: the delta remains a
meaningful arm-pair comparison the dissertation may report with the caveat; the problem was the
label, not the arithmetic. An arm the partition does not classify **fails closed** at lookup.

**Watched failing, as committed tests** (`TestTheExchangePartitionGuard`): both directions of
the straddling pair downgrade with the round trip named on the record; the two
exchange-to-exchange increments and all seven non-exchange increments still read
`mechanism-increment` with `unmodelled` empty; an exhaustive sweep of all 15×15 ordered pairs
finds the tag on **exactly two** ordered pairs and **exactly nine** surviving increment pairs;
the negative arm flips `B2-exchange-task` out of the partition and the straddling pair reads
`mechanism-increment` again — ecaef48's behaviour reproduced, proving the downgrade flows from
the partition entry; and deleting the entry makes the pair refuse (totality enforced at lookup,
so a future §E.5 row is unlabellable until classified, the ADR 0035 obligation applied to this
enumeration too).

**The claim boundary, stated explicitly** (this widens the second Consequences bullet below to
the ablations, by dated note rather than rewrite): the dissertation **may** state the isolated
cost of **DPoP holder binding**, of the **jti replay cache**, and of **each of the six §E.6
ablations**; it **may not** state a per-mechanism cost for the **exchange**, for **`B1`'s
secret verification**, or for **anything read off a pair that straddles the exchange
partition**.

## Status

accepted — 2026-08-05 (the RQ4 analysis layer; placeholder letter, the number is the Commander's;
the two derivation limits are findings recorded for the Commander, not corrections. Dated
addition, same day, on the Commander's decision: limit 1's reach is enforced by the
exchange-partition guard rather than left to the reader)

## Consequences

- RQ4's four components can each be reported, per arm and phase, from campaign samples — with
  the same refusal discipline the row 1 machinery has: nothing pooled across phases, nothing
  pooled with the refusal path, nothing averaged over a half-measured repetition, and **still no
  timing number anywhere outside `smoke/g3/REPORT.md`**: the new code measures nothing and its
  tests are synthetic, per the existing structural guarantee over all of `analysis/`.
- The results chapter may state the isolated cost of **DPoP holder binding** and of **the jti
  replay cache**, each as a point estimate with a bootstrap CI. Every other pairwise difference
  is a labelled composite or a refusal, and the per-mechanism cost of the **exchange** and of
  **`B1`'s secret verification** cannot be claimed from the bitmask derivation at all.
- No new decision rule exists: `equivalence_decision` and `lightweight_claim` remain the only
  producers of a `Decision` (asserted by test), and row 1's margin remains the only threshold.
- Re-triggered by: any amendment to §E.5's bitmask table (the transcription pin fails), any
  change to the runner's timing seams (the span pin fails), and any change to `frozen_parameters`
  rows 1 or 7 (the literal scan derives its forbidden set from the readers).
- `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is **not** amended by this ADR: the two absences are
  recorded here as findings for the Commander, who decides whether §E.5 gains a note, the
  pre-registration carries the constraint, or both.
