# Gate G-3 — boundary-verification cost — **PASS**

> **This file and `smoke/g3/spike.py` are the only places in the repository where a timing number
> appears.** The project's "no timing number" invariant became *narrower* on 2026-08-02, not void:
> no latency figure belongs in an ADR, a README, a commit message, or any other gate's report.

**Part G's row:** *"Sign/verify 1,000 HTC+INV pairs (Ed25519); time boundary verification."*
**Criterion (`frozen_parameters` row 2, ADR 0025):** the **median single boundary-verification cost**
is `≤ 5 ms` on the row 9 sealed measurement platform.

**Adjudicated 2026-08-02 on the row 9 platform**
(`Windows 25H2 build 26200.8875; i7-12700H; 14C/20T; 15.75 GiB DDR4; High performance; on AC`),
recorded in full in `docs/measurement_platform.md`. Row 9 was **locked in a separate commit before
this measurement was taken**, so the platform was sealed before the number existed.

## Result

| quantity | value |
|---|---|
| **median** | **2.8264 ms** |
| p95 | 3.4841 ms |
| IQR | 0.2898 ms |
| pairs timed | 1,000 (4 batches × 250) |
| warm-up discarded | 100 |
| per-batch medians | 2.9190, 2.8259, 2.8213, 2.7511 ms |
| last-vs-first batch drift | **−5.8%** |

**Verdict: `2.8264 ms ≤ 5 ms` — PASS.** Nothing else decides it.

## The quantity is `boundary_verification` ALONE

This is **row 2**, not row 1, and ADR 0026 separated them deliberately:

| | row 2 (this gate) | row 1 (after the seal, not here) |
|---|---|---|
| quantity | `boundary_verification` alone — `arm.decide(...)` | `presentation + boundary_verification` |
| statistic | median, single invocation | `median(B3) − median(B0)`, 95% bootstrap CI upper bound |
| bar | ≤ 5 ms | < 20 ms |

The two bars differ on purpose — a gate threshold wants headroom, an equivalence margin encodes what
the field tolerates. **Nothing here says anything about row 1's estimand**, and the number above must
not be quoted as though it did.

Each of the 1,000 iterations re-runs `delegate` (signing the HTC chain) and `present` (signing the
INV), so a **fresh pair is signed** as Part G's row requires; only `decide` — the verification — is
inside the timed span.

## The headroom is real but **thinner than ADR 0025 argued**, and that is a finding

ADR 0025 justified 5 ms partly on the expectation that *"Ed25519 plus RFC 8785 canonicalization over
the golden-thread payloads sit well below it, leaving roughly three- to tenfold headroom — so both
outcomes are informative and the gate can fail."*

**Measured headroom is 1.77×, not three- to tenfold.** The gate passes and the threshold is
untouched — it was fixed in advance precisely so the data could not move it — but the ADR's
*quantitative* expectation about the margin was optimistic by roughly a factor of two. Recorded here
because a reader comparing the ADR's prose to this result would otherwise find a discrepancy and have
to guess which was adjusted. **Neither was.**

The direction matters for what comes next: **row 1's estimand includes `presentation` as well**, and
`presentation` is where `B3`'s per-invocation signing lives. Nothing here predicts row 1's outcome —
that is RQ4's campaign, after the seal — but the margin is not so large that the result can be
assumed.

## What a failing world looks like here

The comparison is a plain `median <= threshold` on the number printed above, so a failure needs the
verification to cost **1.77× more** than it does — about 5 ms. That is not a hypothetical régime: it
is roughly what this same measurement would report if the process were **not pinned** and a
meaningful share of repetitions landed on E-cores, or if it ran **on battery**. Both are refused by
the spike rather than left to chance (`G-3.H1`, `G-3.H2`), and both would otherwise have moved the
number in the direction that fails.

So the gate is not one whose criterion cannot fail: two ordinary and *unremarkable* conditions on
this machine would push it over, which is why the hazards are handled rather than hoped away.

## The three hazards

**1. P-core / E-core scheduling — pinned, and the mask was DETECTED.**
`GetSystemCpuSetInformation` was walked record by record and each logical processor's
`EfficiencyClass` read; **two classes** were found and the process was pinned to the highest,
logical processors `[0…11]`. The detection **fails closed** — no mask is guessed — because a guessed
logical-processor range would silently reintroduce exactly the bias the pinning removes. Unpinned,
Thread Director scatters repetitions across E-cores and the distribution goes bimodal, so the p95 and
IQR §E.5 requires would be reporting the **scheduler's** spread as the mechanism's.

**2. AC power — asserted.** `G-3.H2` confirms mains; the spike refuses on battery with a named error,
because a laptop throttles on battery whatever the power plan says.

**3. Thermal — measured, and NOT observed.** Four batches, medians `2.9190, 2.8259, 2.8213,
2.7511 ms`. The last batch is **5.8% faster** than the first, not slower, so there is **no thermal
degradation across this run** — if anything the warm-up continued mildly past its first 100
iterations. Stated explicitly because the check exists to be able to say the opposite: a
systematically slower late batch would have been thermal, and it would have been reported rather than
averaged into the median.

**Hazard state as found, and deliberately not changed** (changing the power plan between locking
row 9 and adjudicating G-3 is forbidden): sleep on AC is **600 s and is not off**; hibernate is
never; USB selective suspend is enabled. The run is far shorter than ten minutes, and no USB device
is in the measured path — G-3 times signature verification with no effect ledger involved.

## Warm-up

**100 iterations discarded**, ~10% of the sample. Fixed *in advance* rather than chosen by looking at
where the curve flattens, which would be fitting the warm-up to the data. It is comfortably past the
first-call effects that dominate early iterations here: lazy imports in the crypto and Biscuit paths,
first-touch allocation, and cold branch predictors.

## Linux CI is regression protection only, and is **never adjudicative**

Row 2 names *the row 9 sealed measurement platform*. On any non-Windows platform the spike prints
that it is **NOT ADJUDICATED**, completes the pairs as a regression check, and **records no verdict**
— the same rule G-12 applies to its ledger-backed limbs. A Windows-platform criterion must not be
laundered into a green Linux tick.

## IA-3

**Moves to verified.** Fixing a threshold was never verifying an assumption — ADR 0025 says so
explicitly — and measuring against it on the sealed platform is.

## Scope

This gate establishes **cost on this platform for `boundary_verification`**. It does **not**
establish row 1's estimand, the equivalence margin, or anything about `B0`; it adjudicates no other
gate; and it re-triggers if row 9 changes — a power-plan, hardware, driver or Windows-build change
invalidates this adjudication (ADR 0025).
