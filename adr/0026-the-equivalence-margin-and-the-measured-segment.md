# 0026 — The equivalence margin, and the code extent of the segment it is measured over (`frozen_parameters` row 1)

## Context

§E.5 fixes the retraction rule in words this ADR must not paraphrase away:

> the "lightweight" claim is pre-registered as **retracted** if the absolute added
> **boundary-verification** latency of **B3 over B0** exceeds the equivalence margin.

Row 1 is that margin. ADR 0025 fixed the G-3 threshold first and separately, as Part H step 2
requires; this ADR sets the margin afterwards and does not re-open it.

**A defect found while fixing the extent, and it runs toward the hypothesis.** The retraction rule
names a *segment*, and the apparatus already has a `boundary_verification` seam — but that seam
brackets `arm.decide(...)` **alone**. `arm.present(...)` is in no sub-span at all, and for `B3`
that is exactly where the per-invocation cryptographic work lives: RFC 8785 canonicalization of the
arguments, `access_token_hash`, and the Ed25519 INV signature. Measuring the segment as currently
bracketed would omit `B3`'s principal per-invocation cost from the very test the "lightweight"
claim is settled by — an omission that makes `B3` look cheaper. It is fixed here, before any
measurement, rather than discovered afterwards.

## Decision

### The margin

`[DESIGN]` **Equivalence margin = 20 ms.**

- **Estimand:** `median(B3) − median(B0)` over the measured segment defined below, **warm path**.
- **Decision rule:** the claim stands iff the **upper bound of the 95% bootstrap confidence
  interval** on that difference is **< 20 ms**. A point estimate below the margin with a CI upper
  bound above it does **not** support the claim.
- **Sampling:** per §E.5, **≥ 200 end-to-end repetitions per configuration across ≥ 3 independent
  batches**, cold and warm reported separately, condition order randomised or Latin-square
  counterbalanced within each batch, warm-up discarded.
- **Comparison:** `B3` against `B0`, exactly as §E.5 words it. No other pair may be substituted for
  this test, and the arms compared are not renegotiated after seeing results.

**Anchors.** 20 ms is 1% of `T_full` (ADR 0025) and is **precisely** the per-step operating point
that published runtime agent-guard work already treats as deployable. "Lightweight" thereby
acquires an operational definition — *no worse than an operating point the literature already
accepts* — rather than remaining an adjective. Note the deliberate asymmetry with ADR 0025: the
G-3 smoke threshold is 5 ms because a gate should have headroom; the equivalence margin is 20 ms
because it encodes what the field already tolerates. They answer different questions and are not
required to agree.

### The measured segment, pinned once, here

`[DESIGN]` The **measured segment** is `presentation + boundary_verification`, where each span
brackets exactly one call and nothing else:

| span | code extent | why |
|---|---|---|
| `presentation` **(new seam)** | exactly `arm.present(credentials, invocation)` in `GoldenThreadRunner` | the per-invocation credential assembly the mechanism performs. `B3`: JCS canonicalization, `access_token_hash`, INV signing. `B0`: returns an empty mapping, so its contribution is ~0 and the difference isolates the added cost |
| `boundary_verification` | exactly `arm.decide(tool, arguments)` — the present extent, unchanged | the per-invocation verification the boundary performs |

**Excluded, and named individually so the exclusion is auditable rather than implied:**

1. the harness's `boundary_observations.append(...)` — instrument bookkeeping, and it already
   executes before the span opens;
2. the `MediationEvent` emission inside `install_boundary` — instrument, and after `decide` returns;
3. **every effect-ledger append** — the `ToolIngressEvent` written by the ingress recorder and the
   `EffectEvent` written by the effector. Both occur after admission, inside the tool dispatch path.
   The ledger is an **experimental instrument with no deployment counterpart**, so charging it to
   any arm would measure the apparatus rather than the mechanism. *(This is the question the
   Commander asked to have settled: ledger append is **outside** the segment, and it already is,
   structurally.)*
4. the tool's own execution;
5. `arm.provision(...)` — that is `setup`, excluded from the delegation estimand by §E.2;
6. `arm.delegate(...)` — that is `delegation`, reported separately and never folded in.

**The audit sink.** `B3` carries `audit = 1` and `CapabilityDecisionPath._audit(...)` runs inside
`decide`, hence inside the segment. For any run that counts toward row 1, the audit sink **MUST**
be a bounded in-memory buffer flushed outside the segment; a sink performing disk or network I/O
inside `decide` would charge `B3` for the apparatus. Asserted structurally, not by convention.

**One cell is excluded from every per-arm mean, by name.** On `gt-f1-chain-tamper`,
`B2-exchange-task` performs a **failed** AS round trip and receives no token, while the capability
arms do purely local work. Pooling that cell with benign cells would average a network refusal
together with local cryptography. **Refusal-path latency is reported as its own series**, never
folded into a benign per-arm mean or into the row 1 estimand. This carries into the G-3/RQ4
analysis plan.

## Rejected alternatives

**Leaving `present` out of the segment.** Rejected: it omits `B3`'s principal per-invocation cost
from the test that settles the claim, and the omission favours this work's own hypothesis. The bias
direction is what makes this non-negotiable rather than a matter of taste.

**Extending `boundary_verification` to swallow `present`.** Rejected in favour of a separate seam:
redefining an existing span's meaning would silently reinterpret anything already recorded under
it, and §E.5 asks for the latency to be **decomposed**. Two spans reported separately and summed
for the estimand is finer-grained and auditable; one widened span is neither.

**Using `end_to_end` as the estimand.** Rejected: it includes tool execution and instrument
overhead, which no deployment would attribute to the authorization mechanism, and it is not what
§E.5's retraction rule names.

**Choosing the margin after a pilot run.** Rejected for the same reason ADR 0025 rejects it: a
margin fitted to observed data cannot retract anything.

## Status

accepted — 2026-07-31 (row 1 of `docs/frozen_parameters.md`; amendable by a later ADR until Part H
step 3)

## Consequences

- `docs/frozen_parameters.md` row 1 is set with the margin, the estimand, the decision rule and a
  pointer to the segment definition above.
- `GoldenThreadRunner` gains the `presentation` seam. **Instrumentation only — no number is emitted
  and nothing is benchmarked by this ADR.** A test asserts each span's extent structurally: that
  `presentation` brackets `present` alone, that `boundary_verification` brackets `decide` alone,
  and that no ledger write occurs inside either.
- `PRE_REGISTRATION.md` carries the retraction rule in §E.5's own words, the margin, the estimand
  and the sampling plan, before the seal.
- **Re-triggered by:** any change to `T_full` (ADR 0025), since the 1% anchor would move; any change
  to what `present` or `decide` does for `B3`; and any change to the sealed measurement platform.
