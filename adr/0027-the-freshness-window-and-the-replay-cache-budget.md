# 0027 — The freshness window `Δ`, and the replay-cache budget it governs (`frozen_parameters` row 3)

## Context

Three mechanisms in this design consume a time window, and until now each could have been given its
own:

- the **`jti` replay cache** that makes `B3⁺`'s single-use semantics meaningful (D37; gate G-9,
  whose pass criterion explicitly requires a **frozen `(mechanism_tag, jti)` / TTL / capacity
  budget**);
- the **DPoP proof `iat` acceptance window** (RFC 9449, which deliberately leaves the window to the
  server rather than specifying one);
- **INV freshness** at the boundary (§F.2).

Gate **G-14** attaches the same authenticated-request-ID cache to `B2-DPoP` and to `B3` and compares
them. If the two arms ran under different windows, any difference G-14 observed could be an artifact
of window asymmetry rather than of the mechanisms — a confound introduced by the apparatus, in a
gate whose entire purpose is attribution.

## Decision

`[DESIGN]` **`Δ = 60 s`, and the same `Δ` governs all three consumers.**

**Anchors.** RFC 7519 §4.1.4 and §4.1.5 state that implementers may allow *some small leeway,
usually no more than a few minutes*, for clock skew; sixty seconds sits at the conservative end of
that range. RFC 9449 leaves the DPoP proof window to the server, so no specification fixes it for
us. *(No claim is made about any particular library's default leeway — several default to zero and
require the value to be supplied — so the anchor is the RFC sentence, not common practice.)* `Δ` is therefore an **apparatus constant chosen for comparability**, not a security
recommendation, and the dissertation must present it as such: nothing in this work claims 60 s is
the right window for a deployment.

**One window, three consumers, no exceptions:**

| consumer | binding |
|---|---|
| `jti` cache TTL and eviction | entries live exactly `Δ`; eviction is by age, never by an independent timer |
| DPoP proof `iat` acceptance | a proof is fresh iff `\|now − iat\| ≤ Δ` |
| INV freshness at the boundary | identical rule, identical `Δ` |

Because the window is shared, **G-14's two arms cannot differ in window**, and any difference it
reports is attributable to holder binding and invocation binding rather than to the clock.

### Two conditions that come with `Δ`, and they are part of the decision

**1. The verifier's time source MUST be injectable.** Every consumer of `Δ` takes `now` as a
parameter; none reads a wall clock internally. This is already the pattern the boundary follows
(`now_epoch` is injected) and it is what makes the next condition possible.

**2. Over-window replay fixtures MUST advance a logical clock. Real waiting is forbidden.** A
fixture that establishes over-window behaviour by sleeping for sixty seconds would add sixty
seconds per repetition to a campaign specified at **≥ 200 repetitions per configuration** — hours
of wall-clock time that measure nothing — and would make the suite's runtime depend on `Δ`, so a
later amendment to `Δ` would silently change how long the experiment takes. Fixtures translate the
injected instant instead. A test asserts that no `sleep` occurs on any replay path.

### The G-9 capacity budget, frozen here

`[DESIGN]` The replay cache holds **2^16 = 65,536** entries and **fails closed on overflow** —
an insertion that cannot be recorded results in a **denial**, never in an admission, and never in a
silent eviction of an unexpired entry.

**Why fail-closed rather than LRU eviction.** Evicting an unexpired entry to make room would let an
attacker replay a previously-seen `jti` by first flooding the cache — the cache would appear to
work while providing no guarantee, which is the failure mode ADR 0014 rejected in a different guise
for the effect ledger. **Availability is deliberately sacrificed to integrity**, and this is a
property of the experimental apparatus rather than advice for a production deployment; the
dissertation must say so rather than presenting fail-closed overflow as a recommendation.

**Why 2^16.** One campaign arm runs ≥ 200 repetitions and the pilot corpus has four scenarios, so
the working set is three orders of magnitude below the budget. The budget exists to make the
overflow path **reachable and testable** — G-9 must be able to induce it — not to be a limit the
campaign approaches. A budget large enough never to overflow would leave the fail-closed path
unexercised, which is the same as not having it.

## Rejected alternatives

**A per-mechanism window.** Rejected: it is exactly the confound G-14 exists to avoid, and there is
no principled basis on which the three would differ in this apparatus.

**A shorter `Δ` (5–10 s) to make over-window fixtures cheaper.** Rejected: with an injectable clock,
fixture cost is independent of `Δ`, so the argument evaporates — and a window below conventional
clock-skew allowance would make the apparatus fragile against ordinary scheduling jitter on the
measurement box.

**Unbounded cache capacity.** Rejected: it removes the overflow path G-9's criterion names, and an
unbounded cache is not a mechanism anyone would deploy.

## Status

accepted — 2026-07-31 (row 3 of `docs/frozen_parameters.md`; amendable by a later ADR until Part H
step 3)

## Consequences

- `docs/frozen_parameters.md` row 3 is set with `Δ`, the three consumers it binds, the injectable
  clock condition, the no-real-waiting condition, and the capacity budget.
- The `jti` cache does not exist yet — it is `B3⁺`'s and G-9's work. This ADR **fixes its
  parameters in advance**; it does not build it and must not be read as having verified anything.
  **`IA-9` stays `[UNVERIFIED-IA]` for G-9.**
- G-14's two arms are constructed under one window, so the gate's attribution claim is not
  confounded by the apparatus.
- **Re-triggered by:** any change to `Δ` (which re-triggers G-9 and G-14), and any change to the
  sealed measurement platform's clock resolution.

### Addition, 2026-07-31 — a fixture constraint `Δ` creates, fixed in advance

*Nothing above is retracted; this records a consequence found while binding `Δ` to INV
freshness at the boundary.*

**The bit-identical replay fixture MUST be constructed WITHIN `Δ`.** §E.4 predicts
`F3 dpop-captured-proof-replay (bit-identical)` as **`B3` = A (admits)** and **`B3⁺` = B
(blocks)**, and that single cell is `B3⁺`'s entire reason to exist — §E.1's *price of closing
duplicate replay*. Once `Δ` governs INV freshness, a replay constructed **outside** `Δ` would be
blocked by `B3` as well, for a reason that has nothing to do with duplicate detection, and the
distinction the cell exists to measure would **collapse**.

The direction matters and is why this is fixed now rather than noticed later: the collapse would
make `B3` look **stronger** than §E.4 predicts, i.e. it runs toward this project's own
hypothesis. Recording the constraint in advance is what stops it becoming a **post-hoc fixture
adjustment** made after the cell disagrees — at which point no reader could tell whether the
fixture was corrected or the result was.

So: the captured proof and its INV are replayed at an instant `t` with `|t − iat| ≤ Δ`, so every
conjunct **other than** duplicate detection still passes and `B3` admits. If a future amendment
to `Δ` makes that construction impossible, the finding is reported — the fixture is not moved
outside the window to make a run succeed. Carried into §E.4 beside the row and into §J.2 item 9.
