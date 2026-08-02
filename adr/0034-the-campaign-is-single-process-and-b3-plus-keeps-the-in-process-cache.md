# 0034 — The campaign is **single-process**, and `B3⁺` keeps the in-process replay cache

## Context

Gate **G-9 PASSES** and `IA-9` is verified. It was adjudicated on
`src/sut/replay_arbiter/` — the single-writer arbiter process ADR 0033 introduced — reached through
`src/sut/authz/replay_client.py`. What it establishes is that the §F.5 check-and-insert is atomic
**across processes**: exactly one of N concurrent bit-identical requests proceeds, an induced backend
error denies, overflow is reached and fails closed, and the lock-removed world genuinely
double-admits.

**EXP5 STEP 13's standing check then measured something G-9 does not cover**, and recorded it rather
than leaving it to be inferred from a green gate:

- within **one** SUT process, `B3⁺` admits the first use and blocks the bit-identical replay at
  `b3_replay_duplicate` — §E.4's cell, unmoved by process separation;
- across **two** SUT processes, both submissions are **admitted**, because `B3PlusArm.__init__`
  constructs one `JtiCache` **per arm instance** and the second child has never seen the id;
- **no ladder arm is wired to the arbiter.** `RemoteJtiCache` appears only in G-9's spike.

So a green G-9 and the ladder's `B3⁺` are **two different claims about two different objects**, and
the gap between them needs a decision rather than a silent default.

## Decision

`[DESIGN]` **The campaign runs in a single-process configuration, and `B3⁺` keeps the in-process
`JtiCache`.** The arbiter is **not** wired into the ladder for this study.

### What each of the two claims actually says

| | object | claim |
|---|---|---|
| **G-9** | `src/sut/replay_arbiter/` + `RemoteJtiCache` | the **mechanism** — §F.5's check-and-insert — is **sound under multi-process concurrency**, with the frozen `Δ = 60 s` TTL and `2^16` capacity, failing closed on overflow and on backend error |
| **the ladder** | `B3PlusArm`'s own `JtiCache` | in a **single-process** campaign, `B3⁺` blocks the bit-identical replay inside `Δ` that `B3` admits — §E.4's `F3 dpop-captured-proof-replay` row |

**These are not the same claim, and the dissertation must not let a green G-9 be read as *"the ladder
arm has multi-process atomicity."*** It does not. What the ladder measures is correct for the
configuration it is measured in, and that configuration is fixed here rather than assumed: **one SUT
process per scenario**, which is what `sut_mode="in-process"` (the default since EXP5) and the
single spawned child of `sut_mode="separate"` both provide for one scenario's two submissions.

### Why single-process is the right configuration for this study

**It is the configuration §E.4's cell was predicted for.** The `B3` = A / `B3⁺` = B distinction is
`B3⁺`'s entire reason to exist, and ADR 0027 already fixes the one condition that could collapse it
(the replay must be constructed **within `Δ`**). Nothing in §E.4, §E.5 or §F.5 predicts a cell for a
replay arriving at a *different process*; introducing one would be adding a measurement the
pre-registered matrix does not contain.

**Per-process atomicity is sufficient for what is measured.** A scenario's first use and its replay
are two submissions through **one** arm instance in **one** process. §F.5's requirement — *"no window
in which two identical `jti` both pass"* — is met within that process by `JtiCache`'s single critical
section, whose own docstring has always been explicit about the scope of that guarantee.

**Wiring the arbiter into the ladder would change what the ladder measures.** Every `B3⁺` decision
would acquire a loopback round trip, which lands inside ADR 0026's measured segment
(`presentation + boundary_verification`, and the consume happens inside `decide`). RQ4 would then be
comparing an arm that talks to a second process against arms that do not — an apparatus difference
reported as a mechanism difference, which is the error gates G-14 and G-15 both exist to prevent.
**The deferral protects the timing comparison as well as the security one**, and G-3 has not run.

### The seam, so this is a decision and not an absence

`RemoteJtiCache` **exists, is tested, and is a drop-in**: the same `consume(mechanism_tag, jti, *,
now)` signature, the same three `Consumption` outcomes, the same `(mechanism_tag, jti)` key, the same
injected clock. `B3Arm.attach_replay_cache(cache)` and `B2ExchangeTaskDPoPArm.attach_replay_cache(
cache)` accept any object with that method — gate G-14 uses exactly that seam to put **one** cache on
two arms. `tests/test_f3_matrix.py::test_no_ladder_arm_is_wired_to_the_g9_arbiter` asserts both
halves: that no baseline module reaches for `RemoteJtiCache`, and that its `consume` signature is
identical to `JtiCache`'s, **so the gap is wiring rather than capability**. A later block that wires
it changes one construction and announces itself in that test.

### Enforced, not merely written down

`src/harness/campaign.py` refuses a **confirmatory** run that is **multi-process** while the ladder's
replay cache is in-process, with a named error. The refusal is keyed on the seam rather than on a
constant: it lifts automatically when a baseline module reaches `RemoteJtiCache`, so the check
encodes *the reason* rather than *the current answer*. A ruling only a reader enforces is not
enforced.

## Rejected alternatives

**(a) Wire `B3⁺` to the arbiter for the campaign.** Rejected on the grounds above: it puts a loopback
round trip inside ADR 0026's measured segment for exactly one arm, so RQ4's `B3⁺` overhead would
include an apparatus artifact with no deployment counterpart in a single-process deployment. It would
also make the F3 replay cell depend on a third process being alive, converting a mechanism failure
and an infrastructure failure into the same observation — which Part H's abort rules keep apart.

**(c) Leave it undecided and let the configuration follow from whatever the campaign happens to do.**
Rejected: that is the silent default this ADR exists to replace. EXP5's sweep found the gap; a
finding that produces no decision is a finding that will be rediscovered.

**(d) Report `B3⁺` as having multi-process atomicity because G-9 passed.** Rejected as false, and it
is the specific misreading this ADR is written to prevent.

## Consequences

- The confirmatory campaign is **single-process**, recorded in the run manifest (`RunRecord.sut_mode`)
  so every table says which configuration produced it.
- **`B3⁺`'s §E.5 bitmask is unchanged.** `jti_cache = 1` records that the arm *has* a replay cache;
  where that cache runs is not a ladder property, exactly as ADR 0033 already states.
- **G-9's row and its PASS are unchanged.** This ADR adjudicates no gate and edits no Part G row; it
  records what G-9's result does and does not license.
- **`IA-9` stays verified** — it is a property of the mechanism, which is what G-9 measured.
- A **§J** entry records the residual for the dissertation: a multi-process deployment of `B3⁺` would
  need the arbiter, and **this study does not measure that configuration**. The mechanism is shown
  sound for it (G-9); the *arm* is not measured in it.
- Re-triggered by: any change to `Δ` or the capacity (ADR 0027), any change to ADR 0026's measured
  segment, or any block that wires a ladder arm to the arbiter — which must then revisit both the
  RQ4 comparison and this ADR.

`[DESIGN]`. §F.5 requires multi-process atomicity of the **mechanism**, which G-9 adjudicates; the
**configuration the ladder is measured in** is this project's to choose, and it is chosen here.

## Status

accepted — 2026-08-02 (Commander's ruling, option (b); EXP7 STEP 8)
