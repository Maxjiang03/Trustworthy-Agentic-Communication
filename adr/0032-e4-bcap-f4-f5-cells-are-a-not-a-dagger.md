# 0032 — §E.4's `F4` and `F5` cells for `B-cap` are a plain **A**, not `A†`

*Adjudicated by the author, 2026-08-01. The companion to ADR 0031, in the opposite direction.*

## Context

§E.4 marks `B-cap` **`A†`** on `F4 sensitive egress, no declassification` and `F5 high-risk action,
no approval artifact`. The dagger's own footnote glosses it: *"the `A†` cells therefore denote
'admitted **absent** the shared monitor'; with the shared monitor the OAuth arms also block"*. The
annotation means **this cell flips when the monitor is attached**.

`B-cap`'s cell does not flip. Measured over both configurations in
`tests/test_f45_matrix.py`, all four F4/F5 fixtures:

| arm | `monitor_attached=false` | `monitor_attached=true` |
|---|---|---|
| the four OAuth arms | **A** | **B** — the dagger is real |
| `B-cap` | **A** | **A** — unchanged |

`B-cap`'s §E.5 bitmask sets `context = 0` and `approval = 0`. It is a bearer capability with **no
policy plane**, so it never runs the two §A.5 conjuncts a monitor answers for, and attaching one to
it changes nothing.

## Decision

`[DESIGN]` **§E.4's `F4` and `F5` cells for `B-cap` are corrected from `A†` to a plain `A`.** Both
are scored, under both configurations, exactly as before; only the annotation changes.

**The footnote's literal wording is not violated.** It says *"the **OAuth arms** also block"*, and
`B-cap` is not an OAuth arm — so nothing in the sentence is false. That is precisely why this needed
adjudication rather than a bug report. But a symbol that means *"this flips with configuration"*,
sitting on a cell that does not flip, misleads in exactly the way gate **G-15** exists to prevent: a
reader comparing `B3`'s **B** against `B-cap`'s `A†` would take the difference for a configuration
artifact that a shared monitor would erase, when it is a genuine mechanism difference — `B3` has a
policy plane and `B-cap` does not.

**This corrects a PREDICTION, not code.** `B-cap`'s behaviour follows from its §E.5 bits, which are
its ladder position and the entire reason the arm exists (§E.1: *offline attenuation, separated from
binding*). Nothing in `src/` changes.

### One drafting cause behind both ADR 0031 and this one

ADR 0031 corrected `B-cap` from `NA` to **B** on two F3 rows; this corrects it from `A†` to **A** on
two F4/F5 rows. Opposite directions, one cause: **§E.4 was drafted by filling `B-cap` in as "a
capability arm" rather than from its own §E.5 bits.** As a capability arm it inherited `B3`'s
policy-plane annotation on F4/F5 and a *"capability arm → NA"* pattern on two rows labelled *OAuth
neg. control*. Read off its bitmask instead, `B-cap` is `oauth_authn = 1` (so the OAuth controls
apply, ADR 0031) and `context = 0, approval = 0` (so the monitor annotation does not, this ADR).

### Audit: does any other `A†` cell carry the same pattern?

Every `A†` cell was checked. There are ten — the `F4` and `F5` rows for `B2-broad-noexchange`,
`B2-exchange-broad`, `B2-exchange-task`, `B2-exchange-task-DPoP` and `B-cap`.

**The `context`/`approval` bits alone do not settle it, and that is a finding about the audit rule
rather than about the table.** All five arms carry `context = 0, approval = 0`, so a bit-only rule
("both bits zero ⇒ the dagger is a no-op") would strip the dagger from **all ten cells** — and four
of those strippings would be wrong, because the OAuth arms measurably do flip. The bits are
*necessary* for a dagger to be suspect and not *sufficient*.

The property that decides it is **how the monitor reaches the arm's decision**:

| arm | `context`/`approval` | how a monitor reaches the decision | dagger |
|---|---|---|---|
| `B2-broad-noexchange` | 0 / 0 | a boundary layer **orthogonal** to the bitmask | correct |
| `B2-exchange-broad` | 0 / 0 | as above | correct |
| `B2-exchange-task` | 0 / 0 | as above | correct |
| `B2-exchange-task-DPoP` | 0 / 0 | as above | correct |
| `B-cap` | 0 / 0 | **only** via the §A.5 conjuncts, which its bitmask gates off | **wrong** |

The OAuth arms have no §A.5 conjunct plane at all, so the monitor is attached beside their decision
path and `monitor_attached` is genuinely a property of the run. `B-cap` shares `B3`'s
`CapabilityDecisionPath`, in which the monitor's verdicts arrive **through** `context_policy_ok` and
`approval_artifact_ok` — and those two conjuncts are exactly the bits that distinguish `B-cap` from
`B3`. So the sharpest statement of the finding is:

> **For `B-cap`, "attach the monitor" is not a configuration change — it is a change of arm.**
> Setting `context = 1, approval = 1` on `B-cap` produces `B3`. An "unmonitored `B-cap`" versus
> "monitored `B-cap`" pair would be comparing `B-cap` against something that is no longer `B-cap`,
> which is why the cell cannot flip and why the dagger was never available to it.

**Result: no other `A†` cell carries the pattern.** The four OAuth arms' daggers are correct and
stay. `B3` and `B3⁺` carry no dagger. Nothing beyond `B-cap`'s two cells is corrected.

## Consequences

- Two annotations change; **no code changes**, and no measured cell moves.
- The `A†` symbol keeps one meaning across the table: *admitted absent the shared monitor, blocks
  with it*. A cell that cannot flip no longer wears it.
- G-15's `A†`-semantics check (criterion 5) becomes checkable without a special case for `B-cap`.
- A rule worth carrying forward, since it caught what the bits alone did not: **an `A†` is correct
  only if the arm's decision path can reach a monitor without changing the arm's bitmask.**
- §E.4 is amended with a dated update note rather than silently rewritten, so the record shows
  `A† → A` and the reason, in sequence — as ADR 0031 did for `NA → B`.
- `docs/frozen_parameters.md` is untouched; no row moves. `Ω`, `Γ`, the registry and the policy
  document are untouched.

`[DESIGN]`. Anchored in `B-cap`'s own §E.5 bitmask, in §E.4's own gloss of the dagger, and in the
measured behaviour of the built arm under both configurations — not in a preference about how the
cell should read.
