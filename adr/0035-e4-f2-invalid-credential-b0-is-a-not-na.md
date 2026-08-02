# 0035 — §E.4's `F2 invalid_credential` cell for `B0` is **A**, not `NA`

## Context

EXP7 STEP 3 requires every `NA` to be **derived from the §E.5 bit governing its row, never from the
arm's family** — the lesson ADR 0031 and ADR 0032 both exist to enforce. Recomputing the
`F2 invalid_credential` row from the bitmask surfaced two problems, one in the derivation rule and
one in the cell.

### 1. The bit rule cannot decide this row at all

The stated derivation was *`B0` is `NA` because `oauth_authn = 0`*. Read from the code rather than
from the table, `oauth_authn = 0` holds for **`B0` and `B1`** — and `B1` is **B**:

```
B0   oauth_authn=0        B1   oauth_authn=0        (every other arm: 1)
```

`B1` blocks an invalid credential, demonstrated in `tests/test_b1.py`, because its credential is a
**static API key** and it verifies one. Its own bitmask comment says why the column reads zero:
*"not OAuth: no issuer, no audience, no scope, no expiry."*

**§E.5's ten columns carry no bit for `B1`'s static shared secret.** `B1`'s row is
`0 0 0 0 0 0 0 0 0 1` — only `audit` — so the one authentication mechanism it has is invisible to the
bitmask. This row's `NA` set therefore **cannot be derived from §E.5 at all**; it has to come from
§E.1's arm definitions. That is a real limit on the bit rule, recorded here rather than worked
around, and it is the first case found where the bitmask under-describes an arm.

### 2. The cell itself is the ADR 0031 pattern, a third time

This repository has already settled the governing question, in `tests/test_f3_matrix.py`, for the
`F3 expired token` row:

> The arms with no clock to move: they read no token, so "expired" is not a condition they can
> perceive. **That is the vulnerability §E.4 predicts as A, not an inability to express the case
> (which would be `NA`).**

`B0` on `F2 invalid_credential` is the same situation and was recorded the opposite way.

## Decision

`[DESIGN]` **§E.4's `F2 invalid_credential` row reads `A` for `B0`.** The row becomes:

| | B0 | B1 | B2-broad-noexch | B2-exch-broad | B2-exch-task | B2-DPoP | B-cap | B3 | B3⁺ |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| F2 invalid_credential | **A** | B | B | B | B | B | B | B | B |

**`B1` stays `B`, on behaviour.** The bit derivation says `NA`, `tests/test_b1.py` shows it blocking,
and §E.4 says `B`. Where a derivation and a measurement disagree, the measurement governs: `B1` can
express the case and does.

**The governing rule, stated so it is reusable.** Give the arm the case and observe. If it **admits**,
that is `A` — a measurable vulnerability, and quantifying exactly that is what this study exists to
do. `NA` is reserved for an arm that **cannot express the case at all** (ADR 0028's meaning), and
recording a measurable admission as `NA` files a hole under *not applicable*, which is the specific
harm ADR 0031 corrected on the OAuth negative controls.

Hand `B0` a credential that does not verify and it **admits**, because it runs no boundary check of
any kind. That is a result, and one of the more important ones in the ladder's bottom row: the null
arm's vulnerability is the baseline every other cell is read against.

**This corrects a PREDICTION, never code.** No arm changes, no predicate changes, and no fixture is
adjusted toward the cell. `B0`'s behaviour is fixed by §E.1 (`B0` = no delegation protection); it was
the table that was wrong about it.

## Audit of every other `NA` in §E.4

ADR 0031 and ADR 0032 each carried one, and the same obligation applies here: check whether any other
cell shows this pattern — an `NA` on an arm whose behaviour is a measurable vulnerability rather than
an inability. After this correction the table holds `NA` in exactly two rows.

**`F1-chain-tamper` — `B0`, `B1`, `B2-broad-noexchange`, `B2-exchange-broad`. These survive, and for
a stronger reason than "the artifact is absent".** The scenario's distinguishing feature is a hop
that *attempts to widen what it passes on*. An arm with no per-hop authority chain has nothing to
append a widening block to, so the instance built for it would be **byte-identical to `gt-f1-root`** —
same tool, same arguments, same required authority. Scoring it would **double-count one instance**,
not measure a second. That is inability in the strict sense, and it is materially different from
`B0`'s invalid credential, which is a real artifact riding along in a request the arm admits.

**`F2 wrong_holder_proof / wrong_dpop_key` — the six arms with `htc_holder = 0`. REPORTED, NOT
CORRECTED, because it may follow from this decision and that is not this ADR's to settle.** Those six
`NA`s rest on the reasoning *"there is no holder proof in this arm's presentation to be from the
wrong holder"* — which is the same shape as the reasoning just overruled for `B0`. Under the
behavioural rule adopted above, at least `B2-exchange-task` has a claim to **A**: hand its bearer
token to a different party and it admits, and **§D.2's own matrix scores exactly that as ❌ (admitted)
on the `K-none | T-reuse` cell**. §E.4 also scores `B2-exchange-task` as **A** on
`F3 dpop-stolen-AT-key-substitution`, which is the same tampering point. So §E.4 may be recording one
tampering point twice with two different answers for one arm. **Not corrected here**; it is reported
for adjudication, with the evidence, exactly as this cell was.

## Consequences

- §E.4's `F2 invalid_credential` row is amended with a **dated update note**, not a rewrite.
- The `F2 invalid_credential` corpus scenario (EXP7 Phase A) records **no `NA` arms**; every one of
  the nine is scored, and `B0` is expected to admit.
- The **bit rule now has a stated exception**: §E.5 does not describe `B1`'s API key, so `NA` for any
  credential-verification row must be derived from §E.1's arm definitions and confirmed against
  behaviour. Any future block deriving `NA` from `oauth_authn` alone will get `B1` wrong.
- No frozen row, `Ω`/`Γ`, registry, policy document or `H(·)` is touched. `B0`'s and `B1`'s §E.5
  bitmasks are unchanged — the fault is in the table's reading of them, not in the bits.
- Re-triggered by any amendment to §E.1's arm definitions, and by whatever is decided about the
  `wrong_holder_proof` row above.

## Status

accepted — 2026-08-02 (Commander's adjudication; EXP7, before the `F2 invalid_credential` scenario
was built)
