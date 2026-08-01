# 0031 — §E.4's `F3 audience mismatch` and `F3 expired token` are **B** for `B-cap`, not `NA`

*Adjudicated by the author, 2026-08-01.*

## Context

Building the F3 family (EXP4 Phase B) required reading §E.4's two OAuth negative-control rows
against the arms as built. `B-cap` is marked **NA** on both. That is wrong, and four independent
pieces of evidence say so.

**1. §E.1 mandates the opposite.** The `B-cap fixed [E6]` paragraph: *"primary B-cap fixes
`oauth_authn = 1` on the same OAuth substrate as B3, and **MUST** verify audience and expiry. A
standalone-capability (`oauth_authn = 0`) configuration may exist **only** as a separate exploratory
arm, never in the formal matrix."* An arm that is required to verify audience and expiry cannot be
unable to express an audience mismatch or an expired token.

**2. The built arm blocks, measured.** A one-second base token judged five seconds later, with the
capability's own hour-long window still open so the refusal is attributable to the token and not to
the capability:

    B-cap + EXPIRED base token -> (False, 'b3_oauth_resource_authorization')
       detail: exp: token has expired
    B-cap + WRONG audience     -> (False, 'b3_oauth_resource_authorization')
       detail: aud: audience does not name this resource server

Pinned by `tests/test_b_cap.py::TestOAuthAuthnIsOnAndVerifies`, each with a negative arm — the same
token at an instant inside its window is admitted — so neither refusal passes vacuously.

**3. `NA` has a fixed meaning in this project, and ADR 0028 pinned it.** `NA` asserts the arm
**cannot express the case**. ADR 0028 turned on exactly that distinction when it insisted the
deferred `F2 wrong_principal` row is *"emphatically **not** `NA`"* because every arm *could* express
it and the study merely declines to score it. `B-cap` can express these two cases, does, and blocks.

**4. §E.4 contradicts itself, not merely §E.1.** In the same table `B-cap` is **B** on
`F2 invalid_credential` and **B** on `F2 unauthenticated_caller` — both of which it can only reach
through the very OAuth verification path that checks `aud` and `exp` — while its **NA** on
`F2 wrong_holder_proof / wrong_dpop_key` is **correct**, because it genuinely carries no holder
binding. An arm that blocks an invalid credential and an unauthenticated caller cannot be unable to
express an expired token or a wrong audience. The two cells are a *"capability arm → NA"* pattern
applied to two rows labelled *"OAuth neg. control"*, overlooking that §E.1/E6 fixes
`oauth_authn = 1` for `B-cap`.

## Decision

`[DESIGN]` **§E.4's `F3 audience mismatch (OAuth neg. control)` and `F3 expired token (OAuth neg.
control)` rows are corrected for `B-cap` from `NA` to B.** Both cells are scored normally from
here on.

**This corrects a PREDICTION, not code.** The distinction is the whole reason this needed an ADR
rather than a fix. `B-cap`'s behaviour is *mandated* by §E.1/E6's "MUST verify audience and expiry";
adjusting the arm to produce `NA` would have violated the specification that governs it, and would
have required removing the `oauth_authn = 1` that makes `B-cap` a formal-matrix arm at all. The
prediction was drafted wrongly; the implementation was right. Nothing in `src/` changes.

**`NA` keeps its ADR 0028 meaning everywhere else**, including `B-cap`'s own remaining `NA` on
`F2 wrong_holder_proof / wrong_dpop_key`, which stays and is correct: `htc_holder = 0`, no HTC
chain, no INV, no DPoP key, so there is no holder proof to get wrong. This ADR narrows nothing about
what `NA` means; it removes two cells that were never entitled to it.

### Audit: does any other cell carry the same pattern?

Every `NA` in §E.4 was checked mechanically against the §E.5 bit that governs whether the arm can
express that row's case. An `NA` is correct exactly when that bit is `0`.

| Row | Governing bit | Arms marked `NA` | Verdict |
|---|---|---|---|
| `F1-chain-tamper` | `crypto_chain` | B0, B1, B2-broad-noexch, B2-exch-broad | all `0` — **correct** |
| `F2 invalid_credential` | `oauth_authn` | B0 | `0` — **correct** |
| `F2 wrong_holder_proof / wrong_dpop_key` | `htc_holder` | B0, B1, B2-broad-noexch, B2-exch-broad, B2-exch-task, B-cap | all `0` — **correct** |
| `F3 audience mismatch` | `oauth_authn` | B-cap | **`1` — WRONG, corrected here** |
| `F3 expired token` | `oauth_authn` | B-cap | **`1` — WRONG, corrected here** |

**Result: no other cell carries the pattern.** Of the three capability arms, `B3` and `B3⁺` have
**no `NA` cell anywhere** in the table, and after this correction `B-cap`'s only remaining `NA` is
the correct one. The `F1-chain-tamper` `NA`s additionally carry independent corroboration the two
corrected cells never had: they are recorded in the sealed record as `not_applicable.arms` with a
stated reason, and `tests/test_nine_arm_matrix.py` asserts each `NA` arm *is* applicable elsewhere,
so the `NA` is about the subcase and not about the arm.

Nothing beyond the two named cells is corrected.

## Consequences

- Two `A`/`B`/`NA` predictions change; **no code changes**, and no arm's behaviour changes.
- `B-cap` now has a scored cell on both OAuth negative controls, which is what those rows are for:
  they exist to confirm the OAuth substrate is real and identical across every arm carrying it. With
  `B-cap` excluded, one of the six arms with `oauth_authn = 1` went unchecked on the substrate the
  ladder's whole comparison rests on.
- The correction runs **against** this work's own hypothesis in the mild direction — it gives a
  weaker arm two more blocks — which is worth recording, since a prediction correction that only
  ever flattered the thesis would be worth distrusting.
- §E.4 is amended in the same commit with a dated update note rather than a silent rewrite, so the
  record shows `NA → B` and the reason, in sequence.
- `docs/frozen_parameters.md` is untouched; no row moves. `Ω`, `Γ`, the registry and the policy
  document are untouched. This ADR changes a predicted-outcome table and nothing else.

`[DESIGN]`. The correction is anchored in §E.1/E6's own MUST, in ADR 0028's fixed meaning of `NA`,
and in the measured behaviour of the built arm — not in a preference about how the cell should read.
