# 0029 — The §E.1 ladder row, not the client identity, determines an arm's base grant

## Context

ADR 0024 provisions the **delegating client's** Phase-1 base `AT@aud` with authority exactly
`C_0 = U_task`, because `B2-exchange-task` needs the AS to enforce `C_1 ⊆ C_0` against the subject
token's own `authorization_details`. Left coarse, an `F1-chain-tamper` hop widening to
`(mail.send, mail/outbox)` — an element inside `Ω` — would have been **issued** rather than refused.

Building the two broad arms surfaces the other half of that decision, and it points the opposite
way. §E.4 predicts `B2-broad-noexchange` and `B2-exchange-broad` **admit** `F1-root`, and `F1-root`
requires `(mail.send, mail/outbox)`, which lies **outside** `U_task`. Handed the supervisor's
task-scoped token, a broad arm would **block** it.

That is not a small mismatch. §E.1 gives `B2-exchange-broad` one job — *isolates the exchange
round-trip cost from narrowing* — and an arm that narrowed, for any reason including the shape of
the token it was handed, would isolate nothing. The study would report an OAuth arm blocking scope
amplification and attribute it to the exchange, when the cause was the provisioning. It would also
silently contradict §E.4 in a cell §E.4 predicts, which is precisely the situation the block's
instructions call a **finding**, not a number to adjust.

**Both directions bias, and they bias different arms.** A coarse token weakens `B2-exchange-task`
(ADR 0024). A task-scoped token destroys the broad arms. There is no single grant that serves both.

## Decision

`[DESIGN]` **The §E.1 ladder row an arm occupies determines its base grant.** Broad rows are
provisioned with the coarse `Ω` grant; strong rows with `C_0 = U_task`.

ADR 0024 is thereby **applied rather than amended.** Its rule was always about what the *mechanism*
needs — a token that is the authority plane must carry exactly the authority being propagated — and
the two families of arm need different things because the broad arms have no narrowing to enforce.
ADR 0024's own words, that the granted set differs "because the two mechanisms put the narrowing in
different places", extend without alteration to a mechanism that puts the narrowing nowhere.

### The mechanism: an explicit named per-arm input, checked against the arm's own row

1. **The arm class declares its row**, as data: `ladder_grant = "task" | "broad"`, alongside
   `performs_exchange` and `narrows_at_the_hop`. Breadth is a property of the arm.
2. **Provisioning carries the name**, and the arm **refuses** if the row it is handed disagrees with
   the row it declares. Breadth therefore cannot be smuggled in by passing a different token.
3. **The arm then verifies the token it actually holds**, exactly as ADR 0024 required: the
   authority it recomputes from the token's own claims must **equal** the element set its row
   specifies. Still `==`, not `⊆` — a token wider than the row would let a chain-tamper hop be
   issued, and one narrower would make a broad arm block what §E.4 predicts it admits.
4. **One client holds both grants.** The AS's Phase-1 section gains `additional_grants`, a named
   extra base `AT@aud` per client on the same pre-issued path (`issue_initial`, ADR 0021), so the
   delegating client holds `C_0 = U_task` under its own id and `Ω` under the name `broad`. Same
   call, same shape, same exclusion from the delegation estimand; only the granted set differs.
5. **The runner reads both element sets from the frozen artifacts** — `U_task` from the corpus, `Ω`
   from `omega_gamma_v1.json` — so the AS's provisioning and the arm's self-check cannot be handed
   two different answers by one caller mistake.

### Rejected alternative: delegate the broad arms from a different principal

Rejected, and it is the alternative that looks easiest. A second client would carry the coarse grant
already, needing no AS change at all — but `may_act` is a property of the delegating principal, so
changing the principal changes the **delegation relation** as a side effect. The broad and strong
arms would then differ in *two* respects rather than one, and any difference the study later
reported could be attributed to either. An arm comparison whose arms differ in more than the named
respect is not a comparison. This is the same discipline §E.6 states for the matched ablations: a
delta that cannot differ in more than the one named respect.

### Rejected alternative: give the broad arms `U_task` and re-annotate §E.4

Rejected outright: that is editing the prediction to match the code. §E.4's broad-arm cells are what
the study exists to measure — that audience binding alone does not attenuate, and that a broad
exchange narrows nothing — and a matrix in which the broad arms blocked would be reporting the
provisioning as a finding about OAuth.

## Status

accepted — 2026-07-31 (no `frozen_parameters` row; a provisioning rule, sealed with the AS
configuration at Part H step 3 like ADR 0017's parameters)

## Consequences

- `B2ExchangeTaskArm` gains three ladder attributes and its ADR 0024 check generalises to *this
  row's grant*; `B2BroadNoExchangeArm` and `B2ExchangeBroadArm` are **configurations** of it, not
  copies, overriding only the declared data. The no-exchange arm builds **no TLS context and no
  connection** — an arm that never dials should not hold a socket.
- `GoldenThreadRunner.b2_setup(ladder_grant=…)` selects both the token and the expected element set;
  `ladder_grant_elements` reads them from the frozen artifacts.
- A test per arm asserts its **realized** `C_0` — recomputed by the independent verifier from the
  presented token, never asserted — equals what its §E.1 row specifies: `Ω` for the broad arms,
  `U_task` for the strong ones. Measured: 7 elements and 3 respectively.
- `B2-exchange-broad` still performs a **real** exchange round trip; it asks for exactly the grant it
  already holds. A test asserts the round trip happened *and* that the authority did not move.
- **Re-triggered by:** any change to `U_task` or to `Ω` (both element sets move), and any change to
  the AS's Phase-1 provisioning path.
