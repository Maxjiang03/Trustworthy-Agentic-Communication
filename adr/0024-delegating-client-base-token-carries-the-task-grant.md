# 0024 — The delegating client's Phase-1 base token carries the task grant `C_0`

## Context

§E.2 defines Phase 1 as setup and says of the base `AT@aud`: *"No delegation authority is
expressed in the base token; it establishes only MCP resource authorization and the OAuth actor
identity."* ADR 0021 implemented that as one pre-issued token per registered client, and the
golden-thread pilot provisioned every client with the **coarse RS-level grant** — the whole
frozen `Ω` at the one resource server — because in `B3` the capability is the narrowing plane
and effective authority is the §A.4 intersection, which a coarse base grant leaves to the
capability.

`B2-exchange-task` has **no capability plane**. The token *is* the authority plane, and the
pinned AS profile enforces `C_i ⊆ C_{i−1}` against the **subject token's own**
`authorization_details` (§E.2; `smoke/g4/DESIGN.md` §5.3 step 7). Left coarse, the delegating
party's base token would carry all of `Ω`, so the AS would enforce only `C_1 ⊆ Ω`.

That is not a cosmetic difference. §E.3's `F1-chain-tamper` is a hop that widens to
`(mail.send, mail/outbox)` — an element that **is** in `Ω` — and §E.3 predicts a **block** on the
exchange arms "by the pinned AS profile refusing a widened `AT_i`". Against a coarse subject
token the AS would have **issued** that token, and `B2-exchange-task` would have failed the
subcase for a provisioning reason. G-13's cross-arm criterion — that all strong arms realize the
**same** `C_0 → … → C_n` — would fail for the same reason, since `B3`'s `C_0 = Allowed(P_0)` is
`U_task`, not `Ω`.

EXP2 forbidden action 3 forbids weakening `B2-exchange-task` in any respect. Provisioning it so
that its own containment check is toothless is exactly such a weakening, so the coarse default
cannot stand for this arm.

## Decision

[DESIGN] The **delegating client's** Phase-1 base `AT@aud` is provisioned with authority exactly
`C_0 = U_task`. Every other client — including the specialist, whose base token is the one `B3`
and `B-cap` present at the boundary — keeps the coarse `Ω` grant, so no already-built arm moves.

This is the OAuth analogue of what §A.3 already fixes for the capability plane: *"the AS mints
`U_task` as `P_0`; the Supervisor only narrows."* `B3`'s root capability is minted with authority
exactly `C_0` at task start by the root key; `B2-exchange-task`'s `AT_0` is minted with authority
exactly `C_0` at task start by the AS. Both are **task-start issuance**, both sit outside the
Phase-2 per-hop measurement, and neither is produced by a delegation hop.

What stays identical across arms, and is what §E.2's "identical" governs: the **path** (ADR
0021's pre-issued start-up line), the **call** (`exchange.issue_initial`, unreachable from the
token endpoint), the **shape** (`at+jwt`, RFC 9068 claim set, RFC 9396 `authorization_details`,
`aud` = the one RS, scope `mcp.invoke`), and the **exclusion from the delegation estimand**. Only
the granted set differs, and it differs because the two mechanisms put the narrowing in different
places — which is the measured difference the study exists to report.

Implemented as an explicit, named parameter rather than a silent default:
`golden_thread_as_document(..., task_grant=…, task_grant_client="agent-supervisor")`. Omitting it
reproduces the previous coarse behaviour exactly, and naming an unregistered client fails closed.

### Rejected alternative: obtain `AT_0` by an exchange from the coarse base token

Rejected because the pinned profile makes it impossible, not merely inconvenient. `smoke/g4/DESIGN.md`
§5.3 step 5 requires the subject token's `may_act.sub` to name the principal of the requested
actor, and the supervisor's base token names *the specialist*. A supervisor→supervisor
self-narrowing exchange is therefore refused as `may-act`, and RFC 8693 §4.4's `may_act` is about
another party acting for the subject rather than a party re-scoping its own token. Loosening the
delegation policy to permit self-delegation would invent policy the frozen
`task_authorization_policy` (row 5, **UNSET**) has not decided, and would widen the
G-4-adjudicated surface.

### Rejected alternative: leave the base token coarse and choose a tamper target outside `Ω`

Rejected because it would test the wrong thing. An out-of-`Ω` element is refused by
`rar.validate_details` as `rar-outside-omega` — a **malformed-request** refusal, not a
**widening** refusal — so the scenario would no longer exercise §E.3's `C_i ⊄ C_{i−1}` condition
at all, and the capability arms' block-scoping property would go unexercised too.

## Status

accepted — 2026-07-31

## Consequences

- `src/harness/as_process.golden_thread_as_document` gains `task_grant` / `task_grant_client`
  and a `rar_objects` helper; the RAR encoding rule (one object per element, never one object's
  product over all actions × all datatypes) is now stated in one place.
- `GoldenThreadRunner.b2_setup` passes the **supervisor's** Phase-1 token as the exchange's
  `subject_token`, per §5.3's "the delegating agent (holder of `AT_{i−1}`) is the client of the
  exchange". `b3_setup` is unchanged and still passes the specialist's.
- Regression tests assert both halves: the delegating client's base token carries exactly `C_0`,
  and the specialist's still carries the coarse `Ω` — so the narrowing is confined to the one
  client and `B3`'s Phase 1 is provably untouched.
- §E.2's sentence is now qualified rather than contradicted: it holds for arms whose authority
  plane is elsewhere. Part B.2 of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` records this in the
  same commit.
- **Re-triggered by:** any change to `U_task` in the corpus (the base token must track it), and
  any change to the AS's `may_act` / delegation-policy handling, which is what closed the
  rejected alternative. `frozen_parameters` row 5 staying UNSET is unaffected — this decision
  fixes a provisioning grant, not a task→principal policy.
