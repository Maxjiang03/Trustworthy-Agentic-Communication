"""The two BROAD OAuth arms (SS E.1), and why breadth is a ladder property.

`B2-broad-noexchange` -- OAuth 2.1, broad, bearer, RFC 8707 resource
indicators, **no** exchange. `Isolates`: *audience binding alone does not
attenuate*.

`B2-exchange-broad` -- the same breadth **with** the exchange round trip, scope
**unchanged**. `Isolates`: *the exchange round-trip cost, separated from
narrowing*. That separation is the entire arm: an implementation that quietly
narrowed at the hop would destroy it and would silently contradict SS E.4.

**The grant conflict these arms create, and how ADR 0029 settles it.** ADR 0024
provisions the *delegating client's* base token with authority exactly
`C_0 = U_task`, because `B2-exchange-task` needs the AS to enforce
`C_1 subset-of C_0`. But SS E.4 predicts the broad arms **admit** `F1-root`, and
`(mail.send, mail/outbox)` lies **outside** `U_task` -- so on a task-scoped
token a broad arm would **block** it, contradicting SS E.4 and destroying the
arm. The resolution is that **the ladder row, not the client identity,
determines the grant**: broad rows are provisioned with the coarse `Omega`
grant, strong rows with `C_0 = U_task`. It is an explicit, named per-arm
provisioning input (`ladder_grant`), checked against the arm class's own
declaration, rather than a consequence of which client happens to be used.

Delegating the broad arms from a **different principal** was rejected: it would
change the `may_act` relation as a side effect and confound the arms in a
second respect, so a difference later attributed to breadth could equally be
the delegation relation. The same client therefore holds two named base grants
(ADR 0029), and each arm takes the one its row specifies.

**Both are configurations of the existing exchange arm, not copies.** They
inherit its provisioning, its four anti-bias requirements, and its boundary
decision -- `src/sut/authz/boundary.py` unchanged. What they override is
declared as data: `ladder_grant`, and for the no-exchange arm
`performs_exchange`, and for the broad exchange arm `narrows_at_the_hop`.
"""

from collections.abc import Mapping
from typing import Any

from src.sut.baselines.b2_exchange_task import (
    REASON_NOT_PROVISIONED,
    B2ExchangeTaskArm,
)
from src.sut.baselines.base import ArmBitmask, HopContext


class B2BroadNoExchangeArm(B2ExchangeTaskArm):
    """OAuth 2.1, broad, bearer, RFC 8707 -- and no exchange at all.

    Part C's row: the broad `AT` is **forwarded** at the hop and presented as
    `AT@aud` at the boundary. It binds **audience only**. What it isolates is
    that audience binding alone does not attenuate: the token that reaches the
    boundary carries the same authority the delegating party held, so the
    boundary's own `admits` check -- the same unchanged one every OAuth arm
    uses -- has nothing narrower to enforce.

    `performs_exchange = False`, so no TLS context and no connection are built:
    an arm that never dials should not hold a socket, and the absence is
    asserted rather than assumed.
    """

    name = "B2-broad-noexchange"
    ladder_grant = "broad"
    performs_exchange = False
    narrows_at_the_hop = False
    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=0,
        authorizer=0,
        htc_holder=0,
        invoke=0,
        contain=0,  # SS E.5: broad only -- nothing narrows
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )

    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        """Forward the base token. There is no per-hop object and no round trip.

        `hop` names the narrowing the Supervisor intends; this arm has no
        mechanism that could apply it, which is precisely what SS E.1's
        `receives per-hop C_i = broad only` records. `widening_elements` is
        likewise unusable, which is why SS E.3 marks `F1-chain-tamper` **NA**
        here rather than expecting a block.
        """
        if self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        self.exchanges.append({"hop": len(self.exchanges), "issued": False, "exchanged": False})
        return {"access_token": self._setup["access_token"], "audience": hop.audience}


class B2ExchangeBroadArm(B2ExchangeTaskArm):
    """The exchange round trip, with the scope **unchanged**.

    A **real** online RFC 8693 exchange happens at the hop -- that round trip
    IS what this arm isolates, and an arm that skipped it to save time would
    measure nothing. What it does not do is narrow: it asks the AS for exactly
    the grant it already holds, so `Allowed(AT_1) = Allowed(AT_0) = Omega`.

    Placing it beside `B2-broad-noexchange` on one side and `B2-exchange-task`
    on the other is what lets the study separate two things a single OAuth
    number would confound: the **cost of contacting the AS per hop**, and the
    **security effect of narrowing when you do**.
    """

    name = "B2-exchange-broad"
    ladder_grant = "broad"
    performs_exchange = True
    narrows_at_the_hop = False
    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=0,
        authorizer=0,
        htc_holder=0,
        invoke=0,
        contain=0,  # SS E.5: broad -- the exchange restates rather than narrows
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )
