"""`B3+`: `B3` plus the bounded `jti` replay cache (SS E.5 bits `1 1 1 1 1 1 1 1 1 1`).

SS E.1's top row, and its `Isolates` column is one thing: **the price of
closing duplicate replay**. `B3` binds the invocation and the holder but does
**not** close bit-identical replay -- an attacker who captures a complete,
valid request and resubmits it unchanged inside the window presents something
every conjunct accepts, because every conjunct is a function of the request and
the request is identical. SS E.4 records that honestly as `B3` = **A** and
`B3+` = **B** on `F3 dpop-captured-proof-replay`, and that single cell is this
arm's entire reason to exist.

**A configuration of the existing decision path, not a copy.** The ten SS A.5
conjuncts are the same functions `B3` runs; the only difference is that this
arm hands the path a `JtiCache`, which SS E.5 records as bit 9. Everything else
-- provisioning, delegation, presentation -- is inherited unchanged.

**The cost is real and is stated rather than hidden.** SS F.5's trade-off: if
the tool call fails *after* the id is consumed, the id stays consumed for
`Delta`, so a legitimate retry inside the window is rejected as a duplicate.
`B3+` trades retry-within-`Delta` for duplicate-replay prevention, and the
false-blocking analysis reports the "legitimate retry" near-miss as blocked
rather than hiding it.

**Building this arm is not running gate G-9.** G-9 adjudicates atomic
**multi-process** check-and-insert under concurrency and induced backend error.
This cache is atomic within one process and has no backend, so it has neither
of those properties yet; `src/sut/authz/jti_cache.py` says exactly which
properties it does and does not have. `IA-9` stays `[UNVERIFIED-IA]`.
"""

from typing import Any

from src.sut.authz.jti_cache import JtiCache
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.base import ArmBitmask, ArmIdentity


class B3PlusArm(B3Arm):
    """`B3` + duplicate detection. One cache per arm instance."""

    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=1,
        authorizer=1,
        htc_holder=1,
        invoke=1,
        contain=1,
        context=1,
        approval=1,
        jti_cache=1,  # the only bit that differs from `B3`
        audit=1,
    )

    def __init__(self, identity: ArmIdentity | None = None) -> None:
        super().__init__(identity or ArmIdentity(name="B3+"))
        # ADR 0027's frozen parameters and no others: TTL `Delta`, capacity
        # 2^16, fail-closed on overflow. Constructed with no arguments so the
        # arm cannot quietly choose its own.
        self.jti_cache = JtiCache()

    def provision(self, setup: "dict[str, Any] | Any") -> None:
        super().provision(setup)
        # The decision path is built by `B3Arm.provision`; hand it the cache
        # afterwards rather than duplicating that method to pass one argument.
        self._decision_path._jti_cache = self.jti_cache
