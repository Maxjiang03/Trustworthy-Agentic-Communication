"""`B0`: no delegation protection. Every bit zero (SS E.5).

Part C row: Phase-2 hop carries **none**; the boundary sees a **plain call**;
nothing binds authority to the invocation; nothing prevents stolen-credential
reuse. SS E.1: what B0 isolates is that *the vulnerability exists* -- when B0
admits `gt-f1-root` and `gt-f1-terminal`, that is the measured phenomenon,
not a bug (EXP1 STEP 9).

The class below is honestly incapable of doing anything else: it holds no
credential state, stages nothing at presentation, and its decision path has
no input other than the constant it returns. `audit = 0` too -- B0 emits no
decision log of its own (the trusted mediation record is the HARNESS's,
Part I, and exists for every arm).
"""

from collections.abc import Mapping
from typing import Any

from src.sut.baselines.base import ArmBitmask, HopContext, InvocationContext

REASON_FORWARDED = "b0_no_boundary_check"


class B0Arm:
    """No delegation protection, no credential, no boundary check."""

    name = "B0"
    bitmask = ArmBitmask(
        oauth_authn=0,
        crypto_chain=0,
        authorizer=0,
        htc_holder=0,
        invoke=0,
        contain=0,
        context=0,
        approval=0,
        jti_cache=0,
        audit=0,
    )

    def provision(self, setup: Mapping[str, Any]) -> None:
        """Nothing to provision: B0 has no credential plane."""

    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        """The envelope carries nothing (Part C: 'none')."""
        return {}

    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        """Nothing to stage: the boundary sees a plain call, so the wire is empty."""
        return {}

    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        """Forward, unconditionally. There is no input that could change this."""
        return True, REASON_FORWARDED
