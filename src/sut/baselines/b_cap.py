"""`B-cap`: the ablation that keeps `B3`'s benefits attributable (SS E.1, SS E.6).

SS E.5 bits `1 1 1 0 0 1 0 0 0 1`. Offline attenuation exactly as `B3` does it
and **no exchange round trip**, but a **bearer capability**: no HTC chain, no
INV, no policy plane. What it isolates (SS E.1's `Isolates` column) is *offline
attenuation, separated from binding*.

**Why it exists, and it is the whole reason.** Without it, every security
difference `B3` shows over `B2-exchange-task` could be attributed to "the
capability token" when it is really the work of the HTC chain (who holds it)
and the INV (which invocation it authorizes). `B-cap` runs the capability plane
*alone*, so a difference that survives between `B-cap` and `B3` is attributable
to binding and holder proof rather than to capabilities as such. The
captured-capability contrast in `tests/test_b_cap.py` is that argument made
concrete: one capability, captured from its legitimate holder and presented by
a different party -- **admitted** by `B-cap`, **blocked** by `B3`.

**Primary `B-cap` is fixed by SS E.1's `B-cap fixed [E6]` paragraph:**
`oauth_authn = 1`, on the same OAuth substrate as `B3`, and it **MUST** verify
audience and expiry. It does, through the unchanged
`src/sut/authz/boundary.py` that `oauth_resource_authorization_ok` calls. A
standalone-capability (`oauth_authn = 0`) configuration would be a separate
exploratory arm and is **not built here at all** -- no undecided cell appears
in the formal matrix.

**A configuration, not a copy.** The four conjuncts it runs --
`crypto_chain_ok`, `authorizer_policy_ok`, `containment_ok`,
`oauth_resource_authorization_ok` -- are the *same functions* `B3` runs, in the
same `CapabilityDecisionPath`, and the SS E.5 bitmask is what selects them
(`ArmBitmask.enabled_conjuncts`). Provisioning is inherited unchanged. Only the
two operations that *produce* the planes `B-cap` does not have are overridden:
delegation mints and attenuates without issuing an HTC hop, and presentation
stages the capability and the base `AT@aud` without signing an INV. `B-cap`
never pays for a plane it does not carry.

Its bitmask position is **not** an SS E.6 ablation of `B3`: `enabled` is the
arm's ladder position and `disabled` is the ablation seam, and the two are
deliberately kept apart (see `CapabilityDecisionPath`). `B-cap` is a declared
arm in its own right and carries no `disabled` conjunct.
"""

from collections.abc import Mapping
from typing import Any

from src.sut.authz.capability_path import B3Presentation
from src.sut.baselines.b3 import REASON_NOT_PROVISIONED, B3Arm
from src.sut.baselines.base import ArmBitmask, ArmIdentity, HopContext, InvocationContext


class BCapArm(B3Arm):
    """Offline attenuation, bearer capability, OAuth authn on."""

    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=1,
        authorizer=1,
        htc_holder=0,  # no HTC chain, so no terminal holder and no identity-plane map
        invoke=0,  # no INV: nothing binds the capability to this invocation
        contain=1,
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )

    def __init__(self, identity: ArmIdentity | None = None) -> None:
        super().__init__(identity or ArmIdentity(name="B-cap"))

    # -- delegate: offline mint + append, and NOTHING else -------------------- #
    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        """`P_0 -> P_1` offline, with no HTC hop and no AS round trip.

        `hop.widening_elements` is the SS E.3 chain-tamper intent as a
        capability arm realizes it: the elements are appended in the
        attenuation block, which verifies cryptographically under `kappa_pub`
        yet carries no authority, because block scoping means a later block can
        only narrow what block 0 granted.
        """
        if self._issuer is None or self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        root_hop = self._issuer.mint_root(
            list(hop.authority_elements),
            audience=hop.audience,
            task_id=hop.task_id,
            expiry_epoch=hop.expiry_epoch,
        )
        attenuated = self._issuer.attenuate(
            root_hop, list(hop.attenuation_elements) + list(hop.widening_elements)
        )
        return {
            "capability_hops": [root_hop.token_bytes, attenuated.token_bytes],
            "block_ids": [list(root_hop.block_ids), list(attenuated.block_ids)],
            # Named and EMPTY rather than absent, so a reader of the wire sees
            # that this arm carries no holder plane instead of inferring it.
            "htc_chain": [],
            "access_token": self._setup["access_token"],
            "audience": hop.audience,
        }

    # -- present: the capability and the base AT, as BEARER material ---------- #
    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        """Stage a bearer capability: no INV is signed, so nothing proves who
        is presenting it or which invocation it authorizes.

        That is the arm, not an oversight: `B-cap` admitting a captured
        capability is the measurement `B3`'s holder and invocation binding is
        compared against.
        """
        if self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        hops = tuple(bytes(hop) for hop in credentials["capability_hops"])
        access_token = credentials["access_token"]
        presentation = {
            "capability_hops": [bytes(hop) for hop in hops],
            "htc_chain": [],
            "invocation_assertion": b"",
            "access_token": access_token,
        }
        self._staged = B3Presentation(
            capability_hops=hops,
            htc_chain=(),
            invocation_assertion=b"",
            access_token=access_token,
            task_id=invocation.task_id,
            audience=invocation.audience,
            method=invocation.method,
            now_epoch=invocation.now_epoch,
        )
        return presentation


def capture(credentials: Mapping[str, Any]) -> dict[str, Any]:
    """What a party that is NOT the legitimate holder comes to possess.

    The bearer material only: the capability hops and the base `AT@aud`. The
    HTC chain and the INV are deliberately dropped, because the point of the
    contrast is that `B-cap` needs neither to admit -- it is exactly the
    material SS E.6's `-holder` fixture describes as "a capability captured
    from the legitimate holder".
    """
    return {
        "capability_hops": [bytes(hop) for hop in credentials["capability_hops"]],
        "block_ids": [list(ids) for ids in credentials["block_ids"]],
        "htc_chain": [],
        "access_token": credentials["access_token"],
        "audience": credentials["audience"],
    }
