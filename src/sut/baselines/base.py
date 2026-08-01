"""The arm interface: what the SS E.1 ladder needs, and no more.

An arm is a **mechanism configuration** over the one shared substrate (agents,
port, tool server). The four operations are the ladder's seams:

    provision  Phase-1 setup (SS E.2): identical across arms in shape, excluded
               from the delegation estimand. Key material and AS artifacts are
               INJECTED by the composition root; an arm never reads a fixture
               file or derives a seed itself.
    delegate   per hop (SS E.2 Phase 2): produce the credentials mapping the
               DelegationEnvelope carries -- empty for B0; capability prefix +
               HTC chain + AT for B3. What an agent carries is decided HERE,
               by the arm, never by the agent (EXP1 STEP 6).
    present    at the boundary: stage the credentials the Specialist presents
               for one concrete invocation, and return the presentation as it
               would ride the wire (raw bytes included) -- which is what the
               harness observes into `ObservedRequest.evidence` (SS F.1).
    decide     at the boundary: the arm's admission decision for the presented
               invocation. The trusted mediation layer RECORDS this outcome
               (Part I: provenance of the record is the mediation layer, not
               the SUT); the decision itself is the mechanism under
               measurement.

`B1`, `B2x5`, `B-cap` and `B3+` are NOT implemented in this pass (EXP1
forbidden action 11); nothing here may assume their absence -- the interface
carries the full SS E.5 bitmask so any later arm is a configuration of the
same shape.

The bitmask is DATA (SS E.5), so an arm's configuration is inspectable rather
than implied: `audit` never sits on the decision path, and `contain` being 0
for B0 is what makes B0's admissions an honest measurement of the
vulnerability rather than a bug.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ArmBitmask:
    """SS E.5: `[oauth_authn | crypto_chain | authorizer | htc/holder | invoke |
    contain | context | approval | jti_cache | audit]`, each 0 or 1."""

    oauth_authn: int
    crypto_chain: int
    authorizer: int
    htc_holder: int
    invoke: int
    contain: int
    context: int
    approval: int
    jti_cache: int
    audit: int

    def as_bits(self) -> tuple[int, ...]:
        return (
            self.oauth_authn,
            self.crypto_chain,
            self.authorizer,
            self.htc_holder,
            self.invoke,
            self.contain,
            self.context,
            self.approval,
            self.jti_cache,
            self.audit,
        )

    def enabled_conjuncts(self) -> frozenset[str]:
        """The SS A.5 conjuncts this arm's bitmask selects.

        An arm's ladder position is DATA, not a branch: the same decision-path
        functions serve `B3` and `B-cap`, and the bitmask is what chooses which
        of them run. `jti_cache` and `audit` select no conjunct -- the first is
        `B3+`'s replay cache (gate G-9) and the second never sits on the
        decision path at all (SS E.5).
        """
        selected: set[str] = set()
        for bit, conjuncts in BIT_TO_CONJUNCTS.items():
            if getattr(self, bit):
                selected.update(conjuncts)
        return frozenset(selected)


class ArmIdentityError(Exception):
    """An arm's declared identity does not permit what it was configured to do."""


@dataclass(frozen=True)
class ArmIdentity:
    """Who an arm declares itself to be, and what that permits (EXP2 STEP 6).

    Before SS E.6's ablation arms exist, this closes the gap that nothing
    stopped `B3` **proper** from carrying a `disabled` conjunct: a decision
    path may only skip a conjunct if the arm presenting it has *declared*
    itself an ablation of exactly that conjunct.
    """

    name: str
    is_ablation: bool = False
    ablates: str | None = None

    def __post_init__(self) -> None:
        if self.is_ablation and not self.ablates:
            raise ArmIdentityError(f"ablation arm {self.name!r} names no ablated conjunct")
        if self.ablates and not self.is_ablation:
            raise ArmIdentityError(f"arm {self.name!r} names an ablated conjunct but is not one")

    def check_disabled(self, disabled: "frozenset[str]", *, run_mode: str) -> None:
        """The four rules. Every one refuses rather than warns."""
        if not disabled:
            return
        if not self.is_ablation:
            raise ArmIdentityError(
                f"{self.name!r} is not a declared ablation variant and may not disable "
                f"{sorted(disabled)} (SS E.6 ablations are separate arms)"
            )
        if disabled != {self.ablates}:
            # SS E.6: each ablation is B3 with EXACTLY ONE conjunct disabled,
            # and an orthogonal fixture blocked only by that conjunct. Two
            # would make the leave-one-out unmatched.
            raise ArmIdentityError(
                f"{self.name!r} declares it ablates {self.ablates!r} but disables "
                f"{sorted(disabled)}"
            )
        if run_mode == "confirmatory":
            raise ArmIdentityError(
                f"ablation variant {self.name!r} may not drive a confirmatory run"
            )


# SS E.5 bit -> the SS A.5 conjuncts that bit selects. `htc_holder` carries
# three: without an HTC chain there is no terminal holder to prove against and
# none to map an `oauth_actor` onto (SS A.5.1), so the identity-plane check has
# nothing to check.
BIT_TO_CONJUNCTS: dict[str, tuple[str, ...]] = {
    "oauth_authn": ("oauth_resource_authorization_ok",),
    "crypto_chain": ("crypto_chain_ok",),
    "authorizer": ("authorizer_policy_ok",),
    "htc_holder": ("htc_chain_ok", "holder_proof_ok", "identity_plane_consistency_ok"),
    "invoke": ("invocation_binding_ok",),
    "contain": ("containment_ok",),
    "context": ("context_policy_ok",),
    "approval": ("approval_artifact_ok",),
}


@dataclass(frozen=True)
class HopContext:
    """What one delegation hop may legitimately know. All SUT-visible (SS A.3):
    the task grant and the attenuation are the Supervisor's own material."""

    task_id: str
    audience: str
    from_agent: str
    to_agent: str
    authority_elements: tuple[tuple[str, str], ...]
    attenuation_elements: tuple[tuple[str, str], ...]
    now_epoch: int
    expiry_epoch: int
    # SS E.3 `F1-chain-tamper`, carried as the declared INTENT and nothing more:
    # the elements the delegating party attempts to add to what it passes on,
    # which lie outside `C_{i-1}`. **Each mechanism realizes it its own way** --
    # the exchange arm sends them in the request and the AS refuses to issue;
    # the capability arms append them as a widening block that verifies under
    # `kappa_pub` yet carries no authority under block scoping. Empty for every
    # benign scenario, so no existing hop changes.
    widening_elements: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class InvocationContext:
    """What presenting one concrete invocation at the boundary may know.

    `invocation_id` is the harness-minted correlation id, injected so the
    B3 INV can bind it as `jti` (SS F.1: bound into sealed intent, records,
    and the INV jti). It is an identifier the harness hands the SUT, never
    a value the SUT mints.
    """

    tool: str
    arguments: Mapping[str, Any]
    method: str
    task_id: str
    audience: str
    invocation_id: str
    now_epoch: int
    # ADR 0030's artifacts, as the SS F.1 `ObservedRequest` carries them. The
    # scenario supplies them; the arm presents them; the boundary VERIFIES
    # them. Empty for every scenario that carries no labels, so no existing
    # invocation changes shape.
    payload_labels: tuple[Mapping[str, Any], ...] = ()
    declassification: Any | None = None
    approval_artifact: bytes | None = None


class Arm(Protocol):
    """The ladder's seam. Concrete arms: `b0.B0Arm` (this pass), `b3.B3Arm`
    (Phase B); the remaining arms plug in here later, unimplemented for now."""

    name: str
    bitmask: ArmBitmask

    def provision(self, setup: Mapping[str, Any]) -> None: ...

    def delegate(self, hop: HopContext) -> Mapping[str, Any]: ...

    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]: ...

    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]: ...
