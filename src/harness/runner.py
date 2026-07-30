"""The harness runner: correlation, records, and the sealed-truth wall (EXP1 STEP 8).

The instrument side of the golden thread. One `run_scenario` call drives one
scenario under one arm across the whole path -- provision, A2A delegation,
MCP tool call -- and produces the SS F.1 records the oracle will later read:
the sealed `IntendedInvocation`, the `ObservedRequest` assembled from **raw**
evidence, the trusted `MediationEvent`s, and the effect-ledger file. It
adjudicates nothing: no oracle predicate runs here (G-12 territory).

What this module guarantees, each with its own test:

* the **unforgeable 128-bit `correlation_id`** is minted here, per invocation,
  and bound into the sealed intent and every trusted record; the SUT receives
  it (Specialist -> INV `jti` in Phase B) and can never mint one;
* `H(Gamma)` and `H(R)` are verified against `docs/frozen_parameters.md` at
  start-up, **fail closed**, before any scenario runs;
* no SUT-computed verdict and no SUT-computed digest enters any record the
  oracle reads: `raw_arguments` are captured at the mediation boundary (a
  non-bypassable path, gate G-6), digests are recomputed harness-side, and
  `P_hashes` come from the ADR 0003 commitment over the raw presented hops;
* `tau_gt` and every sealed object are reachable only through
  `src/harness/sealed_truth` (red line 5).

The mediation `decide` callable invokes the **arm's** boundary decision and
records the outcome. Part I's "NOT the SUT" is about the **provenance of the
record** -- the trusted mediation layer emits it -- not about who made the
decision: the decision IS the mechanism under measurement. If the arm raises,
the boundary records a denial and the tool does not run (fail closed).
"""

import asyncio
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from mcp.shared.memory import create_connected_server_and_client_session

from src.harness import frozen_parameters, key_material, sealed_truth
from src.harness.authorizer import frozen_config
from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger
from src.harness.effectors import LedgerEffector
from src.harness.mediation.boundary import install_boundary
from src.harness.oracle import commitment
from src.harness.schema import (
    CapabilityEvidence,
    EvidenceBundle,
    IntendedInvocation,
    MediationEvent,
    OAuthEvidence,
    ObservedRequest,
)
from src.harness.verifier import registry as registry_mod
from src.sut.agents.specialist import Specialist
from src.sut.agents.supervisor import Supervisor
from src.sut.protocol.a2a import InProcessDelegationTransport
from src.sut.protocol.mcp_tools import build_server

CORPUS_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "pilot" / "golden_thread"


class RunnerError(Exception):
    """Base: the runner failed closed."""


class FrozenConfigurationMismatch(RunnerError):
    """A frozen artifact does not hash to the recorded value. Nothing may run."""


def mint_correlation_id() -> str:
    """The unforgeable 128-bit correlation id (SS F.1). Harness-minted only."""
    return secrets.token_hex(16)


def verify_frozen_configuration() -> None:
    """`H(Gamma)` and `H(R)` against `docs/frozen_parameters.md`. Fail closed."""
    gamma_doc = frozen_config.load_document()
    recorded = frozen_parameters.expected_h_gamma()
    computed = frozen_config.h_gamma(gamma_doc)
    if computed != recorded:
        raise FrozenConfigurationMismatch(
            f"H(Gamma) mismatch: artifact {computed} != recorded {recorded} (ADR 0016)"
        )
    registry_doc = registry_mod.load_document()
    recorded = frozen_parameters.expected_h_registry()
    computed = registry_mod.h_registry(registry_doc)
    if computed != recorded:
        raise FrozenConfigurationMismatch(
            f"H(R) mismatch: artifact {computed} != recorded {recorded} (ADR 0019)"
        )


@dataclass
class ScenarioRun:
    """Everything one invocation produced. Harness-side; never handed to the SUT."""

    scenario_id: str
    arm_name: str
    correlation_id: str
    intent: IntendedInvocation
    observed: ObservedRequest
    mediation_events: list[MediationEvent]
    ledger_path: str
    tool_result_error: bool
    presentation: Mapping[str, Any] = field(default_factory=dict)

    def ledger_entries(self) -> list[dict[str, Any]]:
        return read_ledger(self.ledger_path)

    def effects(self) -> list[dict[str, Any]]:
        return [e for e in self.ledger_entries() if "effect_request_digest" in e]


def _evidence_from(presentation: Mapping[str, Any]) -> EvidenceBundle:
    """The SS F.1 bundle from the raw presented material. Empty presentation = B0."""
    capability = None
    oauth = None
    if "capability_hops" in presentation:
        capability = CapabilityEvidence(
            kind="capability",
            signed_blocks=[bytes(hop) for hop in presentation["capability_hops"]],
            htc_chain=[bytes(htc) for htc in presentation.get("htc_chain", [])],
            invocation_assertion=bytes(presentation.get("invocation_assertion", b"")),
            raw_at=presentation.get("access_token", "").encode("ascii"),
        )
    if "access_token" in presentation:
        oauth = OAuthEvidence(kind="oauth", raw_at=presentation["access_token"].encode("ascii"))
    return EvidenceBundle(oauth=oauth, capability=capability, api_key=None, inv_only=None)


class GoldenThreadRunner:
    """Runs pilot scenarios under an injected arm. Verifies the freeze first."""

    def __init__(self, *, corpus_dir: Path = CORPUS_DIR, ledger_dir: Path) -> None:
        verify_frozen_configuration()  # before any scenario runs (fail closed)
        self._corpus_dir = corpus_dir
        self._ledger_dir = Path(ledger_dir)
        self._corpus = self._load_json(corpus_dir / "corpus.json")
        if self._corpus["derivation_info_prefix"] != key_material.DERIVATION_INFO_PREFIX.decode(
            "ascii"
        ):
            raise RunnerError("corpus derivation rule drifted from src/harness/key_material.py")
        self.seed = bytes.fromhex(self._corpus["seed_hex"])

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        import json

        return json.loads(path.read_text(encoding="utf-8"))

    def visible(self, scenario_id: str) -> dict[str, Any]:
        """The SUT-visible document -- the ONLY scenario material the SUT gets."""
        return self._load_json(self._corpus_dir / "sut_visible" / f"{scenario_id}.json")

    def run_scenario(
        self, scenario_id: str, arm: Any, *, setup: Mapping[str, Any] | None = None
    ) -> ScenarioRun:
        """One scenario, one arm, one invocation; returns the SS F.1 records."""
        visible = self.visible(scenario_id)
        sealed = sealed_truth.load_sealed(scenario_id)
        correlation_id = mint_correlation_id()

        arm.provision(dict(setup or {}))

        # --- the tool stack, wired in the g7 order (recorder first, boundary
        # outermost, so a denied call reaches neither recorder nor tool) ------
        audience = visible["audience"]
        ledger_path = str(self._ledger_dir / f"{scenario_id}-{arm.name}-{correlation_id[:8]}.jsonl")
        writer = LedgerWriter(ledger_path)
        mediation_events: list[MediationEvent] = []
        boundary_observations: list[dict[str, Any]] = []
        sealed_intent: dict[str, IntendedInvocation] = {}
        presentations: list[Mapping[str, Any]] = []

        effector = LedgerEffector(
            writer,
            audience=audience,
            principal=visible["specialist"],
            correlation_provider=lambda: correlation_id,
        )
        server = build_server(effector)
        install_ingress_recorder(
            server,
            audience=audience,
            correlation_provider=lambda: correlation_id,
            writer=writer,
        )

        def decide(tool: str, arguments: dict[str, Any]) -> tuple[bool, str]:
            # Non-bypassable observation point (gate G-6): every dispatch path
            # converges here, so the observed tool/arguments are recorded by
            # the harness whatever the SUT does or claims.
            boundary_observations.append({"tool": tool, "arguments": dict(arguments)})
            # Part I "NOT the SUT" concerns the RECORD's provenance (this
            # trusted layer emits the MediationEvent); the decision itself is
            # the arm's -- the mechanism under measurement. An arm that raises
            # is a denial: fail closed, the tool never runs.
            try:
                return arm.decide(tool, arguments)
            except Exception as exc:  # noqa: BLE001 -- any arm failure is a denial
                return False, f"arm_error:{type(exc).__name__}"

        install_boundary(
            server,
            decide=decide,
            correlation_provider=lambda: correlation_id,
            emit=mediation_events.append,
        )

        # --- agents over the injected port -----------------------------------
        transport = InProcessDelegationTransport()

        def observed_present(credentials: Mapping[str, Any], invocation: Any) -> Mapping[str, Any]:
            presentation = arm.present(credentials, invocation)
            presentations.append(dict(presentation))
            return presentation

        arm_proxy = _PresentObserver(arm, observed_present)
        tool_caller = _LateBoundToolCaller()
        specialist = Specialist(
            arm=arm_proxy,
            tool_caller=tool_caller,  # bound to the live session inside drive()
            method=visible["method"],
            audience=audience,
            now_epoch=visible["now_epoch"],
            invocation_id_provider=lambda: correlation_id,
        )

        def seal_and_receive(envelope: Any) -> Any:
            # Seal the intent BEFORE the Specialist acts: the sealed record can
            # never be a function of the boundary outcome. P_hashes are the
            # ADR 0003 commitments over the raw presented hops (empty when the
            # arm carries no capability, as B0 does).
            sealed_intent["intent"] = self._complete_intent(
                sealed, correlation_id, envelope.credentials
            )
            return specialist.receive(envelope)

        transport.register(visible["specialist"], seal_and_receive)
        supervisor = Supervisor(arm=arm_proxy, transport=transport)

        # --- drive it: sync agents bridged onto the async MCP session --------
        tool_error: dict[str, bool] = {}

        async def drive() -> None:
            async with create_connected_server_and_client_session(server._mcp_server) as client:
                loop = asyncio.get_running_loop()

                def call_over_session(tool: str, arguments: Mapping[str, Any]) -> Any:
                    future = asyncio.run_coroutine_threadsafe(
                        client.call_tool(tool, dict(arguments)), loop
                    )
                    result = future.result(timeout=30)
                    tool_error["error"] = bool(result.isError)
                    return result

                tool_caller.target = call_over_session
                await asyncio.to_thread(supervisor.run, visible)

        try:
            asyncio.run(drive())
        finally:
            writer.close()

        # --- assemble the ObservedRequest from RAW evidence ------------------
        if not boundary_observations:
            raise RunnerError("no tool dispatch reached the mediation boundary")
        observation = boundary_observations[-1]
        presentation = presentations[-1] if presentations else {}
        observed = ObservedRequest(
            correlation_id=correlation_id,
            evidence=_evidence_from(presentation),
            audience=audience,
            method=visible["method"],
            tool=observation["tool"],
            raw_arguments=rfc8785.dumps(observation["arguments"]),
            payload_labels=[],
            declassification=None,
            approval_artifact=None,
            iat=visible["now_epoch"],
        )

        return ScenarioRun(
            scenario_id=scenario_id,
            arm_name=arm.name,
            correlation_id=correlation_id,
            intent=sealed_intent["intent"],
            observed=observed,
            mediation_events=mediation_events,
            ledger_path=ledger_path,
            tool_result_error=tool_error.get("error", True),
            presentation=presentation,
        )

    def _complete_intent(
        self, sealed: dict[str, Any], correlation_id: str, credentials: Mapping[str, Any]
    ) -> IntendedInvocation:
        """The full SS F.1 IntendedInvocation: fixture statics + runtime completion.

        `P_hashes` are recomputed here from the raw presented hop bytes with the
        harness's own ADR 0003 implementation -- never accepted from the SUT.
        """
        p_hashes: list[str] = []
        hops = credentials.get("capability_hops") if credentials else None
        if hops:
            _, root_pub = key_material.biscuit_root(self.seed)
            block_ids = commitment.block_ids_from_raw(bytes(hops[-1]), root_pub)
            p_hashes = [
                commitment.commit_prefix(block_ids, index).hex() for index in range(len(block_ids))
            ]
        return IntendedInvocation(
            correlation_id=correlation_id,
            resource_owner=tuple(sealed["resource_owner"]),
            oauth_actor=tuple(sealed["oauth_actor"]),
            htc_holder_kid=sealed["htc_holder_kid"],
            audience=sealed["audience"],
            method=sealed["method"],
            tool=sealed["tool"],
            intended_request_digest=sealed["intended_request_digest"],
            intended_labels=list(sealed["intended_labels"]),
            requires_approval=bool(sealed["requires_approval"]),
            U_task=frozenset((a, r) for a, r in sealed["U_task"]),
            P_hashes=p_hashes,
            C_sets=[frozenset((a, r) for a, r in c_set) for c_set in sealed["C_sets"]],
            R=frozenset((a, r) for a, r in sealed["R"]),
            tau_gt=frozenset((a, r) for a, r in sealed["tau_gt"]),
            attack_subcase=sealed["attack_subcase"],
        )


class _LateBoundToolCaller:
    """A callable seam bound to the live MCP session once it exists."""

    def __init__(self) -> None:
        self.target: Any = None

    def __call__(self, tool: str, arguments: Mapping[str, Any]) -> Any:
        if self.target is None:
            raise RunnerError("tool caller used before the session was bound")
        return self.target(tool, arguments)


class _PresentObserver:
    """Harness interposition on the arm's presentation seam (observation only).

    Forwards every operation unchanged; records what `present` returns -- the
    raw material the boundary saw -- so `ObservedRequest.evidence` is a
    harness observation, not a SUT report. Everything else is delegated.
    """

    def __init__(self, arm: Any, observed_present: Any) -> None:
        self._arm = arm
        self._observed_present = observed_present

    @property
    def name(self) -> str:
        return self._arm.name

    @property
    def bitmask(self) -> Any:
        return self._arm.bitmask

    def provision(self, setup: Mapping[str, Any]) -> None:
        self._arm.provision(setup)

    def delegate(self, hop: Any) -> Mapping[str, Any]:
        return self._arm.delegate(hop)

    def present(self, credentials: Mapping[str, Any], invocation: Any) -> Mapping[str, Any]:
        return self._observed_present(credentials, invocation)

    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        return self._arm.decide(tool, arguments)
