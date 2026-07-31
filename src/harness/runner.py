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
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from mcp.shared.memory import create_connected_server_and_client_session

from src.harness import as_process, frozen_parameters, key_material, sealed_truth
from src.harness.authorizer import frozen_config
from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger
from src.harness.effectors import LedgerEffector
from src.harness.mediation.boundary import install_boundary
from src.harness.oracle import commitment
from src.harness.policy import frozen_policy
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
    """`H(Gamma)`, `H(R)` and `H(Lambda)` against `docs/frozen_parameters.md`.

    Fail closed, before any scenario runs. Three frozen artifacts, three
    digests, three rows-or-row-groups: 8 (ADR 0016), 11 (ADR 0019), and
    4/6/10 (ADR 0022).
    """
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
    policy_doc = frozen_policy.load_document()
    recorded = frozen_parameters.expected_h_policy()
    computed = frozen_policy.h_policy(policy_doc)
    if computed != recorded:
        raise FrozenConfigurationMismatch(
            f"H(Lambda) mismatch: artifact {computed} != recorded {recorded} (ADR 0022)"
        )


@dataclass
class TimingSeams:
    """The RQ4 measurement seams, correlated by `correlation_id`. UNMEASURED.

    Four spans, decomposed as Part H's latency protocol requires -- `setup`
    (SS E.2 Phase 1, excluded from the delegation estimand), `delegation`
    (SS E.2 Phase 2, the compared quantity), `boundary_verification`, and
    `end_to_end`. The seams EXIST and are correlated; **no number is emitted,
    reported, or interpreted in this pass** (EXP1 forbidden action 4): the
    G-3 threshold (`frozen_parameters` row 2) and the equivalence margin
    (row 1) are UNSET and must be fixed from external engineering need before
    any timing measurement (Part H step 2, Part J.2 item 9). `IA-3` stays
    `[UNVERIFIED-IA]` for G-3.

    Spans are recorded as monotonic-clock intervals so a later measurement
    pass needs no new instrumentation -- only a threshold, an ADR, and G-3.
    """

    correlation_id: str
    spans: dict[str, tuple[int, int]] = field(default_factory=dict)

    def mark(self, name: str, start_ns: int, end_ns: int) -> None:
        self.spans[name] = (start_ns, end_ns)

    def recorded(self) -> tuple[str, ...]:
        """Which seams captured a span. Deliberately returns NAMES, not values."""
        return tuple(sorted(self.spans))


@dataclass
class ScenarioRun:
    """Everything one invocation produced. Harness-side; never handed to the SUT."""

    scenario_id: str
    arm_name: str
    correlation_id: str
    intent: IntendedInvocation
    observed: ObservedRequest
    mediation_events: list[MediationEvent]
    ledger_path: str | None
    tool_result_error: bool
    presentation: Mapping[str, Any] = field(default_factory=dict)
    timing: TimingSeams | None = None
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    def ledger_entries(self) -> list[dict[str, Any]]:
        """The ledger's records. **Raises** on a run that had no ledger.

        Deliberately not an empty list: returning one would let a test assert
        "no effect occurred" and pass vacuously on a run that never recorded
        effects in the first place. Absence of evidence must not be readable
        as evidence of absence (ADR 0014).
        """
        if self.ledger_path is None:
            raise RunnerError(
                f"scenario {self.scenario_id!r} ran WITHOUT the effect ledger (ADR 0014): "
                "no effect evidence exists for it, and none may be inferred"
            )
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

    def __init__(self, *, corpus_dir: Path = CORPUS_DIR, ledger_dir: Path | None = None) -> None:
        verify_frozen_configuration()  # before any scenario runs (fail closed)
        self._corpus_dir = corpus_dir
        # Optional only because a non-ledger-backed run has nowhere to write;
        # a ledger-backed run without a directory fails closed below.
        self._ledger_dir = Path(ledger_dir) if ledger_dir is not None else None
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

    def b3_setup(self, *, access_token: str, as_public_jwk: dict[str, str]) -> dict[str, Any]:
        """The injected provisioning material for a capability arm.

        Everything the arm needs arrives as DATA from the composition root:
        the frozen documents (never imported by the SUT), the runner-resolved
        public keys and this campaign's private material (ADR 0007 seeds), the
        Phase-1 base token from the AS start-up line (ADR 0021), and the frozen
        rows 4/6/10 document (ADR 0022/0023), which the arm's loader evaluates
        itself and refuses to default if absent.
        """
        # The ONE policy source (ADR 0022): the frozen document itself. The
        # PILOT-PROVISIONAL stand-in is deleted, not merely bypassed.
        return {
            "gamma_document": frozen_config.load_document(),
            "registry_document": registry_mod.load_document(),
            "resolved_keys": key_material.resolve_public(self.seed),
            "kappa_private": key_material.derive_raw(self.seed, "kappa"),
            "holder_privates": {
                label: key_material.derive_raw(self.seed, label)
                for label in ("holder-supervisor", "holder-specialist", "holder-worker")
            },
            "access_token": access_token,
            "as_public_jwk": as_public_jwk,
            "issuer": self._corpus["issuer"],
            "resource_server": self._corpus["audience"],
            "rar_type": as_process.RAR_TYPE,
            "policy_document": frozen_policy.load_document(),
            "run_mode": "pilot",  # never "confirmatory": the seal is Part H's
        }

    def task_grant(self) -> list[list[str]]:
        """`U_task` as the pilot corpus itself declares it (ADR 0024).

        Read from the SUT-visible documents rather than accepted as an
        argument, so the AS's Phase-1 provisioning and the arm's own
        self-check cannot be handed two different answers by one caller
        mistake. The corpus must declare exactly one task grant across its
        scenarios -- they are one task with different invocations -- and more
        than one fails closed rather than silently picking the first.
        """
        grants: dict[str, tuple[tuple[str, str], ...]] = {}
        for path in sorted((self._corpus_dir / "sut_visible").glob("*.json")):
            visible = self._load_json(path)
            grants[path.stem] = tuple(
                (action, resource) for action, resource in visible["authority_elements"]
            )
        if not grants:
            raise RunnerError("the corpus declares no scenarios, so U_task is undefined")
        distinct = set(grants.values())
        if len(distinct) != 1:
            raise RunnerError(f"the pilot corpus declares more than one U_task: {grants}")
        return [[action, resource] for action, resource in sorted(distinct.pop())]

    def b2_setup(
        self,
        *,
        access_token: str,
        as_public_jwk: dict[str, str],
        as_port: int,
        as_tls_cert_pem: str,
        client_id: str = "agent-supervisor",
        actor_id: str = "agent-specialist",
        scope: str = "mcp.invoke",
        task_grant: list[list[str]] | None = None,
    ) -> dict[str, Any]:
        """The injected provisioning material for `B2-exchange-task` (SS E.2).

        `access_token` is the **delegating** client's Phase-1 base `AT@aud` --
        the exchange's `subject_token`, and SS 5.3's "the delegating agent
        (holder of `AT_{i-1}`) is the client of the exchange". `B3`'s setup
        passes the specialist's instead, because there the base token is authn
        only; the difference is which principal's token each mechanism starts
        from, not which provisioning path minted it.

        The client secret and the actor-assertion key are **mirrored** from the
        AS's documented derivations rather than imported (ADR 0015 rule 4 bars
        the harness from importing `src/sut/oauth_as/`), and both are
        runtime-only: derived here, in memory, handed to the arm, never written
        to disk, the repository, or `results/` (CLAUDE.md red line 8).

        `task_grant` defaults to the corpus's own `U_task` and is what the arm
        checks its subject token against before it will provision at all
        (ADR 0024). Passing one explicitly is a deliberate act -- it says "this
        run's task grant is not the corpus's" -- and the arm still refuses if
        the token it holds does not match whatever is passed.
        """
        principal = registry_mod.load_document()["actors"][actor_id]
        return {
            "as_port": as_port,
            "as_tls_cert_pem": as_tls_cert_pem,
            "as_public_jwk": as_public_jwk,
            "issuer": self._corpus["issuer"],
            "resource_server": self._corpus["audience"],
            "rar_type": as_process.RAR_TYPE,
            "access_token": access_token,
            "client_id": client_id,
            "client_secret": key_material.as_client_secret(self.seed, client_id),
            "actor_id": actor_id,
            "actor_identity_private_jwk": key_material.identity_private_jwk(self.seed, principal),
            "scope": scope,
            "task_grant": self.task_grant() if task_grant is None else task_grant,
            "run_mode": "pilot",  # never "confirmatory": the seal is Part H's
        }

    def run_scenario(
        self,
        scenario_id: str,
        arm: Any,
        *,
        setup: Mapping[str, Any] | None = None,
        ledger_backed: bool = True,
    ) -> ScenarioRun:
        """One scenario, one arm, one invocation; returns the SS F.1 records.

        `ledger_backed=False` runs the whole thread **without the effect
        ledger**: no `LedgerWriter`, no ingress recorder, and an effector that
        does nothing. It is **not** a POSIX ledger and not a substitute for one
        -- ADR 0014's enforcement is Win32 share-mode locking and has no
        stand-in. It exists so the assertions that do not concern effects (the
        boundary admitted, the tool dispatched and returned, the shape of the
        presented evidence, the sealed-truth relations) have coverage on every
        platform instead of being invisible to CI. Any attempt to read effect
        evidence from such a run **raises** (see `ledger_entries`), so no test
        can mistake the absence of a ledger for the absence of an effect.
        """
        visible = self.visible(scenario_id)
        sealed = sealed_truth.load_sealed(scenario_id)
        correlation_id = mint_correlation_id()
        timing = TimingSeams(correlation_id=correlation_id)
        end_to_end_start = time.perf_counter_ns()
        # ONE clock for the run: every credential window (capability, HTC,
        # INV) and the live AS-minted OAuth token are judged against this
        # instant. The scenario supplies the validity DURATION, never a
        # frozen "now" -- see src/sut/agents/supervisor.py.
        run_epoch = int(time.time())

        # SS E.2 Phase 1: setup, identical across arms, EXCLUDED from the
        # delegation estimand. Bracketed, never measured in this pass.
        setup_start = time.perf_counter_ns()
        arm.provision(dict(setup or {}))
        timing.mark("setup", setup_start, time.perf_counter_ns())

        # --- the tool stack, wired in the g7 order (recorder first, boundary
        # outermost, so a denied call reaches neither recorder nor tool) ------
        audience = visible["audience"]
        mediation_events: list[MediationEvent] = []
        boundary_observations: list[dict[str, Any]] = []
        sealed_intent: dict[str, IntendedInvocation] = {}
        presentations: list[Mapping[str, Any]] = []

        ledger_path: str | None = None
        writer: LedgerWriter | None = None
        if ledger_backed:
            if self._ledger_dir is None:
                raise RunnerError("a ledger-backed run needs a ledger directory")
            ledger_path = str(
                self._ledger_dir / f"{scenario_id}-{arm.name}-{correlation_id[:8]}.jsonl"
            )
            writer = LedgerWriter(ledger_path)
            effector = LedgerEffector(
                writer,
                audience=audience,
                principal=visible["specialist"],
                correlation_provider=lambda: correlation_id,
            )
        else:
            # Not a writer of any kind: the tool executes and records NOTHING.
            # There is no object here that could be mistaken for a ledger.
            def effector(**_: Any) -> None:
                return None

        server = build_server(effector)
        if writer is not None:
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
            verification_start = time.perf_counter_ns()
            try:
                return arm.decide(tool, arguments)
            except Exception as exc:  # noqa: BLE001 -- any arm failure is a denial
                return False, f"arm_error:{type(exc).__name__}"
            finally:
                timing.mark("boundary_verification", verification_start, time.perf_counter_ns())

        install_boundary(
            server,
            decide=decide,
            correlation_provider=lambda: correlation_id,
            emit=mediation_events.append,
        )

        # --- agents over the injected port -----------------------------------
        transport = InProcessDelegationTransport()

        def observed_delegate(hop: Any) -> Mapping[str, Any]:
            # SS E.2 Phase 2: the delegation cost -- the quantity the arms are
            # compared on (B2's online exchange vs B3's offline attenuation).
            delegation_start = time.perf_counter_ns()
            try:
                return arm.delegate(hop)
            finally:
                timing.mark("delegation", delegation_start, time.perf_counter_ns())

        def observed_present(credentials: Mapping[str, Any], invocation: Any) -> Mapping[str, Any]:
            presentation = arm.present(credentials, invocation)
            presentations.append(dict(presentation))
            return presentation

        arm_proxy = _PresentObserver(arm, observed_present, observed_delegate)
        tool_caller = _LateBoundToolCaller()
        specialist = Specialist(
            arm=arm_proxy,
            tool_caller=tool_caller,  # bound to the live session inside drive()
            method=visible["method"],
            audience=audience,
            clock=lambda: run_epoch,
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
        supervisor = Supervisor(arm=arm_proxy, transport=transport, clock=lambda: run_epoch)

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
            if writer is not None:
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
            iat=run_epoch,
        )

        timing.mark("end_to_end", end_to_end_start, time.perf_counter_ns())
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
            timing=timing,
            audit_log=list(getattr(arm, "audit_log", [])),
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

    def __init__(self, arm: Any, observed_present: Any, observed_delegate: Any) -> None:
        self._arm = arm
        self._observed_present = observed_present
        self._observed_delegate = observed_delegate

    @property
    def name(self) -> str:
        return self._arm.name

    @property
    def bitmask(self) -> Any:
        return self._arm.bitmask

    def provision(self, setup: Mapping[str, Any]) -> None:
        self._arm.provision(setup)

    def delegate(self, hop: Any) -> Mapping[str, Any]:
        return self._observed_delegate(hop)

    def present(self, credentials: Mapping[str, Any], invocation: Any) -> Mapping[str, Any]:
        return self._observed_present(credentials, invocation)

    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        return self._arm.decide(tool, arguments)
