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

from src.harness import as_process, credential_faults, frozen_parameters, key_material, sealed_truth
from src.harness.authorizer import frozen_config
from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger
from src.harness.effectors import LedgerEffector
from src.harness.mediation.boundary import install_boundary
from src.harness.oracle import commitment
from src.harness.policy import frozen_policy, label_artifacts
from src.harness.schema import (
    ApiKeyEvidence,
    CapabilityEvidence,
    EvidenceBundle,
    IntendedInvocation,
    MediationEvent,
    OAuthEvidence,
    ObservedRequest,
)
from src.harness.sut_process import SutProcess
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

    Five spans, decomposed as Part H's latency protocol requires -- `setup`
    (SS E.2 Phase 1, excluded from the delegation estimand), `delegation`
    (SS E.2 Phase 2, the compared quantity), `presentation`,
    `boundary_verification`, and `end_to_end`.

    **The MEASURED SEGMENT is `presentation + boundary_verification`**
    (ADR 0026, `frozen_parameters` row 1), each bracketing exactly one call --
    `arm.present(...)` and `arm.decide(...)` respectively -- and summed for
    the estimand rather than folded into one widened span, because SS E.5 asks
    for the latency to be *decomposed* and redefining an existing span's
    meaning would silently reinterpret anything already recorded under it.
    `tests/test_measured_segment.py` asserts both extents structurally, that
    no effect-ledger write falls inside either, and that neither contains
    `provision` or `delegate`.

    *(Update note: this docstring read "Four spans" and named rows 1 and 2 as
    UNSET. Both were true when written; ADR 0025/0026 set them and added the
    `presentation` seam. `presentation` exists because the previous segment
    bracketed `decide` alone and therefore omitted `B3`'s principal
    per-invocation cost -- JCS canonicalization, `access_token_hash`, the INV
    signature -- from the very test the "lightweight" claim is settled by, an
    omission that ran toward this project's own hypothesis.)*

    **The seams EXIST and are correlated; no number is emitted, reported or
    interpreted here.** Rows 1 and 2 being set does not authorize measurement:
    G-3 owns timing, and ADR 0025 requires an adjudicative run on the row 9
    sealed measurement platform, which is not yet locked. `IA-3` stays
    `[UNVERIFIED-IA]` for G-3.

    Spans are recorded as monotonic-clock intervals so a later measurement
    pass needs no new instrumentation -- only G-3 and a locked platform.
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
    api_key = None
    if "api_key_id" in presentation:
        # `raw_key_ref` is a REFERENCE (SS F.1). `B1` presents the key id here
        # and compares the secret in-process, so no shared secret enters any
        # record the oracle reads (PROJECT_RULES.md red line 8).
        api_key = ApiKeyEvidence(kind="api_key", raw_key_ref=presentation["api_key_id"])
    return EvidenceBundle(oauth=oauth, capability=capability, api_key=api_key, inv_only=None)


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

    def b3_setup(
        self,
        *,
        access_token: str,
        as_public_jwk: dict[str, str],
        actor_id: str = "agent-specialist",
        monitor_attached: bool = True,
    ) -> dict[str, Any]:
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
        label_issuers, approvers = label_artifacts.trusted_sets(self.seed)
        resource_owner = registry_mod.load_document()["resource_owners"][0]
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
            # ADR 0030's monitor material. The two trusted sets are DISJOINT by
            # role and by derivation label; `policy_version` is `H(Lambda)`, so
            # an artifact issued under one rows-4/6 policy cannot survive an
            # amendment to it. `resource_owner` and `oauth_actor` are identity
            # CONFIGURATION -- the same values the sealed record also carries,
            # but reaching the SUT from the composition root rather than from a
            # sealed document, exactly as `audience` does (red line 5).
            "label_issuers": label_issuers,
            "approvers": approvers,
            "policy_version": frozen_parameters.expected_h_policy(),
            "resource_owner": (self._corpus["issuer"], resource_owner),
            "oauth_actor": (self._corpus["issuer"], actor_id),
            "monitor_attached": monitor_attached,
            "run_mode": "pilot",  # never "confirmatory": the seal is Part H's
        }

    def task_grant(self, scenario_id: str | None = None) -> list[list[str]]:
        """`U_task` as the pilot corpus itself declares it (ADR 0024).

        Read from the SUT-visible documents rather than accepted as an
        argument, so the AS's Phase-1 provisioning and the arm's own self-check
        cannot be handed two different answers by one caller mistake.

        **Named rather than assumed, since the corpus grew a second chain.**
        The F4/F5 families run on a chain that includes `(mail.send,
        mail/outbox)` and `(notes.delete, notes/project)` -- deliberately, so
        that `containment_ok` cannot refuse a labelled egress before
        `context_policy_ok` ever runs. So "the corpus's `U_task`" is no longer
        a single answer, and a caller that needs one must say which family it
        is provisioning for. Passing no `scenario_id` still works while the
        scenarios in scope agree, and **fails closed with the disagreement
        spelled out** when they do not -- rather than silently picking one and
        provisioning an AS for the wrong family.
        """
        grants: dict[str, tuple[tuple[str, str], ...]] = {}
        for path in sorted((self._corpus_dir / "sut_visible").glob("*.json")):
            visible = self._load_json(path)
            grants[path.stem] = tuple(
                (action, resource) for action, resource in visible["authority_elements"]
            )
        if not grants:
            raise RunnerError("the corpus declares no scenarios, so U_task is undefined")
        if scenario_id is not None:
            if scenario_id not in grants:
                raise RunnerError(f"no such scenario in the pilot corpus: {scenario_id!r}")
            return [[action, resource] for action, resource in sorted(grants[scenario_id])]
        distinct = set(grants.values())
        if len(distinct) != 1:
            by_grant: dict[tuple, list[str]] = {}
            for name, grant in sorted(grants.items()):
                by_grant.setdefault(grant, []).append(name)
            families = " | ".join(f"{sorted(names)}" for names in by_grant.values())
            raise RunnerError(
                f"the pilot corpus declares {len(distinct)} distinct task grants ({families}); "
                "pass task_grant(scenario_id=...) to say which family this AS provisions for"
            )
        return [[action, resource] for action, resource in sorted(distinct.pop())]

    def ladder_grant_elements(
        self, ladder_grant: str, scenario_id: str | None = None
    ) -> list[list[str]]:
        """The element set an SS E.1 row's base token must carry (ADR 0029).

        `"task"` is the corpus's own `U_task` -- for the family named by
        `scenario_id`, since the corpus carries two chains (see `task_grant`);
        `"broad"` is the whole frozen `Omega` and is family-independent. Read
        from the frozen artifacts rather than passed in, so the AS's
        provisioning and the arm's self-check cannot be handed two different
        answers by one caller mistake.
        """
        if ladder_grant == "task":
            return self.task_grant(scenario_id)
        if ladder_grant == "broad":
            omega = frozen_config.load_document()["omega"]["elements"]
            return [[action, resource] for action, resource in sorted(map(tuple, omega))]
        raise RunnerError(f"unknown SS E.1 ladder grant {ladder_grant!r} (ADR 0029)")

    def b1_setup(self, *, key_id: str = "pilot-api-key") -> dict[str, Any]:
        """`B1`'s injected provisioning material (SS E.1's appendix arm).

        One shared secret, derived from the sealed seed and handed over in
        memory. There is nothing else to provision: `B1` expresses no
        authority, no audience and no scope, so no frozen document, no key
        material and no token reaches it.
        """
        return {
            "api_key_id": key_id,
            "api_key_secret": key_material.b1_api_key(self.seed, key_id),
        }

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
        ladder_grant: str = "task",
        grant_elements: list[list[str]] | None = None,
        scenario_id: str | None = None,
        monitor_attached: bool = False,
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
        to disk, the repository, or `results/` (PROJECT_RULES.md red line 8).

        `ladder_grant` names which SS E.1 row the arm occupies, and decides
        BOTH which of the delegating client's base tokens it receives and what
        its own provisioning check compares against (ADR 0029). `"task"` gives
        the ADR 0024 task-scoped `AT@aud` and `C_0 = U_task`; `"broad"` gives
        the coarse `Omega` grant the same client also holds, because SS E.4
        predicts the broad arms ADMIT `F1-root` and a task-scoped token would
        make them block it. The arm refuses to provision if the row it declares
        and the row it is handed disagree, so breadth cannot be smuggled in.
        `grant_elements` overrides the element set for a deliberate
        counterfactual; the arm still verifies the token against whatever is
        passed.
        """
        if ladder_grant not in ("task", "broad"):
            raise RunnerError(f"unknown SS E.1 ladder grant {ladder_grant!r} (ADR 0029)")
        principal = registry_mod.load_document()["actors"][actor_id]
        # ADR 0030 / G-15. The SAME material `b3_setup` injects, so the shared
        # monitor an OAuth arm attaches is configured identically to `B3`'s.
        # `monitor_attached` defaults FALSE here: SS E.4 predicts the OAuth arms
        # admit F4/F5 `A-dagger` -- *absent* the monitor -- and a default of
        # true would quietly make the dagger untestable.
        label_issuers, approvers = label_artifacts.trusted_sets(self.seed)
        resource_owner = registry_mod.load_document()["resource_owners"][0]
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
            "ladder_grant": ladder_grant,
            "grant_elements": (
                self.ladder_grant_elements(ladder_grant, scenario_id)
                if grant_elements is None
                else grant_elements
            ),
            "label_issuers": label_issuers,
            "approvers": approvers,
            "policy_version": frozen_parameters.expected_h_policy(),
            "policy_document": frozen_policy.load_document(),
            "resource_owner": (self._corpus["issuer"], resource_owner),
            "oauth_actor": (self._corpus["issuer"], actor_id),
            "monitor_attached": monitor_attached,
            "run_mode": "pilot",  # never "confirmatory": the seal is Part H's
        }

    def b2_dpop_setup(
        self,
        *,
        access_token: str,
        as_public_jwk: dict[str, str],
        as_port: int,
        as_tls_cert_pem: str,
        as_token_endpoint: str,
        resource_url: str = "https://mcp.aasc.local/tools/invoke",
        holder_label: str = "holder-specialist",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """`B2-exchange-task-DPoP`'s material: the exchange arm's plus a proof key.

        The DPoP holder key is derived from the sealed seed and injected in
        memory, never written anywhere (PROJECT_RULES.md red line 8). It is a
        DIFFERENT key from the AS's signing key and from any actor-assertion
        key -- `smoke/g4/DESIGN.md` SS 7.3 warns the DPoP holder and the HTC
        holder must never be conflated, so the label is stated rather than
        implied.

        `as_token_endpoint` is the AS's **configured** endpoint, which is what
        it compares `htu` against; the client dials `127.0.0.1` and the two
        differ by construction.
        """
        setup = self.b2_setup(
            access_token=access_token,
            as_public_jwk=as_public_jwk,
            as_port=as_port,
            as_tls_cert_pem=as_tls_cert_pem,
            **kwargs,
        )
        return dict(
            setup,
            dpop_private_jwk=key_material.dpop_private_jwk(self.seed, holder_label),
            as_token_endpoint=as_token_endpoint,
            resource_url=resource_url,
        )

    def run_scenario(
        self,
        scenario_id: str,
        arm: Any,
        *,
        setup: Mapping[str, Any] | None = None,
        ledger_backed: bool = True,
        sut_mode: str = "in-process",
        fault: str = "none",
        artifacts: Mapping[str, Any] | None = None,
        credential_fault: str = "none",
        wrong_audience_token: str | None = None,
        now: int | None = None,
    ) -> ScenarioRun:
        """One scenario, one arm, one invocation; returns the SS F.1 records.

        `sut_mode` selects where the SUT runs, and **`"in-process"` is the
        default on purpose**: ten gates were adjudicated in-process, and a
        default flip would silently re-adjudicate all of them (EXP5 STEP 3).
        `"separate"` spawns `src/sut/sut_process` and runs the agents, the arm
        and the arm's decision there, over the pipe.

        **Both modes drive the SAME stack.** The MCP server, the mediation
        boundary, the ingress recorder, the effector and the ledger writer are
        built once, above, and used by both -- a second stack for the separated
        path would let the two modes diverge silently, which would defeat the
        reason for keeping both.

        `fault` is G-12's injection and reaches the SUT only in `"separate"`
        mode, where the child owns its own self-report.

        `artifacts` are the ADR 0030 artifacts the invocation carries —
        `payload_labels`, `declassification`, `approval_artifact`, as
        `label_artifacts.mint_for_scenario` shapes them. They reach the arm
        through the `InvocationContext` **and** the `ObservedRequest`, because
        Part I's `realized_harm_F4`/`_F5` and `reference_allow` read them from
        the observation and an observation that always said `None` would make
        every F4/F5 cell unscorable (EXP6 STEP 6). Empty for an unlabelled
        scenario, which is every F1 scenario — so no existing caller changes.

        `now` lets a **caller that must build something for this cell before
        the cell runs** supply the run's instant, so the cell is judged at the
        instant its material was built at. The one-clock-per-run invariant
        below is unchanged and is the reason this parameter exists: the
        harness mints the ADR 0030 artifacts *before* calling, and without a
        way to hand the same instant down, the artifacts and the run read the
        wall clock separately and the separation grows with the caller's pass.
        It is **not** a frozen `now` from the corpus -- a scenario still
        supplies the validity DURATION and never an instant -- and the only
        caller passes a value it read immediately beforehand. Defaults to
        `None`, which reads the wall clock exactly as before, so no existing
        caller changes.

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
        # Configuration is validated FIRST, before a ledger, an AS pipe or a
        # child process is opened: an unrecognised mode is a configuration
        # error, and failing closed on it late would leave resources open and
        # report the wrong cause.
        if sut_mode not in ("in-process", "separate"):
            raise RunnerError(f"unknown sut_mode {sut_mode!r} (in-process | separate)")
        visible = self.visible(scenario_id)
        sealed = sealed_truth.load_sealed(scenario_id)
        correlation_id = mint_correlation_id()
        timing = TimingSeams(correlation_id=correlation_id)
        end_to_end_start = time.perf_counter_ns()
        # ONE clock for the run: every credential window (capability, HTC,
        # INV) and the live AS-minted OAuth token are judged against this
        # instant. The scenario supplies the validity DURATION, never a
        # frozen "now" -- see src/sut/agents/supervisor.py.
        #
        # A caller that had to build this cell's material BEFORE the call may
        # supply the instant it built at, which keeps the invariant (still one
        # clock) and closes the seam where the caller's clock and this one
        # drift apart. Absent that, this reads the wall clock as it always did.
        run_epoch = int(time.time()) if now is None else int(now)

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

        # In separated mode the arm's decision arrives over the pipe with the
        # invocation; `decide` below returns it so the SAME boundary emits the
        # SAME `MediationEvent` in both modes. The RECORD stays the
        # instrument's and the DECISION stays the SUT's, which is exactly the
        # split Part I rests on.
        remote_decision: dict[str, Any] = {}

        def decide(tool: str, arguments: dict[str, Any]) -> tuple[bool, str]:
            # Non-bypassable observation point (gate G-6): every dispatch path
            # converges here, so the observed tool/arguments are recorded by
            # the harness whatever the SUT does or claims.
            boundary_observations.append({"tool": tool, "arguments": dict(arguments)})
            if sut_mode == "separate":
                if not remote_decision:
                    # No decision reached us for this dispatch: fail closed.
                    return False, "sut_process_no_decision"
                return bool(remote_decision["decision"]), str(remote_decision["reason_code"])
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
            # ADR 0026's `presentation` span, bracketing EXACTLY
            # `arm.present(...)` and nothing else. For B3 this is where the
            # per-invocation cryptographic work lives -- JCS canonicalization
            # of the arguments, `access_token_hash`, the Ed25519 INV signature
            # -- so a segment that omitted it would leave B3's principal
            # per-invocation cost out of the very test the "lightweight" claim
            # is settled by, in the direction that flatters the hypothesis.
            presentation_start = time.perf_counter_ns()
            try:
                presentation = arm.present(credentials, invocation)
            finally:
                timing.mark("presentation", presentation_start, time.perf_counter_ns())
            # The attacker between the arm and the resource server (EXP7), applied
            # AFTER the span closes so the arm is never charged for the attacker's
            # work -- ADR 0026's segment brackets `arm.present(...)` and nothing else.
            credential_faults.apply_to_presentation(
                credential_fault,
                arm,
                seed=self.seed,
                now=run_epoch,
                wrong_audience_token=wrong_audience_token,
            )
            # Instrument bookkeeping, deliberately OUTSIDE the span (ADR 0026
            # excludes it by name).
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
            artifacts=dict(artifacts or {}),
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
        sut_outcome: dict[str, Any] = {}
        sut_process = None
        if sut_mode == "separate":
            sut_process = SutProcess()
            provisioned = sut_process.call(
                "provision", arm=arm.name, setup=dict(setup or {}), fault=fault
            )
            if "error" in provisioned:
                sut_process.stop()
                raise RunnerError(
                    f"the SUT process refused to provision {arm.name}: "
                    f"{provisioned.get('error')} {provisioned.get('detail', '')}"
                )

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

                if sut_mode == "separate":
                    # The child runs BOTH agents and the A2A hop and emits one
                    # `invoke` event per tool call. This handler is the parent
                    # half: it seals the intent, hands the arm's decision to
                    # the boundary, and calls the tool over the SAME session
                    # the in-process path uses -- so the same boundary, the
                    # same ingress recorder and the same effector run either
                    # way.
                    def on_invoke(message: Mapping[str, Any]) -> dict[str, Any]:
                        remote_decision.clear()
                        remote_decision.update(
                            {
                                "decision": message.get("decision", False),
                                "reason_code": message.get("reason_code", "sut_process_no_reason"),
                                # Recorded but NEVER read by the oracle: this is
                                # the SUT's claim, and G-12 makes it disagree.
                                "self_verdict": message.get("self_verdict"),
                            }
                        )
                        presentations.append(dict(message.get("presentation") or {}))
                        if "intent" not in sealed_intent:
                            sealed_intent["intent"] = self._complete_intent(
                                sealed, correlation_id, message.get("credentials") or {}
                            )
                        try:
                            call_over_session(message["tool"], message["arguments"])
                        except Exception as exc:  # noqa: BLE001 -- a denial, not a crash
                            return {"result": None, "error": type(exc).__name__}
                        return {"result": None}

                    outcome = await asyncio.to_thread(
                        sut_process.run_task,
                        visible=visible,
                        now_epoch=run_epoch,
                        invocation_id=correlation_id,
                        on_invoke=on_invoke,
                        artifacts=dict(artifacts or {}),
                    )
                    sut_outcome.update(outcome if isinstance(outcome, dict) else {})
                else:
                    tool_caller.target = call_over_session
                    await asyncio.to_thread(supervisor.run, visible)

        try:
            asyncio.run(drive())
        finally:
            if sut_process is not None:
                sut_process.stop()
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
            # The artifacts the invocation carried, as the harness OBSERVED
            # them. Sourced from the run's own injected material rather than
            # from anything the arm returned: the SUT is what must verify
            # these, so accepting its copy would be reading its arithmetic.
            payload_labels=list((artifacts or {}).get("payload_labels", ())),
            declassification=(artifacts or {}).get("declassification"),
            approval_artifact=(artifacts or {}).get("approval_artifact"),
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
            # Drained OUTSIDE both spans (ADR 0026): the buffer is bounded and
            # in-memory precisely so nothing here is charged to the arm.
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
