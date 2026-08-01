"""Gate G-13 campaign fixture: one AS, four scenarios, three strong arms.

Everything the gate adjudicates is read from **raw presented evidence** -- the
`ObservedRequest` the harness recorded at the boundary -- rather than from a
value an arm returned. `AT_0` and `kappa_pub` come from the runner's own
injected material, which no system under test computes either.

Nothing here is timed (EXP2 forbidden action 5), and no ledger is used, which
is what makes the gate platform-independent.
"""

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.harness import key_material  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import matched_authority as ma  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut import freshness as fresh  # noqa: E402
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm  # noqa: E402
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.b3_plus import B3PlusArm  # noqa: E402
from src.sut.baselines.b_cap import BCapArm  # noqa: E402
from src.sut.baselines.base import HopContext, InvocationContext  # noqa: E402

CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
SCOPE = "mcp.invoke"

SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
# ALL FIVE arms that receive per-hop `C_i` (SS E.1). The two added on
# 2026-07-31 are exactly the ones whose absence forced G-13 to pass over three
# of five, and whose limbs the earlier row recorded as OPEN.
STRONG_ARMS = (
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
    "B-cap",
    "B3",
    "B3+",
)
# Which plane an arm's per-hop authority-bearing object lives in. Declared
# rather than inferred from the name, so adding an arm is a data change.
PLANE = {
    "B2-exchange-task": "token",
    "B2-exchange-task-DPoP": "token",
    "B-cap": "capability",
    "B3": "capability",
    "B3+": "capability",
}
F1_SUBCASES = ("gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")


def freshness_offset() -> int:
    """An offset that is stale by `Delta` yet inside every credential's validity.

    ADR 0027 fixes `Delta = 60 s`; the capability's own expiry is an hour out
    and the exchanged token's five minutes, so `Delta + 1` is refused at the
    BOUNDARY while leaving both artifacts valid. Read from the SUT-side
    constant so an amendment to row 3 moves this with it.
    """
    return fresh.DELTA_SECONDS + 1


def visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def sealed(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def c_sets(scenario_id: str) -> list[frozenset[tuple[str, str]]]:
    """The SEALED `C_0 .. C_n`. Oracle-side truth; no SUT principal reads it."""
    return [frozenset((a, r) for a, r in c) for c in sealed(scenario_id)["C_sets"]]


@dataclass
class Cell:
    """One (scenario, arm) run and the per-hop authority recomputed from it."""

    scenario_id: str
    arm_name: str
    admitted: bool
    reason_code: str
    per_hop: list[frozenset[tuple[str, str]]]
    hop_objects: int  # how many per-hop authority-bearing objects the arm realized
    note: str = ""


class Campaign:
    """A running AS plus everything the gate needs to recompute independently."""

    def __init__(self) -> None:
        registry_document = reg.load_document()
        self.runner = GoldenThreadRunner()
        # NAMED, since the corpus grew a second authority chain when the F4/F5
        # families joined it (EXP4 STEP 10). G-13 runs the four F1-family
        # scenarios listed above, so it provisions for that family; asking
        # without a name now fails closed rather than picking one.
        self.u_task = self.runner.task_grant(SCENARIOS[0])
        document = golden_thread_as_document(
            corpus={"issuer": ISSUER, "audience": AUDIENCE},
            registry_document=registry_document,
            resolved_keys=key_material.resolve_public(SEED),
            identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
            omega_elements=frozen_config.load_document()["omega"]["elements"],
            task_grant=self.u_task,
        )
        self.process = ASProcess(document, SEED)
        self.gamma_document = frozen_config.load_document()
        self.omega = ma.omega()
        _, self.root_pub = key_material.biscuit_root(SEED)
        self.b3_setup = self.runner.b3_setup(
            access_token=self.process.phase1_tokens["agent-specialist"],
            as_public_jwk=self.process.public_jwk,
        )
        self.b2_setup = self.runner.b2_setup(
            scenario_id=SCENARIOS[0],
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_public_jwk=self.process.public_jwk,
            as_port=self.process.port,
            as_tls_cert_pem=self.process.tls_cert_pem,
        )
        self.b2_dpop_setup = self.runner.b2_dpop_setup(
            scenario_id=SCENARIOS[0],
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_public_jwk=self.process.public_jwk,
            as_port=self.process.port,
            as_tls_cert_pem=self.process.tls_cert_pem,
            as_token_endpoint=document["token_endpoint"],
        )
        self.token_config = ma.TokenVerifierConfig(
            issuer=ISSUER,
            resource_server=AUDIENCE,
            as_public_jwk=self.process.public_jwk,
            rar_type=self.b2_setup["rar_type"],
            required_scope=SCOPE,
        )
        self._opened: list[Any] = []
        self._last_run: Any = None

    # -- lifecycle ---------------------------------------------------------- #
    def stop(self) -> None:
        for arm in self._opened:
            if hasattr(arm, "close"):
                arm.close()
        self.process.stop()

    def __enter__(self) -> "Campaign":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def _arm(self, arm_name: str):
        factory, setup = {
            "B2-exchange-task": (B2ExchangeTaskArm, "b2"),
            "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, "b2_dpop"),
            "B-cap": (BCapArm, "b3"),
            "B3": (B3Arm, "b3"),
            "B3+": (B3PlusArm, "b3"),
        }[arm_name]
        arm = factory()
        self._opened.append(arm)
        return arm, {
            "b2": self.b2_setup,
            "b2_dpop": self.b2_dpop_setup,
            "b3": self.b3_setup,
        }[setup]

    # -- the cells ----------------------------------------------------------- #
    def run_cell(self, scenario_id: str, arm_name: str) -> Cell:
        arm, setup = self._arm(arm_name)
        run = self.runner.run_scenario(scenario_id, arm, setup=setup, ledger_backed=False)
        self._last_run = run
        event = run.mediation_events[-1]
        evidence = run.observed.evidence
        note = ""
        if PLANE[arm_name] == "token":
            if evidence.oauth is None:
                # The AS refused the exchange, so no AT_1 exists. Hop 0 is still
                # the runner's injected base token, whose authority is checkable.
                per_hop = [self._token_authority(setup["access_token"], run.observed.iat)]
                note = "the AS issued no AT_1: nothing was presented at hop 1"
            else:
                per_hop = [
                    self._token_authority(setup["access_token"], run.observed.iat),
                    self._token_authority(evidence.oauth.raw_at.decode("ascii"), run.observed.iat),
                ]
        else:
            per_hop = ma.capability_allowed_per_hop(
                evidence.capability.signed_blocks,
                self.root_pub,
                self.gamma_document,
                now_epoch=run.observed.iat,
                audience=run.observed.audience,
                task_id=visible(scenario_id)["task_id"],
            )
        return Cell(
            scenario_id=scenario_id,
            arm_name=arm_name,
            admitted=event.admitted,
            reason_code=event.reason_code,
            per_hop=per_hop,
            hop_objects=len(per_hop),
            note=note,
        )

    def _token_authority(self, token: str, now_epoch: int) -> frozenset[tuple[str, str]]:
        return ma.token_allowed(token, self.token_config, self.omega, now=now_epoch)

    def matrix(self) -> dict[tuple[str, str], Cell]:
        cells: dict[tuple[str, str], Cell] = {}
        for scenario_id in SCENARIOS:
            for arm_name in STRONG_ARMS:
                cells[(scenario_id, arm_name)] = self.run_cell(scenario_id, arm_name)
        return cells

    # -- would-have-failed worlds -------------------------------------------- #
    def exchange_with(
        self, requested, arm_name: str = "B2-exchange-task"
    ) -> frozenset[tuple[str, str]]:
        """Drive ONE real exchange asking for `requested`, and recompute `AT_1`.

        The arm's own interface, not a bypass: a misprovisioned deployment is
        exactly one that asks for the wrong set at the hop.
        """
        arm, setup = self._arm(arm_name)
        arm.provision(setup)
        now = int(time.time())
        credentials = arm.delegate(self._hop("gt-benign", requested, now))
        if "access_token" not in credentials:
            raise RuntimeError(f"the AS refused the counterfactual exchange: {credentials}")
        return self._token_authority(credentials["access_token"], now)

    def attenuate_to(self, elements, arm_name: str = "B-cap") -> list[frozenset[tuple[str, str]]]:
        """Mint a capability chain narrowed to `elements` and recompute per hop."""
        arm, setup = self._arm(arm_name)
        arm.provision(setup)
        now = int(time.time())
        credentials = arm.delegate(self._hop("gt-benign", elements, now))
        return ma.capability_allowed_per_hop(
            credentials["capability_hops"],
            self.root_pub,
            self.gamma_document,
            now_epoch=now,
            audience=AUDIENCE,
            task_id=visible("gt-benign")["task_id"],
        )

    def misprovisioned_b2_decision(
        self, requested, scenario_id: str, arm_name: str = "B2-exchange-task"
    ) -> tuple[bool, str]:
        """A `B2` whose hop was provisioned at `requested`, asked for a scenario's call."""
        arm, setup = self._arm(arm_name)
        arm.provision(setup)
        now = int(time.time())
        credentials = arm.delegate(self._hop(scenario_id, requested, now))
        spec = visible(scenario_id)
        arm.present(
            credentials,
            InvocationContext(
                tool=spec["delegation_intent"]["tool"],
                arguments=spec["delegation_intent"]["arguments"],
                method=spec["method"],
                task_id=spec["task_id"],
                audience=spec["audience"],
                invocation_id="cid-g13-counterfactual",
                now_epoch=now,
            ),
        )
        return arm.decide(spec["delegation_intent"]["tool"], spec["delegation_intent"]["arguments"])

    def authority_at(
        self, arm_name: str, scenario_id: str, *, offset: int
    ) -> tuple[list[frozenset[tuple[str, str]]], list[frozenset[tuple[str, str]]]]:
        """`Allowed(.)` recomputed at `now` and again at `now + offset`.

        Used to establish that the instrument measures **authority**, a
        property of the artifacts, and never the boundary's **acceptance
        policy**. The SUT boundary applies an INV freshness window (ADR 0027)
        that the SS F.2 verifier deliberately does not; if any part of L1
        routed through something freshness-dependent, the two recomputations
        would differ and the gate would be reporting acceptance as authority.

        The offset is chosen to be stale by `Delta` yet well inside the
        credential's OWN validity -- the capability expires an hour out and the
        token five minutes out -- so what moves is only the boundary's
        willingness to act, not the artifacts.
        """
        cell = self.run_cell(scenario_id, arm_name)
        run = self._last_run
        evidence = run.observed.evidence
        if PLANE[arm_name] == "token":
            if evidence.oauth is None:
                return cell.per_hop, cell.per_hop
            token = evidence.oauth.raw_at.decode("ascii")
            base = self.b2_dpop_setup if "DPoP" in arm_name else self.b2_setup
            later = [
                self._token_authority(base["access_token"], run.observed.iat + offset),
                self._token_authority(token, run.observed.iat + offset),
            ]
            return cell.per_hop, later
        later = ma.capability_allowed_per_hop(
            evidence.capability.signed_blocks,
            self.root_pub,
            self.gamma_document,
            now_epoch=run.observed.iat + offset,
            audience=run.observed.audience,
            task_id=visible(scenario_id)["task_id"],
        )
        return cell.per_hop, later

    def boundary_refuses_at(self, arm_name: str, *, offset: int) -> tuple[bool, str]:
        """Does the SUT boundary refuse the SAME presentation `offset` later?

        Makes L1c's contrast measured rather than claimed: the world it
        describes is one where the boundary refuses and the authority is
        unchanged, so the refusal has to be observed too.
        """
        import dataclasses

        self.run_cell("gt-benign", arm_name)
        arm = self._opened[-1]
        arm._staged = dataclasses.replace(
            arm._staged, now_epoch=self._last_run.observed.iat + offset
        )
        spec = visible("gt-benign")["delegation_intent"]
        return arm.decide(spec["tool"], spec["arguments"])

    def replay_denied_authority(
        self, scenario_id: str = "gt-benign"
    ) -> tuple[tuple[bool, str], list[frozenset[tuple[str, str]]]]:
        """A `B3+` cache DENIAL, and the authority its evidence still realizes.

        The cache is a duplicate detector: it must not change `Allowed(P_i)` at
        any hop. Returns the denial and the per-hop authority recomputed from
        the SAME presented evidence, so the gate can show a cache denial is not
        a granularity mismatch.
        """
        cell = self.run_cell(scenario_id, "B3+")
        arm = self._opened[-1]
        denial = arm.decide(
            visible(scenario_id)["delegation_intent"]["tool"],
            visible(scenario_id)["delegation_intent"]["arguments"],
        )
        return denial, cell.per_hop

    def _hop(self, scenario_id: str, attenuation, now: int) -> HopContext:
        spec = visible(scenario_id)
        return HopContext(
            task_id=spec["task_id"],
            audience=spec["audience"],
            from_agent=spec["supervisor"],
            to_agent=spec["specialist"],
            authority_elements=tuple(map(tuple, spec["authority_elements"])),
            attenuation_elements=tuple(tuple(e) for e in attenuation),
            widening_elements=tuple(map(tuple, spec["widening_elements"])),
            now_epoch=now,
            expiry_epoch=now + int(spec["validity_seconds"]),
        )
