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
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.b_cap import BCapArm  # noqa: E402
from src.sut.baselines.base import HopContext, InvocationContext  # noqa: E402

CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
SCOPE = "mcp.invoke"

SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
STRONG_ARMS = ("B2-exchange-task", "B-cap", "B3")
F1_SUBCASES = ("gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")


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
        self.u_task = self.runner.task_grant()
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
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_public_jwk=self.process.public_jwk,
            as_port=self.process.port,
            as_tls_cert_pem=self.process.tls_cert_pem,
        )
        self.token_config = ma.TokenVerifierConfig(
            issuer=ISSUER,
            resource_server=AUDIENCE,
            as_public_jwk=self.process.public_jwk,
            rar_type=self.b2_setup["rar_type"],
            required_scope=SCOPE,
        )
        self._opened: list[Any] = []

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
        factory = {
            "B2-exchange-task": B2ExchangeTaskArm,
            "B-cap": BCapArm,
            "B3": B3Arm,
        }[arm_name]
        arm = factory()
        self._opened.append(arm)
        return arm, (self.b2_setup if arm_name == "B2-exchange-task" else self.b3_setup)

    # -- the cells ----------------------------------------------------------- #
    def run_cell(self, scenario_id: str, arm_name: str) -> Cell:
        arm, setup = self._arm(arm_name)
        run = self.runner.run_scenario(scenario_id, arm, setup=setup, ledger_backed=False)
        event = run.mediation_events[-1]
        evidence = run.observed.evidence
        note = ""
        if arm_name == "B2-exchange-task":
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
    def exchange_with(self, requested) -> frozenset[tuple[str, str]]:
        """Drive ONE real exchange asking for `requested`, and recompute `AT_1`.

        The arm's own interface, not a bypass: a misprovisioned deployment is
        exactly one that asks for the wrong set at the hop.
        """
        arm, setup = self._arm("B2-exchange-task")
        arm.provision(setup)
        now = int(time.time())
        credentials = arm.delegate(self._hop("gt-benign", requested, now))
        if "access_token" not in credentials:
            raise RuntimeError(f"the AS refused the counterfactual exchange: {credentials}")
        return self._token_authority(credentials["access_token"], now)

    def attenuate_to(self, elements) -> list[frozenset[tuple[str, str]]]:
        """Mint a capability chain narrowed to `elements` and recompute per hop."""
        arm, setup = self._arm("B-cap")
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

    def misprovisioned_b2_decision(self, requested, scenario_id: str) -> tuple[bool, str]:
        """A `B2` whose hop was provisioned at `requested`, asked for a scenario's call."""
        arm, setup = self._arm("B2-exchange-task")
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
