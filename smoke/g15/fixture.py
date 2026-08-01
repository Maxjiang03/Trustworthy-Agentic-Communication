"""Gate G-15 campaign fixture: one AS, four F4/F5 fixtures, nine arms, two configurations.

Everything the gate needs to recompute independently. The arms are driven
through their own interfaces — provision, delegate, present, decide — so no
outcome here is read off anything but a decision the arm actually made.

Nothing is timed and nothing sleeps. No effect ledger is opened, which is what
makes this gate platform-independent (confirmed by running it in CI, not
assumed).
"""

import json
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

from src.harness import frozen_parameters, key_material  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.matrix_grouping import ARMS, Cell  # noqa: E402
from src.harness.policy import frozen_policy, label_artifacts  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.authz.reference_monitor import RequestContext  # noqa: E402
from src.sut.baselines.b0 import B0Arm  # noqa: E402
from src.sut.baselines.b1 import B1Arm  # noqa: E402
from src.sut.baselines.b2_broad import (  # noqa: E402
    B2BroadNoExchangeArm,
    B2ExchangeBroadArm,
)
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm  # noqa: E402
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.b3_plus import B3PlusArm  # noqa: E402
from src.sut.baselines.b_cap import BCapArm  # noqa: E402
from src.sut.baselines.base import HopContext, InvocationContext  # noqa: E402

SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
PROVISIONING_SCENARIO = "gt-f4-sensitive-egress"

FIXTURES = (
    ("gt-f4-sensitive-egress", "F4", False),
    ("gt-f4-declassified", "F4", True),
    ("gt-f5-unapproved-high-risk", "F5", False),
    ("gt-f5-approved", "F5", True),
)
OAUTH_ARMS = (
    "B2-broad-noexchange",
    "B2-exchange-broad",
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
)

CLASSES = {
    "B0": B0Arm,
    "B1": B1Arm,
    "B2-broad-noexchange": B2BroadNoExchangeArm,
    "B2-exchange-broad": B2ExchangeBroadArm,
    "B2-exchange-task": B2ExchangeTaskArm,
    "B2-exchange-task-DPoP": B2ExchangeTaskDPoPArm,
    "B-cap": BCapArm,
    "B3": B3Arm,
    "B3+": B3PlusArm,
}


def visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def frozen_policy_digest() -> str:
    return frozen_policy.h_policy(frozen_policy.load_document())


def expected_policy_digest() -> str:
    return frozen_parameters.expected_h_policy()


def oauth_and_capability_bind_identically() -> bool:
    """One request, both planes, one `authz_context_hash`.

    Built through the shared `RequestContext.for_request` -- the constructor
    both arms call -- from inputs neither plane monopolizes. A disagreement here
    would make an artifact bind on one arm and not the other, and the F4/F5
    comparison would be measuring a digest disagreement.
    """
    common = dict(
        task_id="task-gt-pilot",
        audience=AUDIENCE,
        tool="mail.send",
        arguments={"to": "partner@example.test", "subject": "Q3", "body": "x"},
        resource_owner=(ISSUER, reg.load_document()["resource_owners"][0]),
        oauth_actor=(ISSUER, "agent-specialist"),
    )
    one = RequestContext.for_request(**common).authz_context_hash()
    other = RequestContext.for_request(**common).authz_context_hash()
    # ...and a DIFFERENT request must not collide, or the equality above would
    # be two constants matching rather than a binding.
    moved = RequestContext.for_request(
        **dict(common, arguments={"to": "partner@example.test", "subject": "Q3", "body": "y"})
    ).authz_context_hash()
    return one == other != moved


def forged_artifact_is_refused() -> bool:
    """W4: an artifact signed by a key the monitor was never told to trust.

    If acceptance were a hole, the F4 control and the F4 attack would produce
    the same cell and the family would measure nothing.
    """
    from src.sut.authz.boundary_policy import BoundaryPolicy
    from src.sut.authz.reference_monitor import ContextApprovalMonitor

    label_issuers, approvers = label_artifacts.trusted_sets(SEED)
    monitor = ContextApprovalMonitor(
        policy=BoundaryPolicy.load(frozen_policy.load_document()),
        label_issuers=label_issuers,
        approvers=approvers,
        policy_version=expected_policy_digest(),
    )
    now = 1_800_000_000
    context = RequestContext.for_request(
        task_id="t",
        audience=AUDIENCE,
        tool="notes.delete",
        arguments={"resource": "notes/project"},
        resource_owner=(ISSUER, "user-yixian"),
        oauth_actor=(ISSUER, "agent-specialist"),
    )
    genuine = label_artifacts.issue_approval(
        SEED,
        authz_context_hash=context.authz_context_hash(),
        iat=now,
        nbf=now - 5,
        exp=now + 300,
        jti="g15-genuine",
    )
    forged = label_artifacts.issue_approval(
        bytes.fromhex("02" * 32),  # a real key nobody trusts
        authz_context_hash=context.authz_context_hash(),
        iat=now,
        nbf=now - 5,
        exp=now + 300,
        jti="g15-forged",
    )
    accepted = monitor.approval_decision(
        context, approval=genuine, now=now, high_risk=True
    ).admitted
    refused = monitor.approval_decision(context, approval=forged, now=now, high_risk=True).refused
    # Both halves: the genuine one is accepted (so the refusal is not blanket)
    # and the forged one is refused (so acceptance is not a hole).
    return accepted and refused


class Campaign:
    """One AS; every arm run over every F4/F5 fixture under both configurations."""

    def __enter__(self) -> "Campaign":
        registry_document = reg.load_document()
        self.runner = GoldenThreadRunner()
        self.document = golden_thread_as_document(
            corpus={"issuer": ISSUER, "audience": AUDIENCE},
            registry_document=registry_document,
            resolved_keys=key_material.resolve_public(SEED),
            identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
            omega_elements=frozen_config.load_document()["omega"]["elements"],
            # NAMED: the corpus carries two authority chains, and F4/F5 run on
            # the one where their actions are inside `C_1` -- otherwise
            # containment would refuse before the policy conjuncts ran.
            task_grant=self.runner.task_grant(PROVISIONING_SCENARIO),
        )
        self.process = ASProcess(self.document, SEED)
        self.process.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        self.process.__exit__(*exc)

    def _factories(self, *, monitor_attached: bool) -> dict:
        common = {
            "as_public_jwk": self.process.public_jwk,
            "as_port": self.process.port,
            "as_tls_cert_pem": self.process.tls_cert_pem,
            "scenario_id": PROVISIONING_SCENARIO,
            "monitor_attached": monitor_attached,
        }
        b3_setup = self.runner.b3_setup(
            access_token=self.process.phase1_tokens["agent-specialist"],
            as_public_jwk=self.process.public_jwk,
            monitor_attached=monitor_attached,
        )
        broad = self.runner.b2_setup(
            access_token=self.process.phase1_tokens["agent-supervisor:broad"],
            ladder_grant="broad",
            **common,
        )
        task = self.runner.b2_setup(
            access_token=self.process.phase1_tokens["agent-supervisor"],
            ladder_grant="task",
            **common,
        )
        dpop = self.runner.b2_dpop_setup(
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_token_endpoint=self.document["token_endpoint"],
            **common,
        )
        return {
            "B0": {},
            "B1": self.runner.b1_setup(),
            "B2-broad-noexchange": broad,
            "B2-exchange-broad": broad,
            "B2-exchange-task": task,
            "B2-exchange-task-DPoP": dpop,
            "B-cap": b3_setup,
            "B3": b3_setup,
            "B3+": b3_setup,
        }

    def _cell(self, setups, arm_name, scenario_id, family, monitor_attached) -> Cell:
        doc = visible(scenario_id)
        arm = CLASSES[arm_name]()
        arm.provision(dict(setups[arm_name]))
        now = int(time.time())
        credentials = arm.delegate(
            HopContext(
                task_id=doc["task_id"],
                audience=doc["audience"],
                from_agent=doc["supervisor"],
                to_agent=doc["specialist"],
                authority_elements=tuple(map(tuple, doc["authority_elements"])),
                attenuation_elements=tuple(map(tuple, doc["attenuation_elements"])),
                widening_elements=tuple(map(tuple, doc["widening_elements"])),
                now_epoch=now,
                expiry_epoch=now + int(doc["validity_seconds"]),
            )
        )
        artifacts = label_artifacts.mint_for_scenario(
            SEED,
            doc,
            now=now,
            resource_owner=(ISSUER, reg.load_document()["resource_owners"][0]),
            oauth_actor=(ISSUER, "agent-specialist"),
            policy_version=expected_policy_digest(),
        )
        intent = doc["delegation_intent"]
        arm.present(
            credentials,
            InvocationContext(
                tool=intent["tool"],
                arguments=intent["arguments"],
                method=doc["method"],
                task_id=doc["task_id"],
                audience=doc["audience"],
                invocation_id=f"g15-{scenario_id}-{arm_name}",
                now_epoch=now,
                **artifacts,
            ),
        )
        admitted, reason_code = arm.decide(intent["tool"], intent["arguments"])
        if hasattr(arm, "close"):
            arm.close()
        return Cell(
            family=family,
            subcase=scenario_id,
            arm=arm_name,
            admitted=admitted,
            reason_code=reason_code,
            monitor_attached=monitor_attached,
        )

    def f45_matrix(self) -> dict:
        """`(scenario_id, arm, monitor_attached) -> Cell`, every cell run once."""
        cells: dict[tuple[str, str, bool], Cell] = {}
        for monitor_attached in (False, True):
            setups = self._factories(monitor_attached=monitor_attached)
            for scenario_id, family, _control in FIXTURES:
                for arm_name in ARMS:
                    cells[(scenario_id, arm_name, monitor_attached)] = self._cell(
                        setups, arm_name, scenario_id, family, monitor_attached
                    )
        return cells
