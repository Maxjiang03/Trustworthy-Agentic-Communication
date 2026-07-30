"""Regression suite for the deterministic agents and the B0 arm (EXP1 STEPs 6-7).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Determinism is the load-bearing property (same spec + same
injected state -> byte-identical envelopes); its honest scope is stated in
the corpus README: harness-minted correlation ids and Biscuit mints are
non-reproducible BY DESIGN (SS F.1; ADR 0007), so the claim is about what the
agents themselves construct.
"""

import json
from pathlib import Path

from src.sut.agents.specialist import Specialist
from src.sut.agents.supervisor import Supervisor
from src.sut.baselines.b0 import REASON_FORWARDED, B0Arm
from src.sut.baselines.base import ArmBitmask, InvocationContext
from src.sut.protocol.a2a import InProcessDelegationTransport

REPO_ROOT = Path(__file__).resolve().parents[1]
VISIBLE = json.loads(
    (
        REPO_ROOT / "fixtures" / "pilot" / "golden_thread" / "sut_visible" / "gt-benign.json"
    ).read_text(encoding="utf-8")
)


class CapturingTransport:
    def __init__(self):
        self.envelopes = []

    def deliver(self, envelope):
        self.envelopes.append(envelope)
        return "delivered"


class TestSupervisorDeterminism:
    def test_same_spec_same_arm_byte_identical_envelopes(self):
        captured = []
        for _ in range(2):
            transport = CapturingTransport()
            Supervisor(arm=B0Arm(), transport=transport).run(VISIBLE)
            captured.append(transport.envelopes[0].canonical_bytes())
        assert captured[0] == captured[1]

    def test_a_different_scenario_changes_the_bytes(self):
        other = json.loads(
            (
                REPO_ROOT
                / "fixtures"
                / "pilot"
                / "golden_thread"
                / "sut_visible"
                / "gt-f1-root.json"
            ).read_text(encoding="utf-8")
        )
        first, second = CapturingTransport(), CapturingTransport()
        Supervisor(arm=B0Arm(), transport=first).run(VISIBLE)
        Supervisor(arm=B0Arm(), transport=second).run(other)
        assert first.envelopes[0].canonical_bytes() != second.envelopes[0].canonical_bytes()

    def test_the_arm_decides_what_is_carried(self):
        """The agent forwards exactly what arm.delegate returns."""

        class MarkedArm(B0Arm):
            def delegate(self, hop):
                return {"marker": "arm-decided"}

        transport = CapturingTransport()
        Supervisor(arm=MarkedArm(), transport=transport).run(VISIBLE)
        assert transport.envelopes[0].credentials == {"marker": "arm-decided"}
        # Negative arm: B0's own envelope carries nothing.
        empty = CapturingTransport()
        Supervisor(arm=B0Arm(), transport=empty).run(VISIBLE)
        assert empty.envelopes[0].credentials == {}


class TestSpecialist:
    def _specialist(self, arm, calls, presented):
        class RecordingArm(type(arm)):
            def present(self, credentials, invocation):
                presented.append((credentials, invocation))

        return Specialist(
            arm=RecordingArm(),
            tool_caller=lambda tool, args: calls.append((tool, args)) or "ok",
            method=VISIBLE["method"],
            audience=VISIBLE["audience"],
            now_epoch=VISIBLE["now_epoch"],
            invocation_id_provider=lambda: "cid-under-test",
        )

    def test_presents_then_calls_the_scripted_tool(self):
        calls, presented = [], []
        specialist = self._specialist(B0Arm(), calls, presented)
        transport = InProcessDelegationTransport()
        transport.register(VISIBLE["specialist"], specialist.receive)
        Supervisor(arm=B0Arm(), transport=transport).run(VISIBLE)
        assert calls == [
            (
                VISIBLE["delegation_intent"]["tool"],
                dict(VISIBLE["delegation_intent"]["arguments"]),
            )
        ]
        assert len(presented) == 1
        _, invocation = presented[0]
        assert isinstance(invocation, InvocationContext)
        assert invocation.invocation_id == "cid-under-test"  # harness-minted, SUT-received
        assert invocation.tool == VISIBLE["delegation_intent"]["tool"]

    def test_specialist_does_not_compute_R(self):
        """Structural: the agents never import the required-authority module.

        R is the server's to compute (SS A.5); an agent computing it would be
        an agent-reported authority field.
        """
        import ast

        for module in ("supervisor.py", "specialist.py"):
            source = (REPO_ROOT / "src" / "sut" / "agents" / module).read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    module_name = getattr(node, "module", "") or ""
                    assert "required_authority" not in module_name, f"{module} imports R"
                    assert all("required_authority" not in n for n in names)


class TestB0:
    def test_bitmask_every_bit_zero(self):
        assert B0Arm().bitmask == ArmBitmask(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        assert B0Arm().bitmask.as_bits() == (0,) * 10

    def test_decide_admits_unconditionally(self):
        arm = B0Arm()
        for tool, args in [
            ("mail.send", {"to": "attacker@example.test", "subject": "s", "body": "b"}),
            ("calendar.read", {"resource": "calendar/work"}),
            ("notes.delete", {"resource": "notes/project"}),
        ]:
            admitted, reason = arm.decide(tool, args)
            assert admitted is True
            assert reason == REASON_FORWARDED

    def test_b0_holds_no_credential_state(self):
        # Honestly incapable: nothing provisioned, nothing delegated, nothing
        # staged -- and no attribute appears after the full lifecycle.
        arm = B0Arm()
        before = set(vars(arm))
        arm.provision({"anything": "ignored"})
        credentials = arm.delegate(None)
        arm.present({}, None)
        assert credentials == {}
        assert set(vars(arm)) == before
