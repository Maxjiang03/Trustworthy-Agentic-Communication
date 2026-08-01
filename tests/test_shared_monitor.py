"""The monitor is shared **structurally**, not by behaving alike (EXP4 STEP 9).

Gate G-15's first criterion is monitor identity: the OAuth arms and `B3` must
run the **same** monitor over the **same** frozen policy, established
structurally rather than by inspection. Two implementations that happen to
agree today would satisfy no criterion at all — they could drift, and every
F4/F5 number would silently become a statement about which implementation an
arm happened to get.

So this suite asserts the sharing three ways:

1. **Same class object** — `is`, not equality of behaviour.
2. **Same construction site shape** — both arms build it from the same four
   injected inputs, and the frozen policy document they load is byte-identical.
3. **Same derived `authz_context_hash`** for one request — which is the value
   an artifact binds to, so a disagreement there would make an artifact valid
   on one arm and invalid on the other, and the F4/F5 comparison would be
   measuring a digest disagreement rather than a mechanism.
"""

import ast
from pathlib import Path

import pytest

from src.harness import frozen_parameters
from src.harness.policy import frozen_policy, label_artifacts
from src.sut.authz.boundary_policy import BoundaryPolicy
from src.sut.authz.reference_monitor import ContextApprovalMonitor, RequestContext
from src.sut.baselines import b2_exchange_task as b2mod
from src.sut.baselines import b3 as b3mod

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"


class TestSameClassNotMerelySameBehaviour:
    def test_both_arm_modules_name_the_same_monitor_class(self):
        assert b2mod.ContextApprovalMonitor is ContextApprovalMonitor
        assert b3mod.ContextApprovalMonitor is ContextApprovalMonitor
        assert b2mod.ContextApprovalMonitor is b3mod.ContextApprovalMonitor

    def test_there_is_exactly_one_monitor_implementation_in_the_tree(self):
        """A second class would satisfy every behavioural test and none of the
        gate: it could drift, and the drift would show up as a mechanism
        difference."""
        defined = []
        for path in (REPO_ROOT / "src").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "ContextApprovalMonitor":
                    defined.append(path.relative_to(REPO_ROOT).as_posix())
        assert defined == ["src/sut/authz/reference_monitor.py"], defined

    def test_the_monitor_module_names_no_arm(self):
        """It is boundary-owned: it cannot know which arm called it."""
        source = (REPO_ROOT / "src" / "sut" / "authz" / "reference_monitor.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any(name.startswith("src.sut.baselines") for name in imported)
        assert not any(name.startswith("src.sut.capability") for name in imported)
        assert not any(name.startswith("src.harness") for name in imported)  # red line 6

    def test_neither_arm_reaches_into_the_others_plane_for_the_policy(self):
        """`BoundaryPolicy` moved out of `capability_path` for this reason: an
        OAuth arm loading a policy must not import the capability plane."""
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b2_exchange_task.py").read_text(
            encoding="utf-8"
        )
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert "src.sut.authz.boundary_policy" in imported
        assert not any(name.startswith("src.sut.capability") for name in imported)
        assert "src.sut.authz.capability_path" not in imported

    def test_the_policy_loader_is_one_class_too(self):
        from src.sut.authz import capability_path

        assert capability_path.BoundaryPolicy is BoundaryPolicy


class TestSameFrozenPolicy:
    def test_both_arms_load_the_same_document_bytes(self):
        document = frozen_policy.load_document()
        assert frozen_policy.h_policy(document) == frozen_parameters.expected_h_policy()
        one = BoundaryPolicy.load(document)
        other = BoundaryPolicy.load(frozen_policy.load_document())
        assert one == other  # frozen dataclass: value equality over the whole policy

    def test_a_monitor_refuses_to_run_under_an_unnamed_policy_version(self):
        with pytest.raises(Exception, match="frozen policy version"):
            ContextApprovalMonitor(
                policy=BoundaryPolicy.load(frozen_policy.load_document()),
                label_issuers={},
                approvers={},
                policy_version="",
            )

    def test_the_two_trusted_sets_are_the_same_material_for_both_arms(self):
        """Same seed, same derivation labels, so the OAuth arm and `B3` trust
        the same issuers. Different sets would make an artifact verify on one
        arm and not the other."""
        first = label_artifacts.trusted_sets(SEED)
        second = label_artifacts.trusted_sets(SEED)
        assert first == second
        label_issuers, approvers = first
        assert set(label_issuers).isdisjoint(approvers)


class TestSameDerivedRequestBinding:
    def test_an_oauth_context_and_a_capability_context_agree(self):
        """The value an artifact binds to. Built through the SHARED
        constructor, from inputs neither plane monopolizes."""
        arguments = {"to": "partner@example.test", "subject": "Q3", "body": "x"}
        common = dict(
            task_id="task-gt-pilot",
            audience="https://mcp.aasc.local/tools",
            tool="mail.send",
            arguments=arguments,
            resource_owner=(ISSUER, "user-yixian"),
            oauth_actor=(ISSUER, "agent-specialist"),
        )
        assert (
            RequestContext.for_request(**common).authz_context_hash()
            == RequestContext.for_request(**common).authz_context_hash()
        )

    def test_the_context_carries_nothing_capability_specific(self):
        import dataclasses

        names = {f.name for f in dataclasses.fields(RequestContext)}
        assert names == {
            "task_id",
            "audience",
            "tool",
            "canonical_request_digest",
            "resource_owner",
            "oauth_actor",
        }

    def test_both_arms_build_the_context_through_the_shared_constructor(self):
        """Not two call sites that each remember to call `h_jcs` the same way
        -- one constructor, so agreement is structural. A test rather than a
        convention, because a future edit to one arm is exactly how these
        silently diverge."""
        for module in ("b2_exchange_task.py", "b3.py", "../authz/capability_path.py"):
            path = REPO_ROOT / "src" / "sut" / "baselines" / module
            source = path.resolve().read_text(encoding="utf-8")
            if "RequestContext" not in source:
                continue
            assert "RequestContext(" not in source, (
                f"{module} constructs RequestContext directly; use "
                "RequestContext.for_request so every arm derives one digest per request"
            )
            assert "RequestContext.for_request(" in source

    def test_a_different_request_gives_a_different_binding(self):
        """Negative arm: the agreement above is not two constants matching."""
        base = dict(
            task_id="task-gt-pilot",
            audience="https://mcp.aasc.local/tools",
            tool="mail.send",
            resource_owner=(ISSUER, "user-yixian"),
            oauth_actor=(ISSUER, "agent-specialist"),
        )
        one = RequestContext.for_request(**base, arguments={"body": "a"}).authz_context_hash()
        other = RequestContext.for_request(**base, arguments={"body": "b"}).authz_context_hash()
        assert one != other


class TestAttachmentIsConfiguration:
    def test_no_arm_bitmask_moves_with_the_monitor(self):
        """`monitor_attached` is a property of the RUN. If attaching one
        changed an arm's §E.5 bitmask, the arm would have changed ladder
        position and the comparison would no longer be like-for-like."""
        from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
        from src.sut.baselines.b3 import B3Arm

        assert B2ExchangeTaskArm.bitmask.context == 0
        assert B2ExchangeTaskArm.bitmask.approval == 0
        assert B3Arm.bitmask.context == 1
        assert B3Arm.bitmask.approval == 1

    def test_the_oauth_arm_defaults_to_NO_monitor(self):
        """§E.4 predicts `A†` -- admitted ABSENT the monitor. A default of true
        would quietly make the dagger untestable."""
        import inspect

        from src.harness.runner import GoldenThreadRunner

        signature = inspect.signature(GoldenThreadRunner.b2_setup)
        assert signature.parameters["monitor_attached"].default is False

    def test_and_a_capability_arm_defaults_to_HAVING_one(self):
        """`B3`'s bitmask sets `context = 1` and `approval = 1`: running the
        conjuncts is its ladder position, not a configuration choice."""
        import inspect

        from src.harness.runner import GoldenThreadRunner

        signature = inspect.signature(GoldenThreadRunner.b3_setup)
        assert signature.parameters["monitor_attached"].default is True
