"""The golden thread under B3, and the would-have-failed worlds (EXP1 STEP 13).

Two things are proven here, and the second is the one that has caught a real
error every round:

1. **B3 on the three pilot scenarios.** `gt-benign` is admitted; `gt-f1-root`
   and `gt-f1-terminal` are blocked at `R subset-of C_n` with that reason
   code and **no EffectEvent in the ledger** -- the LEDGER, not the agent, is
   what shows nothing executed.
2. **The wrong-outcome world is observable.** For each block, disabling the
   containment conjunct shows the call *would* be admitted -- so the block is
   attributable to containment and not masked by an earlier conjunct (the
   G-11 masking lesson). The same construction runs for `htc_chain_ok` and
   `invocation_binding_ok` with a wrong-holder INV and a tool/argument
   substitution.

Windows-only where the effect ledger is involved (ADR 0014); the
decision-path-only tests run everywhere.
"""

import dataclasses
import json
import shutil
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.authz.capability_path import CONJUNCT_ORDER, REASON_CODES
from src.sut.baselines.b3 import B3Arm
from src.sut.capability import signer

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


def _identity_jwks(registry_document: dict) -> dict[str, dict[str, str]]:
    return {
        principal: {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key_material.public_wire(
                key_material.holder_private(SEED, f"identity-{principal}")
            ),
        }
        for principal in registry_document["principals"]
    }


@pytest.fixture(scope="module")
def running_as():
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": "https://as.aasc.local", "audience": "https://mcp.aasc.local/tools"},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=_identity_jwks(registry_document),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def ledger_dir():
    directory = REPO_ROOT / "tests" / "_ledger_tmp_gt_b3"
    directory.mkdir(parents=True, exist_ok=True)
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _setup(runner: GoldenThreadRunner, running_as) -> dict:
    return runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )


def _forge_inv(credentials, setup, visible, *, tool, arguments) -> bytes:
    """An INV signed by a REGISTERED but wrong holder (the worker).

    Registered on purpose: the registry check then passes, so only the holder
    limb can catch it -- the G-11 construction that isolates the intended
    condition instead of letting an earlier check mask it.
    """
    wrong = Ed25519PrivateKey.from_private_bytes(setup["holder_privates"]["holder-worker"])
    terminal = signer.MintedHop(
        bytes(credentials["capability_hops"][-1]),
        tuple(bytes(b) for b in credentials["block_ids"][-1]),
    )
    now = int(time.time())
    return signer.issue_inv(
        terminal,
        holder_private=wrong,
        holder_kid="kid-holder-worker",
        raw_at=credentials["access_token"],
        raw_arguments=arguments,
        task_id=visible["task_id"],
        audience=visible["audience"],
        method=visible["method"],
        tool=tool,
        label_assertions_digest="00" * 32,
        invocation_id="cid-counterfactual",
        iat=now,
        nbf=now,
        exp=now + 300,
    )


@WIN32_ONLY
class TestB3EndToEnd:
    @pytest.fixture(scope="class")
    @staticmethod
    def runs(ledger_dir, running_as):
        runner = GoldenThreadRunner(ledger_dir=ledger_dir)
        setup = _setup(runner, running_as)
        return {
            scenario_id: runner.run_scenario(scenario_id, B3Arm(), setup=setup)
            for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal")
        }

    def test_benign_is_admitted_and_the_effect_is_recorded(self, runs):
        run = runs["gt-benign"]
        assert run.mediation_events[-1].admitted is True
        assert run.mediation_events[-1].reason_code == "b3_admitted"
        effects = run.effects()
        assert len(effects) == 1
        assert (effects[0]["action"], effects[0]["resource"]) == ("notes.write", "notes/project")

    def test_f1_root_blocked_at_containment_with_no_effect(self, runs):
        run = runs["gt-f1-root"]
        event = run.mediation_events[-1]
        assert event.admitted is False
        assert event.reason_code == REASON_CODES["containment_ok"]
        # The ledger -- not the agent -- shows nothing executed.
        assert run.effects() == []
        assert run.ledger_entries() == []

    def test_f1_terminal_blocked_at_containment_with_no_effect(self, runs):
        run = runs["gt-f1-terminal"]
        event = run.mediation_events[-1]
        assert event.admitted is False
        assert event.reason_code == REASON_CODES["containment_ok"]
        assert run.effects() == []


class TestB3Everywhere:
    """B3's non-effect outcomes, on every platform (EXP2 STEP 5).

    Admission, the reason code, the conjunct trace and the timing seams are
    not effect claims and never touch the ledger, so gating them behind
    Windows left CI blind to whether B3 still decided correctly at all.
    """

    @pytest.fixture(scope="module")
    @staticmethod
    def runs(running_as):
        runner = GoldenThreadRunner()
        setup = _setup(runner, running_as)
        return {
            scenario_id: runner.run_scenario(scenario_id, B3Arm(), setup=setup, ledger_backed=False)
            for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal")
        }

    def test_benign_is_admitted(self, runs):
        event = runs["gt-benign"].mediation_events[-1]
        assert event.admitted is True
        assert event.reason_code == "b3_admitted"

    @pytest.mark.parametrize("scenario_id", ["gt-f1-root", "gt-f1-terminal"])
    def test_f1_blocks_at_containment(self, runs, scenario_id):
        event = runs[scenario_id].mediation_events[-1]
        assert event.admitted is False
        assert event.reason_code == REASON_CODES["containment_ok"]

    def test_every_earlier_conjunct_passed_before_the_block(self, runs):
        """The block is attributable: the audit log shows containment was
        reached, so no earlier conjunct masked it."""
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            entry = runs[scenario_id].audit_log[-1]
            assert entry["arm"] == "B3"
            assert entry["reason_code"] == REASON_CODES["containment_ok"]
            assert entry["evaluated"] == [
                "crypto_chain_ok",
                "authorizer_policy_ok",
                "htc_chain_ok",
                "holder_proof_ok",
                "invocation_binding_ok",
            ]

    def test_timing_seams_exist_and_are_unmeasured(self, runs):
        # EXP1 STEP 14: the seams exist and are correlated; this suite asserts
        # their PRESENCE and never a duration (forbidden action 4).
        run = runs["gt-benign"]
        assert run.timing is not None
        assert run.timing.correlation_id == run.correlation_id
        assert set(run.timing.recorded()) == {
            "setup",
            "delegation",
            "boundary_verification",
            "end_to_end",
        }


@pytest.fixture(scope="module")
def staged(running_as):
    """Provisioning material plus the benign scenario, no ledger needed.

    Module-scoped because the decision-path suites below all need it; these
    tests exercise the boundary alone, so no ledger directory is involved and
    they run on every platform.
    """
    from src.harness import as_process
    from src.harness.policy import frozen_policy

    setup = {
        "gamma_document": frozen_config.load_document(),
        "registry_document": reg.load_document(),
        "resolved_keys": key_material.resolve_public(SEED),
        "kappa_private": key_material.derive_raw(SEED, "kappa"),
        "holder_privates": {
            label: key_material.derive_raw(SEED, label)
            for label in ("holder-supervisor", "holder-specialist", "holder-worker")
        },
        "access_token": running_as.phase1_tokens["agent-specialist"],
        "as_public_jwk": running_as.public_jwk,
        "issuer": "https://as.aasc.local",
        "resource_server": "https://mcp.aasc.local/tools",
        "rar_type": as_process.RAR_TYPE,
        "policy_document": frozen_policy.load_document(),
        "run_mode": "pilot",
    }
    visible = json.loads(
        (
            REPO_ROOT / "fixtures" / "pilot" / "golden_thread" / "sut_visible" / "gt-benign.json"
        ).read_text(encoding="utf-8")
    )
    return setup, visible


class TestWouldHaveFailedWorlds:
    """Construct the wrong-outcome world and confirm it is observable."""

    def _arm_with_presentation(self, setup, visible, *, tool, arguments, ablates=None):
        from src.sut.baselines.base import ArmIdentity, HopContext, InvocationContext

        run_epoch = int(time.time())  # one clock for the whole construction
        if ablates is None:
            arm = B3Arm()  # B3 PROPER: the guard refuses any disabled conjunct
        else:
            # The would-have-failed world is a DECLARED SS E.6 ablation variant,
            # not B3 with a field poked (EXP2 STEP 6): it names what it ablates,
            # and its name rides in every audit record it emits.
            arm = B3Arm(ArmIdentity(name=f"B3-minus-{ablates}", is_ablation=True, ablates=ablates))
            setup = dict(setup, disabled=[ablates])
        arm.provision(setup)
        hop = HopContext(
            task_id=visible["task_id"],
            audience=visible["audience"],
            from_agent=visible["supervisor"],
            to_agent=visible["specialist"],
            authority_elements=tuple(map(tuple, visible["authority_elements"])),
            attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
            now_epoch=run_epoch,
            expiry_epoch=run_epoch + int(visible["validity_seconds"]),
        )
        credentials = arm.delegate(hop)
        arm.present(
            credentials,
            InvocationContext(
                tool=tool,
                arguments=arguments,
                method=visible["method"],
                task_id=visible["task_id"],
                audience=visible["audience"],
                invocation_id="cid-counterfactual",
                now_epoch=run_epoch,
            ),
        )
        return arm, credentials

    # -- containment: the F1 blocks are attributable, not masked ------------ #
    # The counterfactual outcome is EXPECTED PER CASE, never "either is fine":
    # a test that accepts both outcomes cannot fail for the case it was written
    # for. `calendar.read` is non-egress and not high-risk, so removing
    # containment admits it outright. `mail.send` is both an unlabelled egress
    # (row 4) and a frozen high-risk action (row 10), so three independent
    # conjuncts refuse it and removing containment moves the block to
    # `context_policy_ok` -- strictly later than containment, which is what
    # makes the original block attributable rather than masked.
    @pytest.mark.parametrize(
        "tool,arguments,expected_without_containment",
        [
            (
                "mail.send",
                {"to": "partner@example.test", "subject": "s", "body": "b"},
                "context_policy_ok",
            ),
            ("calendar.read", {"resource": "calendar/work"}, None),  # None means ADMITTED
        ],
    )
    def test_containment_block_is_attributable(
        self, staged, tool, arguments, expected_without_containment
    ):
        setup, visible = staged
        arm, _ = self._arm_with_presentation(setup, visible, tool=tool, arguments=arguments)
        admitted, reason = arm.decide(tool, arguments)
        assert admitted is False
        assert reason == REASON_CODES["containment_ok"]

        ablated, _ = self._arm_with_presentation(
            setup, visible, tool=tool, arguments=arguments, ablates="containment_ok"
        )
        ablated_admitted, ablated_reason = ablated.decide(tool, arguments)

        if expected_without_containment is None:
            assert ablated_admitted is True, (
                f"{tool} must be ADMITTED once containment is removed; it was blocked at "
                f"{ablated_reason!r}, so something else was refusing it too"
            )
            return

        assert ablated_admitted is False
        assert ablated_reason == REASON_CODES[expected_without_containment]
        assert CONJUNCT_ORDER.index(expected_without_containment) > CONJUNCT_ORDER.index(
            "containment_ok"
        ), "the expected fallback conjunct must be evaluated strictly AFTER containment"

    # -- htc_chain_ok: a wrong-holder INV ----------------------------------- #
    def test_wrong_holder_inv_blocks_and_is_attributable(self, staged):
        setup, visible = staged
        tool, arguments = "notes.write", {"resource": "notes/project", "content": "x"}
        arm, credentials = self._arm_with_presentation(
            setup, visible, tool=tool, arguments=arguments
        )
        assert arm.decide(tool, arguments) == (True, "b3_admitted")  # baseline: admitted

        # Re-sign the INV with a REGISTERED but wrong holder (the worker), so
        # the registry check passes and only the holder limb can catch it --
        # the G-11 construction that isolates the intended condition.
        forged = _forge_inv(credentials, setup, visible, tool=tool, arguments=arguments)
        arm._staged = dataclasses.replace(arm._staged, invocation_assertion=forged)
        admitted, reason = arm.decide(tool, arguments)
        assert admitted is False
        assert reason == REASON_CODES["holder_proof_ok"]

        # Would-have-failed world: a DECLARED -holder ablation admits the same
        # forged INV -- the block was that limb's, not another's.
        ablated, ablated_credentials = self._arm_with_presentation(
            setup, visible, tool=tool, arguments=arguments, ablates="holder_proof_ok"
        )
        ablated._staged = dataclasses.replace(
            ablated._staged,
            invocation_assertion=_forge_inv(
                ablated_credentials, setup, visible, tool=tool, arguments=arguments
            ),
        )
        assert ablated.decide(tool, arguments) == (True, "b3_admitted")

    # -- invocation_binding_ok: tool and argument substitution -------------- #
    def test_tool_substitution_blocks_at_invocation_binding(self, staged):
        setup, visible = staged
        signed_tool = "notes.write"
        arguments = {"resource": "notes/project", "content": "x"}
        arm, _ = self._arm_with_presentation(setup, visible, tool=signed_tool, arguments=arguments)
        # Substitute the TOOL after signing, keeping arguments in-scope for the
        # substituted tool so containment cannot be what blocks.
        substituted_args = {"resource": "notes/project"}
        admitted, reason = arm.decide("notes.read", substituted_args)
        assert admitted is False
        assert reason == REASON_CODES["invocation_binding_ok"]

        arm, _ = self._arm_with_presentation(
            setup, visible, tool=signed_tool, arguments=arguments, ablates="invocation_binding_ok"
        )
        assert arm.decide("notes.read", substituted_args) == (True, "b3_admitted")

    def test_argument_substitution_blocks_at_invocation_binding(self, staged):
        setup, visible = staged
        tool = "notes.write"
        arm, _ = self._arm_with_presentation(
            setup, visible, tool=tool, arguments={"resource": "notes/project", "content": "x"}
        )
        tampered = {"resource": "notes/project", "content": "TAMPERED"}
        admitted, reason = arm.decide(tool, tampered)
        assert admitted is False
        assert reason == REASON_CODES["invocation_binding_ok"]

        ablated, _ = self._arm_with_presentation(
            setup,
            visible,
            tool=tool,
            arguments={"resource": "notes/project", "content": "x"},
            ablates="invocation_binding_ok",
        )
        assert ablated.decide(tool, tampered) == (True, "b3_admitted")


class TestGammaCheckDiscriminator:
    """The authorizer/containment split, now decided STRUCTURALLY (EXP2 STEP 7).

    The split is evaluated against `P_0`, the authority prefix, which carries
    no attenuation block: `Allowed(P_0)` is empty iff one of `Gamma`'s own
    checks refused, and a narrowed-away or out-of-`C_0` candidate falls through
    to containment unmasked. These four probes are what established that on
    `biscuit-python==0.4.0` before it was adopted; they are pinned here so a
    library bump cannot silently restore the masking the earlier textual
    reading caused.

    Each probe also carries the message-level witness (`gamma_checks_in`) as an
    INDEPENDENT second opinion. The two must agree; they are computed
    differently, so agreement is evidence rather than tautology.
    """

    C0 = [
        ("calendar.read", "calendar/work"),
        ("notes.read", "notes/project"),
        ("notes.write", "notes/project"),
    ]
    C1 = [("notes.read", "notes/project"), ("notes.write", "notes/project")]

    def _chain(self):
        from datetime import datetime, timedelta, timezone

        from biscuit_auth import KeyPair

        from src.harness.authorizer import allowed as authz

        doc = frozen_config.load_document()
        keypair = KeyPair()
        chain = authz.build_chain(
            doc,
            keypair.private_key,
            keypair.public_key,
            self.C0,
            [self.C1],
            audience="https://mcp.aasc.local/tools",
            task="task-gt-pilot",
            expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        return doc, keypair, chain, datetime.now(timezone.utc) + timedelta(seconds=0)

    def _probe(self, element, *, audience="https://mcp.aasc.local/tools", task="task-gt-pilot"):
        """Returns (allowed_at_P0_is_empty, authorizer_check_failed_in_message)."""
        from src.harness.authorizer import allowed as authz
        from src.sut.authz.capability_path import gamma_checks_in
        from src.sut.capability import authority

        doc, keypair, chain, now = self._chain()
        context = authz.RequestContext(now=now, audience=audience, task=task)

        # The STRUCTURAL discriminator, exactly as the decision path computes it.
        allowed_at_root = authority.allowed_set(
            chain.prefix(0),
            keypair.public_key,
            doc,
            now_epoch=int(now.timestamp()),
            audience=audience,
            task_id=task,
        )
        # The message-level witness, on the same prefix and candidate.
        _, evidence = authz.authorize_candidate(
            chain.prefix(0), keypair.public_key, doc["gamma"], element, context
        )
        return not allowed_at_root, bool(gamma_checks_in(evidence))

    def test_probe_a_inside_C0_with_a_failing_gamma_check(self):
        """The CHECK plane: attributable to authorizer_policy_ok."""
        structural, textual = self._probe(
            ("calendar.read", "calendar/work"), audience="https://wrong.audience/"
        )
        assert structural is True
        assert textual is True  # the two witnesses agree

    def test_probe_b_inside_C0_but_narrowed_away_at_hop_1(self):
        """The AUTHORITY plane: must fall through to containment."""
        structural, textual = self._probe(("calendar.read", "calendar/work"))
        assert structural is False
        assert textual is False

    def test_probe_c_outside_C0_entirely(self):
        """The AUTHORITY plane: falls through, so an F1-root block is containment's."""
        structural, textual = self._probe(("mail.send", "mail/outbox"))
        assert structural is False
        assert textual is False

    def test_probe_d_outside_C0_and_a_failing_gamma_check(self):
        """Both planes refuse; the CHECK plane is evaluated first and owns it."""
        structural, textual = self._probe(
            ("mail.send", "mail/outbox"), audience="https://wrong.audience/"
        )
        assert structural is True
        assert textual is True

    # -- the argument that makes the probes conclusive ---------------------- #
    @staticmethod
    def _statements(source: str) -> list[str]:
        """Datalog statements with `//` comment lines stripped."""
        body = "\n".join(line for line in source.splitlines() if not line.strip().startswith("//"))
        return [statement.strip() for statement in body.split(";") if statement.strip()]

    def test_the_authority_block_template_carries_no_check(self):
        """Clause 1: P_0 contains only block 0, and block 0 has no checks.

        This is what makes the P_0 probe conclusive rather than merely
        observed: if block 0 could carry a check, a checks-failed outcome
        against P_0 would no longer identify Gamma as the source.
        """
        templates = frozen_config.load_document()["gamma"]["datalog"]
        statements = self._statements(templates["authority_block_template"])
        assert statements, "the authority template is empty"
        assert not any(s.startswith("check") for s in statements), (
            f"the authority block template carries a check: {statements}"
        )
        # Positive arm: it does carry the four facts Gamma's checks consume.
        joined = " ".join(statements)
        for predicate in ("right(", "token_audience(", "token_task(", "expiry("):
            assert predicate in joined

    def test_the_only_token_carried_check_consumes_scope_alone(self):
        """Clause 2: the attenuation check reads a predicate Gamma never defines."""
        templates = frozen_config.load_document()["gamma"]["datalog"]
        checks = [
            s
            for s in self._statements(templates["attenuation_block_template"])
            if s.startswith("check")
        ]
        assert len(checks) == 1, f"expected exactly one attenuation check, got {checks}"
        check = checks[0]
        assert "scope(" in check
        # It must NOT consume any of the facts Gamma's own checks consume, or
        # the two planes would overlap and P_0 would stop separating them.
        for predicate in ("expiry(", "token_audience(", "token_task("):
            assert predicate not in check
        # And `scope` appears in neither block 0 nor Gamma.
        assert "scope(" not in templates["authority_block_template"]
        assert "scope(" not in templates["authorizer"]

    def test_gamma_checks_are_candidate_independent(self):
        """Clause 3: none of Gamma's checks mentions operation/2.

        So their verdict does not depend on which element of Omega is being
        probed -- which is why an empty Allowed(P_0) is a clean signal rather
        than an artefact of the candidate chosen.
        """
        templates = frozen_config.load_document()["gamma"]["datalog"]
        statements = self._statements(templates["authorizer"])
        checks = [s for s in statements if s.startswith("check")]
        allows = [s for s in statements if s.startswith("allow")]
        assert len(checks) == 3 and len(allows) == 1
        for check in checks:
            assert "operation(" not in check, (
                f"a Gamma check mentions operation/2 and is therefore candidate-dependent: {check}"
            )
        # Negative arm: the ALLOW rule does mention it, so the absence above
        # is a property of the checks specifically, not of the whole authorizer.
        assert "operation(" in allows[0]

    def test_the_decision_path_parses_no_denial_message(self):
        """Structural means structural: no message text on the decision path."""
        import ast

        source = (REPO_ROOT / "src" / "sut" / "authz" / "capability_path.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        decide_path = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_authorizer_policy_ok"
        )
        called = {
            child.func.id
            for child in ast.walk(decide_path)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
        }
        assert "gamma_checks_in" not in called
        # Negative arm: the canary still exists for the suite to call.
        assert "def gamma_checks_in(" in source


class TestFrozenPolicyIsLoadBearing:
    """Rows 4/6/10 are frozen (ADR 0022): the REFUSAL half now bites."""

    def test_no_policy_document_fails_closed(self):
        from src.sut.authz.capability_path import BoundaryPolicy, PolicyConfigurationError

        with pytest.raises(PolicyConfigurationError):
            BoundaryPolicy.load(None)

    def test_a_document_of_the_wrong_shape_fails_closed(self):
        from src.sut.authz.capability_path import BoundaryPolicy, PolicyConfigurationError

        with pytest.raises(PolicyConfigurationError):
            BoundaryPolicy.load({"context": {}, "approval": {}})

    def test_the_frozen_document_carries_the_frozen_values(self):
        from src.harness.policy import frozen_policy
        from src.sut.authz.capability_path import BoundaryPolicy

        policy = BoundaryPolicy.load(frozen_policy.load_document())
        assert policy.high_risk_actions == {"mail.send", "notes.delete"}
        assert policy.sensitive_labels == {"sensitive"}
        assert policy.order == ("public", "internal", "sensitive")
        assert policy.internal_sink_domain == "aasc.local"

    def test_the_egress_set_is_derived_from_omega_not_enumerated(self):
        """ADR 0022's rule applied to the SUT plane yields exactly {mail.send}."""
        from src.harness.authorizer import frozen_config
        from src.harness.policy import frozen_policy
        from src.sut.protocol.required_authority import recipient_carrying_actions

        omega_tools = frozenset(frozen_config.load_document()["omega"]["tools"])
        derived = frozen_policy.egress_actions(omega_tools, recipient_carrying_actions())
        assert derived == {"mail.send"}
        # Negative arm: an action outside Omega cannot be smuggled in as egress.
        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.egress_actions(omega_tools, {"shell.exec"})

    @pytest.mark.parametrize(
        "label,recipient,expected",
        [
            ("public", "a@aasc.local", "permit"),
            ("public", "a@partner.test", "permit"),
            ("internal", "a@aasc.local", "permit"),
            ("internal", "a@partner.test", "escalate"),
            ("sensitive", "a@aasc.local", "block"),
            ("sensitive", "a@partner.test", "block"),
            (None, "a@partner.test", "block"),
        ],
    )
    def test_the_row4_row6_composition(self, label, recipient, expected):
        from src.harness.policy import frozen_policy
        from src.sut.authz.capability_path import BoundaryPolicy

        policy = BoundaryPolicy.load(frozen_policy.load_document())
        assert policy.egress_decision(label, recipient) == expected

    def test_both_planes_agree_on_the_composition(self):
        """Rows 4/6 evaluated independently on each plane, over one document."""
        from src.harness.policy import frozen_policy
        from src.sut.authz.capability_path import BoundaryPolicy

        doc = frozen_policy.load_document()
        harness = frozen_policy.build(doc)
        sut = BoundaryPolicy.load(doc)
        for label in (None, "public", "internal", "sensitive"):
            for recipient in ("a@aasc.local", "a@partner.test"):
                assert harness.outcome(
                    is_egress=True, label=label, recipient=recipient
                ) == sut.egress_decision(label, recipient)

    def test_an_unlabelled_egress_is_refused_and_says_why(self, staged):
        """Row 4 bites: mail.send carries no LabelAssertion, so no permit exists."""
        setup, visible = staged
        worlds = TestWouldHaveFailedWorlds()
        arguments = {"to": "partner@example.test", "subject": "s", "body": "b"}
        # Ablate containment so the request REACHES the policy conjuncts; with
        # containment on, an F1-root block fires at conjunct six as before.
        ablated, _ = worlds._arm_with_presentation(
            setup, visible, tool="mail.send", arguments=arguments, ablates="containment_ok"
        )
        admitted, reason = ablated.decide("mail.send", arguments)
        assert admitted is False
        assert reason == REASON_CODES["context_policy_ok"]
        assert "unlabelled" in ablated.audit_log[-1]["detail"]

    def test_a_non_egress_non_high_risk_action_passes_both(self, staged):
        # Negative arm: the two conjuncts are not refusing everything.
        setup, visible = staged
        worlds = TestWouldHaveFailedWorlds()
        arguments = {"resource": "notes/project", "content": "x"}
        arm, _ = worlds._arm_with_presentation(
            setup, visible, tool="notes.write", arguments=arguments
        )
        assert arm.decide("notes.write", arguments) == (True, "b3_admitted")
        evaluated = arm.audit_log[-1]["evaluated"]
        assert "context_policy_ok" in evaluated and "approval_artifact_ok" in evaluated

    def test_requires_approval_is_computed_from_row_10(self):
        """The freeze enables refusal, not scoring: no labelled fixture exists."""
        sealed = {}
        for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal"):
            sealed[scenario_id] = json.loads(
                (
                    REPO_ROOT
                    / "fixtures"
                    / "pilot"
                    / "golden_thread"
                    / "sealed"
                    / f"{scenario_id}.json"
                ).read_text(encoding="utf-8")
            )
            assert sealed[scenario_id]["intended_labels"] == []  # F4 stays unscored
        assert {k: v["requires_approval"] for k, v in sealed.items()} == {
            "gt-benign": False,
            "gt-f1-root": True,  # mail.send is a frozen high-risk action
            "gt-f1-terminal": False,
        }


class TestDisabledIsBoundToArmIdentity:
    """EXP2 STEP 6's four rules, each refusing rather than warning."""

    def test_b3_proper_refuses_a_disabled_conjunct(self, staged):
        from src.sut.baselines.base import ArmIdentityError

        setup, _ = staged
        with pytest.raises(ArmIdentityError):
            B3Arm().provision(dict(setup, disabled=["containment_ok"]))
        B3Arm().provision(setup)  # positive arm: no disabled set, provisions fine

    def test_only_a_declared_ablation_may_carry_one(self, staged):
        from src.sut.baselines.base import ArmIdentity, ArmIdentityError

        setup, _ = staged
        # Merely renaming the arm is not declaring an ablation.
        with pytest.raises(ArmIdentityError):
            B3Arm(ArmIdentity(name="B3-sneaky")).provision(
                dict(setup, disabled=["holder_proof_ok"])
            )
        # SS E.6: exactly one conjunct, and exactly the one declared.
        identity = ArmIdentity(name="B3-minus-holder", is_ablation=True, ablates="holder_proof_ok")
        with pytest.raises(ArmIdentityError):
            B3Arm(identity).provision(dict(setup, disabled=["containment_ok"]))
        with pytest.raises(ArmIdentityError):
            B3Arm(identity).provision(dict(setup, disabled=["holder_proof_ok", "containment_ok"]))
        B3Arm(identity).provision(dict(setup, disabled=["holder_proof_ok"]))

    def test_the_variant_name_rides_in_every_audit_record(self, staged):
        setup, visible = staged
        worlds = TestWouldHaveFailedWorlds()
        arguments = {"resource": "notes/project", "content": "x"}
        arm, _ = worlds._arm_with_presentation(
            setup, visible, tool="notes.write", arguments=arguments, ablates="containment_ok"
        )
        arm.decide("notes.write", arguments)
        assert arm.audit_log, "an ablation that emits no audit record cannot be attributed"
        for record in arm.audit_log:
            assert record["arm"] == "B3-minus-containment_ok"
            assert record["is_ablation"] is True
            assert record["ablates"] == "containment_ok"
        # Negative arm: B3 proper's records name B3 and declare no ablation.
        proper, _ = worlds._arm_with_presentation(
            setup, visible, tool="notes.write", arguments=arguments
        )
        proper.decide("notes.write", arguments)
        assert all(r["arm"] == "B3" and r["is_ablation"] is False for r in proper.audit_log)

    def test_an_ablation_is_refused_on_a_confirmatory_run(self, staged):
        from src.sut.baselines.base import ArmIdentity, ArmIdentityError

        setup, _ = staged
        identity = ArmIdentity(name="B3-minus-contain", is_ablation=True, ablates="containment_ok")
        with pytest.raises(ArmIdentityError):
            B3Arm(identity).provision(
                dict(setup, disabled=["containment_ok"], run_mode="confirmatory")
            )
        # Positive arm: the same variant provisions for a pilot run.
        B3Arm(identity).provision(dict(setup, disabled=["containment_ok"], run_mode="pilot"))

    def test_an_ablation_identity_must_name_what_it_ablates(self):
        from src.sut.baselines.base import ArmIdentity, ArmIdentityError

        with pytest.raises(ArmIdentityError):
            ArmIdentity(name="B3-minus-nothing", is_ablation=True)
        with pytest.raises(ArmIdentityError):
            ArmIdentity(name="B3-confused", ablates="containment_ok")
        assert ArmIdentity(name="B3").ablates is None
