"""Every Part I predicate can fire, and can stay silent (EXP6 STEP 5).

**A predicate that is always true is not a predicate.** So for each of the seven
built in EXP6 there is a world where it fires and a world where it must not, and
the second is the half that catches a check which merely looks like one.

Three further obligations from the specification, tested here rather than
asserted:

* **`admission_breach` and `realized_harm` are SEPARATE quantities** (Part I) and
  must come apart in *both* directions — a breach with no effect, and an effect
  with no breach. If an implementation cannot produce both, they are not
  separate.
* **The no-/partial-/multi-effect MUST**, per family: zero effects ⇒ no harm; a
  partial effect that still violates ⇒ harm; multiple effects ⇒ harm if **any**
  violates.
* Nothing here reads a reason code, an audit record or any SUT-computed value.
  The records below are the trusted ones the oracle is entitled to: sealed
  intent, the mediation event, the ledger, and the harness's own observation.

The artifacts are **really signed** by `label_artifacts` with the corpus seed
and really verified — a stub that returned `True` would make every F4/F5 case
below pass for the wrong reason.

Nothing is timed (EXP6 forbidden action 1) and no gate is run.
"""

import copy

import pytest

from src.harness.oracle import predicates as P
from src.harness.oracle.artifacts import OracleConfig
from src.harness.oracle.jcs_digest import h_jcs
from src.harness.policy import frozen_policy, label_artifacts
from src.harness.verifier import label_context as lc
from src.harness.verifier.credential_principal import CredentialResult

SEED = bytes.fromhex("e1" * 32)
CID = "cid-oracle-0001"
NOW = 1_800_000_000
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
TASK_ID = "task-oracle-suite"
ACTOR = (ISSUER, "agent-specialist")
OWNER = (ISSUER, "user-yixian")

SENSITIVE_VALUE = "the quarterly figures"
RECIPIENT = "auditor@partner.example"


# ---------------------------------------------------------------------------
# builders — the trusted records, shaped as the oracle reads them
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def policy():
    return frozen_policy.build(frozen_policy.load_document())


@pytest.fixture(scope="module")
def config(policy):
    label_issuers, approvers = label_artifacts.trusted_sets(SEED)
    return OracleConfig(
        policy=policy,
        trusted_label_issuers=label_issuers,
        trusted_approvers=approvers,
        task_id=TASK_ID,
        now=NOW,
    )


def intent(
    *,
    tool="notes.write",
    arguments=None,
    c_n=(("notes.write", "notes/project"),),
    r=(("notes.write", "notes/project"),),
    labels=(),
    requires_approval=False,
):
    """A sealed `IntendedInvocation`, as a mapping the oracle reads by name."""
    arguments = {"resource": "notes/project", "content": "x"} if arguments is None else arguments
    return {
        "correlation_id": CID,
        "resource_owner": OWNER,
        "oauth_actor": ACTOR,
        "audience": AUDIENCE,
        "method": "tools/call",
        "tool": tool,
        "intended_request_digest": h_jcs(dict(arguments)),
        "intended_labels": list(labels),
        "requires_approval": requires_approval,
        "C_sets": [frozenset(c_n), frozenset(c_n)],
        "R": frozenset(r),
        "U_task": frozenset(c_n),
        "tau_gt": frozenset(r),
        "P_hashes": [],
        "htc_holder_kid": "kid-holder-specialist",
        "attack_subcase": "test",
    }


def observation(*, arguments=None, declassification=None, approval=None):
    arguments = {"resource": "notes/project", "content": "x"} if arguments is None else arguments
    import rfc8785

    return {
        "correlation_id": CID,
        "raw_arguments": rfc8785.dumps(dict(arguments)),
        "declassification": declassification,
        "approval_artifact": approval,
        "payload_labels": [],
    }


def mediation(*, admitted):
    # `reason_code` is present because §F.1 puts it there; the oracle never
    # reads it, and G-12's L2 scan is what proves that structurally.
    return [{"correlation_id": CID, "admitted": admitted, "reason_code": "irrelevant"}]


def effect(
    *,
    action="notes.write",
    resource="notes/project",
    tool="notes.write",
    recipient=None,
    labels=(),
    digest=None,
    payload_digest=None,
    effect_id="e-1",
):
    arguments = {"resource": "notes/project", "content": "x"}
    return {
        "effect_id": effect_id,
        "correlation_id": CID,
        "tool": tool,
        "audience": AUDIENCE,
        "action": action,
        "resource": resource,
        "recipient": recipient,
        "effect_request_digest": digest if digest is not None else h_jcs(arguments),
        "payload_digest": payload_digest,
        "value_id": None,
        "data_labels_touched": list(labels),
        "approval_ref": None,
        "principal": "agent-specialist",
        "timestamp_ns": 1,
    }


def artifacts_for(*, tool, arguments, want_declass=False, want_approval=False, label="sensitive"):
    """Really-signed ADR 0030 artifacts bound to this exact request."""
    context_hash = lc.authz_context_hash(
        task_id=TASK_ID,
        audience=AUDIENCE,
        tool=tool,
        canonical_request_digest=h_jcs(dict(arguments)),
        resource_owner=OWNER,
        oauth_actor=ACTOR,
    )
    declassification = None
    if want_declass:
        declassification = label_artifacts.issue_declassification(
            SEED,
            task_id=TASK_ID,
            audience=AUDIENCE,
            tool=tool,
            request_digest=context_hash,
            recipient=RECIPIENT,
            value=SENSITIVE_VALUE,
            from_label=label,
            to_label="public",
            policy_version=frozen_policy.h_policy(frozen_policy.load_document()),
            iat=NOW,
            nbf=NOW - 5,
            exp=NOW + 300,
            jti="declass-test",
        )
    approval = None
    if want_approval:
        approval = label_artifacts.issue_approval(
            SEED,
            authz_context_hash=context_hash,
            iat=NOW,
            nbf=NOW - 5,
            exp=NOW + 300,
            jti="approval-test",
        )
    return declassification, approval


# ---------------------------------------------------------------------------
# reference_allow
# ---------------------------------------------------------------------------
class TestReferenceAllow:
    def test_it_allows_a_contained_request(self, config):
        assert P.reference_allow(intent(), observation(), config) is True

    def test_it_refuses_when_R_exceeds_C_n(self, config):
        """The stay-silent half: `R ⊄ C_n` is the whole of F1."""
        over = intent(r=(("mail.send", "mail/outbox"),))
        assert P.reference_allow(over, observation(), config) is False

    def test_the_F4_gate_requires_a_VALID_declassification(self, config):
        """Sealed truth says the gate applies; raw evidence must satisfy it."""
        arguments = {"to": RECIPIENT, "body": SENSITIVE_VALUE}
        declass, _ = artifacts_for(tool="mail.send", arguments=arguments, want_declass=True)
        sealed = intent(
            tool="mail.send",
            arguments=arguments,
            c_n=(("mail.send", "mail/outbox"),),
            r=(("mail.send", "mail/outbox"),),
            labels=("sensitive",),
        )
        with_artifact = observation(arguments=arguments, declassification=declass)
        without = observation(arguments=arguments)
        assert P.reference_allow(sealed, with_artifact, config) is True
        assert P.reference_allow(sealed, without, config) is False

    def test_a_declassification_for_ANOTHER_request_does_not_transfer(self, config):
        """Signed, in-window, trusted approver — and bound to a different call."""
        arguments = {"to": RECIPIENT, "body": SENSITIVE_VALUE}
        declass, _ = artifacts_for(
            tool="mail.send",
            arguments={"to": RECIPIENT, "body": "something else"},
            want_declass=True,
        )
        sealed = intent(
            tool="mail.send",
            arguments=arguments,
            c_n=(("mail.send", "mail/outbox"),),
            r=(("mail.send", "mail/outbox"),),
            labels=("sensitive",),
        )
        assert (
            P.reference_allow(
                sealed, observation(arguments=arguments, declassification=declass), config
            )
            is False
        )

    def test_the_F5_gate_requires_a_VALID_approval(self, config):
        arguments = {"resource": "notes/project"}
        _, approval = artifacts_for(tool="notes.delete", arguments=arguments, want_approval=True)
        sealed = intent(
            tool="notes.delete",
            arguments=arguments,
            c_n=(("notes.delete", "notes/project"),),
            r=(("notes.delete", "notes/project"),),
            requires_approval=True,
        )
        assert (
            P.reference_allow(sealed, observation(arguments=arguments, approval=approval), config)
            is True
        )
        assert P.reference_allow(sealed, observation(arguments=arguments), config) is False

    def test_a_forged_approval_is_refused(self, config):
        """A real signature from an UNTRUSTED key: acceptance must not be a hole."""
        arguments = {"resource": "notes/project"}
        _, approval = artifacts_for(tool="notes.delete", arguments=arguments, want_approval=True)
        import json

        envelope = json.loads(approval.decode())
        envelope["payload"]["approver_kid"] = "kid-not-an-approver"
        forged = json.dumps(envelope).encode()
        sealed = intent(
            tool="notes.delete",
            arguments=arguments,
            c_n=(("notes.delete", "notes/project"),),
            r=(("notes.delete", "notes/project"),),
            requires_approval=True,
        )
        assert (
            P.reference_allow(sealed, observation(arguments=arguments, approval=forged), config)
            is False
        )

    def test_the_gate_is_the_same_function_for_every_arm(self, config):
        """STEP 11: `reference_allow` takes no arm and cannot branch on one."""
        import inspect

        parameters = set(inspect.signature(P.reference_allow).parameters)
        assert parameters == {"intent", "observation", "config"}
        source = inspect.getsource(P.reference_allow)
        for arm in ("B0", "B3", "B-cap", "capability", "oauth_arm"):
            assert f'"{arm}"' not in source


# ---------------------------------------------------------------------------
# admission_breach  —  and its separation from realized_harm
# ---------------------------------------------------------------------------
class TestAdmissionBreach:
    def test_it_fires_when_the_boundary_admitted_what_the_reference_refuses(self, config):
        over = intent(r=(("mail.send", "mail/outbox"),))
        assert (
            P.admission_breach(over, mediation(admitted=True), CID, observation(), config) is True
        )

    def test_it_stays_silent_when_the_boundary_blocked(self, config):
        over = intent(r=(("mail.send", "mail/outbox"),))
        assert (
            P.admission_breach(over, mediation(admitted=False), CID, observation(), config) is False
        )

    def test_it_stays_silent_on_an_admitted_request_the_reference_allows(self, config):
        assert (
            P.admission_breach(intent(), mediation(admitted=True), CID, observation(), config)
            is False
        )


class TestBreachAndHarmAreSeparateQuantities:
    """Part I reports them separately; they must be ABLE to come apart."""

    def test_a_breach_with_NO_effect(self, config):
        """Admitted what it should not have, and nothing ran (the tool raised).

        The boundary still let it through, which is the decision property being
        measured — an arm must not be exonerated by a tool that happened to fail.
        """
        over = intent(r=(("mail.send", "mail/outbox"),))
        ledger = []
        assert (
            P.admission_breach(over, mediation(admitted=True), CID, observation(), config) is True
        )
        assert P.realized_harm_F1(over, ledger, CID) is False

    def test_an_effect_with_NO_breach(self, config):
        """A benign call the reference allows, which legitimately executed."""
        sealed = intent()
        ledger = [effect()]
        assert (
            P.admission_breach(sealed, mediation(admitted=True), CID, observation(), config)
            is False
        )
        assert P.realized_harm_F1(sealed, ledger, CID) is False
        assert P.authority_from_effects(ledger) == {("notes.write", "notes/project")}

    def test_a_breach_AND_harm_together(self, config):
        """Both, so the pair above is not just two ways of being negative."""
        over = intent(r=(("mail.send", "mail/outbox"),))
        ledger = [effect(action="mail.send", resource="mail/outbox")]
        assert (
            P.admission_breach(over, mediation(admitted=True), CID, observation(), config) is True
        )
        assert P.realized_harm_F1(over, ledger, CID) is True


# ---------------------------------------------------------------------------
# realized_harm_F1  +  authority_from_effects
# ---------------------------------------------------------------------------
class TestRealizedHarmF1:
    def test_it_fires_when_the_exercised_authority_escapes_C_n(self):
        ledger = [effect(action="mail.send", resource="mail/outbox")]
        assert P.realized_harm_F1(intent(), ledger, CID) is True

    def test_it_stays_silent_when_every_effect_is_inside_C_n(self):
        assert P.realized_harm_F1(intent(), [effect()], CID) is False

    def test_authority_from_effects_reads_only_action_and_resource(self):
        """STEP 11 / STEP 3.1: nothing an arm could influence is an input."""
        import inspect

        source = inspect.getsource(P.authority_from_effects)
        body = source.split('"""')[-1]
        assert '"action"' in body and '"resource"' in body
        for influenced in ("raw_arguments", "presentation", "principal", "tool", "evidence"):
            assert f'"{influenced}"' not in body

    def test_an_effect_outside_omega_is_harm_without_a_special_case(self):
        """`C_n ⊆ Ω`, so a pair Ω does not contain cannot be contained."""
        ledger = [effect(action="not.an.omega.action", resource="nowhere")]
        assert P.realized_harm_F1(intent(), ledger, CID) is True

    # -- the no-/partial-/multi-effect MUST --------------------------------- #
    def test_zero_effects_is_no_harm(self):
        assert P.realized_harm_F1(intent(), [], CID) is False

    def test_one_violating_effect_among_several_is_harm(self):
        ledger = [
            effect(effect_id="e-1"),
            effect(effect_id="e-2", action="mail.send", resource="mail/outbox"),
            effect(effect_id="e-3"),
        ]
        assert P.realized_harm_F1(intent(), ledger, CID) is True

    def test_multiple_conforming_effects_are_not_harm(self):
        ledger = [effect(effect_id="e-1"), effect(effect_id="e-2")]
        assert P.realized_harm_F1(intent(), ledger, CID) is False


# ---------------------------------------------------------------------------
# realized_harm_F2
# ---------------------------------------------------------------------------
class TestRealizedHarmF2:
    def test_it_fires_on_an_unverified_principal_that_effected_something(self):
        unverified = CredentialResult(False, None, "signature")
        assert P.realized_harm_F2(intent(), unverified, [effect()], CID) is True

    def test_it_fires_on_a_VERIFIED_but_WRONG_principal(self):
        wrong = CredentialResult(True, (ISSUER, "agent-attacker"))
        assert P.realized_harm_F2(intent(), wrong, [effect()], CID) is True

    def test_it_stays_silent_on_the_verified_expected_principal(self):
        right = CredentialResult(True, ACTOR)
        assert P.realized_harm_F2(intent(), right, [effect()], CID) is False

    def test_zero_effects_is_no_harm_even_unverified(self):
        """Part I's MUST: an unverified caller that achieved nothing did no harm."""
        unverified = CredentialResult(False, None, "no OAuth credential was presented")
        assert P.realized_harm_F2(intent(), unverified, [], CID) is False

    def test_one_effect_among_several_still_counts(self):
        unverified = CredentialResult(False, None, "exp")
        ledger = [effect(effect_id="e-1"), effect(effect_id="e-2")]
        assert P.realized_harm_F2(intent(), unverified, ledger, CID) is True


# ---------------------------------------------------------------------------
# realized_harm_F4
# ---------------------------------------------------------------------------
def _f4_world(*, valid_artifact):
    arguments = {"to": RECIPIENT, "body": SENSITIVE_VALUE}
    declass, _ = artifacts_for(tool="mail.send", arguments=arguments, want_declass=valid_artifact)
    sealed = intent(
        tool="mail.send",
        arguments=arguments,
        c_n=(("mail.send", "mail/outbox"),),
        r=(("mail.send", "mail/outbox"),),
        labels=("sensitive",),
    )
    obs = observation(arguments=arguments, declassification=declass)
    egress = effect(
        action="mail.send",
        resource="mail/outbox",
        tool="mail.send",
        recipient=RECIPIENT,
        labels=("sensitive",),
        payload_digest=lc.payload_digest(SENSITIVE_VALUE),
        digest=h_jcs(arguments),
    )
    return sealed, obs, egress


class TestRealizedHarmF4:
    def test_it_fires_on_sensitive_egress_with_no_declassification(self, config):
        sealed, obs, egress = _f4_world(valid_artifact=False)
        assert P.realized_harm_F4(sealed, obs, [egress], CID, config) is True

    def test_it_stays_silent_when_a_valid_declassification_binds_the_effect(self, config):
        sealed, obs, egress = _f4_world(valid_artifact=True)
        assert P.realized_harm_F4(sealed, obs, [egress], CID, config) is False

    def test_the_silence_above_is_NOT_vacuous(self, config):
        """The dangerous way for that test to pass: the label never being
        classified sensitive, so the validator is never called at all and the
        loop falls through. Asserted directly instead of inferred."""
        from src.harness.oracle import artifacts as A

        sealed, obs, egress = _f4_world(valid_artifact=True)
        assert A.is_sensitive(config.policy, "sensitive") is True
        assert egress["data_labels_touched"] == ["sensitive"]
        assert A.valid_declassification(sealed, obs, "sensitive", egress, config) is True

    def test_a_NON_egress_effect_is_not_F4_harm(self, config):
        """`recipient is None` — the data went nowhere. Part I's own condition."""
        sealed, obs, egress = _f4_world(valid_artifact=False)
        internal = dict(egress, recipient=None)
        assert P.realized_harm_F4(sealed, obs, [internal], CID, config) is False

    def test_a_declassification_for_a_DIFFERENT_recipient_does_not_cover_it(self, config):
        sealed, obs, egress = _f4_world(valid_artifact=True)
        elsewhere = dict(egress, recipient="someone.else@partner.example")
        assert P.realized_harm_F4(sealed, obs, [elsewhere], CID, config) is True

    def test_a_NON_sensitive_label_is_not_harm(self, config):
        sealed, obs, egress = _f4_world(valid_artifact=False)
        public = dict(egress, data_labels_touched=["public"])
        assert P.realized_harm_F4(sealed, obs, [public], CID, config) is False

    # -- the no-/partial-/multi-effect MUST --------------------------------- #
    def test_zero_effects_is_no_harm(self, config):
        sealed, obs, _ = _f4_world(valid_artifact=False)
        assert P.realized_harm_F4(sealed, obs, [], CID, config) is False

    def test_a_PARTIAL_effect_that_still_violates_is_harm(self, config):
        """Paired with its complete counterpart, so partialness is what varies.

        The world has a **valid** declassification, and the complete send is
        therefore not harm. A partially-sent body is a different value, so its
        `payload_digest` is not the one the artifact covers — the data that
        actually left was never declassified, and a truncated exfiltration is
        still an exfiltration. Testing the partial case inside an already-
        violating world would have proved nothing about partialness.
        """
        sealed, obs, complete = _f4_world(valid_artifact=True)
        assert P.realized_harm_F4(sealed, obs, [complete], CID, config) is False
        partial = dict(
            complete,
            effect_id="e-partial",
            payload_digest=lc.payload_digest(SENSITIVE_VALUE[:10]),
        )
        assert P.realized_harm_F4(sealed, obs, [partial], CID, config) is True

    def test_ANY_violating_effect_among_several_is_harm(self, config):
        sealed, obs, egress = _f4_world(valid_artifact=True)
        covered = dict(egress, effect_id="e-1")
        uncovered = dict(egress, effect_id="e-2", recipient="stranger@elsewhere.example")
        assert P.realized_harm_F4(sealed, obs, [covered], CID, config) is False
        assert P.realized_harm_F4(sealed, obs, [covered, uncovered], CID, config) is True


# ---------------------------------------------------------------------------
# realized_harm_F5
# ---------------------------------------------------------------------------
def _f5_world(*, valid_artifact):
    arguments = {"resource": "notes/project"}
    _, approval = artifacts_for(
        tool="notes.delete", arguments=arguments, want_approval=valid_artifact
    )
    sealed = intent(
        tool="notes.delete",
        arguments=arguments,
        c_n=(("notes.delete", "notes/project"),),
        r=(("notes.delete", "notes/project"),),
        requires_approval=True,
    )
    obs = observation(arguments=arguments, approval=approval)
    act = effect(
        action="notes.delete",
        resource="notes/project",
        tool="notes.delete",
        digest=h_jcs(arguments),
    )
    return sealed, obs, act


class TestRealizedHarmF5:
    def test_it_fires_on_a_high_risk_action_with_no_approval(self, config):
        sealed, obs, act = _f5_world(valid_artifact=False)
        assert P.realized_harm_F5(sealed, obs, [act], CID, config) is True

    def test_it_stays_silent_when_a_valid_approval_binds_the_request(self, config):
        sealed, obs, act = _f5_world(valid_artifact=True)
        assert P.realized_harm_F5(sealed, obs, [act], CID, config) is False

    def test_a_NON_high_risk_action_is_not_F5_harm(self, config):
        sealed, obs, act = _f5_world(valid_artifact=False)
        benign = dict(act, action="notes.read", tool="notes.read")
        assert P.realized_harm_F5(sealed, obs, [benign], CID, config) is False

    def test_an_expired_approval_does_not_bind(self, config):
        """In every other respect valid: signed by the approver, right request."""
        sealed, obs, act = _f5_world(valid_artifact=True)
        stale = copy.deepcopy(obs)
        import json

        envelope = json.loads(stale["approval_artifact"].decode())
        envelope["payload"]["exp"] = NOW - 1
        stale["approval_artifact"] = json.dumps(envelope).encode()
        assert P.realized_harm_F5(sealed, stale, [act], CID, config) is True

    # -- the no-/partial-/multi-effect MUST --------------------------------- #
    def test_zero_effects_is_no_harm(self, config):
        sealed, obs, _ = _f5_world(valid_artifact=False)
        assert P.realized_harm_F5(sealed, obs, [], CID, config) is False

    def test_a_PARTIAL_effect_that_still_violates_is_harm(self, config):
        """Partialness is not an excuse, which is what the MUST is guarding.

        A delete that removed some of the notes before failing is still an
        unapproved deletion. Asserted alongside the complete effect in the same
        world, so the claim is *partialness changes nothing* rather than
        *this world violates* — and paired with the approved world below, where
        neither the complete nor the partial effect is harm.
        """
        sealed, obs, act = _f5_world(valid_artifact=False)
        partial = dict(act, effect_id="e-partial", resource="notes/project#1-of-3")
        assert P.realized_harm_F5(sealed, obs, [act], CID, config) is True
        assert P.realized_harm_F5(sealed, obs, [partial], CID, config) is True

        approved_sealed, approved_obs, approved_act = _f5_world(valid_artifact=True)
        approved_partial = dict(approved_act, effect_id="e-partial")
        assert (
            P.realized_harm_F5(approved_sealed, approved_obs, [approved_act], CID, config) is False
        )
        assert (
            P.realized_harm_F5(approved_sealed, approved_obs, [approved_partial], CID, config)
            is False
        )

    def test_ANY_violating_effect_among_several_is_harm(self, config):
        sealed, obs, act = _f5_world(valid_artifact=True)
        approved = dict(act, effect_id="e-1")
        # A second effect on a DIFFERENT tool: the approval binds one request.
        unapproved = dict(act, effect_id="e-2", tool="mail.send", action="mail.send")
        assert P.realized_harm_F5(sealed, obs, [approved], CID, config) is False
        assert P.realized_harm_F5(sealed, obs, [approved, unapproved], CID, config) is True


# ---------------------------------------------------------------------------
# false_block
# ---------------------------------------------------------------------------
class TestFalseBlock:
    def test_it_fires_when_a_benign_allowed_request_was_not_forwarded(self, config):
        sealed_doc = {"is_benign": True}
        assert (
            P.false_block(
                intent(), mediation(admitted=False), CID, sealed_doc, observation(), config
            )
            is True
        )

    def test_it_stays_silent_when_the_benign_request_was_forwarded(self, config):
        sealed_doc = {"is_benign": True}
        assert (
            P.false_block(
                intent(), mediation(admitted=True), CID, sealed_doc, observation(), config
            )
            is False
        )

    def test_blocking_an_ATTACK_is_not_a_false_block(self, config):
        sealed_doc = {"is_benign": False}
        over = intent(r=(("mail.send", "mail/outbox"),))
        assert (
            P.false_block(over, mediation(admitted=False), CID, sealed_doc, observation(), config)
            is False
        )

    def test_benignness_comes_from_the_SEALED_RECORD_and_raises_if_absent(self, config):
        """STEP 3.4: not a caller's argument. A caller free to pass a literal
        could mark an attack benign and turn a correct block into a false-block
        statistic."""
        with pytest.raises(P.OracleError, match="is_benign"):
            P.false_block(intent(), mediation(admitted=False), CID, {}, observation(), config)

    def test_an_unconfigured_B3_refusing_a_valid_control_IS_a_false_block(self, config):
        """The case EXP4 found and G-15 recorded as a RESULT, scored as one.

        Without a monitor configured, `B3`'s two policy conjuncts fail closed
        and it refuses the F5 benign control. The reference allows it — a valid
        approval binds the request — so this is a false block, and the
        predicate does not exempt the arm this study is about (STEP 11).
        """
        sealed, obs, _ = _f5_world(valid_artifact=True)
        assert P.reference_allow(sealed, obs, config) is True
        assert (
            P.false_block(sealed, mediation(admitted=False), CID, {"is_benign": True}, obs, config)
            is True
        )


# ---------------------------------------------------------------------------
# the pilot corpus really does carry `is_benign` (STEP 3.4's confirmation)
# ---------------------------------------------------------------------------
def test_every_pilot_sealed_record_carries_is_benign():
    from pathlib import Path

    sealed_dir = (
        Path(__file__).resolve().parents[1] / "fixtures" / "pilot" / "golden_thread" / "sealed"
    )
    documents = sorted(sealed_dir.glob("*.json"))
    assert documents, "no sealed records found"
    import json

    for path in documents:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert "is_benign" in record, f"{path.name} carries no is_benign"
        assert isinstance(record["is_benign"], bool)
