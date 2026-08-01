"""The ADR 0030 reference monitor: what it accepts, and the five ways it refuses.

Block 2 found `_context_policy_ok` reading `entry.get("label")` off an
unverified mapping and the fix was to refuse everything presented. This suite
pins that ADR 0030 did **not** undo that refusal but earned an acceptance: for
each of the three artifact types, the same five negative worlds are constructed
and each is refused with its own condition named.

    unsigned                the signature is absent or is not over these bytes
    unregistered key        a real signature, from a key nobody trusts
    different request       a valid artifact for some OTHER authz_context_hash
    outside Delta           a valid artifact, stale (ADR 0027)
    replayed                a valid artifact presented twice

Each is the *same* artifact as the accepted one with exactly one thing wrong,
so a refusal is attributable to that one thing and to nothing else. The
positive control sits beside every group: if the accepted case stopped being
accepted, these tests would pass for the wrong reason.

`monitor_attached` is CONFIGURATION (ADR 0030): every test here runs with one
attached, which is what makes the acceptance half observable at all.
"""

import json

import pytest

from src.harness import frozen_parameters, key_material
from src.harness.policy import frozen_policy, label_artifacts
from src.sut import freshness
from src.sut.authz import label_context as lc
from src.sut.authz.capability_path import BoundaryPolicy
from src.sut.authz.reference_monitor import (
    ContextApprovalMonitor,
    MonitorConfigurationError,
    RequestContext,
)

SEED = b"\x01" * 32
NOW = 1_800_000_000
SENSITIVE_BODY = "quarterly revenue: 4.2M"
EXTERNAL = "partner@example.test"
INTERNAL = "colleague@aasc.local"


@pytest.fixture(scope="module")
def policy():
    return BoundaryPolicy.load(frozen_policy.load_document())


@pytest.fixture
def monitor(policy):
    """A fresh monitor per test: the jti cache is state, and a replay test that
    inherited another test's consumed jti would pass without proving anything."""
    label_issuers, approvers = label_artifacts.trusted_sets(SEED)
    return ContextApprovalMonitor(
        policy=policy,
        label_issuers=label_issuers,
        approvers=approvers,
        policy_version=frozen_parameters.expected_h_policy(),
    )


@pytest.fixture
def context():
    return RequestContext(
        task_id="task-7",
        audience="https://mcp.aasc.local/tools",
        tool="mail.send",
        canonical_request_digest="23" * 32,
        resource_owner=("https://as.aasc.local", "user-alice"),
        oauth_actor=("https://as.aasc.local", "agent-specialist"),
    )


@pytest.fixture
def carried():
    """What the SERVER extracted from the request, never what the agent said."""
    return {lc.payload_digest(SENSITIVE_BODY): SENSITIVE_BODY}


def a_label(*, label="sensitive", value=SENSITIVE_BODY, seed=SEED):
    return label_artifacts.issue_label_assertion(
        seed, value=value, label=label, iat=NOW - 86_400, exp=NOW + 86_400
    )


def a_declassification(context, *, seed=SEED, now=NOW, **overrides):
    fields = dict(
        task_id=context.task_id,
        audience=context.audience,
        tool=context.tool,
        request_digest=context.authz_context_hash(),
        recipient=EXTERNAL,
        value=SENSITIVE_BODY,
        from_label="sensitive",
        to_label="public",
        policy_version=frozen_parameters.expected_h_policy(),
        iat=now,
        nbf=now - 5,
        exp=now + 300,
        jti="declass-1",
    )
    fields.update(overrides)
    return label_artifacts.issue_declassification(seed, **fields)


def an_approval(context, *, seed=SEED, now=NOW, **overrides):
    fields = dict(
        authz_context_hash=context.authz_context_hash(),
        iat=now,
        nbf=now - 5,
        exp=now + 300,
        jti="approval-1",
    )
    fields.update(overrides)
    return label_artifacts.issue_approval(seed, **fields)


def unsign(artifact):
    """The same artifact with its signature destroyed and nothing else changed."""
    if isinstance(artifact, bytes):
        envelope = json.loads(artifact)
        envelope["signature"] = ""
        return json.dumps(envelope).encode("utf-8")
    return dict(artifact, signature="")


# A key that is real and signs correctly, but that the monitor was never told
# to trust -- the difference between "no signature" and "the wrong signer".
UNTRUSTED_SEED = b"\x02" * 32


class TestConfigurationFailsClosed:
    def test_a_kid_in_both_trusted_sets_is_refused(self, policy):
        """A label issuer says what data IS; an approver authorizes an ACTION.
        One key doing both would let whoever labels a payload also approve a
        high-risk action on it (ADR 0030)."""
        shared = {"kid-both": "x"}
        with pytest.raises(MonitorConfigurationError, match="both trusted sets"):
            ContextApprovalMonitor(
                policy=policy,
                label_issuers=shared,
                approvers=shared,
                policy_version="h",
            )

    def test_no_policy_version_is_refused(self, policy):
        with pytest.raises(MonitorConfigurationError, match="frozen policy version"):
            ContextApprovalMonitor(policy=policy, label_issuers={}, approvers={}, policy_version="")

    def test_the_two_derived_roles_are_disjoint(self):
        label_issuers, approvers = label_artifacts.trusted_sets(SEED)
        assert not set(label_issuers) & set(approvers)
        assert set(label_issuers.values()).isdisjoint(approvers.values())


class TestLabelAssertionVerification:
    """A label is believed only when a trusted issuer asserted it."""

    def test_the_accepted_case(self, monitor, carried):
        resolved, reason = monitor.verified_labels(
            assertions=[a_label()], carried_payloads=carried, now=NOW
        )
        assert reason == ""
        assert resolved == {lc.payload_digest(SENSITIVE_BODY): "sensitive"}

    def test_unsigned_is_refused(self, monitor, carried):
        _, reason = monitor.verified_labels(
            assertions=[unsign(a_label())], carried_payloads=carried, now=NOW
        )
        assert "does not verify" in reason and "AASC-LABEL-v1" in reason

    def test_a_real_signature_from_an_untrusted_issuer_is_refused(self, monitor, carried):
        """The kid is one the monitor knows; the SIGNATURE is from another key.
        Refused at the signature, not at the name -- naming a trusted issuer
        must not be enough."""
        forged = a_label(seed=UNTRUSTED_SEED)
        _, reason = monitor.verified_labels(assertions=[forged], carried_payloads=carried, now=NOW)
        assert "does not verify" in reason

    def test_an_unregistered_kid_is_refused(self, monitor, carried):
        _, reason = monitor.verified_labels(
            assertions=[dict(a_label(), issuer_kid="kid-holder-specialist")],
            carried_payloads=carried,
            now=NOW,
        )
        assert "not a trusted label issuer" in reason

    def test_outside_its_own_window_is_refused(self, monitor, carried):
        expired = label_artifacts.issue_label_assertion(
            SEED, value=SENSITIVE_BODY, label="sensitive", iat=NOW - 100, exp=NOW - 1
        )
        _, reason = monitor.verified_labels(assertions=[expired], carried_payloads=carried, now=NOW)
        assert "outside its own iat/exp window" in reason

    def test_delta_does_NOT_apply_to_a_label(self, monitor, carried):
        """§A.6: labels are asserted at ingestion and *exist before task-time
        capability issuance*. A label issued a week ago and valid for a year is
        the NORMAL case; applying ADR 0027's Δ here would refuse every genuinely
        pre-labelled payload and make the model unimplementable."""
        old = label_artifacts.issue_label_assertion(
            SEED,
            value=SENSITIVE_BODY,
            label="sensitive",
            iat=NOW - 7 * 86_400,
            exp=NOW + 365 * 86_400,
        )
        assert NOW - old["iat"] > freshness.DELTA_SECONDS * 100
        resolved, reason = monitor.verified_labels(
            assertions=[old], carried_payloads=carried, now=NOW
        )
        assert reason == "" and resolved

    def test_a_label_for_a_payload_not_carried_is_refused(self, monitor, carried):
        """Otherwise a presented assertion could relabel a value that is not
        there -- or, worse, launder a sensitive payload by attaching a `public`
        label for some other value entirely."""
        _, reason = monitor.verified_labels(
            assertions=[a_label(value="a different value", label="public")],
            carried_payloads=carried,
            now=NOW,
        )
        assert "does not carry" in reason

    def test_a_label_outside_the_frozen_vocabulary_is_refused(self, monitor, carried):
        _, reason = monitor.verified_labels(
            assertions=[a_label(label="top-secret")], carried_payloads=carried, now=NOW
        )
        assert "outside the frozen label vocabulary" in reason

    def test_two_verified_assertions_disagreeing_is_refused(self, monitor, carried):
        """Not resolved by taking the more restrictive one: two trusted issuers
        contradicting each other is a broken ingestion plane, and picking a
        winner would hide it."""
        _, reason = monitor.verified_labels(
            assertions=[a_label(label="sensitive"), a_label(label="public")],
            carried_payloads=carried,
            now=NOW,
        )
        assert "disagree on the label" in reason

    def test_a_malformed_shape_is_refused(self, monitor, carried):
        _, reason = monitor.verified_labels(
            assertions=[{"label": "public"}], carried_payloads=carried, now=NOW
        )
        assert "not the SS F.1 shape" in reason or "not the" in reason


class TestContextPolicyOverVerifiedLabels:
    """Rows 4/6 decide; the monitor only supplies labels it verified."""

    def test_a_sensitive_payload_to_an_external_sink_blocks(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=None,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused
        assert "no DeclassificationArtifact was presented" in decision.reason

    def test_a_public_payload_to_an_external_sink_is_permitted(self, monitor, context):
        value = "the weather is fine"
        decision = monitor.context_decision(
            context,
            assertions=[a_label(label="public", value=value)],
            carried_payloads={lc.payload_digest(value): value},
            declassification=None,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.admitted and decision.verified_labels == ("public",)

    def test_an_unlabelled_egress_still_blocks(self, monitor, context, carried):
        """The row-4 unlabelled rule is unchanged by ADR 0030: absence of a
        verified label is not evidence of harmlessness."""
        decision = monitor.context_decision(
            context,
            assertions=[],
            carried_payloads=carried,
            declassification=None,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "unlabelled payload" in decision.reason

    def test_non_egress_is_permitted_at_every_label(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=None,
            recipient=None,
            now=NOW,
        )
        assert decision.admitted


class TestDeclassificationIsAnAcceptancePathNotAnException:
    def test_the_accepted_case(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.admitted, decision.reason

    def test_unsigned_is_refused(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=unsign(a_declassification(context)),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "does not verify" in decision.reason

    def test_an_untrusted_approver_is_refused(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context, seed=UNTRUSTED_SEED),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "does not verify" in decision.reason

    def test_an_unregistered_kid_is_refused(self, monitor, context, carried):
        artifact = dict(a_declassification(context), approver_kid="kid-holder-specialist")
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=artifact,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "not a trusted approver" in decision.reason

    def test_a_valid_artifact_for_a_DIFFERENT_request_is_refused(self, monitor, context, carried):
        """The core F3 property, at the declassification: an artifact is
        perfectly valid and signed by the real approver, but for another
        request. Nothing about it is malformed -- only its binding is wrong."""
        other = RequestContext(
            task_id=context.task_id,
            audience=context.audience,
            tool=context.tool,
            canonical_request_digest="ff" * 32,  # a different request body
            resource_owner=context.resource_owner,
            oauth_actor=context.oauth_actor,
        )
        assert other.authz_context_hash() != context.authz_context_hash()
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(other),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused
        assert "different authz_context_hash" in decision.reason

    def test_outside_delta_is_refused(self, monitor, context, carried):
        stale = a_declassification(
            context, iat=NOW - freshness.DELTA_SECONDS - 1, nbf=NOW - 600, exp=NOW + 600
        )
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=stale,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and f"Delta={freshness.DELTA_SECONDS}s" in decision.reason

    def test_replay_is_refused(self, monitor, context, carried):
        artifact = a_declassification(context)
        first = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=artifact,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert first.admitted
        second = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=artifact,
            recipient=EXTERNAL,
            now=NOW,
        )
        assert second.refused and "already consumed" in second.reason

    def test_a_stale_policy_version_is_refused(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context, policy_version="00" * 32),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "different frozen policy version" in decision.reason

    def test_a_from_label_that_was_never_verified_is_refused(self, monitor, context, carried):
        """The artifact claims to declassify `internal`; the VERIFIED label is
        `sensitive`. Believing the artifact's own account of the label would
        reintroduce exactly the read-what-was-claimed bug ADR 0030 closes."""
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context, from_label="internal"),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "from_label" in decision.reason

    def test_declassifying_to_a_still_forbidden_pair_is_refused(self, monitor, context, carried):
        """*Declassification is not a bypass.* Rows 4/6 are re-evaluated over
        the substituted label, so an approver cannot authorize a pair the
        frozen policy forbids -- only a pair it already permits."""
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context, to_label="internal"),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused
        assert "still does not permit egress" in decision.reason

    def test_a_declassification_for_another_recipient_is_refused(self, monitor, context, carried):
        decision = monitor.context_decision(
            context,
            assertions=[a_label()],
            carried_payloads=carried,
            declassification=a_declassification(context, recipient=INTERNAL),
            recipient=EXTERNAL,
            now=NOW,
        )
        assert decision.refused and "different recipient or tool" in decision.reason


class TestApprovalArtifactBindsOneRequest:
    """F5. The high-risk half of row 10."""

    def test_a_high_risk_action_with_no_approval_is_refused(self, monitor, context, policy):
        assert context.tool in policy.high_risk_actions
        decision = monitor.approval_decision(context, approval=None, now=NOW, high_risk=True)
        assert decision.refused and "no ApprovalArtifact was presented" in decision.reason

    def test_the_accepted_case(self, monitor, context):
        decision = monitor.approval_decision(
            context, approval=an_approval(context), now=NOW, high_risk=True
        )
        assert decision.admitted, decision.reason

    def test_a_non_high_risk_action_needs_none(self, monitor, context):
        assert monitor.approval_decision(context, approval=None, now=NOW, high_risk=False).admitted

    def test_a_presented_approval_is_verified_even_when_not_required(self, monitor, context):
        """An artifact nobody checks is an artifact an attacker may shape
        freely; and a forged approval accepted silently on a low-risk call is
        a forged approval that was never observed."""
        decision = monitor.approval_decision(
            context, approval=unsign(an_approval(context)), now=NOW, high_risk=False
        )
        assert decision.refused

    def test_unsigned_is_refused(self, monitor, context):
        decision = monitor.approval_decision(
            context, approval=unsign(an_approval(context)), now=NOW, high_risk=True
        )
        assert decision.refused and "does not verify" in decision.reason

    def test_an_untrusted_approver_is_refused(self, monitor, context):
        decision = monitor.approval_decision(
            context, approval=an_approval(context, seed=UNTRUSTED_SEED), now=NOW, high_risk=True
        )
        assert decision.refused and "does not verify" in decision.reason

    def test_an_unregistered_kid_is_refused(self, monitor, context):
        envelope = json.loads(an_approval(context))
        envelope["payload"]["approver_kid"] = "kid-label-issuer"
        decision = monitor.approval_decision(
            context,
            approval=json.dumps(envelope).encode("utf-8"),
            now=NOW,
            high_risk=True,
        )
        assert decision.refused and "not a trusted approver" in decision.reason

    def test_a_LABEL_ISSUER_signature_is_refused_in_the_approval_domain(self, monitor, context):
        """The two roles are separate by KEY, not only by name: the label
        issuer's own key signing an approval is refused."""
        payload = {
            "authz_context_hash": context.authz_context_hash(),
            "approver_kid": label_artifacts.APPROVER_KID,
            "iat": NOW,
            "nbf": NOW - 5,
            "exp": NOW + 300,
            "jti": "cross-role",
            "replay_rule": "single-use",
        }
        signature = label_artifacts.label_issuer_private(SEED).sign(
            lc.signing_input(lc.APPROVAL_TAG, payload)
        )
        envelope = json.dumps(
            {
                "payload": payload,
                "signature": key_material.urlsafe_b64encode(signature).rstrip(b"=").decode(),
            }
        ).encode("utf-8")
        decision = monitor.approval_decision(context, approval=envelope, now=NOW, high_risk=True)
        assert decision.refused and "does not verify" in decision.reason

    def test_a_valid_approval_for_a_DIFFERENT_request_is_refused(self, monitor, context):
        """F5 proper: a genuine approval, genuinely signed, for another call.
        This is the confused deputy the study exists to measure -- an approval
        obtained for a harmless request, replayed onto a harmful one."""
        other = RequestContext(
            task_id=context.task_id,
            audience=context.audience,
            tool=context.tool,
            canonical_request_digest="ab" * 32,
            resource_owner=context.resource_owner,
            oauth_actor=context.oauth_actor,
        )
        decision = monitor.approval_decision(
            context, approval=an_approval(other), now=NOW, high_risk=True
        )
        assert decision.refused and "different authz_context_hash" in decision.reason

    @pytest.mark.parametrize(
        "field,value",
        [
            ("task_id", "task-other"),
            ("audience", "https://elsewhere.test"),
            ("tool", "notes.write"),
            ("canonical_request_digest", "cd" * 32),
            ("resource_owner", ("https://as.aasc.local", "user-bob")),
            ("oauth_actor", ("https://as.aasc.local", "agent-worker")),
        ],
    )
    def test_every_bound_input_breaks_the_approval(self, monitor, context, field, value):
        """All six §F.2 inputs are load-bearing. One that did not break the
        binding would be a dimension an attacker could vary for free."""
        import dataclasses

        approval = an_approval(context)
        moved = dataclasses.replace(context, **{field: value})
        decision = monitor.approval_decision(moved, approval=approval, now=NOW, high_risk=True)
        assert decision.refused and "different authz_context_hash" in decision.reason

    def test_outside_delta_is_refused(self, monitor, context):
        stale = an_approval(
            context, iat=NOW - freshness.DELTA_SECONDS - 1, nbf=NOW - 600, exp=NOW + 600
        )
        decision = monitor.approval_decision(context, approval=stale, now=NOW, high_risk=True)
        assert decision.refused and f"Delta={freshness.DELTA_SECONDS}s" in decision.reason

    def test_outside_its_own_window_is_refused(self, monitor, context):
        decision = monitor.approval_decision(
            context,
            approval=an_approval(context, nbf=NOW + 10, exp=NOW + 300),
            now=NOW,
            high_risk=True,
        )
        assert decision.refused and "outside its validity window" in decision.reason

    def test_replay_is_refused(self, monitor, context):
        approval = an_approval(context)
        assert monitor.approval_decision(
            context, approval=approval, now=NOW, high_risk=True
        ).admitted
        second = monitor.approval_decision(context, approval=approval, now=NOW, high_risk=True)
        assert second.refused and "already consumed" in second.reason

    def test_an_unsupported_replay_rule_fails_closed(self, monitor, context):
        decision = monitor.approval_decision(
            context,
            approval=an_approval(context, replay_rule="multi-use"),
            now=NOW,
            high_risk=True,
        )
        assert decision.refused and "unsupported replay_rule" in decision.reason

    def test_a_malformed_envelope_is_refused(self, monitor, context):
        for bad in (b"not json", b"[]", b'{"payload": {}}'):
            assert monitor.approval_decision(context, approval=bad, now=NOW, high_risk=True).refused


class TestTheMonitorTakesNothingCapabilitySpecific:
    """G-15's precondition: if the monitor needed a capability, `A†` could not
    be tested and every F4/F5 number would be a statement about which arm
    happened to have one attached."""

    def test_the_request_context_names_only_the_six_F2_inputs(self):
        import dataclasses

        fields = {f.name for f in dataclasses.fields(RequestContext)}
        assert fields == {
            "task_id",
            "audience",
            "tool",
            "canonical_request_digest",
            "resource_owner",
            "oauth_actor",
        }
        for forbidden in ("capability", "htc", "inv", "dpop", "biscuit"):
            assert not any(forbidden in name for name in fields)

    def test_an_oauth_arm_computes_the_same_hash_as_a_capability_arm(self, context):
        """Same request, no capability token in sight, identical value. This is
        the property the shared monitor rests on."""
        from src.harness.verifier import label_context as harness_lc

        assert context.authz_context_hash() == harness_lc.authz_context_hash(
            task_id=context.task_id,
            audience=context.audience,
            tool=context.tool,
            canonical_request_digest=context.canonical_request_digest,
            resource_owner=context.resource_owner,
            oauth_actor=context.oauth_actor,
        )

    def test_the_monitor_module_imports_no_capability_machinery(self):
        from pathlib import Path

        from src.sut.authz import reference_monitor

        source = Path(reference_monitor.__file__).read_text(encoding="utf-8")
        assert "src.harness" not in source  # red line 6
        for forbidden in ("capability_path", "src.sut.capability", "oauth_as"):
            assert f"import {forbidden}" not in source
            assert f"from {forbidden}" not in source
