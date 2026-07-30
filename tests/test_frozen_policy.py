"""Regression suite for the frozen label/approval policy (ADR 0022, rows 4/6/10).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: the recorded `H(Lambda)`, the domain tag's distinctness
from every tag in service, the loader's necessity enforcement, the fail-closed
version handling, and the row 4/6/10 semantics as the harness plane computes
them. Platform-independent.
"""

import copy

import pytest

from src.harness import frozen_parameters
from src.harness.policy import frozen_policy
from src.harness.verifier import at_digest


class TestDigest:
    def test_matches_the_recorded_value(self):
        doc = frozen_policy.load_document()
        assert frozen_policy.h_policy(doc) == frozen_parameters.expected_h_policy()

    def test_a_mutation_changes_it(self):
        # Negative arm: the digest covers the whole document.
        doc = frozen_policy.load_document()
        mutated = copy.deepcopy(doc)
        mutated["row10_oracle_classification"]["high_risk_actions"].append(
            {"action": "notes.write", "necessity": "smuggled in"}
        )
        assert frozen_policy.h_policy(mutated) != frozen_policy.h_policy(doc)

    def test_a_reserialization_does_not_change_it(self):
        # RFC 8785 canonicalization: member order is not part of the content.
        doc = frozen_policy.load_document()
        reordered = dict(reversed(list(doc.items())))
        assert frozen_policy.h_policy(reordered) == frozen_policy.h_policy(doc)

    def test_unsupported_version_fails_closed(self):
        with pytest.raises(frozen_policy.UnsupportedVersionError):
            frozen_policy.h_policy(frozen_policy.load_document(), version=2)

    def test_unsupported_config_version_fails_closed(self, tmp_path):
        import json

        doc = frozen_policy.load_document()
        doc["config_version"] = 99
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(frozen_policy.UnsupportedVersionError):
            frozen_policy.load_document(path)

    def test_the_tag_is_distinct_from_every_tag_in_service(self):
        assert frozen_policy.TAG in at_digest._TAGS_IN_USE
        family = at_digest._TAGS_IN_USE + (at_digest.TAG,)
        assert len(set(family)) == len(family), "domain tags must be pairwise distinct"
        # And it is not a prefix of another tag, which length-delimited
        # framing makes harmless but which would still be confusing.
        others = [t for t in family if t != frozen_policy.TAG]
        assert not any(t.startswith(frozen_policy.TAG) for t in others)


class TestLoaderEnforcesNecessity:
    @pytest.mark.parametrize(
        "path",
        [
            ("row4_context_policy", "label_vocabulary", "labels", 0),
            ("row4_context_policy", "outcomes", 0),
            ("row4_context_policy", "unlabelled", 0),
            ("row6_sink_policy", "sink_classes", 0),
            ("row6_sink_policy", "allowed_pairs", 0),
            ("row10_oracle_classification", "high_risk_actions", 0),
            ("row10_oracle_classification", "sensitive_labels", 0),
        ],
    )
    def test_an_entry_without_a_necessity_is_refused(self, tmp_path, path):
        import json

        doc = frozen_policy.load_document()
        node = doc
        for key in path[:-1]:
            node = node[key]
        node[path[-1]].pop("necessity")
        target = tmp_path / "no_necessity.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(target)

    def test_the_unmutated_document_loads(self):
        # Positive arm: the parametrized refusals are not refusing everything.
        assert frozen_policy.load_document()["config_version"] == 1


class TestStructuralInvariants:
    def _mutated(self, tmp_path, mutate):
        import json

        doc = frozen_policy.load_document()
        mutate(doc)
        target = tmp_path / "mutated.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        return target

    def test_rank_contradicting_the_order_is_refused(self, tmp_path):
        def mutate(doc):
            doc["row4_context_policy"]["label_vocabulary"]["labels"][0]["rank"] = 2

        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(self._mutated(tmp_path, mutate))

    def test_a_missing_egress_outcome_is_refused(self, tmp_path):
        def mutate(doc):
            outcomes = doc["row4_context_policy"]["outcomes"]
            doc["row4_context_policy"]["outcomes"] = [
                entry for entry in outcomes if entry.get("label") != "internal"
            ]

        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(self._mutated(tmp_path, mutate))

    def test_an_allowed_pair_naming_an_unknown_sink_is_refused(self, tmp_path):
        def mutate(doc):
            doc["row6_sink_policy"]["allowed_pairs"][0]["sink"] = "nowhere-sink"

        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(self._mutated(tmp_path, mutate))

    def test_a_sensitive_label_outside_the_vocabulary_is_refused(self, tmp_path):
        def mutate(doc):
            doc["row10_oracle_classification"]["sensitive_labels"][0]["label"] = "secret"

        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(self._mutated(tmp_path, mutate))

    def test_a_rule_that_stops_referencing_internal_domain_is_refused(self, tmp_path):
        def mutate(doc):
            internal = next(
                entry
                for entry in doc["row6_sink_policy"]["sink_classes"]
                if entry["sink"] == "internal-sink"
            )
            internal["rule"] = "whatever the implementation decides"

        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(self._mutated(tmp_path, mutate))


@pytest.fixture(scope="module")
def policy():
    return frozen_policy.build(frozen_policy.load_document())


class TestSemantics:
    def test_row10(self, policy):
        assert policy.is_high_risk("mail.send") and policy.is_high_risk("notes.delete")
        assert not policy.is_high_risk("notes.write")
        assert not policy.is_high_risk("notes.read")
        assert not policy.is_high_risk("calendar.read")
        assert policy.is_sensitive("sensitive")
        assert not policy.is_sensitive("internal")

    def test_join_takes_the_least_upper_bound(self, policy):
        assert policy.join(["public", "internal"]) == "internal"
        assert policy.join(["internal", "sensitive", "public"]) == "sensitive"
        assert policy.join(["public"]) == "public"
        assert policy.join([]) is None

    def test_join_refuses_an_unknown_label(self, policy):
        with pytest.raises(frozen_policy.FrozenPolicyError):
            policy.join(["public", "top-secret"])

    def test_sink_classes_are_byte_exact(self, policy):
        assert policy.sink_class("user@aasc.local") == "internal-sink"
        assert policy.sink_class("user@partner.test") == "external-sink"
        # No normalization, no case folding: a near-miss is external.
        assert policy.sink_class("user@AASC.local") == "external-sink"
        assert policy.sink_class("user@aasc.local.evil.test") == "external-sink"
        assert policy.sink_class("user@sub.aasc.local") == "external-sink"

    def test_non_egress_permits_at_every_label(self, policy):
        for label in (None, "public", "internal", "sensitive"):
            assert policy.outcome(is_egress=False, label=label, recipient=None) == "permit"

    def test_unlabelled_egress_fails_closed(self, policy):
        assert policy.outcome(is_egress=True, label=None, recipient="a@aasc.local") == "block"

    def test_declared_egress_without_a_recipient_blocks(self, policy):
        # The whitelist cannot be consulted, so no permit can be established.
        assert policy.outcome(is_egress=True, label="public", recipient=None) == "block"


class TestVerdictTable:
    """ADR 0023: row 6 is the permit whitelist, row 4 supplies the severity.

    One verdict per cell, never two combined. ADR 0022's first reading composed
    the rows and took the more restrictive, which falsified two of the frozen
    artifact's own necessity statements; the last test here is the one that
    would have caught it.
    """

    CELLS = {
        ("public", "internal-sink"): "permit",
        ("public", "external-sink"): "permit",
        ("internal", "internal-sink"): "permit",
        ("internal", "external-sink"): "escalate",
        ("sensitive", "internal-sink"): "block",
        ("sensitive", "external-sink"): "block",
    }
    RECIPIENTS = {"internal-sink": "a@aasc.local", "external-sink": "a@partner.test"}

    @pytest.mark.parametrize("cell,expected", sorted(CELLS.items()))
    def test_each_cell(self, policy, cell, expected):
        label, sink = cell
        assert (
            policy.outcome(is_egress=True, label=label, recipient=self.RECIPIENTS[sink]) == expected
        )

    def test_unlabelled_blocks_at_either_sink(self, policy):
        for recipient in self.RECIPIENTS.values():
            assert policy.outcome(is_egress=True, label=None, recipient=recipient) == "block"

    def test_the_written_table_and_the_rule_agree(self):
        """The artifact writes the table out; the loader recomputes it.

        The loader already refuses a document where the two disagree; this
        asserts the check is real by reading the written cells directly.
        """
        doc = frozen_policy.load_document()
        written = {
            (entry["label"], entry["sink"]): entry["verdict"]
            for entry in doc["row6_sink_policy"]["verdict_table"]
        }
        assert written == dict(self.CELLS) | {(None, "*"): "block"}

    def test_a_table_that_contradicts_the_rule_is_refused(self, tmp_path):
        # Negative arm: the loader's cross-check is not vacuous.
        import json

        doc = frozen_policy.load_document()
        for entry in doc["row6_sink_policy"]["verdict_table"]:
            if entry["label"] == "internal" and entry["sink"] == "internal-sink":
                entry["verdict"] = "escalate"  # ADR 0022's falsified value
        target = tmp_path / "drifted.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(frozen_policy.PolicyStructureError):
            frozen_policy.load_document(target)

    def test_the_two_necessity_statements_adr_0023_restores(self, policy):
        """The evidence that made ADR 0022's composition wrong, as a test.

        Row 6's `(internal, internal-sink)` necessity says ordinary internal
        traffic must be able to run; row 4's `internal` necessity says
        `escalate` is what makes the declassification path observable. Under
        the composition the first cell escalated and `escalate` survived ONLY
        there -- both statements false. Both now hold.
        """
        assert (
            policy.outcome(is_egress=True, label="internal", recipient="a@aasc.local") == "permit"
        ), "row 6 lists (internal, internal-sink) as allowed; it must permit"
        assert (
            policy.outcome(is_egress=True, label="internal", recipient="a@partner.test")
            == "escalate"
        ), "escalate must survive where a declassification would be needed"
        # And escalate is reachable in exactly one cell -- the one that needs it.
        escalating = [
            cell for cell, verdict in TestVerdictTable.CELLS.items() if verdict == "escalate"
        ]
        assert escalating == [("internal", "external-sink")]
