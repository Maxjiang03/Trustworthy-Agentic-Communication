"""The ingestion label directory (ADR 0030 item 4): where the ledger learns a label.

The property this suite exists for is a single one, and it is the reason the
directory is instrument-side rather than request-side: **an effect's recorded
labels must not depend on what the request claimed.** If they did, stripping a
label would make an exfiltration look harmless to `realized_harm_F4`, which is
the one thing that predicate must never do.

**Platform gate, per class rather than per file** (block 1's rule). The
directory is pure computation and runs everywhere; only the class that opens a
`LedgerWriter` sits behind the Windows gate, because ADR 0014 makes the
ledger's independence enforcement Win32 share-mode locking with no POSIX
equivalent. Gating the whole module would take the label-resolution assertions
off Linux for a reason that has nothing to do with them, and those are the
assertions that carry the F4 property.
"""

import sys

import pytest

from src.harness.policy import frozen_policy, label_directory
from src.harness.verifier import label_context as lc
from src.sut.authz.capability_path import BoundaryPolicy

WINDOWS_LEDGER_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)

SECRET = "quarterly revenue: 4.2M"
PUBLIC = "the weather is fine"
UNKNOWN = "nobody labelled this"


@pytest.fixture(scope="module")
def order():
    return BoundaryPolicy.load(frozen_policy.load_document()).order


@pytest.fixture
def directory():
    return label_directory.LabelDirectory.from_values(
        {"val-secret": (SECRET, "sensitive"), "val-public": (PUBLIC, "public")}
    )


class TestResolutionIsByBytes:
    def test_a_known_value_resolves(self, directory, order):
        digest, value_id, labels = directory.observe({"body": SECRET}, order=order)
        assert digest == lc.payload_digest(SECRET)
        assert value_id == "val-secret"
        assert labels == ["sensitive"]

    def test_the_field_name_is_irrelevant(self, directory, order):
        """Copying a value into another field must not detach its label --
        otherwise `F4` is defeated by renaming an argument."""
        by_body = directory.observe({"body": SECRET}, order=order)
        by_other = directory.observe({"attachment": SECRET}, order=order)
        assert by_body == by_other

    def test_every_argument_is_examined_not_one_nominated_field(self, directory, order):
        """A sensitive value smuggled into `subject` is still touched."""
        _, _, labels = directory.observe(
            {"to": "partner@example.test", "subject": SECRET, "body": PUBLIC}, order=order
        )
        assert labels == ["public", "sensitive"]

    def test_the_governing_payload_is_the_most_restrictive(self, directory, order):
        digest, value_id, labels = directory.observe(
            {"subject": PUBLIC, "body": SECRET}, order=order
        )
        assert (value_id, digest) == ("val-secret", lc.payload_digest(SECRET))
        assert labels == ["public", "sensitive"]

    def test_a_str_and_its_utf8_bytes_are_the_same_value(self, directory, order):
        assert directory.observe({"body": SECRET.encode("utf-8")}, order=order) == (
            lc.payload_digest(SECRET),
            "val-secret",
            ["sensitive"],
        )

    def test_an_unlabelled_value_carries_no_join(self, directory, order):
        assert directory.observe({"body": UNKNOWN}, order=order) == (None, None, [])

    def test_a_value_outside_the_payload_domain_is_unlabelled_not_an_error(self, directory, order):
        """The ledger must record EVERY effect, including effects whose
        arguments are numbers or objects. Refusing here would drop a ledger
        row, and gate G-7 rests on the ledger being complete."""
        assert directory.observe({"count": 3, "flags": {"a": True}}, order=order) == (
            None,
            None,
            [],
        )

    def test_resolution_is_deterministic_without_an_order(self, directory):
        first = directory.observe({"a": SECRET, "b": PUBLIC})
        second = directory.observe({"b": PUBLIC, "a": SECRET})
        assert first == second


class TestTheDirectoryIsNotTheRequest:
    def test_stripping_the_assertion_does_not_strip_the_label(self, directory, order):
        """The whole point. The directory never sees a `LabelAssertion`, so
        presenting none changes nothing about what the effect touched."""
        _, _, labels = directory.observe({"body": SECRET}, order=order)
        assert labels == ["sensitive"]

    def test_a_forged_public_label_cannot_relabel_a_value(self, directory, order):
        """An attacker controls the request, not the ingestion plane. Even a
        perfectly-formed assertion calling this value `public` is irrelevant
        here -- the ledger asks the directory, not the requester."""
        assert directory.observe({"body": SECRET}, order=order)[2] == ["sensitive"]

    def test_the_directory_takes_no_assertions_at_all(self):
        import inspect

        signature = inspect.signature(label_directory.LabelDirectory.observe)
        assert set(signature.parameters) == {"self", "arguments", "order"}

    def test_the_empty_directory_is_the_pre_ADR_0030_behaviour(self, order):
        assert label_directory.EMPTY.observe({"body": SECRET}, order=order) == (None, None, [])
        assert len(label_directory.EMPTY) == 0


@WINDOWS_LEDGER_ONLY
class TestTheEffectLedgerRecordsWhatItObserved:
    """The only class here that opens a ledger, and therefore the only one
    ADR 0014's platform decision applies to. No fallback writer exists and none
    is introduced: a stub would make these assertions pass on a platform where
    the property they assert -- that the ledger is independently enforced --
    does not hold."""

    def test_an_effector_populates_the_three_fields(self, tmp_path, directory, order):
        from src.harness.effect_ledger import LedgerWriter, read_ledger
        from src.harness.effectors import LedgerEffector

        path = tmp_path / "ledger.jsonl"
        writer = LedgerWriter(path)
        effector = LedgerEffector(
            writer,
            audience="https://mcp.aasc.local/tools",
            principal="agent-specialist",
            correlation_provider=lambda: "corr-1",
            labels=directory,
            label_order=order,
        )
        effector(
            tool="mail.send",
            action="mail.send",
            resource="mail/outbox",
            recipient="partner@example.test",
            arguments={"to": "partner@example.test", "subject": "Q3", "body": SECRET},
        )
        writer.close()
        (event,) = [e for e in read_ledger(path) if "effect_id" in e]
        assert event["data_labels_touched"] == ["sensitive"]
        assert event["value_id"] == "val-secret"
        assert event["payload_digest"] == lc.payload_digest(SECRET)

    def test_without_a_directory_an_effector_records_no_labels(self, tmp_path):
        """No pilot scenario declares a labelled value, so every existing
        ledger row is unchanged by ADR 0030."""
        from src.harness.effect_ledger import LedgerWriter, read_ledger
        from src.harness.effectors import LedgerEffector

        path = tmp_path / "ledger.jsonl"
        writer = LedgerWriter(path)
        LedgerEffector(
            writer,
            audience="https://mcp.aasc.local/tools",
            principal="agent-specialist",
            correlation_provider=lambda: "corr-1",
        )(
            tool="notes.write",
            action="notes.write",
            resource="notes/project",
            recipient=None,
            arguments={"resource": "notes/project", "content": SECRET},
        )
        writer.close()
        (event,) = [e for e in read_ledger(path) if "effect_id" in e]
        assert event["data_labels_touched"] == []
        assert event["payload_digest"] is None and event["value_id"] is None
