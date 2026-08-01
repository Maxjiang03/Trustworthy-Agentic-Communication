"""D21: the two ADR 0030 implementations agree, and are genuinely two.

`src/harness/verifier/label_context.py` is the instrument's; `src/sut/authz/
label_context.py` is the measured system's. D21 requires the boundary and the
oracle to compute these values **independently**, so that agreement is evidence
rather than a tautology -- if the oracle imported the SUT's construction, a bug
in the SUT would be invisible to the instrument built to catch it.

The two are written differently on purpose (one streams the framed bytes into
the hash, the other materializes them) and this suite pins that they produce
identical output over a corpus that includes the boundary cases: empty values,
non-ASCII, the empty label set, and the exact worked example ADR 0030 records.
"""

import hashlib

import pytest
import rfc8785

from src.harness.verifier import at_digest
from src.harness.verifier import label_context as harness_lc
from src.sut.authz import label_context as sut_lc

# ADR 0030's worked example, transcribed from the ADR rather than recomputed:
# if either implementation drifts, the ADR is what they are measured against.
ADR_VALUE = "quarterly revenue: 4.2M"
ADR_PAYLOAD_DIGEST = "58c2164bbc62f7ce24846b98a9c3d290a139a26e18379223ef901db70952b555"
ADR_REQUEST_DIGEST = "2347288282d7524da93c726840ed973a767c884b51939603a72a1746ec458b39"
ADR_AUTHZ_CONTEXT_HASH = "96d6ede29b459cae481674cb88aeb4a61bd3c530d7a0369771bcb74c2107a5ab"
ADR_EMPTY_LABEL_SET = "59d8ec21cab8de767fdf16c246c6a168fd9fd1049fdaa3bd0637f9cd3836232b"
ADR_ONE_LABEL_SET = "eee883389e93be9edcccd8dd5859e200ec11a3feb79f70462341af4c2f234bed"

ADR_CONTEXT = {
    "task_id": "task-7",
    "audience": "https://mcp.aasc.local/tools",
    "tool": "mail.send",
    "canonical_request_digest": ADR_REQUEST_DIGEST,
    "resource_owner": ("https://as.aasc.local", "user-alice"),
    "oauth_actor": ("https://as.aasc.local", "agent-specialist"),
}

VALUES = [
    "",
    "a",
    ADR_VALUE,
    "unicode: é中文\U0001f512",
    b"",
    b"\x00\xff\x10",
    "a" * 4096,
]


class TestTheWorkedExampleIsReproduced:
    """The ADR fixes bytes; both sides must land on them."""

    def test_payload_digest(self):
        assert harness_lc.payload_digest(ADR_VALUE) == ADR_PAYLOAD_DIGEST
        assert sut_lc.payload_digest(ADR_VALUE) == ADR_PAYLOAD_DIGEST

    def test_authz_context_hash(self):
        assert harness_lc.authz_context_hash(**ADR_CONTEXT) == ADR_AUTHZ_CONTEXT_HASH
        assert sut_lc.authz_context_hash(**ADR_CONTEXT) == ADR_AUTHZ_CONTEXT_HASH

    def test_label_set_digests(self):
        for fn in (harness_lc.label_assertions_digest, sut_lc.label_assertions_digest):
            assert fn([]) == ADR_EMPTY_LABEL_SET
            assert fn([ADR_PAYLOAD_DIGEST]) == ADR_ONE_LABEL_SET

    def test_the_empty_set_is_a_digest_not_a_sentinel(self):
        """*"No labels" must be BOUND, not left unfilled.*

        A sentinel would let an INV signed over no labels be presented with a
        label set attached, because nothing would contradict it.
        """
        empty = harness_lc.label_assertions_digest([])
        assert empty != "0" * 64
        assert empty != harness_lc.label_assertions_digest([ADR_PAYLOAD_DIGEST])
        assert len(empty) == 64


class TestTheTwoImplementationsAgree:
    @pytest.mark.parametrize("value", VALUES)
    def test_payload_digest_agrees(self, value):
        assert harness_lc.payload_digest(value) == sut_lc.payload_digest(value)

    def test_a_str_and_its_utf8_bytes_are_the_same_join_key(self):
        """SS A.6's resolution is a JOIN: one value, one key, four sites."""
        for value in ("", "a", ADR_VALUE, "中文"):
            assert harness_lc.payload_digest(value) == harness_lc.payload_digest(
                value.encode("utf-8")
            )
            assert sut_lc.payload_digest(value) == sut_lc.payload_digest(value.encode("utf-8"))

    @pytest.mark.parametrize("bad", [1, 1.5, None, True, {"a": 1}, ["a"], ("a",)])
    def test_both_refuse_a_value_with_no_fixed_serialization(self, bad):
        with pytest.raises(harness_lc.UnhashablePayloadError):
            harness_lc.payload_digest(bad)
        with pytest.raises(sut_lc.LabelContextError):
            sut_lc.payload_digest(bad)

    @pytest.mark.parametrize(
        "override",
        [
            {},
            {"task_id": "other-task"},
            {"audience": "https://elsewhere.test"},
            {"tool": "notes.write"},
            {"canonical_request_digest": "ff" * 32},
            {"resource_owner": ("https://as.aasc.local", "user-bob")},
            {"oauth_actor": ("https://as.aasc.local", "agent-worker")},
        ],
    )
    def test_authz_context_hash_agrees(self, override):
        context = dict(ADR_CONTEXT, **override)
        assert harness_lc.authz_context_hash(**context) == sut_lc.authz_context_hash(**context)

    def test_every_named_input_changes_the_hash(self):
        """All six §F.2 inputs are BOUND. One that did not move the value would
        be a field an attacker could vary for free."""
        base = harness_lc.authz_context_hash(**ADR_CONTEXT)
        moved = {
            "task_id": "other-task",
            "audience": "https://elsewhere.test",
            "tool": "notes.write",
            "canonical_request_digest": "ff" * 32,
            "resource_owner": ("https://as.aasc.local", "user-bob"),
            "oauth_actor": ("https://as.aasc.local", "agent-worker"),
        }
        for field, value in moved.items():
            assert harness_lc.authz_context_hash(**dict(ADR_CONTEXT, **{field: value})) != base
        assert set(moved) == set(harness_lc.AUTHZ_CONTEXT_FIELDS)

    def test_a_tuple_and_a_list_are_the_same_pair(self):
        """Presentation shape is not content: the same principal supplied as a
        tuple or a list must bind identically, or two arms carrying the same
        identity would compute different hashes for one request."""
        listed = dict(
            ADR_CONTEXT,
            resource_owner=list(ADR_CONTEXT["resource_owner"]),
            oauth_actor=list(ADR_CONTEXT["oauth_actor"]),
        )
        assert harness_lc.authz_context_hash(**listed) == ADR_AUTHZ_CONTEXT_HASH
        assert sut_lc.authz_context_hash(**listed) == ADR_AUTHZ_CONTEXT_HASH

    @pytest.mark.parametrize(
        "digests",
        [[], [ADR_PAYLOAD_DIGEST], ["bb" * 32, "aa" * 32], ["aa" * 32, "bb" * 32, "cc" * 32]],
    )
    def test_label_set_digest_agrees(self, digests):
        assert harness_lc.label_assertions_digest(digests) == sut_lc.label_assertions_digest(
            digests
        )

    def test_presentation_order_does_not_change_the_binding(self):
        forward = ["aa" * 32, "bb" * 32, "cc" * 32]
        for fn in (harness_lc.label_assertions_digest, sut_lc.label_assertions_digest):
            assert fn(forward) == fn(list(reversed(forward)))

    def test_signing_input_agrees(self):
        payload = {"b": 2, "a": [1, "x"], "c": {"n": None}}
        for tag in harness_lc.NEW_TAGS:
            assert harness_lc.signing_input(tag, payload) == sut_lc.signing_input(tag, payload)

    def test_signing_input_is_the_frozen_layout(self):
        """`TAG || VERSION || u32be(len(C)) || C`, checked against the layout
        written out by hand rather than against either implementation."""
        payload = {"a": 1}
        canonical = rfc8785.dumps(payload)
        expected = (
            harness_lc.APPROVAL_TAG
            + bytes([harness_lc.VERSION])
            + len(canonical).to_bytes(4, "big")
            + canonical
        )
        assert harness_lc.signing_input(harness_lc.APPROVAL_TAG, payload) == expected
        assert sut_lc.signing_input(harness_lc.APPROVAL_TAG, payload) == expected

    def test_the_digest_layout_is_the_same_frame_hashed(self):
        assert (
            hashlib.sha256(harness_lc.signing_input(harness_lc.PAYLOAD_TAG, {"a": 1})).hexdigest()
            != harness_lc.payload_digest("x")  # sanity: different domains, different bytes
        )
        canonical = ADR_VALUE.encode("utf-8")
        framed = (
            harness_lc.PAYLOAD_TAG
            + bytes([harness_lc.VERSION])
            + len(canonical).to_bytes(4, "big")
            + canonical
        )
        assert hashlib.sha256(framed).hexdigest() == ADR_PAYLOAD_DIGEST


class TestTheImplementationsAreIndependent:
    """D21 is about provenance, not only about output."""

    def test_neither_imports_the_other(self):
        from pathlib import Path

        harness_source = Path(harness_lc.__file__).read_text(encoding="utf-8")
        sut_source = Path(sut_lc.__file__).read_text(encoding="utf-8")
        assert "src.sut" not in harness_source
        # Red line 6, restated where it would be easiest to break.
        assert "src.harness" not in sut_source

    def test_they_do_not_share_a_helper(self):
        """Same specification, two constructions. The harness streams the frame
        into the hash; the SUT materializes it. Sharing `_digest` would make
        the agreement above a tautology."""
        assert harness_lc._digest is not getattr(sut_lc, "_digest", None)
        assert hasattr(sut_lc, "_framed")
        assert not hasattr(harness_lc, "_framed")


class TestTheSixTagsAreDistinctAndRegistered:
    def test_all_six_are_in_the_family_registry(self):
        for tag in harness_lc.NEW_TAGS:
            assert tag in at_digest._TAGS_IN_USE, f"{tag!r} must collide visibly with a seventh"

    def test_the_whole_family_is_pairwise_distinct(self):
        family = at_digest._TAGS_IN_USE + (at_digest.TAG,)
        assert len(set(family)) == len(family)

    def test_no_tag_is_a_prefix_of_another(self):
        """Length-delimiting protects `C`, not the tag: two tags where one
        prefixes the other would frame identically for some input."""
        family = at_digest._TAGS_IN_USE + (at_digest.TAG,)
        for one in family:
            for other in family:
                if one is not other:
                    assert not other.startswith(one), f"{other!r} starts with {one!r}"

    def test_the_two_sides_name_the_same_tags(self):
        assert harness_lc.NEW_TAGS == sut_lc.NEW_TAGS

    def test_one_value_digests_differently_under_each_domain(self):
        """G-11 found domain-tag confusion real in both directions."""
        canonical = b"the same bytes"
        seen = {
            tag: hashlib.sha256(
                tag + bytes([harness_lc.VERSION]) + len(canonical).to_bytes(4, "big") + canonical
            ).hexdigest()
            for tag in harness_lc.NEW_TAGS
        }
        assert len(set(seen.values())) == len(harness_lc.NEW_TAGS)


class TestUnsupportedVersionsFailClosed:
    @pytest.mark.parametrize("version", [0x00, 0x02, 0xFF])
    def test_both_refuse(self, version):
        with pytest.raises(harness_lc.UnsupportedVersionError):
            harness_lc.payload_digest("x", version=version)
        with pytest.raises(sut_lc.LabelContextError):
            sut_lc.payload_digest("x", version=version)
        with pytest.raises(harness_lc.UnsupportedVersionError):
            harness_lc.authz_context_hash(**ADR_CONTEXT, version=version)
        with pytest.raises(sut_lc.LabelContextError):
            sut_lc.authz_context_hash(**ADR_CONTEXT, version=version)
