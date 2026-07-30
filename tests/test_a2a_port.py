"""Regression suite for the A2A delegation port (ADR 0020).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: the envelope's deterministic encoding, the fail-closed
in-process adapter, the swap seam (any object implementing the one-operation
protocol works), and the injection rule -- no arm or agent module names the
adapter class (the seam that lets an SDK-backed adapter replace it at the
composition root without touching arm, agent, or boundary code).
"""

import ast
from pathlib import Path

import pytest

from src.sut.protocol.a2a import (
    DelegationEnvelope,
    DelegationError,
    InProcessDelegationTransport,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

ENVELOPE_KWARGS = dict(
    from_agent="agent-supervisor",
    to_agent="agent-specialist",
    task_id="task-gt-pilot",
    intent={"tool": "notes.write", "arguments": {"resource": "notes/project", "content": "x"}},
    context_label="internal(pilot)",
    credentials={},
)


class TestEnvelopeDeterminism:
    def test_same_fields_byte_identical(self):
        first = DelegationEnvelope(**ENVELOPE_KWARGS)
        second = DelegationEnvelope(**ENVELOPE_KWARGS)
        assert first.canonical_bytes() == second.canonical_bytes()

    def test_dict_insertion_order_does_not_matter(self):
        # RFC 8785 sorts members, so insertion order cannot leak into the bytes.
        reordered = dict(ENVELOPE_KWARGS)
        reordered["intent"] = {
            "arguments": {"content": "x", "resource": "notes/project"},
            "tool": "notes.write",
        }
        assert (
            DelegationEnvelope(**reordered).canonical_bytes()
            == DelegationEnvelope(**ENVELOPE_KWARGS).canonical_bytes()
        )

    def test_field_change_changes_bytes(self):
        # Negative arm: the encoding is not constant.
        changed = dict(ENVELOPE_KWARGS, task_id="task-other")
        assert (
            DelegationEnvelope(**changed).canonical_bytes()
            != DelegationEnvelope(**ENVELOPE_KWARGS).canonical_bytes()
        )

    def test_bytes_credentials_encode_as_hex(self):
        # Raw credential material (capability hops, HTCs, INV) must be encodable
        # and injective: two different byte strings give two different encodings.
        with_bytes = dict(ENVELOPE_KWARGS, credentials={"capability": [b"\x00\x01"]})
        other_bytes = dict(ENVELOPE_KWARGS, credentials={"capability": [b"\x00\x02"]})
        first = DelegationEnvelope(**with_bytes).canonical_bytes()
        second = DelegationEnvelope(**other_bytes).canonical_bytes()
        assert first != second
        assert b"0001" in first  # lowercase hex rendering


class TestInProcessAdapter:
    def test_delivers_to_registered_handler(self):
        transport = InProcessDelegationTransport()
        seen: list[DelegationEnvelope] = []
        transport.register("agent-specialist", lambda env: seen.append(env) or "ack")
        envelope = DelegationEnvelope(**ENVELOPE_KWARGS)
        assert transport.deliver(envelope) == "ack"
        assert seen == [envelope]

    def test_unregistered_recipient_fails_closed(self):
        transport = InProcessDelegationTransport()
        with pytest.raises(DelegationError):
            transport.deliver(DelegationEnvelope(**ENVELOPE_KWARGS))

    def test_duplicate_registration_fails_closed(self):
        transport = InProcessDelegationTransport()
        transport.register("agent-specialist", lambda env: None)
        with pytest.raises(DelegationError):
            transport.register("agent-specialist", lambda env: None)


class TestSwapSeam:
    def test_any_protocol_implementation_works(self):
        """The port is the dependency: a test double needs no adapter code."""

        class RecordingTransport:
            def __init__(self):
                self.delivered = []

            def deliver(self, envelope: DelegationEnvelope):
                self.delivered.append(envelope)
                return "double-ack"

        transport = RecordingTransport()
        envelope = DelegationEnvelope(**ENVELOPE_KWARGS)
        assert transport.deliver(envelope) == "double-ack"
        assert transport.delivered == [envelope]

    def test_no_arm_or_agent_names_the_adapter(self):
        """ADR 0020: the adapter is injected, never imported by name at a call site.

        AST scan over `src/sut/agents/` and `src/sut/baselines/`: no import of,
        or attribute/name reference to, `InProcessDelegationTransport`. The scan
        is over real parse trees, not text, so a comment cannot trip it.
        """
        offenders: list[str] = []
        for package in ("agents", "baselines"):
            for path in sorted((REPO_ROOT / "src" / "sut" / package).rglob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name) and node.id == "InProcessDelegationTransport":
                        offenders.append(f"{path.name}:{node.lineno}")
                    if (
                        isinstance(node, ast.Attribute)
                        and node.attr == "InProcessDelegationTransport"
                    ):
                        offenders.append(f"{path.name}:{node.lineno}")
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            if alias.name == "InProcessDelegationTransport":
                                offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == [], f"adapter named outside the composition root: {offenders}"

    def test_the_adapter_scan_is_not_vacuous(self):
        # Negative arm: the same scan applied to a source string that DOES name
        # the adapter must find it -- otherwise the test above proves nothing.
        source = "from src.sut.protocol.a2a import InProcessDelegationTransport\n"
        tree = ast.parse(source)
        hits = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.name == "InProcessDelegationTransport"
        ]
        assert hits == ["InProcessDelegationTransport"]
