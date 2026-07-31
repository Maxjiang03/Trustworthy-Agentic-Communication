"""The measured segment's code extent, pinned structurally (ADR 0026, STEP 4).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. `frozen_parameters` row 1 settles the "lightweight" claim over
`presentation + boundary_verification`, so **what those two spans bracket is
part of the frozen decision** and cannot be left resting on a comment. A span
whose boundaries are documented but not asserted drifts.

Four things are asserted, exactly as STEP 4 lists them:

1. `presentation` brackets `arm.present(...)` **alone**;
2. `boundary_verification` brackets `arm.decide(...)` **alone**;
3. **no effect-ledger write occurs inside either** -- the ledger is an
   experimental instrument with no deployment counterpart, so charging it to
   any arm would measure the apparatus;
4. neither span includes `provision` or `delegate`.

Plus the audit-sink bound: `B3` carries `audit = 1` and `_audit` runs inside
`decide`, so a sink performing disk or network I/O there would charge `B3` for
the apparatus. The decision path refuses one.

**No number is emitted anywhere in this file.** Span *boundaries* are compared
for containment and ordering; no duration is computed, reported or compared
against a threshold. `IA-3` stays `[UNVERIFIED-IA]` for G-3.
"""

import ast
import builtins
import socket
import sys
from pathlib import Path

import pytest

from src.harness.runner import GoldenThreadRunner
from src.sut.authz.capability_path import AuditSinkError, BoundedAuditBuffer, CapabilityDecisionPath
from src.sut.baselines.b0 import B0Arm

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_SOURCE = REPO_ROOT / "src" / "harness" / "runner.py"

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking, which has no direct POSIX equivalent",
)


# ---------------------------------------------------------------------------
# 1 & 2 — each span brackets exactly one call, read off the source
# ---------------------------------------------------------------------------
def _marked_span_bodies() -> dict[str, list[ast.stmt]]:
    """For each `timing.mark("<name>", ...)`, the `try` body it protects.

    The seams are written as `try: <one call> finally: timing.mark(...)`, so
    the guarded body is exactly what the span brackets. Reading it from the
    AST is what makes the extent auditable rather than conventional.
    """
    tree = ast.parse(RUNNER_SOURCE.read_text(encoding="utf-8"))
    bodies: dict[str, list[ast.stmt]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for stmt in node.finalbody:
            call = getattr(stmt, "value", None)
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "mark"
                and call.args
                and isinstance(call.args[0], ast.Constant)
            ):
                bodies[call.args[0].value] = node.body
    return bodies


def _sole_call(body: list[ast.stmt]) -> ast.Call:
    assert len(body) == 1, f"the span brackets {len(body)} statements, not one"
    stmt = body[0]
    value = stmt.value if isinstance(stmt, (ast.Assign, ast.Return, ast.Expr)) else None
    assert isinstance(value, ast.Call), f"the bracketed statement is not a call: {ast.dump(stmt)}"
    return value


def _callee(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ast.dump(func)


class TestEachSpanBracketsOneCall:
    def test_presentation_brackets_present_alone(self):
        bodies = _marked_span_bodies()
        assert "presentation" in bodies, "ADR 0026's new seam is missing"
        assert _callee(_sole_call(bodies["presentation"])) == "arm.present"

    def test_boundary_verification_brackets_decide_alone(self):
        """Its present extent, unchanged. ADR 0026 rejected widening it."""
        bodies = _marked_span_bodies()
        assert "boundary_verification" in bodies
        assert _callee(_sole_call(bodies["boundary_verification"])) == "arm.decide"

    def test_instrument_bookkeeping_is_outside_the_presentation_span(self):
        """`presentations.append(...)` is excluded by name in ADR 0026.

        It is the harness recording what the arm produced -- instrument, not
        mechanism -- so it must sit after the span closes.
        """
        body = _marked_span_bodies()["presentation"]
        rendered = "\n".join(ast.dump(stmt) for stmt in body)
        assert "presentations" not in rendered
        # Negative arm: the append DOES exist in the enclosing function, so its
        # absence above is placement rather than the call having been deleted.
        assert "presentations.append(dict(presentation))" in RUNNER_SOURCE.read_text(
            encoding="utf-8"
        )

    def test_the_scan_can_see_a_widened_span(self):
        """Negative arm for the whole approach: a two-statement body is caught."""
        widened = ast.parse(
            "try:\n    a = arm.present(x, y)\n    b = arm.decide(t, g)\nfinally:\n    pass"
        ).body[0]
        with pytest.raises(AssertionError):
            _sole_call(widened.body)


# ---------------------------------------------------------------------------
# 4 — the excluded phases, asserted on real recorded intervals
# ---------------------------------------------------------------------------
class TestTheExcludedPhases:
    @pytest.fixture(scope="class")
    @staticmethod
    def spans():
        runner = GoldenThreadRunner()
        run = runner.run_scenario("gt-benign", B0Arm(), setup={}, ledger_backed=False)
        return run.timing.spans

    def test_all_five_seams_are_recorded(self, spans):
        assert set(spans) == {
            "setup",
            "delegation",
            "presentation",
            "boundary_verification",
            "end_to_end",
        }

    @pytest.mark.parametrize("excluded", ["setup", "delegation"])
    @pytest.mark.parametrize("segment", ["presentation", "boundary_verification"])
    def test_the_segment_contains_neither_provision_nor_delegate(self, spans, excluded, segment):
        """SS E.2 puts `setup` outside the delegation estimand and reports
        `delegation` separately; ADR 0026 excludes both from the segment."""
        outer_start, outer_end = spans[segment]
        inner_start, inner_end = spans[excluded]
        assert not (outer_start <= inner_start and inner_end <= outer_end)
        # And they really are disjoint intervals, not merely not-nested.
        assert inner_end <= outer_start or outer_end <= inner_start

    def test_both_segment_spans_sit_inside_end_to_end(self, spans):
        """Positive arm: the containment test above can succeed, so its
        failures elsewhere are about placement rather than about the check."""
        outer_start, outer_end = spans["end_to_end"]
        for name in ("presentation", "boundary_verification"):
            start, end = spans[name]
            assert outer_start <= start and end <= outer_end

    def test_presentation_precedes_boundary_verification(self, spans):
        """The arm stages, then the boundary decides. Summing two spans for the
        estimand is only meaningful if they do not overlap."""
        assert spans["presentation"][1] <= spans["boundary_verification"][0]


# ---------------------------------------------------------------------------
# 3 — no effect-ledger write inside either span
# ---------------------------------------------------------------------------
@WIN32_ONLY
class TestNoLedgerWriteInsideTheSegment:
    """ADR 0026 excludes every ledger append by name.

    Needs a real ledger, so it is Windows-gated (ADR 0014) -- and deliberately
    so: the assertion is about writes that only happen when a ledger exists.
    """

    def test_every_ledger_append_falls_outside_both_spans(self, tmp_path):
        import time

        from src.harness import effect_ledger

        stamps: list[int] = []
        original = effect_ledger.LedgerWriter.append

        def stamped(self, event):
            stamps.append(time.perf_counter_ns())
            return original(self, event)

        effect_ledger.LedgerWriter.append = stamped
        try:
            runner = GoldenThreadRunner(ledger_dir=tmp_path)
            run = runner.run_scenario("gt-benign", B0Arm(), setup={})
        finally:
            effect_ledger.LedgerWriter.append = original

        assert stamps, "no ledger write happened, so the exclusion is untested"
        assert run.effects(), "the benign scenario must have produced an effect"
        for name in ("presentation", "boundary_verification"):
            start, end = run.timing.spans[name]
            inside = [s for s in stamps if start <= s <= end]
            assert inside == [], f"{len(inside)} ledger write(s) fell inside {name}"


# ---------------------------------------------------------------------------
# The audit sink: bounded, in-memory, and anything else refused
# ---------------------------------------------------------------------------
class TestTheAuditSinkIsBoundedAndInMemory:
    def test_an_arbitrary_callable_is_refused(self):
        """A sink that could open a file or a socket inside `decide` is not
        accepted at all, rather than trusted not to."""

        def writes_to_disk(record):
            with open("audit.jsonl", "a", encoding="utf-8") as handle:
                handle.write("x")

        with pytest.raises(AuditSinkError) as raised:
            CapabilityDecisionPath(
                gamma_document={},
                registry_view=None,
                oauth_config=None,
                policy=None,
                arm_identity=None,
                audit_buffer=writes_to_disk,
            )
        assert "ADR 0026" in str(raised.value)

    def test_a_plain_list_append_is_refused_too(self):
        """Even a harmless callable: the seam accepts one TYPE, so the
        guarantee does not depend on inspecting what a callable happens to do.
        """
        with pytest.raises(AuditSinkError):
            CapabilityDecisionPath(
                gamma_document={},
                registry_view=None,
                oauth_config=None,
                policy=None,
                arm_identity=None,
                audit_buffer=[].append,
            )

    def test_the_buffer_append_performs_no_io(self, monkeypatch):
        """The positive arm, proven rather than asserted: `open` and
        `socket.socket` are trapped for the duration of a real append."""

        def refuse(*args, **kwargs):
            raise AssertionError("the audit buffer performed I/O inside the segment")

        buffer = BoundedAuditBuffer()
        monkeypatch.setattr(builtins, "open", refuse)
        monkeypatch.setattr(socket, "socket", refuse)
        buffer.append({"reason_code": "b3_admitted"})
        assert len(buffer) == 1
        assert buffer[-1]["reason_code"] == "b3_admitted"

    def test_the_buffer_is_bounded_and_counts_what_it_drops(self):
        buffer = BoundedAuditBuffer(capacity=3)
        for index in range(5):
            buffer.append({"n": index})
        assert len(buffer) == 3
        assert buffer.dropped == 2
        assert [record["n"] for record in buffer] == [2, 3, 4]

    def test_overflow_drops_rather_than_denying(self):
        """Deliberately the OPPOSITE of the `jti` cache's fail-closed overflow.

        SS E.5: `audit` never sits on the decision path, so a sink failure may
        cost log completeness and never a prevention outcome. Turning an audit
        overflow into a denial would make logging load-bearing.
        """
        buffer = BoundedAuditBuffer(capacity=1)
        buffer.append({"n": 0})
        buffer.append({"n": 1})  # must not raise
        assert len(buffer) == 1 and buffer.dropped == 1
        # Negative arm: a non-positive capacity is a configuration error, and
        # that IS refused -- so the tolerance above is about overflow only.
        with pytest.raises(AuditSinkError):
            BoundedAuditBuffer(capacity=0)

    def test_b3_uses_one(self):
        from src.sut.baselines.b3 import B3Arm

        assert isinstance(B3Arm().audit_log, BoundedAuditBuffer)

    def test_the_runner_drains_it_outside_the_segment(self):
        """`ScenarioRun.audit_log` is a plain list, read after both spans close."""
        source = RUNNER_SOURCE.read_text(encoding="utf-8")
        bodies = _marked_span_bodies()
        for name in ("presentation", "boundary_verification"):
            rendered = "\n".join(ast.dump(stmt) for stmt in bodies[name])
            assert "audit_log" not in rendered
        assert 'audit_log=list(getattr(arm, "audit_log", []))' in source
