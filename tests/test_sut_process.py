"""SUT process separation: the three properties, and the channel as an attack surface.

EXP5 STEP 3–4. Gates G-6 and G-7 each carry a residual naming SUT process
separation and deferring it to G-12 — *"in-process raw-reference/introspection
paths"* and *"in-process reachability inside the harness process"*. Until this
module those were excluded by **assumption**. Every test below is written so it
would **fail** if the SUT ran in the harness process.

Platform-independent: no effect ledger is opened here.
"""

import ast
import json
import os
from pathlib import Path

import pytest

from src.harness.sut_process import (
    HARNESS_TYPES_A_CORESIDENT_SUT_COULD_REACH,
    SutProcess,
    decode,
    encode,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sut():
    with SutProcess() as process:
        yield process


class TestPropertyOneNoSharedObjectGraph:
    """The residual G-6 and G-7 both deferred, now measured rather than assumed."""

    def test_the_sut_runs_in_a_different_process(self, sut):
        assert sut.pid != os.getpid()
        assert sut.call("ping")["pid"] == sut.pid

    def test_no_harness_object_is_reachable_from_the_sut(self, sut):
        """The introspection path, swept for INSIDE the child.

        In-process, `gc.get_objects()` finds the ledger writer, the effector,
        the mediation boundary and the runner — a co-resident SUT could reach
        past both gates by holding a reference. Across a process boundary the
        count is zero because the objects are in another address space.
        """
        sweep = sut.call("gc_sweep", types=list(HARNESS_TYPES_A_CORESIDENT_SUT_COULD_REACH))
        assert sweep["found"] == dict.fromkeys(HARNESS_TYPES_A_CORESIDENT_SUT_COULD_REACH, 0)

    def test_the_sweep_is_not_vacuous(self, sut):
        """Negative arm: the same sweep DOES find a type the child really has,
        so a zero above is an absence rather than a broken sweep."""
        sweep = sut.call("gc_sweep", types=["Session", "dict"])
        assert sweep["found"]["dict"] > 0

    def test_no_harness_module_is_even_loaded_in_the_sut(self, sut):
        """Red line 6 as a runtime measurement rather than an import scan: a
        future edit that pulled harness code into the SUT process shows up as a
        number, not as a review miss."""
        assert sut.call("gc_sweep", types=[])["harness_modules"] == []


class TestPropertyTwoTheLedgerWriterStaysInTheParent:
    def test_the_child_is_handed_no_ledger_path_and_no_writer(self, sut):
        """ADR 0014's Win32 exclusive-share handle is what makes the ledger
        unforgeable; a child holding it would defeat what G-7 established."""
        sweep = sut.call("gc_sweep", types=["LedgerWriter", "LedgerEffector"])
        assert sweep["found"] == {"LedgerWriter": 0, "LedgerEffector": 0}

    def test_the_channel_exposes_no_ledger_operation(self, sut):
        """Structural: the child's operation vocabulary is closed and contains
        nothing that could open, append to or truncate a ledger."""
        for forbidden in ("ledger", "write", "append", "truncate", "delete", "open"):
            assert not any(forbidden in op for op in sut.operations), sut.operations

    def test_an_unknown_operation_is_refused_rather_than_dispatched(self, sut):
        reply = sut.call("ledger_append", path="x", row={})
        assert reply["error"] == "unknown-op"
        assert sut.alive


class TestPropertyThreeTheChannelCarriesDataNotCapability:
    def test_the_codec_is_json_and_not_pickle(self):
        """`pickle` would make the channel a CAPABILITY channel — it
        reconstructs arbitrary objects and can execute code on load. JSON has
        no representation for a callable, a handle or a live object graph, so
        property 3 holds by construction of the codec."""
        for relative in ("src/harness/sut_process.py", "src/sut/sut_process/wire.py"):
            source = (REPO_ROOT / relative).read_text(encoding="utf-8")
            imported = set()
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            assert "json" in imported
            for capability_codec in ("pickle", "marshal", "shelve", "dill", "cloudpickle"):
                assert capability_codec not in imported, (relative, capability_codec)

    def test_bytes_survive_the_round_trip_in_one_explicit_tagged_form(self):
        material = {"kappa_private": b"\x00\xff\x10", "nested": [b"ab", {"k": b""}]}
        assert decode(json.loads(json.dumps(encode(material)))) == material

    def test_an_ordinary_string_is_never_coerced_into_bytes(self):
        """Decoding is total and shape-blind: no string becomes bytes by
        accident, so a value cannot change type crossing the boundary."""
        assert decode({"x": "00ff10"}) == {"x": "00ff10"}
        assert decode({"__bytes__": "00ff10", "extra": 1}) == {"__bytes__": "00ff10", "extra": 1}

    def test_the_harness_never_imports_the_sut_process_package(self):
        """Spawn, never import — ADR 0015 rule 4, applied to the SUT. Importing
        it to reach its codec would put SUT code back in the harness process
        and undo the separation."""
        source = (REPO_ROOT / "src" / "harness" / "sut_process.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("src.sut")
            elif isinstance(node, ast.Import):
                assert not any(alias.name.startswith("src.sut") for alias in node.names)


class TestTheChannelAsAnAttackSurface:
    """STEP 4: a new IPC channel is a new way to leak."""

    @pytest.mark.parametrize(
        "field", ["tau_gt", "IntendedInvocation", "C_sets", "R", "intended_request_digest"]
    )
    def test_a_sealed_field_request_gets_nothing_and_is_recorded(self, sut, field):
        reply = sut.call("sealed", field=field)
        assert reply["refused"] is True
        assert field in reply["refused_requests"]
        # Nothing that could be the value came back.
        assert not any(key in reply for key in ("value", "tau_gt", "C_sets", "sealed"))
        assert "no sealed object exists in the SUT process" in reply["reason"]

    def test_the_refusal_is_structural_not_a_policy_that_could_be_edited(self, sut):
        """There is nothing to withhold: this process is never handed a sealed
        object, so the refusal is not a branch someone could invert."""
        sweep = sut.call("gc_sweep", types=["IntendedInvocation"])
        assert sweep["found"]["IntendedInvocation"] == 0

    @pytest.mark.parametrize(
        "raw",
        [
            "{not json",
            "[]",
            '"a bare string"',
            "null",
            '{"op": 12345}',
            '{"no_op_key": true}',
        ],
    )
    def test_a_malformed_message_fails_closed_and_never_crashes_the_child(self, sut, raw):
        reply = sut.send_raw(raw)
        assert "error" in reply
        assert "ok" not in reply
        assert sut.alive
        # ...and the channel still works afterwards, so a malformed message is
        # not a denial-of-service on the run either.
        assert sut.call("ping")["pid"] == sut.pid

    def test_an_oversized_message_fails_closed(self, sut):
        reply = sut.send_raw(json.dumps({"op": "ping", "padding": "A" * 2_000_000}))
        # Either it is answered or it errors -- what it must never do is admit
        # something or take the process down.
        assert "ok" in reply or "error" in reply
        assert sut.alive

    def test_a_child_that_dies_mid_invocation_produces_a_recorded_outcome(self):
        """Not a hang and not a silent pass: an explicit error the harness
        turns into a fail-closed denial."""
        process = SutProcess()
        process.kill()
        reply = process.call("ping")
        assert "error" in reply
        assert reply["error"] in ("sut-process-dead", "sut-process-died-mid-invocation")
        assert process.alive is False

    def test_the_error_is_never_mistakable_for_an_admission(self):
        process = SutProcess()
        process.kill()
        reply = process.call("decide", tool="notes.write", arguments={})
        assert reply.get("decision") is not True
        assert reply.get("ok") is not True
        assert "error" in reply


class TestTheFaultVocabularyIsClosed:
    """G-12 will inject faults; the set the child implements is fixed and
    inspectable, so a fault the parent can ask for is one this module has."""

    def test_an_unknown_fault_is_refused_at_provision(self, sut):
        reply = sut.call("provision", arm="B0", setup={}, fault="make-everything-pass")
        assert "error" in reply
        assert "unknown fault" in reply.get("detail", "")

    def test_the_honest_run_is_the_default(self, sut):
        assert sut.call("ping")["fault"] == "none"
