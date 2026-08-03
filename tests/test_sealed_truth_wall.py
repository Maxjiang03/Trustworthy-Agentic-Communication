"""The sealed-truth wall (PROJECT_RULES.md red line 5; SS A.3; EXP1 STEP 8 item 5).

The test the specification demands: one that FAILS if a SUT module can reach
sealed truth. `test_sut_module_is_refused` constructs a real module whose
`__name__` lives under `src.sut` and calls the accessor from inside it; if
the accessor ever returns the document instead of raising, that test fails.
The positive arm proves the same call succeeds from harness/test context, so
the refusal is attributable to the caller's identity and nothing else.
"""

import types

import pytest

from src.harness import sealed_truth


class TestHarnessAccess:
    def test_harness_context_reads_sealed_truth(self):
        document = sealed_truth.load_sealed("gt-benign")
        assert document["tau_gt"] == [["notes.write", "notes/project"]]
        assert document["scenario_id"] == "gt-benign"

    def test_unknown_scenario_fails_closed(self):
        with pytest.raises(sealed_truth.SealedTruthAccessError):
            sealed_truth.load_sealed("gt-nonexistent")

    def test_unknown_corpus_fails_closed(self):
        with pytest.raises(sealed_truth.SealedTruthAccessError):
            sealed_truth.load_sealed("gt-benign", corpus="confirmatory")


class TestSutIsWalledOff:
    def _module_named(self, name: str) -> types.ModuleType:
        """A real module object executing under the given __name__."""
        module = types.ModuleType(name)
        source = (
            "from src.harness import sealed_truth\n"
            "def grab(scenario_id):\n"
            "    return sealed_truth.load_sealed(scenario_id)\n"
        )
        exec(compile(source, f"<{name}>", "exec"), module.__dict__)
        return module

    def test_sut_module_is_refused(self):
        """FAILS if a SUT module can reach sealed truth (the STEP 8 test)."""
        sut_module = self._module_named("src.sut.agents.rogue")
        with pytest.raises(sealed_truth.SealedTruthAccessError):
            sut_module.grab("gt-benign")

    def test_the_refusal_is_about_identity_not_the_call_shape(self):
        # Negative arm: the byte-identical call from a NON-sut module name
        # succeeds, so the wall discriminates on caller identity alone.
        harness_module = self._module_named("tests.helper.not_sut")
        document = harness_module.grab("gt-benign")
        assert document["scenario_id"] == "gt-benign"

    def test_sut_frames_anywhere_in_the_stack_are_refused(self):
        # Defense in depth: sealed truth cannot be laundered through a helper
        # called FROM SUT code.
        sut_module = self._module_named("src.sut.baselines.rogue")
        # grab() itself calls through src.harness.sealed_truth; the SUT frame
        # sits below it on the stack and must still be seen.
        with pytest.raises(sealed_truth.SealedTruthAccessError):
            sut_module.grab("gt-f1-root")
