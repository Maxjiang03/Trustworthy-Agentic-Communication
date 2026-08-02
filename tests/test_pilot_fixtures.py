"""Regression suite for the golden-thread pilot corpus (ADR 0007, EXP1 STEP 4).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: the committed documents match a deterministic
regeneration; the authority sets in the sealed truth are what the frozen
authorizer computes (never hand-written); the SUT-visible/sealed separation
holds; and `fixtures/confirmatory/` stays empty (CLAUDE.md red line 1).
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"

spec = importlib.util.spec_from_file_location("gt_generator", CORPUS_DIR / "generator.py")
generator = importlib.util.module_from_spec(spec)
sys.modules.setdefault("gt_generator", generator)
spec.loader.exec_module(generator)


@pytest.fixture(scope="module")
def regenerated() -> dict[str, dict]:
    """One in-memory regeneration (write=False): compute + verify, no I/O."""
    return generator.generate(write=False)


def _read(relative: str) -> dict:
    return json.loads((CORPUS_DIR / relative).read_text(encoding="utf-8"))


class TestCommittedDocumentsMatchRegeneration:
    def test_every_document_matches(self, regenerated):
        for relative, document in regenerated.items():
            assert _read(relative) == document, f"{relative} has drifted from the generator"

    def test_the_comparison_is_not_vacuous(self, regenerated):
        mutated = dict(regenerated["sealed/gt-benign.json"], tau_gt=[["mail.send", "mail/outbox"]])
        assert mutated != _read("sealed/gt-benign.json")


class TestComputedAuthoritySets:
    def test_c0_c1_computed_equal_spec(self):
        c0, c1 = generator.compute_authority_sets()
        assert c0 == frozenset((a, r) for a, r in map(tuple, generator.U_TASK_SPEC))
        assert c1 == frozenset((a, r) for a, r in map(tuple, generator.C1_SPEC))

    def test_narrowing_is_strict(self):
        # C_1 is a strict subset of C_0: hop 1 genuinely narrowed something,
        # which is what makes gt-f1-terminal distinguish per-hop narrowing
        # from root-only enforcement (SS E.3).
        c0, c1 = generator.compute_authority_sets()
        assert c1 < c0
        assert ("calendar.read", "calendar/work") in c0 - c1

    def test_scenario_relations_hold(self):
        """Each scenario checked against ITS OWN chain's computed sets.

        The corpus carries two chains since the F4/F5 families joined it: those
        run on a chain that includes `(mail.send, mail/outbox)` and
        `(notes.delete, notes/project)` so that `containment_ok` cannot refuse
        a labelled egress before `context_policy_ok` runs.
        """
        generator.check_scenario_relations(self._sets_by_chain())

    @staticmethod
    def _sets_by_chain():
        sets = {}
        for scenario in generator.SCENARIOS:
            key = generator._chain_of(scenario)
            if key not in sets:
                sets[key] = generator.compute_authority_sets(
                    [list(pair) for pair in key[0]], [list(pair) for pair in key[1]]
                )
        return sets

    def test_there_really_are_two_chains(self):
        """Negative arm for the above: if the corpus collapsed to one chain,
        every F4/F5 fixture would be masked by containment and the per-chain
        machinery would be checking nothing."""
        chains = {generator._chain_of(s) for s in generator.SCENARIOS}
        assert len(chains) == 2
        f45 = generator._chain_of(
            next(s for s in generator.SCENARIOS if s["scenario_id"] == "gt-f4-sensitive-egress")
        )
        assert ("mail.send", "mail/outbox") in f45[1]  # inside C_1, so containment passes
        assert ("notes.delete", "notes/project") in f45[1]

    def test_relation_check_is_not_vacuous(self):
        # Negative arm: refuted relations must raise.
        empty = dict.fromkeys(
            {generator._chain_of(s) for s in generator.SCENARIOS}, (frozenset(), frozenset())
        )
        with pytest.raises(SystemExit):
            generator.check_scenario_relations(empty)


class TestVisibleSealedSeparation:
    SEALED_ONLY_KEYS = {"tau_gt", "R", "C_sets", "U_task", "intended_request_digest"}

    def test_sut_visible_reveals_no_sealed_field(self, regenerated):
        for relative, document in regenerated.items():
            if not relative.startswith("sut_visible/"):
                continue
            leaked = self.SEALED_ONLY_KEYS & set(document)
            assert leaked == set(), f"{relative} leaks sealed fields: {leaked}"

    def test_sealed_documents_do_carry_them(self, regenerated):
        # Negative arm: the key set is real, not a check against nothing.
        for relative, document in regenerated.items():
            if relative.startswith("sealed/"):
                assert self.SEALED_ONLY_KEYS <= set(document)

    def test_tau_gt_is_the_benign_requirement_of_its_own_family(self, regenerated):
        """`tau_gt` is the ground-truth TASK-required scope, per family.

        For the F1 family the task is the benign golden thread and the attacks
        are the Specialist exceeding it. The F4/F5 families ask a different
        question -- may this DATA leave, was this ACTION approved -- so their
        task legitimately requires the action itself, and a `tau_gt` of
        `notes.write` there would make every arm look like it over-reached on a
        request that was within its authority all along.
        """
        expected = {
            "gt-benign": [["notes.write", "notes/project"]],
            "gt-f1-root": [["notes.write", "notes/project"]],
            "gt-f1-terminal": [["notes.write", "notes/project"]],
            "gt-f1-chain-tamper": [["notes.write", "notes/project"]],
            "gt-f4-sensitive-egress": [["mail.send", "mail/outbox"]],
            "gt-f4-declassified": [["mail.send", "mail/outbox"]],
            "gt-f5-unapproved-high-risk": [["notes.delete", "notes/project"]],
            "gt-f5-approved": [["notes.delete", "notes/project"]],
        }
        for relative, document in regenerated.items():
            if relative.startswith("sealed/"):
                scenario_id = relative[len("sealed/") : -len(".json")]
                assert document["tau_gt"] == expected[scenario_id], scenario_id

    def test_attack_scenarios_R_differs_from_tau_gt(self, regenerated):
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            document = regenerated[f"sealed/{scenario_id}.json"]
            assert document["R"] != document["tau_gt"]


class TestTheNAReasonIsMachineCheckable:
    """ADR 0035's adopted test, verified rather than trusted.

    A right answer resting on a reason we overruled would be re-derived wrongly
    by whoever reads it next, so every `NA` names the row its instance would
    duplicate -- and that row must actually score the arm `A`, or the reason is
    a story.
    """

    def test_every_NA_group_names_the_row_it_would_duplicate(self, regenerated):
        found = 0
        for relative, document in regenerated.items():
            if not relative.startswith("sealed/"):
                continue
            na = document["not_applicable"]
            if not na["arms"]:
                continue
            found += 1
            assert na["would_duplicate"], f"{relative}: NA arms with no duplicated row named"
            assert na["would_duplicate"] != document["scenario_id"]
            assert f"sealed/{na['would_duplicate']}.json" in regenerated
        assert found >= 1, "no NA group found; this test would be vacuous"

    def test_the_duplicated_row_exists_and_is_a_DIFFERENT_scenario(self, regenerated):
        chain_tamper = regenerated["sealed/gt-f1-chain-tamper.json"]
        assert chain_tamper["not_applicable"]["would_duplicate"] == "gt-f1-root"
        duplicated = regenerated["sealed/gt-f1-root.json"]
        # Byte-identical in the way that matters: same tool, same arguments'
        # digest, same required authority. That is WHY scoring both would
        # double-count one instance.
        assert duplicated["tool"] == chain_tamper["tool"]
        assert duplicated["R"] == chain_tamper["R"]
        assert duplicated["intended_request_digest"] == chain_tamper["intended_request_digest"]

    def test_a_scenario_with_no_NA_arms_needs_no_duplicated_row(self, regenerated):
        benign = regenerated["sealed/gt-benign.json"]
        assert benign["not_applicable"]["arms"] == []


class TestRedLines:
    def test_confirmatory_stays_empty(self):
        confirmatory = REPO_ROOT / "fixtures" / "confirmatory"
        extras = [p.name for p in confirmatory.iterdir() if p.name != "README.md"]
        assert extras == [], "fixtures/confirmatory/ must stay empty until sealing (red line 1)"

    def test_no_token_bytes_in_any_document(self, regenerated):
        # ADR 0007: specs and seeds, never minted tokens. A Biscuit container
        # would surface as a long base64/hex blob; assert no string value is
        # remotely token-sized apart from the declared seed.
        for relative, document in regenerated.items():
            for key, value in document.items():
                if key in ("seed_hex", "_banner", "intended_request_digest"):
                    continue
                if isinstance(value, str):
                    assert len(value) < 200, f"{relative}:{key} looks like minted material"
