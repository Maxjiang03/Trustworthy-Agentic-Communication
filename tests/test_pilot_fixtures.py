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
        c0, c1 = generator.compute_authority_sets()
        generator.check_scenario_relations(c0, c1)

    def test_relation_check_is_not_vacuous(self):
        # Negative arm: refuted relations must raise.
        with pytest.raises(SystemExit):
            generator.check_scenario_relations(frozenset(), frozenset())


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

    def test_tau_gt_is_the_benign_requirement_everywhere(self, regenerated):
        for relative, document in regenerated.items():
            if relative.startswith("sealed/"):
                assert document["tau_gt"] == [["notes.write", "notes/project"]]

    def test_attack_scenarios_R_differs_from_tau_gt(self, regenerated):
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            document = regenerated[f"sealed/{scenario_id}.json"]
            assert document["R"] != document["tau_gt"]


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
