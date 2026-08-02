"""The construct-validity threats that will be LIVE at seal time (EXP7 STEP 9).

Two notes are carried forward rather than closed, and the risk with a carried
note is not that it is wrong — it is that a later green gate makes a reader
take it for discharged. So each is asserted here: **present, legible, and not
described as closed.**

* **§J.5 item 20** — `raw_arguments` is the harness's canonical re-serialization
  of what the boundary observed, not bytes captured off a wire; and ADR 0020's
  in-process A2A adapter means no conclusion about A2A *transport* behaviour may
  be drawn from any run in this study. Item 20 originally flagged the first half
  *"for the G-12 task specification"* — and **G-12 has since passed without
  closing it**, which is exactly the shape that reads as discharged.
* **§J.5 item 22** — ADR 0034's scope limit: G-9 established multi-process
  soundness of the *mechanism*, on the arbiter; the ladder's `B3⁺` is measured
  single-process only.

And one comment, not an ADR: **G-9's `FILL_TIMEOUT` is a timeout budget, not a
performance baseline.** Nothing in that spike is measured, and 900 is not a
claim that anything takes 900 seconds.

These are documentation assertions, and they are deliberately about **meaning
rather than wording**: each looks for the load-bearing phrase, not for a
sentence a reformat would break.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DESIGN = REPO_ROOT / "docs" / "EXPERIMENT_ARCHITECTURE_FINAL.md"
G9_SPIKE = REPO_ROOT / "smoke" / "g9" / "spike.py"


def _j5_item(number: int) -> str:
    """One numbered §J.5 item, flattened to one line."""
    text = DESIGN.read_text(encoding="utf-8")
    match = re.search(rf"^{number}\. \*\*(.+?)(?=^\d+\. \*\*|^## )", text, re.M | re.S)
    assert match, f"§J.5 item {number} not found"
    return " ".join(match.group(0).split())


class TestItem20StaysLive:
    def test_it_states_the_raw_arguments_threat_in_readable_terms(self):
        item = _j5_item(20)
        assert "raw_arguments" in item
        assert "canonical" in item and "wire bytes" in item

    def test_it_states_ADR_0020s_transport_threat(self):
        item = _j5_item(20)
        assert "ADR 0020" in item
        assert "transport" in item
        # The enumeration gap ADR 0020 records: Part G defines no A2A gate.
        assert "no A2A gate" in item or "defines none" in item

    def test_a_PASSED_G12_is_not_allowed_to_read_as_closure(self):
        """The specific failure mode this test exists for.

        Item 20 flagged `raw_arguments` "for the G-12 task specification".
        G-12 has passed. Without an explicit note, a reader checking the gate
        board would reasonably conclude the item was handled.
        """
        item = _j5_item(20)
        assert "G-12" in item
        assert "did NOT close" in item or "did not close" in item
        assert "LIVE" in item or "live" in item

    def test_it_is_not_described_as_closed(self):
        item = _j5_item(20)
        for closure in ("now closed", "is closed", "resolved by", "discharged by G-12"):
            assert closure not in item, closure

    def test_the_obligation_still_has_no_gate_assigned(self):
        """Honest state: the gate it was flagged to has passed, so the
        obligation is now unassigned rather than owned by someone."""
        item = _j5_item(20)
        assert "no gate assigned" in item


class TestItem22RecordsADR0034sScopeLimit:
    def test_it_separates_what_G9_established_from_what_the_ladder_measures(self):
        item = _j5_item(22)
        assert "ADR 0034" in item
        assert "arbiter" in item
        assert "single-process" in item

    def test_it_forbids_the_specific_misreading(self):
        """A green G-9 must not be read as "the ladder arm has multi-process
        atomicity"."""
        item = _j5_item(22)
        assert "does not license" in item
        assert "multi-process atomicity" in item

    def test_it_says_the_unmeasured_configuration_out_loud(self):
        item = _j5_item(22)
        assert "this study does not measure that configuration" in item

    def test_the_deferral_is_a_decision_not_an_absence(self):
        item = _j5_item(22)
        assert "decision rather than an absence" in item
        assert "RemoteJtiCache" in item


class TestG9sFillTimeoutIsABudgetNotABaseline:
    def test_the_spike_says_so_in_one_comment_line(self):
        source = G9_SPIKE.read_text(encoding="utf-8")
        assert "TIMEOUT BUDGET, NOT A PERFORMANCE BASELINE" in source

    def test_it_says_900_is_not_a_claim_about_duration(self):
        source = G9_SPIKE.read_text(encoding="utf-8")
        assert "not a claim that anything takes 900" in source

    def test_the_reason_is_an_OPERATION_COUNT_not_a_timing(self):
        """The quadratic fill is stated as scan steps — arithmetic from the
        frozen capacity, not a measurement (EXP6/EXP7 forbidden action 1)."""
        report = (REPO_ROOT / "smoke" / "g9" / "REPORT.md").read_text(encoding="utf-8")
        assert "2,147,450,880" in report
        assert "scan steps" in report

    def test_no_ADR_was_written_for_it(self):
        """STEP 9: one comment line in the spike; no ADR."""
        adrs = list((REPO_ROOT / "adr").glob("*.md"))
        for path in adrs:
            assert "FILL_TIMEOUT" not in path.read_text(encoding="utf-8"), path.name
