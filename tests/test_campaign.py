"""The campaign entry point, and the pilot matrix **from oracle verdicts** (STEP 6–8).

The first time this study scores itself. Every cell below is produced by
`src/harness/oracle/`, which imports no SUT module and names no verdict field
(gate G-12's L2) — so `A`/`B` here comes from the trusted `MediationEvent` the
harness emitted, never from the arm's `(admitted, reason_code)` pair.

**Three comparisons, and STEP 8 is explicit that they are not the same thing:**

1. against **§E.4**, cell by cell;
2. against the **reason-code matrix** the existing suites report;
3. and the cells the oracle **cannot** score, named with the reason rather than
   filled in from a reason code.

Agreement with **§E.4** is the result: an independent recomputation from sealed
truth reproduces what the specification predicted. A disagreement would be a
finding, and neither the predicate nor the cell would be adjusted toward the
other.

Agreement with the **reason-code matrix** is weaker than it looks, and this
suite says so rather than banking it: the `A`/`B` column and the reason code
both trace to the same trusted `MediationEvent`, so their agreement is
**structural** — the record being internally consistent — not two independent
measurements coinciding. What the oracle genuinely adds is `reference_allow`
and `admission_breach`, which no reason code could produce, because
correctness is a relation between the decision and sealed truth and no reason
code has access to sealed truth.

Platform-independent: `ledger_backed=False`, so no Win32 handle is involved.
That has a consequence this file states rather than hides — **`realized_harm`
is not scored on these runs**, because with no ledger the absence of effect
records is indistinguishable from the absence of effects, and `False` would
read as *no harm*. `realized_harm` is exercised on constructed ledgers in
`tests/test_oracle_predicates.py`, where the evidence exists.

Nothing here is timed (EXP6 forbidden action 1) and no gate is run.
"""

import json
from pathlib import Path

import pytest

from src.harness import campaign as C
from src.harness import key_material
from src.harness import matrix_grouping as grouping
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# The F1 chain. F4/F5 run on the OTHER authority chain and under both monitor
# configurations, which `tests/test_f45_matrix.py` owns; this campaign run
# covers the ladder families, and the F4/F5 campaign cells are the reason
# `monitor_attached` is a REQUIRED argument rather than an optional one.
SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")

# §E.4's expected matrix for these rows, as the ORACLE reports it: `A` when the
# trusted mediation record says admitted, `B` when it does not.
_STRONG = grouping.STRONG
EXPECTED_E4: dict[tuple[str, str], str] = {}
for _arm in grouping.ARMS:
    EXPECTED_E4[("gt-benign", _arm)] = "A"
for _scenario in ("gt-f1-root", "gt-f1-terminal"):
    for _arm in grouping.ARMS:
        EXPECTED_E4[(_scenario, _arm)] = "B" if _arm in _STRONG else "A"
for _arm in _STRONG:
    EXPECTED_E4[("gt-f1-chain-tamper", _arm)] = "B"


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def as_document(runner):
    registry_document = reg.load_document()
    return golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def factories(runner, running_as, as_document):
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
    }
    broad = runner.b2_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor:broad"],
        ladder_grant="broad",
        **common,
    )
    task = runner.b2_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        ladder_grant="task",
        **common,
    )
    dpop = runner.b2_dpop_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_token_endpoint=as_document["token_endpoint"],
        **common,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B2-broad-noexchange": (B2BroadNoExchangeArm, broad),
        "B2-exchange-broad": (B2ExchangeBroadArm, broad),
        "B2-exchange-task": (B2ExchangeTaskArm, task),
        "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, dpop),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
        "B3+": (B3PlusArm, b3_setup),
    }


@pytest.fixture(scope="module")
def result(runner, factories, running_as):
    """One campaign over the pilot corpus, in-process. Run once."""
    return C.run_campaign(
        runner=runner,
        factories=factories,
        scenarios=SCENARIOS,
        seed=SEED,
        as_issuer=ISSUER,
        as_public_jwk=running_as.public_jwk,
        resource_server=AUDIENCE,
        rar_type="urn:aasc:mcp-invoke",
        sut_mode="in-process",
        run_mode="pilot",
        ledger_backed=False,
    )


# ---------------------------------------------------------------------------
# STEP 6 — one entry point, over ONE stack
# ---------------------------------------------------------------------------
class TestTheEntryPoint:
    def test_the_stack_is_not_duplicated(self):
        """Structural, as EXP5 STEP 3 asserted it for the two SUT modes."""
        C.the_stack_is_not_duplicated()  # raises if a second stack exists

    def test_it_covers_every_arm_and_every_applicable_scenario(self, result):
        covered = {(cell.scenario_id, cell.arm) for cell in result.cells}
        assert covered == set(EXPECTED_E4)
        assert {cell.arm for cell in result.cells} == set(grouping.ARMS)

    def test_every_part_I_quantity_is_recorded_SEPARATELY(self, result):
        """Part I reports them separately; the artifact keeps them separate."""
        payload = result.as_dict()
        for cell in payload["cells"]:
            for quantity in (
                "reference_allow",
                "observed_forwarded",
                "admission_breach",
                "realized_harm",
                "false_block",
                "log_integrity_failure",
            ):
                assert quantity in cell, quantity

    def test_the_reason_code_is_recorded_but_labelled_as_diagnosis(self, result):
        payload = result.as_dict()
        assert all("reason_code_FOR_DIAGNOSIS_ONLY" in cell for cell in payload["cells"])
        assert all("reason_code" not in cell for cell in payload["cells"])

    def test_nothing_in_the_scoring_path_reads_a_reason_code(self):
        """`score_cell` computes every quantity before it records one.

        Structural rather than a promise: the oracle module the quantities come
        from is the one G-12's L2 scan certifies, and `score_cell` passes it no
        reason code — the only `reason_code` mention is the recording line.
        """
        import inspect

        source = inspect.getsource(C.score_cell)
        scoring, _, recording = source.partition("return CellVerdict(")
        assert "reason_code" not in scoring
        assert "reason_code" in recording

    def test_no_timing_VALUE_reaches_the_artifact(self, result):
        """Forbidden action 1 forbids *producing* a latency number.

        The seams are carried as NAMES — evidence the segment was instrumented
        and correlated — and no duration appears anywhere in the artifact.
        """
        payload = json.dumps(result.as_dict())
        for cell in result.cells:
            assert set(cell.timing_seams) <= {
                "setup",
                "delegation",
                "presentation",
                "boundary_verification",
                "end_to_end",
            }
            assert all(isinstance(name, str) for name in cell.timing_seams)
        assert "timing_seams_recorded" in payload
        assert "boundary_verification_ns" not in payload

    def test_the_measured_segment_seams_were_captured(self, result):
        """ADR 0026's segment is `presentation + boundary_verification`."""
        for cell in result.cells:
            assert {"presentation", "boundary_verification"} <= set(cell.timing_seams)


# ---------------------------------------------------------------------------
# STEP 7 — the four fail-closed preconditions
# ---------------------------------------------------------------------------
class TestTheScenarioSetIsDerivedNotListed:
    """The gap: `run_campaign`'s only caller passed 4 of 13 scenarios.

    Nothing was wrong — every one of the nine had been read and verified in its
    own module — but the confirmatory campaign calls `run_campaign`, so the
    single sealed run would have produced `F1` results only and the absence
    would have looked like a corpus that never had the other families. Same
    shape as block 6's artifact-plumbing defect: unit tests green, the unified
    path missing something.

    A longer literal fixes today and not tomorrow. These assert the set is
    **derived**, so a scenario that exists is reachable without editing a tuple.
    """

    def test_the_derived_set_is_exactly_what_the_corpus_HOLDS(self):
        sealed = {p.stem for p in (CORPUS / "sealed").glob("*.json")}
        visible = {p.stem for p in (CORPUS / "sut_visible").glob("*.json")}
        assert set(C.corpus_scenarios(CORPUS)) == sealed == visible
        assert len(sealed) == 13

    def test_the_campaign_DEFAULTS_to_every_scenario(self):
        """`scenarios=None` means everything. A caller wanting a subset must
        narrow explicitly; the default is never a short list."""
        import inspect

        assert inspect.signature(C.run_campaign).parameters["scenarios"].default is None
        source = inspect.getsource(C.run_campaign)
        assert "corpus_scenarios(corpus_root) if scenarios is None" in source

    def test_THE_GUARD_FIRES_when_a_scenario_is_added_to_the_corpus(self):
        """**Shown failing, not assumed.** A guard that has never fired is not
        known to work.

        A scenario document is written into the corpus, the derivation is
        checked to pick it up while a hand-written list does not, and it is
        removed again. That is exactly how the present gap opened — silently,
        while everything was green.
        """
        stale_literal = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
        before = C.corpus_scenarios(CORPUS)
        assert set(stale_literal) < set(before)  # the gap, still visible

        intruder = CORPUS / "sealed" / "gt-zz-guard-probe.json"
        try:
            intruder.write_text(json.dumps({"scenario_id": "gt-zz-guard-probe"}), encoding="utf-8")
            after = C.corpus_scenarios(CORPUS)
            # The derivation notices. A literal cannot.
            assert "gt-zz-guard-probe" in after
            assert "gt-zz-guard-probe" not in stale_literal
            assert set(after) - set(before) == {"gt-zz-guard-probe"}
        finally:
            intruder.unlink(missing_ok=True)
        assert C.corpus_scenarios(CORPUS) == before  # reverted

    def test_the_configuration_families_are_derived_too(self):
        """From each sealed record's `attack_subcase`, so a new F4/F5 scenario
        joins by existing rather than by being remembered."""
        assert set(C.configuration_scenarios(CORPUS)) == {
            "gt-f4-declassified",
            "gt-f4-sensitive-egress",
            "gt-f5-approved",
            "gt-f5-unapproved-high-risk",
        }


class TestF45RefusesAConfigurationFreeCampaign:
    """**The decision, stated: the campaign REFUSES rather than guessing.**

    §E.4 marks those cells `A†` — admitted *absent* the shared monitor — so
    running them once under whichever configuration happened to be in force
    would be worse than not running them: it would produce a number that looks
    like a result (G-15). Full coverage is two runs, one per configuration.
    """

    def test_it_refuses_F4_F5_without_a_monitor_configuration(self):
        with pytest.raises(C.PreconditionFailed, match="CONFIGURATION family"):
            C.check_configuration_families(
                scenarios=C.corpus_scenarios(CORPUS), monitor_attached=None, corpus_root=CORPUS
            )

    def test_a_ladder_only_run_needs_no_configuration(self):
        C.check_configuration_families(
            scenarios=("gt-benign", "gt-f1-root"), monitor_attached=None, corpus_root=CORPUS
        )

    def test_either_configuration_is_accepted(self):
        for configured in (False, True):
            C.check_configuration_families(
                scenarios=C.corpus_scenarios(CORPUS),
                monitor_attached=configured,
                corpus_root=CORPUS,
            )


class TestPreconditionsFailClosed:
    def test_frozen_rows_and_hashes_are_checked(self):
        C.check_frozen_rows()  # the real documents agree; raises if they drift

    def test_a_confirmatory_run_refuses_a_pilot_fixture(self, factories):
        with pytest.raises(C.PreconditionFailed, match="fixtures/pilot"):
            C.check_run_mode(run_mode="confirmatory", corpus_root=CORPUS, arms=[])

    def test_an_unknown_run_mode_is_refused(self):
        with pytest.raises(C.PreconditionFailed, match="unknown run_mode"):
            C.check_run_mode(run_mode="whatever", corpus_root=CORPUS, arms=[])

    def test_a_ledger_backed_run_refuses_without_a_ledger_directory(self):
        import os

        if os.name != "nt":
            with pytest.raises(C.PreconditionFailed, match="does not degrade"):
                C.check_ledger_available(ledger_backed=True, ledger_dir=None)
        else:
            with pytest.raises(C.PreconditionFailed, match="ledger directory"):
                C.check_ledger_available(ledger_backed=True, ledger_dir=None)

    def test_an_F4_cell_without_its_monitor_configuration_is_refused(self):
        """Routed THROUGH `matrix_grouping`, not reimplemented beside it."""
        with pytest.raises(grouping.MatrixError, match="monitor configuration"):
            grouping.Cell(
                family="F4",
                subcase="F4:label-confusion:no-declassification",
                arm="B3",
                admitted=False,
                reason_code="",
                monitor_attached=None,
            )

    def test_the_campaign_refuses_before_provisioning_anything(self, runner, factories):
        """A misconfigured campaign costs nothing and leaves no partial table."""
        with pytest.raises(C.PreconditionFailed):
            C.run_campaign(
                runner=runner,
                factories=factories,
                scenarios=SCENARIOS,
                seed=SEED,
                as_issuer=ISSUER,
                as_public_jwk={},
                resource_server=AUDIENCE,
                rar_type="urn:aasc:mcp-invoke",
                run_mode="confirmatory",
                corpus_root=CORPUS,
            )


class TestADR0034TheCampaignIsSingleProcess:
    """The Commander's ruling, enforced rather than written down (EXP7 STEP 8).

    Gate G-9 established multi-process atomicity **on the arbiter**; the
    ladder's `B3⁺` carries its own in-process `JtiCache`. Those are two claims
    about two different objects, and a confirmatory campaign may not be
    multi-process while the second is still true — or the F3 replay row would
    be measured under a configuration §E.4 never predicted a cell for.
    """

    def test_a_confirmatory_multi_process_run_is_REFUSED(self):
        with pytest.raises(C.PreconditionFailed, match="SINGLE-PROCESS"):
            C.check_single_process_campaign(run_mode="confirmatory", sut_mode="separate")

    def test_a_confirmatory_in_process_run_is_allowed(self):
        C.check_single_process_campaign(run_mode="confirmatory", sut_mode="in-process")

    def test_the_PILOT_may_still_run_multi_process(self):
        """The pilot is where the configuration is explored — EXP5 STEP 13
        measured the cross-process behaviour deliberately, in order to find
        this. What must not happen is a SEALED campaign doing it."""
        C.check_single_process_campaign(run_mode="pilot", sut_mode="separate")

    def test_the_refusal_is_keyed_on_the_SEAM_not_on_a_constant(self):
        """So it lifts by itself when a baseline reaches the arbiter.

        Today no baseline does, which is what makes the constraint bind; the
        check encodes *the reason* rather than *the current answer*.
        """
        assert C.ladder_reaches_the_arbiter() is False
        baselines = REPO_ROOT / "src" / "sut" / "baselines"
        for path in sorted(baselines.glob("*.py")):
            assert "RemoteJtiCache" not in path.read_text(encoding="utf-8"), path.name

    def test_the_refusal_names_why_rather_than_just_refusing(self):
        with pytest.raises(C.PreconditionFailed) as raised:
            C.check_single_process_campaign(run_mode="confirmatory", sut_mode="separate")
        message = str(raised.value)
        assert "ADR 0034" in message
        assert "per arm instance" in message
        assert "ARBITER" in message

    def test_the_campaign_routes_through_the_check(self, runner, factories):
        """Not merely available — actually called by `run_campaign`."""
        import inspect

        assert "check_single_process_campaign(" in inspect.getsource(C.run_campaign)


class TestTheRunRecord:
    def test_it_captures_what_part_H_step_6_will_hash(self, result):
        record = result.record.as_dict()
        for key in (
            "git_commit",
            "git_dirty",
            "h_gamma",
            "h_registry",
            "h_policy",
            "frozen_rows",
            "sut_mode",
            "run_mode",
            "platform",
            "python",
            "corpus",
        ):
            assert key in record
        assert record["sut_mode"] == "in-process"
        assert record["run_mode"] == "pilot"
        assert len(record["h_gamma"]) == 64

    def test_it_carries_no_secret(self, result):
        """Red line 8: no key, token or seed reaches the artifact."""
        payload = json.dumps(result.as_dict()).lower()
        for forbidden in ("private", "secret", "seed", "bearer ", "eyj"):
            assert forbidden not in payload


# ---------------------------------------------------------------------------
# STEP 8 — the matrix, FROM ORACLE VERDICTS, compared three ways
# ---------------------------------------------------------------------------
class TestTheOracleMatrix:
    @pytest.mark.parametrize("cell", sorted(EXPECTED_E4))
    def test_the_oracle_cell_agrees_with_E4(self, result, cell):
        """A disagreement is a FINDING; neither side may be adjusted."""
        produced = result.matrix()[cell]
        assert produced == EXPECTED_E4[cell], (
            f"{cell}: the ORACLE reports {produced}, §E.4 predicts {EXPECTED_E4[cell]} — a "
            "disagreement is a finding, and neither the predicate nor the cell may be adjusted "
            "toward the other"
        )

    def test_the_oracle_matrix_agrees_with_the_reason_code_matrix(self, result):
        """STEP 8's second comparison — and what it does **not** establish.

        Both readings trace to the SAME trusted `MediationEvent`: `admitted` is
        the field the boundary gated execution on, and `reason_code` is the
        label it recorded beside it. So their agreement is **structural, not
        evidential** — it confirms the record is internally consistent, and it
        is not two independent measurements coinciding. Recording it as the
        latter would overstate what this comparison can support, which is why
        the claim is written down here rather than left to a reader.

        What the oracle genuinely adds is not this column but the ones below:
        `reference_allow` from sealed truth, and `admission_breach` from the
        two together. Those had no prior counterpart at all — the matrix suites
        compare an outcome to §E.4 and never ask whether the outcome was right.
        """
        disagreements = []
        for cell in result.cells:
            from_reason_code = "A" if cell.reason_code in _ADMIT_CODES else "B"
            if from_reason_code != cell.oracle_outcome:
                disagreements.append(
                    (cell.scenario_id, cell.arm, cell.reason_code, cell.oracle_outcome)
                )
        assert not disagreements, (
            f"the mediation record is internally inconsistent: {disagreements}"
        )

    def test_the_oracle_adds_a_quantity_the_reason_code_matrix_CANNOT_produce(self, result):
        """The substantive half of STEP 8's comparison.

        A reason code says *what the arm did*. It cannot say whether that was
        **correct**, because correctness is a relation between the decision and
        sealed truth — and no reason code has access to sealed truth. This
        asserts the two are genuinely different quantities by finding cells
        where the outcome is identical and the judgement is opposite.

        `gt-benign`/`B0` and `gt-f1-root`/`B0` both read `A` with the same
        reason code, and exactly one of them is an `admission_breach`.
        """
        by_cell = result.by_cell()
        benign, attack = by_cell[("gt-benign", "B0")], by_cell[("gt-f1-root", "B0")]
        assert benign.oracle_outcome == attack.oracle_outcome == "A"
        assert benign.reason_code == attack.reason_code
        assert benign.admission_breach is False
        assert attack.admission_breach is True

    def test_reference_allow_is_what_separates_the_F1_rows(self, result):
        """Non-vacuity: the oracle's own reference decision, not the arm's.

        On the benign scenario the reference allows; on both F1 attacks it
        refuses, for every arm — because `R ⊄ C_n` is a property of the sealed
        scenario and not of the mechanism under test.
        """
        by_cell = result.by_cell()
        for arm in grouping.ARMS:
            assert by_cell[("gt-benign", arm)].reference_allow is True
            assert by_cell[("gt-f1-root", arm)].reference_allow is False
            assert by_cell[("gt-f1-terminal", arm)].reference_allow is False

    def test_admission_breach_fires_exactly_on_the_weak_arms(self, result):
        """The result this study exists to produce, computed independently.

        An `admission_breach` is the boundary admitting what the reference
        refuses. On `F1-root`/`F1-terminal` the four weak arms admit and the
        five strong ones do not — recomputed from sealed truth and the trusted
        record, with no reason code involved.
        """
        by_cell = result.by_cell()
        for scenario in ("gt-f1-root", "gt-f1-terminal"):
            breached = {arm for arm in grouping.ARMS if by_cell[(scenario, arm)].admission_breach}
            assert breached == set(grouping.ARMS) - set(_STRONG), scenario

    def test_no_false_block_on_the_benign_control(self, result):
        """Every arm forwards the benign call, so no arm false-blocks it."""
        by_cell = result.by_cell()
        for arm in grouping.ARMS:
            assert by_cell[("gt-benign", arm)].false_block is False

    def test_blocking_an_attack_is_never_scored_as_a_false_block(self, result):
        for cell in result.cells:
            if cell.scenario_id != "gt-benign":
                assert cell.false_block is False

    def test_the_unscorable_cells_are_NAMED_with_their_reason(self, result):
        """STEP 8's third outcome: say which and why, never fall back to a
        reason code."""
        na_arms = {(scenario, arm) for scenario, arm, _ in result.unscorable}
        assert na_arms == {("gt-f1-chain-tamper", arm) for arm in set(grouping.ARMS) - set(_STRONG)}
        assert all(reason for _, _, reason in result.unscorable)

    def test_realized_harm_is_NOT_SCORED_without_a_ledger_and_says_so(self, result):
        """`None`, never `False`. `False` would read as *no harm*."""
        for cell in result.cells:
            assert cell.realized_harm is None
            assert "no effect ledger" in cell.note

    def test_the_confirmatory_corpus_carries_no_scenario(self):
        """Red line 1, asserted rather than remembered.

        What the red line forbids is a **scenario file** before sealing, not
        the directory's own `README.md` — which exists precisely to say the
        directory is empty by design. Asserting "no files at all" would fail on
        the marker that documents the rule, so this asserts the rule instead:
        no scenario data, no `sealed/`, no `sut_visible/`.
        """
        confirmatory = REPO_ROOT / "fixtures" / "confirmatory"
        scenarios = [
            path
            for path in confirmatory.glob("**/*")
            if path.is_file() and path.name not in (".gitkeep", "README.md")
        ]
        assert scenarios == [], f"fixtures/confirmatory/ carries scenario data: {scenarios}"
        assert not (confirmatory / "sealed").exists()
        assert not (confirmatory / "sut_visible").exists()


# The reason codes that mean "admitted", used ONLY to build the comparison
# matrix in `test_the_oracle_matrix_agrees_with_the_reason_code_matrix`. It is
# deliberately defined in the test file and not in `src/harness/`: nothing in
# the scoring path may map a reason code to an outcome.
_ADMIT_CODES = frozenset({"b0_no_boundary_check", "b1_admitted", "b2_admitted", "b3_admitted"})
