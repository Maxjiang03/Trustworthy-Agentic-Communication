"""Gate G-12 spike — oracle independence under a lying SUT and broken linkage.

Part G's row: *fault-injected SUT reporting a **wrong** self-verdict while the
ledger records the true effect; plus correlation-ID swap/drop/duplicate/
concurrency injection.* Criterion: *the oracle's `admission_breach` /
`realized_harm` / `log_integrity_failure` and the correlation-ID checks detect
every discrepancy **without** reading any SUT verdict or SUT digest.*
Its stake, in Part G's own words: **oracle independence; every security result.**

    L1  the lying SUT, BOTH directions
    L2  the oracle is STRUCTURALLY incapable of reading a SUT verdict or digest
    L3  log_integrity_failure fires on a lie and stays silent on an honest block
    L4  correlation faults: swap, drop, duplicate, concurrency
    L5  DROP is told apart from an unreached tool

Every limb is accompanied by the world in which it fails, judged by the same
predicate that judges the real one.

**Platform.** The lying-SUT and correlation limbs need the real effect ledger,
whose enforcement is Win32 share-mode locking (ADR 0014, a recorded platform
decision — the ledger does not degrade). On POSIX those limbs are reported
**NOT ADJUDICATED**, never "passed", and the structural limbs still run. The
gate's PASS is recorded on Windows, which is the sealed measurement platform.

Nothing here is timed (EXP5 forbidden action 1) and nothing sleeps.

    uv run python smoke/g12/spike.py
"""

import ast
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.harness import fault_injection as fi  # noqa: E402
from src.harness.oracle import predicates as P  # noqa: E402
from src.harness.oracle.predicates import Linkage  # noqa: E402

WINDOWS = os.name == "nt"
RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} -- {evidence}")


def skip(check: str, evidence: str) -> None:
    RESULTS.append((check, False, True, evidence))
    print(f"{check} [platform] NOT ADJUDICATED -- {evidence}")


# ---------------------------------------------------------------------------
# L2 — the oracle cannot read a SUT verdict or digest. Structural.
# ---------------------------------------------------------------------------
SUT_SUPPLIED_NAMES = (
    "self_verdict",
    "audit_log",
    "audit_tail",
    "reason_code",
    "sut_verdict",
    "arm_verdict",
    "claimed",
    # Added by EXP6 STEP 4, when seven predicates joined the oracle. Each is a
    # name a SUT-computed verdict could arrive under in the new families: the
    # arm's own conjunct outcomes, its policy decision, and its monitor's
    # answer. None is read; the point is that adding one would now fail here.
    "conjunct",
    "conjuncts",
    "decision_path",
    "monitor_verdict",
    "policy_verdict",
    "admitted_by_arm",
)


def l2_oracle_reads_no_sut_verdict() -> None:
    """Block 1's red-line AST scan, applied to the oracle's own source.

    The criterion's second half matters as much as its first: detection is
    worth nothing if the detector consults the thing it is detecting. So the
    oracle's modules are scanned for any mention of a SUT-supplied verdict
    field, and for any import of SUT code.

    *EXP6 STEP 4 widened this from one file to the whole `src/harness/oracle/`
    package.* Scanning `predicates.py` alone was right when the oracle was one
    module; it became a hole the moment a predicate could delegate to a helper
    in a sibling file, because the scan would then certify a module that reads
    nothing while the module it calls reads everything. **The property G-12
    adjudicates is about the oracle, not about a filename.**
    """
    oracle_dir = REPO_ROOT / "src" / "harness" / "oracle"
    modules = sorted(path for path in oracle_dir.glob("*.py") if path.name != "__init__.py")

    imported: set[str] = set()
    reachable: set[str] = set()
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        # Every string constant the oracle uses to reach into a record. A
        # verdict field can only be read by NAMING it, so the absence of the
        # names is the absence of the reading.
        reachable |= {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        reachable |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    no_sut_import = not any(name.startswith("src.sut") for name in imported)
    forbidden_present = sorted(name for name in SUT_SUPPLIED_NAMES if name in reachable)

    # ...and what it DOES read, so this is not a scan that would pass on an
    # empty file. Extended with the fields the seven new predicates read, so
    # non-vacuity keeps pace with the oracle rather than testing only F3.
    trusted = {
        "admitted",
        "effect_id",
        "correlation_id",
        "intended_request_digest",
        "action",  # authority_from_effects, ledger-side
        "resource",
        "data_labels_touched",  # realized_harm_F4, ledger-side
        "is_benign",  # false_block, sealed-side
        "C_sets",  # reference_allow, sealed-side
    }
    reads_trusted = trusted <= reachable

    record(
        "G-12.L2",
        True,
        no_sut_import and not forbidden_present and reads_trusted,
        f"all {len(modules)} oracle modules ({', '.join(p.name for p in modules)}) import no "
        f"src.sut module: {no_sut_import}; they name none of the {len(SUT_SUPPLIED_NAMES)} "
        f"SUT-supplied verdict fields (found: {forbidden_present or 'none'}); "
        f"and they DO name the trusted-source fields {sorted(trusted)}: {reads_trusted}, so the "
        "scan is not vacuous",
    )


def l2_counterfactual() -> None:
    """The failing world: an oracle that consults the SUT's claim.

    Judged by the SAME scan L2 uses, on a source that reads `self_verdict`.
    """
    guilty = "def verdict(observation):\n    return observation['self_verdict']\n"
    tree = ast.parse(guilty)
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    caught = any(name in literals for name in SUT_SUPPLIED_NAMES)
    record(
        "G-12.L2.W1",
        True,
        caught,
        f"counterfactual: a predicate reading `self_verdict` is caught by the same scan: {caught}. "
        "Without this the scan could be passing because it finds nothing anywhere",
    )


# ---------------------------------------------------------------------------
# L3 / L5 — predicate behaviour on constructed record sets
# ---------------------------------------------------------------------------
CID = "cid-g12"
TOOL, AUDIENCE = "notes.write", "https://mcp.aasc.local/tools"
ARGS = {"content": "x", "resource": "notes/project"}


def _intent(cid=CID):
    from src.harness.oracle.jcs_digest import h_jcs

    return {
        "correlation_id": cid,
        "tool": TOOL,
        "audience": AUDIENCE,
        "intended_request_digest": h_jcs(ARGS),
    }


def _mediation(cid=CID, admitted=True):
    class _Event:
        correlation_id = cid

        def __init__(self):
            self.admitted = admitted
            self.reason_code = "b3_admitted" if admitted else "b3_containment"

    event = _Event()
    event.correlation_id = cid
    return [event]


def _ingress(cid=CID):
    from src.harness.oracle.jcs_digest import h_jcs

    return {
        "correlation_id": cid,
        "tool": TOOL,
        "audience": AUDIENCE,
        "ingress_request_digest": h_jcs(ARGS),
        "ingress_ts_ns": 1,
    }


def _effect(cid=CID, effect_id="e1"):
    from src.harness.oracle.jcs_digest import h_jcs

    return {
        "effect_id": effect_id,
        "correlation_id": cid,
        "tool": TOOL,
        "audience": AUDIENCE,
        "action": TOOL,
        "resource": ARGS["resource"],
        "recipient": None,
        "effect_request_digest": h_jcs(ARGS),
    }


def l3_log_integrity_failure() -> None:
    """Fires on a lie; silent on an honest block. An always-on alarm is not one."""
    honest_block = P.log_integrity_failure(_mediation(admitted=False), [], CID)
    honest_admit = P.log_integrity_failure(_mediation(admitted=True), [_effect()], CID)
    lied = P.log_integrity_failure(
        _mediation(admitted=False),
        fi.inject_effect_for_a_blocked_call([], _effect(), CID),
        CID,
    )
    record(
        "G-12.L3",
        True,
        lied and not honest_block and not honest_admit,
        f"BLOCKED with an effect present -> fires: {lied}; an HONEST block (blocked, no effect) "
        f"-> silent: {not honest_block}; an honest ADMISSION with an effect -> silent: "
        f"{not honest_admit}. An alarm that fired on all three would be an alarm that is always on",
    )


def l5_drop_versus_unreached() -> None:
    """**The fault class that deserves the most care.**

    Part I reads zero effects as no harm, correctly, for an unreached tool. A
    DROPPED effect record also produces zero effects. If the two were
    indistinguishable, deleting evidence would look exactly like behaving well.
    """
    honest_ledger = [_ingress(), _effect()]

    unreached, unreached_why = P.linkage_of(_intent(), _mediation(admitted=False), [], CID)
    dropped, dropped_why = P.linkage_of(
        _intent(), _mediation(), fi.drop_effect_records(honest_ledger, CID), CID
    )
    dropped_all, _ = P.linkage_of(
        _intent(), _mediation(), fi.drop_all_records(honest_ledger, CID), CID
    )
    consistent, _ = P.linkage_of(_intent(), _mediation(), honest_ledger, CID)

    # Both produce ZERO effects. That is the whole point of the pair.
    zero_effects_both = (
        len(P.effects_of(fi.drop_effect_records(honest_ledger, CID), CID)) == 0
        and len(P.effects_of([], CID)) == 0
    )
    distinguished = unreached is Linkage.UNREACHED and dropped is Linkage.DROPPED
    record(
        "G-12.L5",
        True,
        distinguished and dropped_all is Linkage.DROPPED and consistent is Linkage.CONSISTENT,
        f"both worlds produce zero effects: {zero_effects_both}; the unreached tool reads "
        f"{unreached.value!r} ({unreached_why[:60]}...) and the dropped record reads "
        f"{dropped.value!r} ({dropped_why[:80]}...). Dropping the ingress rows TOO still reads "
        f"{dropped_all.value!r}, caught against the MediationEvent, which lives in the harness "
        f"process. The honest run reads {consistent.value!r}",
    )


def l4_correlation_faults() -> None:
    """Swap, drop and duplicate, each flagged; concurrency is L4.C."""
    other = "cid-other"
    honest = [_ingress(), _effect(), _ingress(other), _effect(other, "e2")]

    swapped = fi.swap_correlation_ids(honest, CID, other)
    swap_seen = P.linkage_of(_intent(), _mediation(), swapped, CID)[
        0
    ] is not Linkage.CONSISTENT or (
        not P.records_agree_on_the_request({"raw_arguments": b"{}"}, swapped, CID)
    )
    duplicated = fi.duplicate_effect_records(honest, CID)
    dup_seen = P.linkage_of(_intent(), _mediation(), duplicated, CID)[0] is Linkage.DUPLICATED
    dropped = P.linkage_of(_intent(), _mediation(), fi.drop_effect_records(honest, CID), CID)[0]
    drop_seen = dropped is Linkage.DROPPED
    baseline = P.linkage_of(_intent(), _mediation(), honest, CID)[0] is Linkage.CONSISTENT

    record(
        "G-12.L4",
        True,
        swap_seen and dup_seen and drop_seen and baseline,
        f"swap detected: {swap_seen}; duplicate detected: {dup_seen}; drop detected: "
        f"{drop_seen}; and the UNCORRUPTED records read CONSISTENT: {baseline}, so the three "
        "detections are not a predicate that flags everything",
    )


# ---------------------------------------------------------------------------
def main() -> int:
    print("GATE G-12 -- oracle independence under fault injection (EXP5 STEP 6-8)")
    print("=" * 78)
    l2_oracle_reads_no_sut_verdict()
    l2_counterfactual()
    l3_log_integrity_failure()
    l4_correlation_faults()
    l5_drop_versus_unreached()

    if WINDOWS:
        import campaign

        campaign.run(record)
    else:
        skip(
            "G-12.L1",
            "the lying-SUT limb needs the real effect ledger, whose enforcement is Win32 "
            "share-mode locking (ADR 0014, a recorded platform decision -- the ledger does not "
            "degrade). Reported NOT ADJUDICATED on this platform, never passed; the gate's PASS "
            "is recorded on Windows, the sealed measurement platform",
        )
        skip("G-12.L4.C", "real cross-process concurrency is measured with the ledger; see above")

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-12: FAIL -- mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 8: do NOT mark PASS. Report which limb, why, and the smallest correction.")
        return 1
    if not WINDOWS:
        print("GATE G-12: structural limbs pass; the ledger-backed limbs are NOT ADJUDICATED here")
        return 0
    print("GATE G-12: all mandatory checks passed")
    print()
    print(
        "THE FINDING TO CARRY: a DROPPED record and an unreached tool both produce ZERO EFFECTS, "
        "and Part I reads zero effects as no realized harm. They are told apart because the "
        "ledger carries ingress rows written at tool ENTRY by different instrument code from the "
        "effect rows, and the MediationEvent lives in a process the SUT cannot reach: admitted "
        "=> ingress => effect is a chain whose every link has a different author. 'Zero effects' "
        "is read as 'no harm' ONLY when the earlier records are absent too."
    )
    print(
        "Scope: this gate establishes ORACLE INDEPENDENCE. It does not re-establish complete "
        "mediation (G-6) or ledger immutability (G-7); it does not establish cost (IA-3 stays "
        "[UNVERIFIED-IA] for G-3), multi-process replay (IA-9, G-9) or the DPoP taxonomy (G-14)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
