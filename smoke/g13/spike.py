"""Gate G-13 spike — matched per-hop authority across the strong baselines.

Adjudicates the Part G G-13 row: *assert `Allowed(AT_i) = C_i` for every hop
and every strong baseline; assert each realizes the same `C_0 -> ... -> C_n` on
F1-root/terminal/chain-tamper (chain-tamper NA where no chain)*. Pass criterion:
*equalities hold; no strong baseline differs in authority granularity*. What
rides on it, in Part G's own words: **matched fairness; the whole comparison.**

Every set below is **computed** by `src/harness/verifier/matched_authority.py`
from raw presented evidence -- one membership decision per element of the
frozen `Omega`, the G-2 discipline -- and compared against the **sealed** `C_i`
that no system under test can read. Nothing is asserted from an arm's return
value, and nothing is timed (EXP2 forbidden action 5).

Every equality is accompanied by the world in which it is FALSE, constructed
through the arms' own interfaces. An equality that cannot fail has not been
tested.

    uv run python smoke/g13/spike.py
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture as fx  # noqa: E402

from src.harness.verifier import matched_authority as ma  # noqa: E402

RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} -- {evidence}")


def _fmt(elements) -> str:
    return "{" + ", ".join(f"{a}/{r}" for a, r in sorted(elements)) + "}"


# The three predicates the gate adjudicates, factored out so a counterfactual
# world is judged by the SAME code that judges the real one. `it would have
# failed` is a claim; running the check and watching it return False is not.
def equalities_hold(per_hop, expected) -> bool:
    """L1's predicate: every realized hop set equals the sealed `C_i`."""
    return all(realized == expected[i] for i, realized in enumerate(per_hop))


def chains_identical(chains) -> bool:
    """L2's predicate: every arm realizes the same `C_0 -> ... -> C_n`."""
    return len({tuple(sorted(map(tuple, hops))) for hops in chains.values()}) == 1


def all_blocked(cells) -> bool:
    """L3's predicate: no strong arm admitted an F1 subcase."""
    return not any(cell.admitted for cell in cells)


# ---------------------------------------------------------------------------
# L1 — Allowed(.) = C_i, per arm, per hop, per scenario
# ---------------------------------------------------------------------------
def l1_per_hop_equalities(matrix) -> None:
    checked, mismatches, inapplicable = 0, [], []
    for (scenario_id, arm_name), cell in sorted(matrix.items()):
        expected = fx.c_sets(scenario_id)
        checked += len(cell.per_hop)
        if not equalities_hold(cell.per_hop, expected):
            mismatches += [
                f"{arm_name}/{scenario_id} hop {i}: {_fmt(r)} != {_fmt(expected[i])}"
                for i, r in enumerate(cell.per_hop)
                if r != expected[i]
            ]
        if cell.hop_objects < len(expected):
            inapplicable.append(
                f"{arm_name}/{scenario_id} (hops realized: {cell.hop_objects}; {cell.note})"
            )
    record(
        "G-13.L1",
        True,
        not mismatches,
        f"{checked} per-hop equalities recomputed from raw evidence and satisfied, over "
        f"{len(matrix)} (scenario, arm) cells. Each set is built by asking the presented "
        f"object about every element of Omega in turn, then compared with the SEALED C_i. "
        f"Mismatches: {mismatches or 'none'}. Cells realizing fewer hop objects than the "
        f"sealed chain has: {inapplicable or 'none'} -- adjudicated separately at G-13.L1b",
    )


def l1b_the_refused_hop(matrix) -> None:
    """`B2` on chain-tamper has NO `AT_1`, so the equality has no object.

    Stated rather than skipped. The AS refused to issue, so the delegate
    realized no hop-1 authority at all -- which is strictly stronger than the
    equality it cannot be asked: an arm that issued nothing cannot have issued
    too much. The capability arms DO realize a hop-1 object on the same
    scenario and it equals `C_1` exactly, which is the whole content of "each
    mechanism realizes the tamper its own way" (SS E.3).
    """
    cell = matrix[("gt-f1-chain-tamper", "B2-exchange-task")]
    caps = [matrix[("gt-f1-chain-tamper", name)] for name in ("B-cap", "B3")]
    expected_c1 = fx.c_sets("gt-f1-chain-tamper")[1]
    ok = (
        cell.hop_objects == 1
        and cell.reason_code == "b2_exchange_refused"
        and all(c.hop_objects == 2 and c.per_hop[1] == expected_c1 for c in caps)
    )
    record(
        "G-13.L1b",
        True,
        ok,
        f"chain-tamper: B2 realized {cell.hop_objects} hop object(s) and was refused at "
        f"{cell.reason_code!r} -- there is no AT_1 to compare, and no authority was granted "
        f"at hop 1 at all, which is stronger than the equality. The capability arms realized "
        f"2 hop objects each with Allowed(P_1) = {_fmt(expected_c1)} = C_1, so block scoping "
        f"admitted the widening block and granted it nothing. The two mechanisms differ in "
        f"the REPRESENTATION of the refusal, not in authority granted",
    )


def l1_counterfactuals(run: fx.Campaign) -> None:
    """The worlds in which L1 is false, one per failure mode the row names."""
    c0, c1 = fx.c_sets("gt-benign")

    # (a) a hop provisioned at C_{i-1} instead of C_i
    at_c0 = run.exchange_with([list(e) for e in sorted(c0)])
    caught = not equalities_hold([c0, at_c0], [c0, c1])
    record(
        "G-13.L1.W1",
        True,
        caught and at_c0 == c0,
        f"world: the hop asks for C_0 rather than C_1. The AS ISSUES it (C_0 is contained in "
        f"C_0) and Allowed(AT_1) = {_fmt(at_c0)} = C_0. L1's OWN predicate was then run over "
        f"that chain and returned False ({caught}) -- the check is shown FAILING, not "
        f"described as one that would have failed. It would have passed silently only if "
        f"the verifier had read the arm's claim instead of the token",
    )

    # (b) a token whose RAR covers one element too many
    one_extra = sorted(c1) + [("calendar.read", "calendar/work")]
    at_extra = run.exchange_with([list(e) for e in one_extra])
    caught = not equalities_hold([c0, at_extra], [c0, c1])
    record(
        "G-13.L1.W2",
        True,
        caught and at_extra == c1 | {("calendar.read", "calendar/work")},
        f"world: the hop asks for C_1 plus exactly ONE more element of C_0. Issued, "
        f"Allowed(AT_1) = {_fmt(at_extra)}, and L1's predicate returns False ({caught}). "
        f"The smallest possible widening is caught, so the equality is not a coarse "
        f"set-size comparison",
    )

    # (c) the capability plane's own version of (a)
    per_hop = run.attenuate_to([list(e) for e in sorted(c0)])
    caught = len(per_hop) == 2 and not equalities_hold(per_hop, [c0, c1])
    record(
        "G-13.L1.W3",
        True,
        caught and per_hop[1] == c0,
        f"world: the attenuation block narrows to C_0 rather than C_1. The chain verifies "
        f"under kappa_pub, Allowed(P_1) = {_fmt(per_hop[1])} = C_0, and L1's predicate "
        f"returns False ({caught}). The capability-plane equality is testable too, so L1 "
        f"is not carried by the token plane alone",
    )

    # (d) an unverifiable token must be REFUSED, never read as admitting nothing
    authentic = run.b2_setup["access_token"]
    tampered = authentic[:-4] + ("BBBB" if authentic.endswith("AAAA") else "AAAA")
    refused = False
    try:
        run._token_authority(tampered, _now())
    except ma.TokenRefused:
        refused = True
    record(
        "G-13.L1.W4",
        True,
        refused,
        "world: the presented token's signature does not verify. The verifier RAISES rather "
        "than returning the empty set -- otherwise a tampered token would look like one that "
        "happens to admit nothing, and every equality against a non-empty C_i would fail for "
        "the wrong reason while an equality against an empty one would pass vacuously",
    )


def _now() -> int:
    import time

    return int(time.time())


# ---------------------------------------------------------------------------
# L2 — cross-arm identity: no strong baseline differs in authority granularity
# ---------------------------------------------------------------------------
def l2_cross_arm_identity(matrix) -> None:
    differing = []
    compared = 0
    for scenario_id in fx.SCENARIOS:
        realized = {
            name: matrix[(scenario_id, name)].per_hop
            for name in fx.STRONG_ARMS
            if matrix[(scenario_id, name)].hop_objects == len(fx.c_sets(scenario_id))
        }
        compared += len(realized)
        if len(realized) > 1 and not chains_identical(realized):
            shown = {n: [_fmt(h) for h in hops] for n, hops in realized.items()}
            differing.append(f"{scenario_id}: {shown}")
    record(
        "G-13.L2",
        True,
        not differing,
        f"{compared} arm-chains compared across {len(fx.SCENARIOS)} scenarios; every arm that "
        f"realizes a full chain realizes the IDENTICAL C_0 -> C_1. Differences: "
        f"{differing or 'none'}. The arms narrow online and offline respectively -- that "
        f"difference is the measurement, and it is not normalized away here; what is asserted "
        f"is only that the SETS agree",
    )


def l2_counterfactual(run: fx.Campaign, matrix) -> None:
    c0, c1 = fx.c_sets("gt-benign")
    misprovisioned = run.exchange_with([list(e) for e in sorted(c0)])
    reference = matrix[("gt-benign", "B3")].per_hop
    caught = not chains_identical({"B3": reference, "B2-bad": [c0, misprovisioned]})
    # Positive control on the SAME predicate, so False is not its only output.
    agrees = chains_identical({"B3": reference, "B-cap": matrix[("gt-benign", "B-cap")].per_hop})
    record(
        "G-13.L2.W1",
        True,
        caught and agrees,
        f"world: one strong arm realizes C_0 at hop 1 while the others narrow to C_1. L2's "
        f"OWN predicate over those chains returns False ({caught}) -- {_fmt(misprovisioned)} "
        f"vs {_fmt(reference[1])} -- while over two REAL arms it returns True ({agrees}). "
        f"So the identity check discriminates rather than always agreeing",
    )


# ---------------------------------------------------------------------------
# L3 — every F1 subcase blocks on every strong arm, cause attributable
# ---------------------------------------------------------------------------
def l3_f1_blocks(matrix) -> None:
    f1_cells = [
        matrix[(scenario_id, arm_name)]
        for scenario_id in fx.F1_SUBCASES
        for arm_name in fx.STRONG_ARMS
    ]
    admitted = [f"{c.arm_name}/{c.scenario_id}" for c in f1_cells if c.admitted]
    causes = {f"{c.arm_name}/{c.scenario_id}": c.reason_code for c in f1_cells}
    benign_admitted = all(matrix[("gt-benign", name)].admitted for name in fx.STRONG_ARMS)
    record(
        "G-13.L3",
        True,
        all_blocked(f1_cells) and benign_admitted,
        f"all {len(fx.F1_SUBCASES)} x {len(fx.STRONG_ARMS)} F1 cells blocked, with the "
        f"attributable cause per arm: {causes}. Every strong arm ADMITS the benign call "
        f"({benign_admitted}), so the blocks are not an arm refusing everything. Admitted F1 "
        f"cells: {admitted or 'none'}",
    )


def l3_counterfactual(run: fx.Campaign) -> None:
    """SS E.3's own warning, made real: an arm enforcing only `C_0` admits F1-terminal."""
    c0, _ = fx.c_sets("gt-benign")
    admitted, reason = run.misprovisioned_b2_decision(
        [list(e) for e in sorted(c0)], "gt-f1-terminal"
    )
    cell = fx.Cell(
        scenario_id="gt-f1-terminal",
        arm_name="B2-misprovisioned",
        admitted=admitted,
        reason_code=reason,
        per_hop=[],
        hop_objects=0,
    )
    caught = not all_blocked([cell])
    record(
        "G-13.L3.W1",
        True,
        caught and admitted is True,
        f"world: a strong arm that realized only C_0 at the hop. It ADMITS gt-f1-terminal "
        f"({admitted}, {reason!r}) -- exactly what SS E.3 says a baseline enforcing only "
        f"C_0 would do, and why matched provisioning is mandatory rather than advisory. "
        f"L3's OWN predicate over that cell returns False ({caught})",
    )


# ---------------------------------------------------------------------------
# L4 — D21: the SUT-side signer is independent of the harness verifier
# ---------------------------------------------------------------------------
def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def l4_d21_independence() -> None:
    sut_signer = REPO_ROOT / "src" / "sut" / "capability" / "signer.py"
    sut_authority = REPO_ROOT / "src" / "sut" / "capability" / "authority.py"
    harness_verifier = REPO_ROOT / "src" / "harness" / "verifier" / "matched_authority.py"
    harness_holder = REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py"

    sut_side = _imports(sut_signer) | _imports(sut_authority)
    harness_side = _imports(harness_verifier) | _imports(harness_holder)
    sut_clean = not any(name.startswith("src.harness") for name in sut_side)
    harness_clean = not any(name.startswith("src.sut") for name in harness_side)
    boundary_unused = "src.sut.authz.boundary" not in harness_side

    agreement = REPO_ROOT / "tests" / "test_sut_signer_agreement.py"
    record(
        "G-13.L4",
        True,
        sut_clean and harness_clean and boundary_unused and agreement.exists(),
        f"D21 adjudicated on three pieces of evidence, not on assertion. (1) STRUCTURE: the "
        f"SUT signer/authority import nothing from src/harness ({sut_clean}) and the harness "
        f"verifiers import nothing from src/sut ({harness_clean}) -- so neither can inherit "
        f"the other's mistake. (2) The token-plane verifier does not reuse "
        f"src/sut/authz/boundary.py as its implementation ({boundary_unused}), which is what "
        f"D13/D21 forbids for an instrument that must be able to find a defect in the "
        f"boundary. (3) AGREEMENT is pinned separately by {agreement.name}, and this gate's "
        f"L1 is itself an agreement test: two independent implementations produced the same "
        f"C_i on every hop of every cell. Residual: agreement is evidence of independence "
        f"only because the implementations are structurally distinct -- which (1) and (2) "
        f"establish and which a future refactor could silently undo",
    )


def l4_counterfactual() -> None:
    """The structural check must be able to fail."""
    source = "from src.sut.authz import boundary\nimport src.harness.oracle\n"
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    caught = any(n.startswith("src.sut") for n in names) and any(
        n.startswith("src.harness") for n in names
    )
    record(
        "G-13.L4.W1",
        True,
        caught,
        "world: a module importing across the boundary in both directions. The same scan "
        f"flags it ({sorted(names)}), so L4's clean result is a measurement rather than a "
        "scan that finds nothing because it looks for nothing",
    )


# ---------------------------------------------------------------------------
# L5 — the verifier's own independence, structurally
# ---------------------------------------------------------------------------
def l5_verifier_placement() -> None:
    module = REPO_ROOT / "src" / "harness" / "verifier" / "matched_authority.py"
    names = _imports(module)
    no_sut = not any(n.startswith("src.sut") for n in names)
    no_as = not any(n.startswith("src.sut.oauth_as") for n in names)
    reuses_g2 = "src.harness.authorizer" in names or any(
        n.startswith("src.harness.authorizer") for n in names
    )
    record(
        "G-13.L5",
        True,
        module.exists() and no_sut and no_as and reuses_g2,
        f"the verifier is at src/harness/verifier/ (SS E.2's instrument), imports nothing from "
        f"src/sut ({no_sut}) and nothing from src/sut/oauth_as in particular ({no_as}, "
        f"ADR 0015 rule 4). Its capability plane REUSES src/harness/authorizer/allowed.py "
        f"({reuses_g2}) -- the Allowed(P_i) gate G-2 adjudicated -- because a third "
        f"implementation would add no independence and could disagree with the artifact G-2 "
        f"verified. Its token plane is new and structurally distinct from the boundary's: "
        f"one yes/no question per candidate with all three planes inside it, versus a "
        f"capability-plane set with scope applied per request",
    )


# ---------------------------------------------------------------------------
def main() -> int:
    print("Gate G-13 spike -- matched per-hop authority (Allowed(.) = C_i)")
    print("Sets are COMPUTED from raw presented evidence, one candidate per element of Omega.")
    print("Compared against the SEALED C_i, which no system under test can read.")
    print("Nothing here is timed: G-13 establishes matched authority, not cost (IA-3, G-3).\n")

    with fx.Campaign() as run:
        matrix = run.matrix()
        l1_per_hop_equalities(matrix)
        l1b_the_refused_hop(matrix)
        l1_counterfactuals(run)
        l2_cross_arm_identity(matrix)
        l2_counterfactual(run, matrix)
        l3_f1_blocks(matrix)
        l3_counterfactual(run)
        l4_d21_independence()
        l4_counterfactual()
        l5_verifier_placement()

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-13: FAIL -- mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 15: do NOT mark PASS. Report which limb, why, and the smallest correction.")
        return 1
    print("GATE G-13: all adjudicable mandatory checks passed")
    print(
        "OPEN LIMBS, and they are open rather than passed: five arms receive per-hop C_i and "
        "three exist. B2-exchange-task-DPoP and B3+ are UNBUILT, so their limbs are open in "
        "the same words G-4's row used when it first passed over its adjudicable limbs only. "
        "DPoP adds holder binding and the jti cache adds duplicate detection, neither of which "
        "adds AUTHORITY, so those limbs are EXPECTED to be formal -- expected, not verified."
    )
    print(
        "Scope: this gate establishes matched per-hop AUTHORITY. It does not establish cost "
        "(IA-3 stays [UNVERIFIED-IA] for G-3), the DPoP taxonomy (G-14), the F4/F5 monitor "
        "(G-15), duplicate replay (G-9), or process-separated mediation (G-12)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
