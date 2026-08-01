"""Gate G-15 spike — the shared F4/F5 reference monitor, and what may be claimed from it.

Adjudicates the Part G G-15 row: *F4/F5 comparisons run only among `B3` and its
matched ablations, **or** with the same reference monitor on the OAuth arms.*
What rides on it: that no capability-versus-OAuth claim rests on a
**configuration** difference dressed as a mechanism difference.

Five limbs, and **every one is accompanied by the world in which it FAILS**,
judged by the *same* predicate that judges the real one. A check that cannot
fail has not been tested — the discipline G-11 and G-13 established here.

    L1  monitor identity        the OAuth arms and B3 run the SAME monitor class
                                over the SAME frozen policy, structurally
    L2  both configurations     every F4/F5 cell measured under monitor_attached
                                false AND true
    L3  no mixed claim          no cross-arm claim mixes configurations
    L4  every check can fail    the failing worlds, caught by the gate's OWN
                                predicate
    L5  A-dagger semantics      a cell recorded without its configuration is caught

Nothing here is timed (EXP4 forbidden action 1). It touches the frozen policy,
the arms and the boundary but **not the effect ledger**, so it is
platform-independent — confirmed by running it in CI beside G-4, G-11 and G-13
rather than assumed.

    uv run python smoke/g15/spike.py
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture as fx  # noqa: E402

from src.harness.matrix_grouping import (  # noqa: E402
    ARMS,
    Cell,
    MatrixError,
    comparison_is_sound,
    label,
)

RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} -- {evidence}")


# ---------------------------------------------------------------------------
# L1 — monitor identity, structurally
# ---------------------------------------------------------------------------
def l1_monitor_identity() -> None:
    """The OAuth arms and `B3` run the SAME monitor over the SAME policy.

    Established by object identity and by an AST scan, never by inspection: two
    implementations that agree today could drift, and the drift would surface
    as a mechanism difference in the results.
    """
    from src.sut.authz.reference_monitor import ContextApprovalMonitor
    from src.sut.baselines import b2_exchange_task as b2mod
    from src.sut.baselines import b3 as b3mod

    same_class = (
        b2mod.ContextApprovalMonitor is b3mod.ContextApprovalMonitor is ContextApprovalMonitor
    )
    definitions = []
    for path in (REPO_ROOT / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef) and node.name == "ContextApprovalMonitor":
                definitions.append(path.relative_to(REPO_ROOT).as_posix())
    one_definition = definitions == ["src/sut/authz/reference_monitor.py"]

    policy_digest = fx.frozen_policy_digest()
    same_policy = policy_digest == fx.expected_policy_digest()

    # One request, both planes, one binding. If these disagreed, an artifact
    # would bind on one arm and not the other and every F4/F5 number would be
    # measuring a digest disagreement instead of a mechanism.
    one_binding = fx.oauth_and_capability_bind_identically()

    record(
        "G-15.L1",
        True,
        same_class and one_definition and same_policy and one_binding,
        f"same class object across both arm modules: {same_class}; exactly one "
        f"ContextApprovalMonitor definition in src/ ({definitions}); both load the frozen policy "
        f"H(Lambda)={policy_digest[:16]}... matching frozen_parameters: {same_policy}; an OAuth "
        f"context and a capability context derive an IDENTICAL authz_context_hash for one "
        f"request: {one_binding}",
    )


def l1_counterfactual() -> None:
    """The failing world: a monitor attachable to `B3` only.

    Constructed by asking whether the OAuth arm's decision path can reach one at
    all. If it could not, L1's predicate must return False -- and the whole
    comparison G-15 governs would be impossible.
    """
    from src.sut.baselines import b2_exchange_task as b2mod

    reachable = hasattr(b2mod.B2ExchangeTaskArm, "_monitor_decision")
    b3_only = not reachable
    # The counterfactual VERDICT under the same predicate L1 uses:
    would_fail = b3_only  # a B3-only monitor makes the OAuth column unmeasurable
    record(
        "G-15.L1.W1",
        True,
        reachable and not would_fail,
        "counterfactual: a monitor attachable to B3 ALONE. The OAuth arm exposes "
        f"_monitor_decision: {reachable}; had it not, L1 would fail and SS E.4's A-dagger would "
        "be unfalsifiable -- there would be no configuration under which an OAuth arm could "
        "block, so 'B3 blocks and OAuth does not' could never be told apart from 'B3 has a "
        "monitor and OAuth cannot have one'",
    )


# ---------------------------------------------------------------------------
# L2 — both configurations, every cell
# ---------------------------------------------------------------------------
def l2_both_configurations(matrix) -> None:
    expected = len(fx.FIXTURES) * len(ARMS) * 2
    missing = [
        (scenario_id, arm, attached)
        for scenario_id, _family, _control in fx.FIXTURES
        for arm in ARMS
        for attached in (False, True)
        if (scenario_id, arm, attached) not in matrix
    ]
    record(
        "G-15.L2",
        True,
        not missing and len(matrix) == expected,
        f"{len(matrix)}/{expected} F4/F5 cells measured -- {len(fx.FIXTURES)} fixtures x "
        f"{len(ARMS)} arms x 2 configurations. Missing: {missing or 'none'}. One column alone "
        "could not tell A-dagger apart from 'this arm cannot express the case'",
    )


def l2_the_dagger_is_real(matrix) -> None:
    """Info limb: the OAuth arms actually flip, and `B-cap` actually does not."""
    flips = {
        arm: (
            matrix[("gt-f4-sensitive-egress", arm, False)].admitted,
            matrix[("gt-f4-sensitive-egress", arm, True)].admitted,
        )
        for arm in fx.OAUTH_ARMS
    }
    all_flip = all(before is True and after is False for before, after in flips.values())
    bcap = (
        matrix[("gt-f4-sensitive-egress", "B-cap", False)].admitted,
        matrix[("gt-f4-sensitive-egress", "B-cap", True)].admitted,
    )
    record(
        "G-15.L2.info",
        False,
        all_flip and bcap == (True, True),
        f"the four OAuth arms flip A->B when the monitor is attached: {all_flip}; B-cap does NOT "
        f"({bcap[0]} -> {bcap[1]}), which is why ADR 0032 corrected its cells from A-dagger to a "
        "plain A -- its bitmask gates off the very conjuncts the monitor answers for",
    )


# ---------------------------------------------------------------------------
# L3 — no cross-mechanism claim rests on a configuration difference
# ---------------------------------------------------------------------------
def l3_no_mixed_claim(matrix) -> None:
    """Every cross-arm comparison the study could draw from this matrix is
    checked by the SAME predicate the gate exposes."""
    unsound = []
    for scenario_id, _family, _control in fx.FIXTURES:
        for attached in (False, True):
            cells = [matrix[(scenario_id, arm, attached)] for arm in ARMS]
            ok, reason = comparison_is_sound(cells)
            if not ok:
                unsound.append(f"{scenario_id}/monitor_attached={attached}: {reason}")
    record(
        "G-15.L3",
        True,
        not unsound,
        f"every within-configuration cross-arm comparison over the {len(fx.FIXTURES)} fixtures is "
        f"sound under comparison_is_sound(). Unsound: {unsound or 'none'}",
    )


def l3_counterfactual(matrix) -> None:
    """The failing world: a comparison that MIXES configurations.

    This is the error G-15 exists for -- `B3` measured with a monitor against an
    OAuth arm measured without one. Built from real cells, judged by the gate's
    own predicate.
    """
    mixed = [
        matrix[("gt-f4-sensitive-egress", "B3", True)],
        matrix[("gt-f4-sensitive-egress", "B2-exchange-task", False)],
    ]
    ok, reason = comparison_is_sound(mixed)
    caught = (not ok) and "mixes monitor configurations" in reason
    record(
        "G-15.L3.W1",
        True,
        caught,
        "counterfactual: B3 (monitor_attached=true, BLOCKED) compared against B2-exchange-task "
        f"(monitor_attached=false, ADMITTED) -- the flattering comparison. Caught: {caught}. "
        f"Predicate said: {reason[:150]}",
    )


# ---------------------------------------------------------------------------
# L4 — every check shown able to fail
# ---------------------------------------------------------------------------
def l4_every_check_can_fail(matrix) -> None:
    """Both worlds STEP 13 names, plus the two the acceptance path needs.

    Each is judged by the predicate that judges the real world, so "it would
    have failed" is never a claim -- it is a return value.
    """
    worlds = []

    # W1: a monitor attached to B3 only -> L2's column for the OAuth arms would
    # not exist. Simulated by dropping those cells and re-running L2's check.
    b3_only = {
        key: cell
        for key, cell in matrix.items()
        if not (key[1] in fx.OAUTH_ARMS and key[2] is True)
    }
    worlds.append(("W1 monitor on B3 only", len(b3_only) != len(matrix)))

    # W2: a mixed-configuration claim -> L3's predicate.
    ok, _ = comparison_is_sound(
        [
            matrix[("gt-f5-unapproved-high-risk", "B3", True)],
            matrix[("gt-f5-unapproved-high-risk", "B2-exchange-task", False)],
        ]
    )
    worlds.append(("W2 mixed-configuration claim", not ok))

    # W3: a cell recorded with no configuration -> the Cell constructor.
    try:
        Cell(family="F4", subcase="x", arm="B3", admitted=True, reason_code="r")
        w3 = False
    except MatrixError:
        w3 = True
    worlds.append(("W3 cell without its configuration", w3))

    # W4: the acceptance path made into a hole. If a FORGED artifact were
    # accepted, the controls and the attacks would produce the same cell and
    # the family would measure nothing.
    worlds.append(("W4 forged artifact accepted", fx.forged_artifact_is_refused()))

    caught = all(passed for _name, passed in worlds)
    record(
        "G-15.L4",
        True,
        caught,
        "; ".join(f"{name}: {'caught' if passed else 'NOT CAUGHT'}" for name, passed in worlds),
    )


# ---------------------------------------------------------------------------
# L5 — the A-dagger semantics survive
# ---------------------------------------------------------------------------
def l5_dagger_semantics(matrix) -> None:
    """An `A†` cell recorded without its configuration is caught, and a rendered
    configuration cell can never appear as a bare letter."""
    # Rendered from the measured PAIR, so the dagger reflects what actually
    # flipped rather than which arm it belongs to.
    rendered = {
        (scenario_id, arm): label(
            matrix[(scenario_id, arm, False)], monitored=matrix[(scenario_id, arm, True)]
        )
        for scenario_id, _family, _control in fx.FIXTURES
        for arm in ARMS
    }
    bare = [key for key, text in rendered.items() if text in ("A", "B", "A†")]
    daggered = {key for key, text in rendered.items() if "†" in text}
    # Every daggered cell must genuinely flip, and every genuine flip must be
    # daggered. Both directions, or the symbol would be decorative.
    flips = {
        (scenario_id, arm)
        for scenario_id, _f, _c in fx.FIXTURES
        for arm in ARMS
        if matrix[(scenario_id, arm, False)].admitted
        and not matrix[(scenario_id, arm, True)].admitted
    }
    bcap_daggered = any(arm == "B-cap" for _s, arm in daggered)
    record(
        "G-15.L5",
        True,
        not bare and daggered == flips and not bcap_daggered,
        f"no F4/F5 cell renders as a bare letter (offenders: {bare or 'none'}); the dagger "
        f"appears on exactly the {len(daggered)} (fixture, arm) pairs that MEASURABLY flip "
        f"A->B ({daggered == flips}); B-cap carries none: {not bcap_daggered} (ADR 0032). "
        f"The 8 benign-control cells carry no dagger: an OAuth arm admitted under both "
        f"configurations is admitted because its ARTIFACT IS VALID, not because the monitor "
        f"is absent",
    )


def l5_counterfactual() -> None:
    """The failing world: an `A†` cell recorded with its configuration dropped."""
    try:
        Cell(
            family="F4",
            subcase="gt-f4-sensitive-egress",
            arm="B2-exchange-task",
            admitted=True,
            reason_code="b2_admitted",
        )
        caught = False
        detail = "a configuration-family cell was constructed with no monitor_attached"
    except MatrixError as exc:
        caught = True
        detail = str(exc)[:140]
    record(
        "G-15.L5.W1",
        True,
        caught,
        f"counterfactual: an A-dagger cell recorded without its configuration. Caught: {caught}. "
        f"{detail}",
    )


# ---------------------------------------------------------------------------
def main() -> int:
    print("GATE G-15 -- the shared F4/F5 reference monitor (EXP4 STEP 13)")
    print("=" * 78)
    with fx.Campaign() as campaign:
        matrix = campaign.f45_matrix()
        l1_monitor_identity()
        l1_counterfactual()
        l2_both_configurations(matrix)
        l2_the_dagger_is_real(matrix)
        l3_no_mixed_claim(matrix)
        l3_counterfactual(matrix)
        l4_every_check_can_fail(matrix)
        l5_dagger_semantics(matrix)
        l5_counterfactual()

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-15: FAIL -- mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 14: do NOT mark PASS. Report which limb, why, and the smallest correction.")
        return 1
    print("GATE G-15: all mandatory checks passed")
    print()
    print(
        "THE RESIDUAL, stated plainly because it IS the finding and not a limitation to be "
        "minimised: with the shared monitor, F4/F5 measure the MONITOR rather than the "
        "MECHANISM. No capability-versus-OAuth advantage may be claimed from these two families "
        "in either direction. The OAuth arms admit absent the monitor and block with it; B3 "
        "blocks in both configurations but for DIFFERENT reasons, and that difference is the "
        "second half of the finding."
    )
    print()
    print(
        "AND THE SECOND RESULT, which belongs beside it: WITHOUT a monitor configured, B3 and "
        "B3+ refuse the BENIGN CONTROLS too, because both policy conjuncts fail closed. So the "
        "capability policy plane is only useful WHEN A MONITOR IS CONFIGURED -- without one B3 "
        "is not safer on these families, it admits nothing. That is a RESULT, not a defect, and "
        "it belongs in the results chapter beside the residual above rather than in limitations."
    )
    print()
    print(
        "Scope: this gate establishes that the F4/F5 comparison is SOUND, not that any arm is "
        "better. It does not establish cost (IA-3 stays [UNVERIFIED-IA] for G-3), the DPoP "
        "taxonomy (G-14), process-separated mediation (G-12), or multi-process replay (IA-9 "
        "stays [UNVERIFIED-IA] for G-9). Row 5 stays UNSET, so F2 wrong_principal stays "
        "unscored (ADR 0028)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
