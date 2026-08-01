"""Gate G-14 spike — the DPoP/INV attribution, measured rather than argued.

Part G's row: *attach the same authenticated-ID cache to B2-DPoP and B3; run the
four-way DPoP taxonomy.* Criterion, and it is **three separate claims**:

    C1  both block `captured-proof-replay` IDENTICALLY
    C2  INV-only blocks `first-use-body-mutation` while the replay cache alone
        does NOT
    C3  a bare bearer CANNOT carry the cache

What rides on it: **the DPoP/INV attribution.**

**C1 rests on the cache being the SAME cache**, asserted structurally the way
G-15 established for the reference monitor — same object, not two that behave
alike. A cache that is merely equivalent is not the same cache, and this whole
gate is an attribution claim.

**C3 is the one that is easy to get wrong.** *"This configuration was not
built"* and *"this configuration is impossible"* look identical in a results
table and mean opposite things. So the bare-bearer arm here is **given** a
cache, and the demonstration is that it protects nothing.

Nothing is timed (EXP5 forbidden action 1) and nothing sleeps: the clock is
injected (ADR 0027). Cross-platform — no effect ledger.

    uv run python smoke/g14/spike.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture as fx  # noqa: E402

from src.sut.authz.jti_cache import Consumption, JtiCache  # noqa: E402

RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} -- {evidence}")


# ---------------------------------------------------------------------------
# C0 — the cache is the SAME cache (the precondition C1 rests on)
# ---------------------------------------------------------------------------
def c0_same_cache(campaign) -> None:
    dpop_arm, b3_arm, cache = campaign.both_arms_sharing_one_cache()
    same_object = dpop_arm._replay_cache is cache and b3_arm._decision_path._jti_cache is cache
    same_class = type(dpop_arm._replay_cache) is type(b3_arm._decision_path._jti_cache) is JtiCache
    # One state, not two: an id consumed through one arm is seen by the other.
    cache.consume("probe", "c0-shared", now=fx.NOW)
    seen_by_both = cache.consume("probe", "c0-shared", now=fx.NOW) is Consumption.DUPLICATE
    record(
        "G-14.C0",
        True,
        same_object and same_class and seen_by_both,
        f"the two arms hold the SAME cache OBJECT (`is`): {same_object}; one class "
        f"({JtiCache.__name__}): {same_class}; and one shared state, so an id consumed once is a "
        f"duplicate on the next look: {seen_by_both}. Two caches that merely behaved alike would "
        "make every difference below an artefact of which arm got which",
    )


def c0_counterfactual(campaign) -> None:
    """The failing world: two equivalent caches instead of one."""
    dpop_arm, b3_arm, _ = campaign.both_arms_sharing_one_cache()
    separate = JtiCache()
    dpop_arm.attach_replay_cache(separate)
    caught = dpop_arm._replay_cache is not b3_arm._decision_path._jti_cache
    record(
        "G-14.C0.W1",
        True,
        caught,
        f"counterfactual: give the arms two equivalent caches and the identity check fails "
        f"({caught}). They would still both 'block replay', which is exactly why behavioural "
        "equivalence is not the criterion",
    )


# ---------------------------------------------------------------------------
# C1 — both block captured-proof-replay, identically
# ---------------------------------------------------------------------------
def c1_both_block_replay(campaign) -> None:
    dpop = campaign.dpop_replay()
    b3 = campaign.b3_replay()
    identical = (
        dpop["first"][0] is True
        and b3["first"][0] is True
        and dpop["replay"][0] is False
        and b3["replay"][0] is False
    )
    record(
        "G-14.C1",
        True,
        identical,
        f"first use: B2-DPoP {dpop['first']}, B3 {b3['first']}; bit-identical replay INSIDE Delta: "
        f"B2-DPoP {dpop['replay']}, B3 {b3['replay']}. Both admit once and block the replay -- "
        f"identically, and NEITHER DOES BETTER THAN THE OTHER on this cell. The reason codes "
        f"differ because the arms name their own conjuncts; the OUTCOME is what the claim is about",
    )


def c1_the_cache_is_what_blocks_it(campaign) -> None:
    """Negative arm: without the cache, the same replay is ADMITTED on both.

    Otherwise 'both block' could be some other conjunct doing the work, and the
    attribution to the shared cache would be unearned.
    """
    dpop = campaign.dpop_replay(with_cache=False)
    b3 = campaign.b3_replay(with_cache=False)
    record(
        "G-14.C1.W1",
        True,
        dpop["replay"][0] is True and b3["replay"][0] is True,
        f"with NO cache attached, the same bit-identical replay is ADMITTED: B2-DPoP "
        f"{dpop['replay']}, B3 {b3['replay']}. So the blocks above are the SHARED CACHE's doing "
        "and not another conjunct's",
    )


# ---------------------------------------------------------------------------
# C2 — INV-only blocks body mutation; the cache alone does not
# ---------------------------------------------------------------------------
def c2_body_mutation(campaign) -> None:
    """§D `dpop-first-use-body-mutation`. Block 3 made this observable on
    `B2-DPoP`; this reuses that rather than rebuilding it."""
    dpop = campaign.dpop_body_mutation()
    b3 = campaign.b3_body_mutation()
    claim = dpop["mutated"][0] is True and b3["mutated"][0] is False
    record(
        "G-14.C2",
        True,
        claim,
        f"a FIRST-USE request whose tool/arguments differ from what was signed: B2-DPoP WITH the "
        f"shared cache -> {dpop['mutated']} (admitted), B3 -> {b3['mutated']} (blocked at "
        f"invocation binding). The cache cannot catch it because the id is fresh -- this is a "
        f"first use, not a replay -- and DPoP binds method and URI, not the body. THIS IS THE "
        f"CELL WHERE INVOCATION BINDING EARNS ITS PLACE",
    )


def c2_the_proof_covers_no_body(campaign) -> None:
    """*Why*, structurally: the proof's claim set names nothing about the call."""
    claims = campaign.dpop_proof_claims()
    absent = {"tool", "arguments", "body", "digest", "canonical_request_digest"}
    record(
        "G-14.C2.W1",
        True,
        not (claims & absent) and {"htm", "htu", "jti"} <= claims,
        f"the DPoP proof's claims are {sorted(claims)}: it names `htm` and `htu` (method and URI) "
        f"and NONE of {sorted(absent)}. The limitation is readable in the artefact, not inferred "
        "from the outcome",
    )


# ---------------------------------------------------------------------------
# C3 — a bare bearer CANNOT carry the cache, and here is why
# ---------------------------------------------------------------------------
def c3_bare_bearer(campaign) -> None:
    """**Given** a cache, and it still protects nothing.

    The cache detects a duplicate **authenticated** request id. `B2-DPoP` has
    one (the proof `jti`, signed by the key `cnf.jkt` binds the token to) and
    `B3` has one (the INV `invocation_id`, signed by the terminal holder). A
    bare bearer arm presents a token and nothing else: any id it offered would
    be **self-asserted and unauthenticated**, so whoever captured the token
    mints a fresh one and the cache never sees a duplicate.

    So this is not "a configuration we did not build". It is a configuration in
    which the mechanism cannot work, demonstrated by building it.
    """
    outcome = campaign.bearer_with_a_cache_replay()
    record(
        "G-14.C3",
        True,
        outcome["replay"][0] is True and outcome["cache_size"] == 0,
        f"a bare bearer arm was GIVEN the shared cache and the captured token was replayed: "
        f"{outcome['replay']} -- ADMITTED. The cache holds {outcome['cache_size']} entries "
        f"afterwards, because the arm has no authenticated request id to consume: there is "
        f"nothing to put in it. 'Not built' and 'impossible' look identical in a results table "
        "and mean opposite things; this is the second",
    )


def c3_the_id_must_be_authenticated(campaign) -> None:
    """The positive half: the two arms that CAN carry it both have an
    authenticated id, and they are different mechanisms — which is why §F.5
    namespaces the key by `(mechanism_tag, jti)`."""
    tags = campaign.mechanism_tags()
    record(
        "G-14.C3.W1",
        True,
        len(set(tags.values())) == 2 and all(tags.values()),
        f"the arms that can carry it name different mechanisms {tags}, so one shared cache cannot "
        "let one arm deny the other's request -- which is what the `(mechanism_tag, jti)` "
        "namespace is for. A bare bearer appears in neither, because it authenticates no id",
    )


def main() -> int:
    print("GATE G-14 -- the DPoP/INV attribution (EXP5 STEP 11-12)")
    print("=" * 78)
    with fx.Campaign() as campaign:
        c0_same_cache(campaign)
        c1_both_block_replay(campaign)
        c1_the_cache_is_what_blocks_it(campaign)
        c2_body_mutation(campaign)
        c2_the_proof_covers_no_body(campaign)
        c3_bare_bearer(campaign)
        c3_the_id_must_be_authenticated(campaign)
        c0_counterfactual(campaign)

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-14: FAIL -- mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 12: do NOT mark PASS; all three claims must hold.")
        return 1
    print("GATE G-14: all mandatory checks passed -- all THREE claims hold")
    print()
    print(
        "THE ATTRIBUTION THIS GATE DELIVERS, and it belongs in the results chapter: DPOP AND "
        "INVOCATION BINDING BLOCK DIFFERENT THINGS, AND THE DIFFERENCE IS MEASURED HERE RATHER "
        "THAN ARGUED. Given the SAME cache, the two arms are indistinguishable on "
        "captured-proof-replay -- the cache blocks it on both, and neither mechanism does better. "
        "They separate on FIRST-USE BODY MUTATION, which the cache cannot touch because the id is "
        "fresh: DPoP binds method and URI, the INV binds the tool and the canonical arguments, and "
        "only the second refuses. The residual difference is credited to INV, not to the "
        "capability -- SS D's own words."
    )
    print(
        "Scope: this gate establishes an ATTRIBUTION, not a ranking. It does not establish cost "
        "(IA-3 stays [UNVERIFIED-IA] for G-3). `B2-DPoP`'s and `B3`'s SS E.5 bitmasks are "
        "unchanged: attaching a cache is CONFIGURATION, exactly as attaching the ADR 0030 monitor "
        "is, and `B3+` remains the arm whose ladder position includes one."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
