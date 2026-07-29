"""Gate G-11 spike — the HTC/INV verifier and the mutation suite (IA: HTC correctness).

Implements and adjudicates `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` SS F.2 / SS F.2.1
through `src/harness/verifier/`. Fourteen mutations, each rejected, each with its
**reason code** recorded so the rejection is attributable to the condition it was
meant to trigger — a rejection for an unrelated reason is a masked check, not a
pass. Plus both positive arms, including the `n = 0` zero-hop case the Part G row
names explicitly.

Two facts about the six commitment-layer mutations, kept distinct as the row
requires: they are **already `[VERIFIED]` at the commitment layer** by the ADR 0003
regression suite (tests 1–8), and G-11 **re-tests** them through the full HTC/INV
verifier. Nothing below presents a re-test as a first verification.

One item in that list needs care, and the report says so rather than fudging it:
a **semantically equivalent container re-encoding must be ACCEPTED**, with the
commitment unchanged. That is ADR 0003's central verified property — rejecting it
would reintroduce the false-rejection bug ADR 0003 was written to fix — so the
check below asserts acceptance for an equivalent re-encoding and rejection for one
that changes a block's content.

    uv run python smoke/g11/spike.py
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture as fx  # noqa: E402
from biscuit_auth import Biscuit, BiscuitBuilder, KeyPair, PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from src.harness.oracle import commitment  # noqa: E402
from src.harness.verifier import holder_binding as hb  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


# ---------------------------------------------------------------------------
# Positive arms
# ---------------------------------------------------------------------------


def positive_arms(run: fx.Campaign) -> tuple[set[str], set[str]]:
    """The valid chain passes at n = 2 and at n = 0 (the zero-hop case)."""
    two = run.verify(run.evidence(2))
    zero = run.verify(run.evidence(0))

    # The zero-hop rule is "the general verification with a one-element chain",
    # so the real invariant is that NO check exists only in the zero-hop case.
    # The n = 2 run additionally exercises the checks that are inherently about a
    # hop i >= 1 (linkage, the holder signature, the task/audience invariant, and
    # exp non-increasing) — a one-element chain has no such hop to compare against.
    only_zero = set(zero.checks) - set(two.checks)
    hop_only = sorted(set(two.checks) - set(zero.checks))

    ok = not only_zero and len(set(zero.checks)) >= 20 and len(hop_only) == 5
    record(
        "G-11.P1",
        True,
        ok,
        f"valid chain verifies at n=2 ({len(two.checks)} checks, {len(set(two.checks))} distinct) "
        f"and at n=0 ({len(zero.checks)} checks, {len(set(zero.checks))} distinct). No check runs "
        f"ONLY in the zero-hop case ({not only_zero}) — so n=0 takes no separate path; the extra "
        f"names at n=2 are exactly the five hop-i>=1 conditions {hop_only}. Would have failed if "
        f"the zero-hop case had its own check, or if it were waved through with a few checks",
    )
    return set(zero.checks), set(two.checks)


def no_zero_hop_branch(run: fx.Campaign) -> None:
    """No branch in the verifier keys on the chain LENGTH (SS F.2: no separate path)."""
    import ast

    source = (REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.If, ast.IfExp)):
            continue
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Compare):
                rendered = ast.unparse(sub)
                mentions_length = "len(" in rendered and (
                    "chain" in rendered or "block_ids" in rendered
                )
                against_small = any(
                    isinstance(c, ast.Constant) and c.value in (0, 1) for c in sub.comparators
                )
                if mentions_length and against_small:
                    offenders.append(rendered)
                if rendered.strip() in {"n == 0", "n != 0", "depth == 0"}:
                    offenders.append(rendered)

    # Deliberately permitted, and distinct from a zero-hop code path:
    #   * `if not evidence.htc_chain` rejects an EMPTY chain (zero HTCs). n = 0
    #     means ONE HTC, so this is a degenerate-input rejection, not a branch on n.
    #   * `index == 0` keys on the HOP INDEX, which the SS F.2 template requires:
    #     HTC_0 is signed by kappa and carries depth 0.
    permitted_empty = "if not evidence.htc_chain" in source
    hop_index_branches = source.count("index == 0")

    ok = not offenders
    record(
        "G-11.P2",
        True,
        ok,
        f"AST scan of holder_binding.py for a branch keyed on the chain LENGTH: "
        f"offenders={offenders or 'none'}. Permitted and distinct: the empty-chain rejection "
        f"({permitted_empty}) refuses ZERO HTCs, whereas n=0 means ONE; and {hop_index_branches} "
        f"branches key on the HOP INDEX (index == 0), which the SS F.2 template requires because "
        f"HTC_0 is signed by kappa and carries depth 0. `prefix_hash` uses max(index-1, 0), a "
        f"formula rather than a branch. Would have failed on any `len(chain) == 1` or `n == 0` "
        f"test",
    )


# ---------------------------------------------------------------------------
# The eight HTC mutations
# ---------------------------------------------------------------------------


def htc_mutations(run: fx.Campaign) -> None:
    base = run.evidence(2)
    attacker = Ed25519PrivateKey.generate()
    outcomes: dict[str, tuple[str, str, str]] = {}  # name -> (reason, expected, failing world)

    def note(name: str, evidence, expected: str, failing: str, *, now: int | None = None) -> None:
        outcomes[name] = (run.reject_reason(evidence, now=now), expected, failing)

    # 1. wrong-signer, two ways.
    #    (a) the declared signer_pubkey is left correct but an unauthorized key signs.
    chain = list(base.htc_chain)
    payload = json.loads(chain[1])["payload"]
    chain[1] = hb.seal(hb.HTC_TAG, payload, attacker)
    note(
        "wrong-signer (unauthorized key signs)",
        run.with_chain(base, chain),
        hb.HTC_SIGNATURE,
        "an agent that never held the capability could mint a hop and be treated as its holder",
    )
    #    (b) the attacker also rewrites signer_pubkey so its own signature verifies.
    #        The identity plane catches this one condition EARLIER than linkage: the
    #        key presented is not the registered holder key for the kid claimed, and
    #        an attacker key is in no registry entry at all (SS F.2.1).
    chain = list(base.htc_chain)
    chain[1] = hb.reseal(
        chain[1], hb.HTC_TAG, attacker, signer_pubkey=hb.public_key_wire(attacker.public_key())
    )
    note(
        "wrong-signer (signer_pubkey rewritten to match)",
        run.with_chain(base, chain),
        hb.REGISTRY_KEY_MISMATCH,
        "a self-consistent hop spliced in by a key the previous holder never named",
    )
    #    (c) linkage in isolation: a LEGITIMATE registered holder signs out of turn,
    #        with kid and signer_pubkey mutually consistent, so the registry check
    #        passes and only `htc_chain_linkage` can catch it. Without this case the
    #        linkage condition would be masked by (b) and never genuinely exercised.
    chain = list(base.htc_chain)
    chain[2] = hb.reseal(
        chain[2],
        hb.HTC_TAG,
        run.holder_private(0),
        kid=run.kid_for("holder-supervisor"),
        signer_pubkey=hb.public_key_wire(run.holder_private(0).public_key()),
    )
    note(
        "wrong-signer (registered holder signs out of turn)",
        run.with_chain(base, chain),
        hb.HTC_CHAIN_LINKAGE,
        "an earlier hop's holder could insert itself mid-chain, so the chain would no longer "
        "reflect who actually held the capability at each step",
    )

    # 2. parent-swap: HTC_2.prefix_hash replaced with a different prefix.
    chain = list(base.htc_chain)
    other_prefix = commitment.commit_prefix(
        commitment.block_ids_from_raw(base.token_bytes, run.root.public_key), 0
    ).hex()
    chain[2] = hb.reseal(chain[2], hb.HTC_TAG, run.holder_private(1), prefix_hash=other_prefix)
    note(
        "parent-swap",
        run.with_chain(base, chain),
        hb.HTC_PREFIX_HASH,
        "a hop could be re-parented onto a different capability prefix than the one presented",
    )

    # 3. child-swap: HTC_1.child_block_hash points at another block.
    chain = list(base.htc_chain)
    block_ids = commitment.block_ids_from_raw(base.token_bytes, run.root.public_key)
    chain[1] = hb.reseal(
        chain[1], hb.HTC_TAG, run.holder_private(0), child_block_hash=block_ids[2].hex()
    )
    note(
        "child-swap",
        run.with_chain(base, chain),
        hb.HTC_CHILD_BLOCK_HASH,
        "an HTC could cover a different attenuation block than the one it was issued for",
    )

    # 4. depth-rollback: HTC_2 claims depth 1.
    chain = list(base.htc_chain)
    chain[2] = hb.reseal(chain[2], hb.HTC_TAG, run.holder_private(1), depth=1)
    note(
        "depth-rollback",
        run.with_chain(base, chain),
        hb.HTC_DEPTH_CONTIGUOUS,
        "a deeper chain could masquerade as a shallower one, hiding an intermediate hop",
    )

    # 5. capability-swap, two ways.
    #    (a) realistic: a different capability is presented with the same HTC/INV.
    other_token, _ = run.mint(2)
    #        The prefix commitment is checked before the child-block one, so this is
    #        where a swapped capability is caught first.
    note(
        "capability-swap (different token presented)",
        run.with_token(base, other_token),
        hb.HTC_PREFIX_HASH,
        "the holder chain could be replayed over a capability it was never issued against",
    )
    #    (b) isolating INV.capability_hash: the HTCs match the presented token, but
    #        the INV binds another capability.
    swapped = run.evidence(2, token_bytes=other_token)
    note(
        "capability-swap (INV binds another capability)",
        run.with_inv(swapped, base.invocation_assertion),
        hb.INV_CAPABILITY_HASH,
        "an INV issued for one capability could authorize a call carrying another",
    )

    # 6. terminal-key-mismatch: the INV is signed by a holder other than the terminal one.
    inv_payload = json.loads(base.invocation_assertion)["payload"]
    mismatched = dict(inv_payload, kid=run.kid_for("holder-supervisor"))
    note(
        "terminal-key-mismatch",
        run.with_inv(base, hb.seal(hb.INV_TAG, mismatched, run.holder_private(0))),
        hb.INV_TERMINAL_HOLDER,
        "a spent hop's holder could sign invocations after delegating the capability onward",
    )

    # 7. domain-tag confusion, both readings.
    #    (a) the tag-isolating form: a structurally valid INV whose signature was
    #        computed in the HTC domain. This is what proves the tag is load-bearing.
    note(
        "domain-tag confusion (INV payload signed in the HTC domain)",
        run.with_inv(base, hb.seal(hb.HTC_TAG, inv_payload, run.holder_private(2))),
        hb.INV_SIGNATURE,
        "a signature made for one object type would authenticate the other, collapsing the "
        "HTC/INV distinction SS F.2's domain separation exists to enforce",
    )
    #    (b) the literal form: HTC bytes submitted in the INV slot.
    note(
        "domain-tag confusion (literal HTC bytes as INV)",
        run.with_inv(base, base.htc_chain[-1]),
        hb.INV_SCHEMA,
        "an HTC accepted as an INV would bind no request at all",
    )

    # 8. expired / nbf-violating cert.
    note(
        "expired cert",
        base,
        hb.HTC_VALIDITY_WINDOW,
        "a delegation could be exercised indefinitely after its certificate lapsed",
        now=run.now + 100_000,
    )
    note(
        "nbf-violating cert",
        base,
        hb.HTC_VALIDITY_WINDOW,
        "a certificate could be used before it became valid",
        now=run.now - 100_000,
    )

    wrong = {
        name: f"got {reason}, expected {expected}"
        for name, (reason, expected, _) in outcomes.items()
        if reason != expected
    }
    ok = not wrong
    record(
        "G-11.M-HTC",
        True,
        ok,
        f"{len(outcomes)} HTC mutations over the eight named families, each rejected with the "
        f"reason code of the condition it targets: "
        + "; ".join(f"{name} -> {reason}" for name, (reason, _, _) in outcomes.items())
        + (f". MISMATCHES: {wrong}" if wrong else "")
        + ". Would have failed if any mutation were ACCEPTED, or rejected for an unrelated "
        "reason — a masked check, which is not a pass",
    )
    return outcomes


# ---------------------------------------------------------------------------
# The six commitment-layer mutations, re-tested through the verifier
# ---------------------------------------------------------------------------


def commitment_mutations(run: fx.Campaign) -> None:
    import reencode

    base = run.evidence(2)
    raw = base.token_bytes
    outcomes: dict[str, str] = {}

    # (i) block reordering, (ii) truncation -- both change the block sequence.
    outcomes["block reordering"] = run.reject_reason(
        run.with_token(base, reencode.swap_appended_blocks(raw))
    )
    outcomes["truncation"] = run.reject_reason(
        run.with_token(base, reencode.truncate_terminal(raw))
    )

    # (iii) container re-encoding -- SEE THE MODULE DOCSTRING. A semantically
    # equivalent re-encoding must be ACCEPTED with the commitment unchanged
    # (ADR 0003's central property); only content-changing re-encoding is refused.
    equivalent = reencode.reorder_top_level(raw)
    equivalent_accepted = run.reject_reason(run.with_token(base, equivalent)) == "ACCEPTED"
    commitment_stable = commitment.capability_commitment(
        equivalent, run.root.public_key
    ) == commitment.capability_commitment(raw, run.root.public_key)
    outcomes["container re-encoding (content changed)"] = run.reject_reason(
        run.with_token(base, reencode.flip_byte_in_authority(raw))
    )

    # (iv) missing HTC coverage -- one fewer HTC than presented signed blocks.
    outcomes["missing HTC coverage"] = run.reject_reason(run.with_chain(base, base.htc_chain[:-1]))

    # (v) unsupported commitment version -- the layer the verifier calls fails closed.
    block_ids = commitment.block_ids_from_raw(raw, run.root.public_key)
    try:
        commitment.commit_prefix(block_ids, 0, version=2)
        outcomes["unsupported commitment version"] = "ACCEPTED"
    except commitment.UnsupportedVersionError:
        outcomes["unsupported commitment version"] = commitment.UnsupportedVersionError.__name__
    version_pinned = "version=" not in _verifier_call_site()

    # (vi) unsupported algorithm -- a real Secp256r1-minted token, which the
    # library verifies and the commitment layer must not.
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der = ec_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    secp = KeyPair.from_private_key(PrivateKey.from_der(der))
    secp_raw = bytes(
        BiscuitBuilder('right("notes.read", "notes/project");').build(secp.private_key).to_bytes()
    )
    library_accepts = bool(Biscuit.from_bytes(secp_raw, secp.public_key))
    try:
        hb.verify(run.with_token(base, secp_raw), run.registry, secp.public_key, now=run.now)
        outcomes["unsupported algorithm"] = "ACCEPTED"
    except hb.HolderBindingRejected as exc:
        outcomes["unsupported algorithm"] = exc.reason_code

    expected = {
        "block reordering": (hb.CAPABILITY_CHAIN_INVALID,),
        "truncation": (hb.CAPABILITY_CHAIN_INVALID, hb.HTC_COVERAGE_COUNT),
        "container re-encoding (content changed)": (hb.CAPABILITY_CHAIN_INVALID,),
        "missing HTC coverage": (hb.HTC_COVERAGE_COUNT,),
        "unsupported commitment version": ("UnsupportedVersionError",),
        "unsupported algorithm": (hb.COMMITMENT_UNSUPPORTED_ALGORITHM,),
    }
    wrong = {
        name: f"got {outcomes[name]}, expected {allowed}"
        for name, allowed in expected.items()
        if outcomes[name] not in allowed
    }

    ok = (
        not wrong
        and equivalent_accepted
        and commitment_stable
        and library_accepts
        and version_pinned
    )
    record(
        "G-11.M-COMMIT",
        True,
        ok,
        "six commitment-layer mutations re-tested THROUGH the HTC/INV verifier (already "
        "[VERIFIED] at the commitment layer by the ADR 0003 suite tests 1-8; this is a re-test, "
        "not a first verification): "
        + "; ".join(f"{name} -> {reason}" for name, reason in outcomes.items())
        + (f". MISMATCHES: {wrong}" if wrong else "")
        + f". On re-encoding, the row's blanket 'each rejected' cannot apply: a SEMANTICALLY "
        f"EQUIVALENT re-encoding is ACCEPTED ({equivalent_accepted}) with the commitment "
        f"unchanged ({commitment_stable}), which is ADR 0003's central property - rejecting it "
        f"would reintroduce the false-rejection bug ADR 0003 fixed; only a content-changing "
        f"re-encoding is refused. The Secp256r1 token is accepted by the library "
        f"({library_accepts}) and refused by the commitment layer, so the Ed25519 mandate is "
        f"project-enforced. The verifier pins commitment version 1 and threads no version from "
        f"input ({version_pinned}). Would have failed if any must-reject mutation were admitted, "
        f"or if the equivalent re-encoding were rejected",
    )
    return outcomes


def _verifier_call_site() -> str:
    """The verifier's commitment calls, to confirm no version is threaded from input."""
    source = (REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py").read_text(
        encoding="utf-8"
    )
    return "\n".join(line for line in source.splitlines() if "commit_prefix(" in line)


# ---------------------------------------------------------------------------
# The frozen registry and the digest family
# ---------------------------------------------------------------------------


def registry_and_digests(run: fx.Campaign) -> None:
    from src.harness.oracle.jcs_digest import h_jcs
    from src.harness.verifier.at_digest import access_token_hash
    from src.sut.dpop import access_token_hash as ath

    document = run.document
    digest = reg.h_registry(document)

    unmapped_actor = "ACCEPTED"
    try:
        run.registry.actor_of("agent-ghost")
    except reg.UnmappedError:
        unmapped_actor = "rejected"
    unmapped_key = "ACCEPTED"
    try:
        run.registry.principal_of_key(hb.public_key_wire(Ed25519PrivateKey.generate().public_key()))
    except reg.UnmappedError:
        unmapped_key = "rejected"

    owner_not_holder = not any(
        owner in run.registry.actor_to_principal for owner in run.registry.resource_owners
    )
    one_key_each = len(set(run.registry.principal_to_key.values())) == len(
        run.registry.principal_to_key
    )

    at_digest = access_token_hash(fx.RAW_AT)
    ath_value = ath(fx.RAW_AT)
    jcs_value = h_jcs({"token": fx.RAW_AT})
    three_distinct = len({at_digest, ath_value, jcs_value}) == 3

    version_fails_closed = False
    try:
        access_token_hash(fx.RAW_AT, version=2)
    except Exception:
        version_fails_closed = True

    ok = (
        unmapped_actor == "rejected"
        and unmapped_key == "rejected"
        and owner_not_holder
        and one_key_each
        and three_distinct
        and version_fails_closed
    )
    record(
        "G-11.R",
        True,
        ok,
        f"frozen registry (ADR 0019) H(R)={digest}; "
        f"{len(run.registry.principal_to_key)} principals, exactly one holder key each "
        f"({one_key_each}); an unmapped actor is {unmapped_actor} and an unmapped holder key "
        f"is {unmapped_key} (SS F.2.1 requires both); resource owners are recorded but absent "
        f"from the holder mapping ({owner_not_holder}, SS A.5.1 MUST NOT). Three digests over "
        f"the same token are mutually distinct ({three_distinct}): "
        f"access_token_hash={at_digest[:16]}... (hex), ath={ath_value[:16]}... (base64url), "
        f"H_JCS={jcs_value[:16]}... (hex over canonical JSON); an unsupported version fails "
        f"closed ({version_fails_closed}). Would have failed if any two digests collided, or "
        f"if an unmapped actor or key resolved",
    )


# ---------------------------------------------------------------------------
# G-4's residuals: L4 and L3, now adjudicable
# ---------------------------------------------------------------------------


def g4_residuals(run: fx.Campaign) -> None:
    from src.harness.verifier.at_digest import access_token_hash

    base = run.evidence(2)

    # L4: INV.access_token_hash == H(presented AT@aud), through the real verifier.
    verified = run.verify(base)
    bound_correctly = verified.inv_payload["access_token_hash"] == access_token_hash(fx.RAW_AT)

    swapped_at = fx.RAW_AT[:-4] + ("AAAA" if not fx.RAW_AT.endswith("AAAA") else "BBBB")
    from dataclasses import replace as _replace

    swapped = _replace(base, raw_at=swapped_at)
    swap_reason = run.reject_reason(swapped)

    # L3: actor -> holder over the FROZEN registry, not the C3 stand-in.
    principal = run.registry.actor_of("agent-specialist")
    holder = run.registry.holder_key(principal)
    resolves = principal == "specialist" and holder == hb.public_key_wire(
        run.private_for("holder-specialist").public_key()
    )
    owner_never_holder = True
    for owner in run.registry.resource_owners:
        try:
            run.registry.principal_of_key(owner)
            owner_never_holder = False
        except reg.UnmappedError:
            pass
        if owner in run.registry.actor_to_principal:
            owner_never_holder = False

    ok = (
        bound_correctly
        and swap_reason == hb.INV_ACCESS_TOKEN_HASH
        and resolves
        and owner_never_holder
    )
    record(
        "G-11.G4",
        True,
        ok,
        f"G-4 residuals closed. **L4**: INV.access_token_hash equals H(presented AT@aud) through "
        f"the real verifier ({bound_correctly}), and a swapped token is rejected with "
        f"{swap_reason} ({swap_reason == hb.INV_ACCESS_TOKEN_HASH}) — G-4 Phase 2 could only show "
        f"the byte string was observable and stable, because no construction existed and INV did "
        f"not exist. **L3**: actor_of('agent-specialist') -> {principal!r} -> exactly one holder "
        f"key, resolved against the FROZEN registry rather than the C3 stand-in ({resolves}); the "
        f"negative test still holds — no resource owner is a holder or an actor "
        f"({owner_never_holder}, SS A.5.1 MUST NOT). Would have failed if the digest bound the "
        f"wrong token, if a swap went undetected, or if the frozen registry changed the L3 outcome",
    )


# ---------------------------------------------------------------------------


def main() -> int:
    print("Gate G-11 spike — HTC/INV holder binding (src/harness/verifier/)")
    print("Registry: the FROZEN artifact identity_registry_v1.json (ADR 0019) — no stand-in.")
    print("access_token_hash: ADR 0018, closing ADR 0009 category (c) and DESIGN SS 9 C2.")
    print("IA-3 (timing) is untouched and stays [UNVERIFIED-IA] for G-3.\n")

    run = fx.Campaign()
    positive_arms(run)
    no_zero_hop_branch(run)
    htc_mutations(run)
    commitment_mutations(run)
    registry_and_digests(run)
    g4_residuals(run)

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-11: FAIL — mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 8: do not mark PASS. Report which limb, why, and the smallest correction.")
        return 1
    print("GATE G-11: all mandatory checks passed")
    print(
        "Scope: this gate establishes HTC/INV CORRECTNESS. It does not establish that "
        "verification fits under the equivalence margin (IA-3, G-3), nor Allowed(AT_i) = C_i "
        "(G-13), the DPoP taxonomy (G-14), or the F4/F5 monitor (G-15). The "
        "task_authorization_policy stays UNSET, so F2 wrong_principal stays unscored."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
