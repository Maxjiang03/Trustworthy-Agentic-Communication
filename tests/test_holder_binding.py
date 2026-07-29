"""Regression suite for HTC/INV holder binding (gate G-11, ADR 0018/0019).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: `src/harness/verifier/` -- the SS F.2 verification, the
SS F.2.1 registry, and the `access_token_hash` construction ADR 0018 fixes.

Platform-independent: pure signing and hashing, so unlike the Windows-only
effect-ledger suite (ADR 0014) it must pass on Linux CI too.

The registry here is the **frozen artifact**, not a stand-in -- that is what
closes `smoke/g4/DESIGN.md` SS 9 C3. Only key *values* are fixture material, and
they enter through `bind()` exactly where per-campaign material is meant to
(ADR 0007).
"""

import ast
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPIKE_DIR = REPO_ROOT / "smoke" / "g11"
for entry in (str(REPO_ROOT), str(SPIKE_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import fixture as fx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from src.harness.oracle import commitment  # noqa: E402
from src.harness.oracle.jcs_digest import h_jcs  # noqa: E402
from src.harness.verifier import at_digest  # noqa: E402
from src.harness.verifier import holder_binding as hb  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.dpop import access_token_hash as ath  # noqa: E402


@pytest.fixture(scope="module")
def run():
    return fx.Campaign()


@pytest.fixture
def base(run):
    return run.evidence(2)


# ---------------------------------------------------------------------------
# access_token_hash (ADR 0018) — closes ADR 0009 category (c) for this field
# ---------------------------------------------------------------------------


def test_access_token_hash_layout_is_the_documented_family():
    """Tagged, versioned, length-delimited, lowercase hex."""
    import hashlib

    token = "abc.def.ghi"
    raw = token.encode("ascii")
    expected = hashlib.sha256(
        at_digest.TAG + bytes([1]) + len(raw).to_bytes(4, "big") + raw
    ).hexdigest()
    assert at_digest.access_token_hash(token) == expected
    assert len(expected) == 64 and expected == expected.lower()


def test_three_digests_over_the_same_token_are_mutually_distinct():
    """SS 9 C2's named trap: ath, H_JCS and access_token_hash must never be confusable."""
    token = fx.RAW_AT
    mine = at_digest.access_token_hash(token)
    theirs = ath(token)  # base64url over the same ASCII bytes
    jcs = h_jcs({"token": token})  # lowercase hex over canonical JSON
    assert len({mine, theirs, jcs}) == 3
    # ath takes the SAME input bytes, so only the tag and encoding separate them.
    assert mine != theirs
    import hashlib

    assert mine != hashlib.sha256(token.encode()).hexdigest()  # not a bare digest either


def test_access_token_hash_rejects_an_unsupported_version():
    assert at_digest.access_token_hash(fx.RAW_AT, version=1)  # positive arm
    with pytest.raises(at_digest.UnsupportedVersionError):
        at_digest.access_token_hash(fx.RAW_AT, version=2)


def test_non_ascii_token_fails_closed():
    """A compact serialization is ASCII; anything else is not a presented token."""
    with pytest.raises(at_digest.NonAsciiTokenError):
        at_digest.access_token_hash("abc.déf.ghi")
    with pytest.raises(at_digest.NonAsciiTokenError):
        at_digest.access_token_hash(b"abc.d\xfff.ghi")


def test_the_new_tag_collides_with_no_tag_in_use():
    assert at_digest.TAG not in at_digest._TAGS_IN_USE
    assert at_digest.TAG != commitment.TAG
    assert at_digest.TAG != hb.HTC_TAG and at_digest.TAG != hb.INV_TAG


# ---------------------------------------------------------------------------
# Positive arms, including the zero-hop rule
# ---------------------------------------------------------------------------


def test_valid_chain_verifies_at_two_hops(run, base):
    result = run.verify(base)
    assert (
        result.capability_hash
        == commitment.capability_commitment(base.token_bytes, run.root.public_key).hex()
    )
    assert result.inv_payload["task_id"] == fx.TASK_ID


def test_valid_chain_verifies_at_zero_hops(run):
    """SS F.2's zero-hop rule: HTC_0 with next_holder = initial holder, INV by that key."""
    zero = run.evidence(0)
    result = run.verify(zero)
    assert len(result.htc_payloads) == 1
    assert result.htc_payloads[0]["depth"] == 0
    assert len(set(result.checks)) >= 20  # substantively verified, not waved through


def test_no_check_runs_only_in_the_zero_hop_case(run):
    """The real invariant: n = 0 is the general verification, not a special path.

    The n = 2 run additionally exercises the five conditions that are inherently
    about a hop i >= 1 -- a one-element chain has no such hop to compare against --
    so the assertion is that nothing runs ONLY at n = 0.
    """
    zero = set(run.verify(run.evidence(0)).checks)
    two = set(run.verify(run.evidence(2)).checks)
    assert zero - two == set()
    assert sorted(two - zero) == [
        hb.HTC_AUDIENCE_INVARIANT,
        hb.HTC_CHAIN_LINKAGE,
        hb.HTC_EXP_NON_INCREASING,
        hb.HTC_SIGNATURE,
        hb.HTC_TASK_INVARIANT,
    ]


def test_no_branch_keys_on_the_chain_length():
    """No `len(chain) == 1` / `n == 0` branch anywhere in the verifier."""
    source = (REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py").read_text(
        encoding="utf-8"
    )
    offenders = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.If, ast.IfExp)):
            continue
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Compare):
                rendered = ast.unparse(sub)
                if (
                    "len(" in rendered
                    and ("chain" in rendered or "block_ids" in rendered)
                    and any(
                        isinstance(c, ast.Constant) and c.value in (0, 1) for c in sub.comparators
                    )
                ):
                    offenders.append(rendered)
    assert offenders == []
    # The empty-chain rejection is a degenerate-input guard, not a zero-hop path:
    # n = 0 means ONE HTC, and an empty chain must be refused.
    assert "if not evidence.htc_chain" in source
    assert "max(index - 1, 0)" in source  # a formula, not a branch


def test_an_empty_chain_is_rejected(run, base):
    assert run.reject_reason(replace(base, htc_chain=())) == hb.HTC_CHAIN_EMPTY


# ---------------------------------------------------------------------------
# The eight HTC mutation families
# ---------------------------------------------------------------------------


def test_wrong_signer_unauthorized_key(run, base):
    chain = list(base.htc_chain)
    chain[1] = hb.seal(hb.HTC_TAG, json.loads(chain[1])["payload"], Ed25519PrivateKey.generate())
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_SIGNATURE


def test_wrong_signer_with_rewritten_signer_pubkey_hits_the_registry(run, base):
    """An attacker key is in no registry entry, so the identity plane refuses it first."""
    attacker = Ed25519PrivateKey.generate()
    chain = list(base.htc_chain)
    chain[1] = hb.reseal(
        chain[1], hb.HTC_TAG, attacker, signer_pubkey=hb.public_key_wire(attacker.public_key())
    )
    assert run.reject_reason(run.with_chain(base, chain)) == hb.REGISTRY_KEY_MISMATCH


def test_linkage_is_exercised_by_a_registered_holder_signing_out_of_turn(run, base):
    """Isolates `htc_chain_linkage`, which the registry check would otherwise mask."""
    chain = list(base.htc_chain)
    chain[2] = hb.reseal(
        chain[2],
        hb.HTC_TAG,
        run.holder_private(0),
        kid=run.kid_for("holder-supervisor"),
        signer_pubkey=hb.public_key_wire(run.holder_private(0).public_key()),
    )
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_CHAIN_LINKAGE


def test_parent_swap(run, base):
    block_ids = commitment.block_ids_from_raw(base.token_bytes, run.root.public_key)
    chain = list(base.htc_chain)
    chain[2] = hb.reseal(
        chain[2],
        hb.HTC_TAG,
        run.holder_private(1),
        prefix_hash=commitment.commit_prefix(block_ids, 0).hex(),
    )
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_PREFIX_HASH


def test_child_swap(run, base):
    block_ids = commitment.block_ids_from_raw(base.token_bytes, run.root.public_key)
    chain = list(base.htc_chain)
    chain[1] = hb.reseal(
        chain[1], hb.HTC_TAG, run.holder_private(0), child_block_hash=block_ids[2].hex()
    )
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_CHILD_BLOCK_HASH


def test_depth_rollback(run, base):
    chain = list(base.htc_chain)
    chain[2] = hb.reseal(chain[2], hb.HTC_TAG, run.holder_private(1), depth=1)
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_DEPTH_CONTIGUOUS


def test_capability_swap_with_a_different_token(run, base):
    other, _ = run.mint(2)
    assert other != base.token_bytes
    assert run.reject_reason(run.with_token(base, other)) == hb.HTC_PREFIX_HASH


def test_capability_swap_isolating_the_inv_binding(run, base):
    """HTCs consistent with the presented token, INV bound to another capability."""
    other, _ = run.mint(2)
    swapped = run.evidence(2, token_bytes=other)
    assert run.verify(swapped)  # positive arm: the swapped presentation is itself valid
    assert (
        run.reject_reason(run.with_inv(swapped, base.invocation_assertion))
        == hb.INV_CAPABILITY_HASH
    )


def test_terminal_key_mismatch(run, base):
    payload = dict(json.loads(base.invocation_assertion)["payload"])
    payload["kid"] = run.kid_for("holder-supervisor")
    forged = hb.seal(hb.INV_TAG, payload, run.holder_private(0))
    assert run.reject_reason(run.with_inv(base, forged)) == hb.INV_TERMINAL_HOLDER


def test_domain_tag_confusion_is_caught_by_the_signature_domain(run, base):
    """The load-bearing form: a valid INV payload signed in the HTC domain."""
    payload = json.loads(base.invocation_assertion)["payload"]
    confused = hb.seal(hb.HTC_TAG, payload, run.holder_private(2))
    assert run.reject_reason(run.with_inv(base, confused)) == hb.INV_SIGNATURE
    # Positive arm: the identical payload signed in the INV domain verifies.
    proper = hb.seal(hb.INV_TAG, payload, run.holder_private(2))
    assert run.verify(run.with_inv(base, proper))


def test_literal_htc_bytes_in_the_inv_slot_are_rejected(run, base):
    """The literal reading. It is refused at the schema, BEFORE the tag matters --
    recorded so the tag-isolating test above is understood as the real evidence."""
    assert run.reject_reason(run.with_inv(base, base.htc_chain[-1])) == hb.INV_SCHEMA


def test_inv_payload_signed_as_htc_also_fails_in_the_other_direction(run, base):
    """An HTC payload signed in the INV domain must not verify as an HTC."""
    chain = list(base.htc_chain)
    payload = json.loads(chain[1])["payload"]
    chain[1] = hb.seal(hb.INV_TAG, payload, run.holder_private(0))
    assert run.reject_reason(run.with_chain(base, chain)) == hb.HTC_SIGNATURE


@pytest.mark.parametrize("offset,label", [(100_000, "expired"), (-100_000, "before nbf")])
def test_validity_window_is_enforced_at_every_hop(run, base, offset, label):
    assert run.verify(base)  # positive arm: in-window now
    assert run.reject_reason(base, now=run.now + offset) == hb.HTC_VALIDITY_WINDOW


def test_inv_window_is_enforced_independently(run, base):
    """The INV has its own window; a chain valid all day does not license a stale INV."""
    payload = dict(json.loads(base.invocation_assertion)["payload"])
    payload["exp"] = run.now - 1
    stale = hb.seal(hb.INV_TAG, payload, run.holder_private(2))
    assert run.reject_reason(run.with_inv(base, stale)) == hb.INV_VALIDITY_WINDOW


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("task_id", "other-task", hb.HTC_TASK_INVARIANT),
        ("audience", "https://elsewhere.example/tools", hb.HTC_AUDIENCE_INVARIANT),
        ("exp", 4_000_000_000, hb.HTC_EXP_NON_INCREASING),
    ],
)
def test_chain_invariants(run, base, field, value, expected):
    chain = list(base.htc_chain)
    chain[1] = hb.reseal(chain[1], hb.HTC_TAG, run.holder_private(0), **{field: value})
    assert run.reject_reason(run.with_chain(base, chain)) == expected


# ---------------------------------------------------------------------------
# INV binding to the concrete request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("method", "tools/list", hb.INV_METHOD_BINDING),
        ("tool", "notes.delete", hb.INV_TOOL_BINDING),
    ],
)
def test_inv_binds_the_concrete_invocation(run, base, field, value, expected):
    assert run.reject_reason(replace(base, **{field: value})) == expected


def test_inv_request_digest_must_match_the_raw_arguments(run, base):
    assert run.reject_reason(replace(base, raw_arguments={"collection": "notes/other"})) == (
        hb.INV_REQUEST_DIGEST
    )
    # The verifier recomputes H_JCS from the raw arguments; it never trusts the INV's claim.
    assert run.verify(base).inv_payload["canonical_request_digest"] == h_jcs(fx.RAW_ARGUMENTS)


def test_inv_access_token_hash_must_match_the_presented_token(run, base):
    """G-4's L4, through the real verifier."""
    swapped = fx.RAW_AT[:-4] + "AAAA"
    assert swapped != fx.RAW_AT
    assert run.reject_reason(replace(base, raw_at=swapped)) == hb.INV_ACCESS_TOKEN_HASH
    assert run.verify(base).inv_payload["access_token_hash"] == at_digest.access_token_hash(
        fx.RAW_AT
    )


def test_label_assertions_digest_is_bound_but_not_recomputed(run, base):
    """Its construction is ADR 0009 category (c), deferred to G-15 (rows 4/6 UNSET).

    The signature covers it, so tampering is caught; the verifier makes no claim
    about how it is built.
    """
    tampered = hb.tamper(base.invocation_assertion, label_assertions_digest="ff" * 32)
    assert run.reject_reason(run.with_inv(base, tampered)) == hb.INV_SIGNATURE
    assert run.verify(base).inv_payload["label_assertions_digest"] == fx.LABEL_ASSERTIONS_DIGEST


def test_tampering_without_resigning_is_always_caught(run, base):
    """Every field is inside the signed bytes."""
    for field, value in [("depth", 99), ("task_id", "x"), ("exp", 4_000_000_000)]:
        chain = list(base.htc_chain)
        chain[1] = hb.tamper(chain[1], **{field: value})
        reason = run.reject_reason(run.with_chain(base, chain))
        assert reason in {hb.HTC_SIGNATURE, hb.HTC_DEPTH_CONTIGUOUS, hb.HTC_TASK_INVARIANT}


# ---------------------------------------------------------------------------
# The six commitment-layer mutations, through the verifier
# ---------------------------------------------------------------------------


def test_missing_htc_coverage(run, base):
    """SS F.2: the HTC count MUST equal the number of presented signed blocks."""
    assert run.reject_reason(run.with_chain(base, base.htc_chain[:-1])) == hb.HTC_COVERAGE_COUNT
    assert run.verify(base)  # positive arm: full coverage passes


def test_extra_htc_beyond_the_presented_blocks(run, base):
    assert (
        run.reject_reason(run.with_chain(base, (*base.htc_chain, base.htc_chain[-1])))
        == hb.HTC_COVERAGE_COUNT
    )


def test_equivalent_re_encoding_is_accepted_with_the_commitment_unchanged(run, base):
    """ADR 0003's central property. Rejecting this would reintroduce the bug it fixed."""
    from reencode import reorder_top_level

    alternative = reorder_top_level(base.token_bytes)
    assert alternative != base.token_bytes
    assert commitment.capability_commitment(
        alternative, run.root.public_key
    ) == commitment.capability_commitment(base.token_bytes, run.root.public_key)
    assert run.verify(run.with_token(base, alternative))


def test_content_changing_re_encoding_is_rejected(run, base):
    from reencode import flip_byte_in_authority

    mutated = flip_byte_in_authority(base.token_bytes)
    assert run.reject_reason(run.with_token(base, mutated)) == hb.CAPABILITY_CHAIN_INVALID


def test_block_reordering_and_truncation(run, base):
    from reencode import swap_appended_blocks, truncate_terminal

    assert (
        run.reject_reason(run.with_token(base, swap_appended_blocks(base.token_bytes)))
        == hb.CAPABILITY_CHAIN_INVALID
    )
    assert run.reject_reason(run.with_token(base, truncate_terminal(base.token_bytes))) in {
        hb.CAPABILITY_CHAIN_INVALID,
        hb.HTC_COVERAGE_COUNT,
    }


def test_unsupported_commitment_version_fails_closed(run, base):
    block_ids = commitment.block_ids_from_raw(base.token_bytes, run.root.public_key)
    assert commitment.commit_prefix(block_ids, 0, version=1)  # positive arm
    with pytest.raises(commitment.UnsupportedVersionError):
        commitment.commit_prefix(block_ids, 0, version=2)
    # And the verifier threads no version from input, so it cannot be talked down.
    source = (REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py").read_text(
        encoding="utf-8"
    )
    assert "version=" not in "\n".join(
        line for line in source.splitlines() if "commit_prefix(" in line
    )


def test_unsupported_algorithm_is_rejected_through_the_verifier(run, base):
    """A real Secp256r1 token: the library verifies it, the commitment layer must not."""
    from biscuit_auth import Biscuit, BiscuitBuilder, KeyPair, PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1())
    der = ec_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    secp = KeyPair.from_private_key(PrivateKey.from_der(der))
    raw = bytes(
        BiscuitBuilder('right("notes.read", "notes/project");').build(secp.private_key).to_bytes()
    )
    assert Biscuit.from_bytes(raw, secp.public_key)  # the library accepts it
    with pytest.raises(hb.HolderBindingRejected) as caught:
        hb.verify(run.with_token(base, raw), run.registry, secp.public_key, now=run.now)
    assert caught.value.reason_code == hb.COMMITMENT_UNSUPPORTED_ALGORITHM


# ---------------------------------------------------------------------------
# The frozen identity-plane registry (SS F.2.1, ADR 0019)
# ---------------------------------------------------------------------------


def test_registry_document_loads_and_hashes(run):
    doc = reg.load_document()
    assert doc["config_version"] == reg.CONFIG_VERSION
    assert reg.h_registry(doc) == run.registry.document_digest
    assert len(reg.h_registry(doc)) == 64


def test_registry_digest_is_domain_separated_and_version_fails_closed(run):
    import hashlib

    import rfc8785

    doc = reg.load_document()
    canonical = rfc8785.dumps(doc)
    assert reg.h_registry(doc) != hashlib.sha256(canonical).hexdigest()
    assert reg.h_registry(doc) != h_jcs(doc)  # a different tag over the same canonical bytes
    with pytest.raises(reg.UnsupportedVersionError):
        reg.h_registry(doc, version=2)


def test_registry_digest_is_member_order_invariant(run):
    doc = reg.load_document()
    reordered = {key: doc[key] for key in reversed(list(doc))}
    assert reg.h_registry(reordered) == reg.h_registry(doc)


def test_every_principal_has_exactly_one_holder_key(run):
    keys = list(run.registry.principal_to_key.values())
    assert len(keys) == len(set(keys))
    for principal in run.registry.principal_to_key:
        assert run.registry.holder_key(principal)


def test_actor_resolves_to_exactly_one_principal(run):
    assert run.registry.actor_of("agent-specialist") == "specialist"
    with pytest.raises(reg.UnmappedError):
        run.registry.actor_of("agent-ghost")


def test_unmapped_holder_key_is_rejected(run):
    """SS F.2.1 requires unmapped KEYS to be rejected too, not only actor claims."""
    stranger = hb.public_key_wire(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(reg.UnmappedError):
        run.registry.principal_of_key(stranger)
    assert run.registry.principal_of_key(run.registry.holder_key("worker")) == "worker"


def test_resource_owners_are_recorded_but_never_holders(run):
    """SS A.5.1 MUST NOT: requiring resource_owner = holder would reject every
    legitimate delegated call."""
    assert run.registry.resource_owners
    for owner in run.registry.resource_owners:
        assert run.registry.is_resource_owner(owner)
        assert owner not in run.registry.actor_to_principal
        with pytest.raises(reg.UnmappedError):
            run.registry.principal_of_key(owner)


def test_registry_rejects_a_duplicate_kid():
    doc = reg.load_document()
    doc["principals"]["worker"]["kid"] = doc["principals"]["supervisor"]["kid"]
    with pytest.raises(reg.RegistryStructureError, match="duplicate kid"):
        reg._validate(doc)


def test_registry_rejects_an_entry_without_a_necessity():
    doc = reg.load_document()
    del doc["principals"]["worker"]["necessity"]
    with pytest.raises(reg.RegistryStructureError, match="necessity"):
        reg._validate(doc)


def test_registry_rejects_an_actor_that_is_also_a_resource_owner():
    doc = reg.load_document()
    doc["actors"]["agent-supervisor"] = "supervisor"
    doc["resource_owners"].append("agent-supervisor")
    with pytest.raises(reg.RegistryStructureError, match="resource owner"):
        reg._validate(doc)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["principals"].__setitem__(
            "intruder", {"kid": "kid-x", "key_reference": "x", "necessity": "n"}
        ),
        lambda d: d["actors"].__setitem__("agent-intruder", "supervisor"),
        lambda d: d["resource_owners"].append("user-someone"),
    ],
)
def test_registry_mutations_change_the_digest(mutate):
    doc = reg.load_document()
    before = reg.h_registry(doc)
    mutate(doc)
    assert reg.h_registry(doc) != before


def test_registry_document_holds_no_key_bytes():
    """The artifact is freezable because it fixes structure, not per-campaign keys.

    ADR 0016 drew the same line for `Gamma`: the cardinality and role of the
    trusted-key set are frozen, the key bytes are not.
    """
    raw = reg.DOCUMENT_PATH.read_text(encoding="utf-8")
    assert "key_reference" in raw
    assert "pubkey" not in raw.replace("htc_holder_pubkey_note", "")
    for entry in reg.load_document()["principals"].values():
        assert set(entry) == {"kid", "key_reference", "necessity"}


def test_binding_rejects_two_principals_sharing_a_key():
    doc = reg.load_document()
    single = Ed25519PrivateKey.generate()
    wire = hb.public_key_wire(single.public_key())
    with pytest.raises(reg.RegistryStructureError, match="collides"):
        reg.bind(doc, lambda label: wire)


def test_registry_is_not_the_task_authorization_policy():
    """The boundary STEP 6 forbids crossing: this registry is actor->holder ONLY."""
    doc = reg.load_document()
    text = json.dumps(doc)
    assert "task_authorization_policy" in doc["scope_boundary"]
    assert "may_act" not in text
    assert "tasks" not in doc and "task_policy" not in doc
    # The frozen-parameters row for that policy stays UNSET.
    rows = (REPO_ROOT / "docs" / "frozen_parameters.md").read_text(encoding="utf-8")
    assert "| 5 |" in rows and "UNSET" in rows.split("| 5 |")[1].split("\n")[0]
