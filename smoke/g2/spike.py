"""Gate G-2 feasibility spike — the frozen authorizer Gamma under the pinned
Biscuit library (IA-2).

Executes the Part G G-2 criteria (a)-(d) against the `Omega`/`Gamma` frozen by
ADR 0016, with every `C_i` **computed** by running the authorizer over `Omega`
(`src/harness/authorizer/allowed.py`), never asserted. This is the FIRST pass in
the project that runs a Biscuit authorizer with policies: G-1 verified mint,
offline append, `kappa_pub`-only verification, prefix stability and
append-detection, and its docstring records that it "does NOT run an authorizer
with policies (that is G-2)".

Every check is built so the WRONG outcome would be observable as a failure, and
each carries its own negative control, so no criterion can pass vacuously (the
G-8 discipline). Prefix identity and prefix commitments are ADR 0003's
`BlockID_i`/`commit_prefix` — the same construction G-1 used — so this gate's
`Allowed(P_i)` and G-1's commitment scheme cannot drift apart.

This is a SPIKE, not production code. Exits non-zero if any MANDATORY check
fails. Token bytes legitimately differ between runs (Biscuit chains blocks with
single-use keypairs); every comparison is within a single run.

Scope: authorizer semantics over the frozen configuration. It adjudicates
nothing about HTC/INV (G-11), the AS (G-4), or any runtime arm.

    uv run python smoke/g2/spike.py
"""

import copy
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from biscuit_auth import (
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BlockBuilder,
    Fact,
    KeyPair,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))  # repo root, for src.*

from src.harness.authorizer import allowed as ev  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.oracle import commitment  # noqa: E402

# Row 8 of docs/frozen_parameters.md (ADR 0016). The gate must leave it intact.
ROW8_H_GAMMA = "f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb"

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
EXPIRY = datetime(2027, 1, 1, tzinfo=timezone.utc)
AUDIENCE = "mcp-boundary"
TASK = "task-g2-pilot"

# The golden thread of ADR 0016 SS 1, over the frozen Omega.
U_TASK = [
    ("calendar.read", "calendar/work"),
    ("notes.read", "notes/project"),
    ("notes.read", "notes/meeting"),
    ("notes.write", "notes/project"),
    ("mail.send", "mail/outbox"),
]
C1_ELEMENTS = [
    ("calendar.read", "calendar/work"),
    ("notes.read", "notes/project"),
    ("notes.read", "notes/meeting"),
]
C2_ELEMENTS = [
    ("notes.read", "notes/project"),
    ("notes.read", "notes/meeting"),
]
# In Omega, outside C_0 — the amplification target (F1-root).
OUTSIDE_C0 = ("notes.delete", "notes/project")
# In C_0, narrowed away at hop 1 — the F1-chain-tamper target.
NARROWED_AWAY = ("mail.send", "mail/outbox")

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


def context() -> ev.RequestContext:
    return ev.RequestContext(now=NOW, audience=AUDIENCE, task=TASK)


def legitimate_chain(doc: dict, keypair: KeyPair) -> ev.Chain:
    """C_0 -> C_1 -> C_2, built from the frozen templates."""
    return ev.build_chain(
        doc,
        keypair.private_key,
        keypair.public_key,
        U_TASK,
        [C1_ELEMENTS, C2_ELEMENTS],
        audience=AUDIENCE,
        task=TASK,
        expiry=EXPIRY,
    )


def append_raw(token_bytes: bytes, root_pub, source: str) -> bytes:
    """Append an arbitrary attacker-authored block, offline, with no root secret."""
    token = Biscuit.from_bytes(token_bytes, root_pub).append(BlockBuilder(source))
    return bytes(token.to_bytes())


def g2_a1_widening_append(doc: dict) -> None:
    """(a) An appended widening fact verifies cryptographically AND leaves C_i subset C_{i-1}."""
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)
    c1 = ev.allowed(ev.Chain(chain.hops[:2], keypair.public_key), doc, context())

    # The attacker holds only the token and the public key.
    widened_bytes = append_raw(
        chain.prefix(1),
        keypair.public_key,
        f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n',
    )

    # 1. Cryptographically valid: the chain verifies under kappa_pub alone, and the
    #    project's own independent extractor accepts it too.
    verified = Biscuit.from_bytes(widened_bytes, keypair.public_key)
    block_ids = commitment.block_ids_from_raw(widened_bytes, keypair.public_key)
    crypto_ok = verified.block_count() == 3 and len(block_ids) == 3
    fact_present = f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}")' in verified.block_source(2)

    # 2. The computed authority set still satisfies containment.
    widened_chain = ev.Chain((*chain.hops[:2], widened_bytes), keypair.public_key)
    c2 = ev.allowed(widened_chain, doc, context())
    contained = c2 <= c1
    excluded = OUTSIDE_C0 not in c2

    ok = crypto_ok and fact_present and contained and excluded
    record(
        "G-2.a1",
        True,
        ok,
        f"appended right{OUTSIDE_C0} offline with no root secret: token VERIFIES under "
        f"kappa_pub (block_count={verified.block_count()}, {len(block_ids)} BlockIDs extracted "
        f"by the ADR 0003 extractor) and the widening fact is present in block 2 "
        f"({fact_present}); computed |C_1|={len(c1)}, |C_2|={len(c2)}, C_2 subset C_1={contained}, "
        f"widened element in C_2={not excluded}. Would have failed if the appended right/2 had "
        f"entered the authority set: C_2 would contain {OUTSIDE_C0} and C_2 subset C_1 would be "
        f"False",
    )


def g2_a2_legitimate_narrowing(doc: dict) -> None:
    """(a) Legitimate narrowing actually narrows: C_2 strict-subset C_1 strict-subset C_0."""
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)
    sets = [
        ev.allowed(ev.Chain(chain.hops[: i + 1], keypair.public_key), doc, context())
        for i in range(chain.length)
    ]
    c0, c1, c2 = sets
    strict = c2 < c1 < c0
    root_exact = c0 == frozenset(U_TASK)
    omega = frozen_config.omega(doc)
    amplification = omega - c0

    ok = strict and root_exact and bool(amplification)
    record(
        "G-2.a2",
        True,
        ok,
        f"computed over Omega by the frozen Gamma (|Omega|={len(omega)}, one authorizer run per "
        f"element per prefix): |C_0|={len(c0)}, |C_1|={len(c1)}, |C_2|={len(c2)}; "
        f"C_2 strict-subset C_1 strict-subset C_0={strict}; C_0 == U_task={root_exact}; "
        f"Omega \\ C_0={sorted(amplification)} (non-empty, so containment is not vacuous). "
        f"Would have failed if attenuation dropped nothing (equal sets) or dropped everything",
    )


def g2_a3_fact_is_live_not_absent(doc: dict) -> None:
    """(a) negative control: the widening fact IS in the token and IS importable by a
    rule that trusts its origin — so a1's exclusion is block scoping, not absence.

    Built on the authority prefix P_0, with no attenuation block present, so the
    only thing that can decide the outcome is whether the appended fact is
    visible to the asking rule.
    """
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)
    widened_bytes = append_raw(
        chain.prefix(0),
        keypair.public_key,
        f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n',
    )

    def probe_block(scope: str) -> bool:
        """Append a check asking for the widening fact under `scope`; True iff it holds."""
        probe_bytes = append_raw(
            widened_bytes,
            keypair.public_key,
            f'check if right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}"){scope};\n',
        )
        authorizer = AuthorizerBuilder("allow if true;").build(
            Biscuit.from_bytes(probe_bytes, keypair.public_key)
        )
        try:
            authorizer.authorize()
            return True
        except AuthorizationError:
            return False

    # Same check, two scopes, opposite outcomes: the fact is live, and default
    # scoping is precisely what hides it.
    visible_when_trusting = probe_block(" trusting previous")
    hidden_by_default = not probe_block("")

    # And no scope annotation available to the AUTHORIZER reaches it.
    reachable_from_authorizer = []
    for annotation in ("", " trusting authority", " trusting previous"):
        probe = AuthorizerBuilder(f"allow if operation($a, $r), right($a, $r){annotation};")
        probe.add_fact(Fact("operation({a}, {r})", {"a": OUTSIDE_C0[0], "r": OUTSIDE_C0[1]}))
        try:
            probe.build(Biscuit.from_bytes(widened_bytes, keypair.public_key)).authorize()
            reachable_from_authorizer.append(annotation.strip() or "default")
        except AuthorizationError:
            pass

    ok = visible_when_trusting and hidden_by_default and not reachable_from_authorizer
    record(
        "G-2.a3",
        True,
        ok,
        f"non-vacuity of a1, on P_0 + one widening block (no attenuation check in play): the "
        f"identical check `right{OUTSIDE_C0}` HOLDS when the asking block opts into "
        f"`trusting previous` ({visible_when_trusting}) and FAILS under default scoping "
        f"({hidden_by_default}) — the fact is live in the token, and scoping is what hides it. "
        f"No authorizer scope reaches it either (default / trusting authority / trusting "
        f"previous; admitted by: {reachable_from_authorizer or 'none'}), and Gamma's grant is "
        f"read by the authorizer policy. Would have failed if the fact were simply absent, or if "
        f"default scoping had also admitted it",
    )


def g2_a4_broadening_vectors(doc: dict) -> None:
    """(a) Widening is not only a `right/2` fact: six appended broadening vectors, none of
    which enlarges C_n, including two probed under the condition they were meant to unlock."""
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)
    baseline = ev.allowed(chain, doc, context())

    vectors = {
        "derivation rule right <- scope": "right($a, $r) <- scope($a, $r);\n",
        "unconditional widening rule": f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}") <- true;\n',
        "expiry extension": "expiry(2099-01-01T00:00:00Z);\n",
        "audience widening": 'token_audience("evil-audience");\n',
        "task widening": 'token_task("other-task");\n',
        f"re-add scope{NARROWED_AWAY}": f'scope("{NARROWED_AWAY[0]}", "{NARROWED_AWAY[1]}");\n',
    }
    grew: list[str] = []
    for name, source in vectors.items():
        tampered = ev.Chain(
            (*chain.hops, append_raw(chain.prefix(chain.length - 1), keypair.public_key, source)),
            keypair.public_key,
        )
        if not ev.allowed(tampered, doc, context()) <= baseline:
            grew.append(name)

    # The two time/audience vectors probed under the condition they were meant to unlock:
    # an expiry extension evaluated AFTER the real expiry, and an audience widening
    # evaluated WITH the widened audience requested.
    late = ev.RequestContext(now=EXPIRY + timedelta(days=180), audience=AUDIENCE, task=TASK)
    extended = ev.Chain(
        (
            *chain.hops,
            append_raw(
                chain.prefix(chain.length - 1),
                keypair.public_key,
                "expiry(2099-01-01T00:00:00Z);\n",
            ),
        ),
        keypair.public_key,
    )
    expiry_unlocked = bool(ev.allowed(extended, doc, late))

    evil = ev.RequestContext(now=NOW, audience="evil-audience", task=TASK)
    widened_aud = ev.Chain(
        (
            *chain.hops,
            append_raw(
                chain.prefix(chain.length - 1),
                keypair.public_key,
                'token_audience("evil-audience");\n',
            ),
        ),
        keypair.public_key,
    )
    audience_unlocked = bool(ev.allowed(widened_aud, doc, evil))

    ok = not grew and not expiry_unlocked and not audience_unlocked
    record(
        "G-2.a4",
        True,
        ok,
        f"{len(vectors)} appended broadening vectors ({', '.join(vectors)}): sets that grew="
        f"{grew or 'none'}. Probed under the unlocking condition: an appended expiry(2099) "
        f"evaluated after the real expiry admits {'something' if expiry_unlocked else 'nothing'}; "
        f"an appended token_audience evaluated with that audience requested admits "
        f"{'something' if audience_unlocked else 'nothing'}. So a1 is not a property of `right/2` "
        f"facts alone: no later-block fact or rule reaches Gamma's policy or its checks. Would "
        f"have failed if any vector enlarged C_n or unlocked a failing check",
    )


def g2_b1_third_party_block(doc: dict) -> None:
    """(b) A third-party block is rejected as out of profile — full construction."""
    keypair = KeyPair()
    attacker = KeyPair()
    chain = legitimate_chain(doc, keypair)

    # Full construction: the library's real third-party machinery, attacker-signed.
    # Built on P_0 so the third-party `right` fact is the only thing that could
    # admit the element — no attenuation check confounds the outcome.
    base = Biscuit.from_bytes(chain.prefix(0), keypair.public_key)
    request = base.third_party_request()
    block = request.create_block(
        attacker.private_key,
        BlockBuilder(f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'),
    )
    tp_bytes = bytes(base.append_third_party(attacker.public_key, block).to_bytes())

    # The LIBRARY accepts it: signature verification is not the rejection.
    tp_token = Biscuit.from_bytes(tp_bytes, keypair.public_key)
    external_key = tp_token.block_external_key(tp_token.block_count() - 1)
    library_accepts = external_key is not None

    # The PROJECT rejects it structurally, before any Datalog runs.
    structural_rejection = "none"
    try:
        commitment.block_ids_from_raw(tp_bytes, keypair.public_key)
        rejected = False
    except commitment.TokenStructureError as exc:
        rejected = True
        structural_rejection = f"{type(exc).__name__}: {exc}"

    # And the evaluator refuses the prefix for the same reason.
    evaluator_refuses = False
    try:
        ev.Chain((*chain.hops[:1], tp_bytes), keypair.public_key)
    except commitment.TokenStructureError:
        evaluator_refuses = True

    # Presented to the AUTHORIZER as well (not only to the structural layer):
    # under the frozen Gamma the third-party fact is trusted by nothing.
    permitted, evidence = ev.authorize_candidate(
        tp_bytes, keypair.public_key, frozen_config.gamma(doc), OUTSIDE_C0, context()
    )

    ok = library_accepts and rejected and evaluator_refuses and not permitted
    record(
        "G-2.b1",
        True,
        ok,
        f"third-party block fully constructed (third_party_request -> create_block(attacker "
        f"private key) -> append_third_party) and the LIBRARY verifies it under kappa_pub alone "
        f"(block_external_key={str(external_key)[:24]}...), so signature verification is NOT the "
        f"rejection. Structural pre-evaluation rejection: {structural_rejection}; the evaluator "
        f"refuses to admit the prefix={evaluator_refuses}. Presented to the authorizer as well: "
        f"frozen Gamma denies {OUTSIDE_C0} ({evidence[:60]}). Would have failed if either layer "
        f"had admitted it",
    )


def g2_b2_trusting_annotation(doc: dict) -> None:
    """(b) A `trusting {attacker_key}` configuration is rejected — and would otherwise admit."""
    keypair = KeyPair()
    attacker = KeyPair()
    chain = legitimate_chain(doc, keypair)
    base = Biscuit.from_bytes(chain.prefix(0), keypair.public_key)
    request = base.third_party_request()
    block = request.create_block(
        attacker.private_key,
        BlockBuilder(f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'),
    )
    tp_bytes = bytes(base.append_third_party(attacker.public_key, block).to_bytes())

    frozen_has_none = sum(
        source.count("trusting")
        for source in doc["gamma"]["datalog"].values()
        if isinstance(source, str)
    )

    # The out-of-profile authorizer, built only to prove the check is not vacuous.
    trusting_gamma = frozen_config.gamma(doc)
    trusting_gamma["datalog"]["authorizer"] = trusting_gamma["datalog"]["authorizer"].replace(
        "allow if operation($action, $resource), right($action, $resource);",
        "allow if operation($action, $resource), right($action, $resource) "
        "trusting authority, {attacker};",
    )
    trusting_gamma["trust"]["trusting_annotations"] = "permitted"

    # It is refused before evaluation.
    profile_rejection = "none"
    try:
        ev.check_profile(doc, trusting_gamma)
        refused = False
    except ev.AuthorizerProfileError as exc:
        refused = True
        profile_rejection = f"{type(exc).__name__}: {exc}"

    # Non-vacuity: if it HAD been evaluated, it would have admitted the widening.
    builder = AuthorizerBuilder()
    builder.add_code(
        trusting_gamma["datalog"]["authorizer"], None, {"attacker": attacker.public_key}
    )
    builder.add_fact(Fact("operation({a}, {r})", {"a": OUTSIDE_C0[0], "r": OUTSIDE_C0[1]}))
    for fact in context().facts():
        builder.add_fact(fact)
    try:
        builder.build(Biscuit.from_bytes(tp_bytes, keypair.public_key)).authorize()
        would_admit = True
    except AuthorizationError:
        would_admit = False

    ok = frozen_has_none == 0 and refused and would_admit
    record(
        "G-2.b2",
        True,
        ok,
        f"`trusting` occurrences in the frozen Gamma Datalog={frozen_has_none}; an authorizer "
        f"carrying `trusting authority, {{attacker_key}}` is refused pre-evaluation "
        f"({profile_rejection}). Non-vacuity: that same authorizer, if evaluated, ADMITS "
        f"{OUTSIDE_C0} from the third-party block ({would_admit}) — the rejection is what "
        f"prevents the escalation, not an inability to express it. Would have failed if the "
        f"out-of-profile authorizer had been accepted, or had made no difference",
    )


def g2_c_gamma_mutation_detected(doc: dict) -> None:
    """(c) Every trust-broadening mutation of a COPY changes H(Gamma); the artifact is intact."""
    on_disk_before = frozen_config.DOCUMENT_PATH.read_bytes()
    baseline = frozen_config.h_gamma(doc)

    mutations: dict[str, dict] = {}

    add_key = copy.deepcopy(doc)
    add_key["gamma"]["trust"]["trusted_keys"] = ["kappa", "attacker"]
    add_key["gamma"]["trust"]["trusted_key_count"] = 2
    mutations["add a trusted key"] = add_key

    accept_tp = copy.deepcopy(doc)
    accept_tp["gamma"]["trust"]["third_party_blocks"] = "accept"
    mutations["accept third-party blocks"] = accept_tp

    permit_trusting = copy.deepcopy(doc)
    permit_trusting["gamma"]["trust"]["trusting_annotations"] = "permitted"
    mutations["permit `trusting` annotations"] = permit_trusting

    edit_datalog = copy.deepcopy(doc)
    edit_datalog["gamma"]["datalog"]["authorizer"] = edit_datalog["gamma"]["datalog"][
        "authorizer"
    ].replace(
        "allow if operation($action, $resource), right($action, $resource);", "allow if true;"
    )
    mutations["edit the Datalog"] = edit_datalog

    widen_omega = copy.deepcopy(doc)
    widen_omega["omega"]["elements"].append(["notes.delete", "notes/meeting"])
    mutations["widen Omega"] = widen_omega

    digests = {name: frozen_config.h_gamma(mutated) for name, mutated in mutations.items()}
    all_changed = all(digest != baseline for digest in digests.values())
    all_distinct = len(set(digests.values())) == len(digests)

    # Negative control: a semantics-preserving reserialization must NOT change it.
    reordered = {key: doc[key] for key in reversed(list(doc))}
    reorder_stable = frozen_config.h_gamma(reordered) == baseline

    on_disk_after = frozen_config.DOCUMENT_PATH.read_bytes()
    artifact_intact = on_disk_after == on_disk_before
    reloaded = frozen_config.h_gamma(frozen_config.load_document())
    row8_intact = reloaded == ROW8_H_GAMMA

    ok = all_changed and all_distinct and reorder_stable and artifact_intact and row8_intact
    record(
        "G-2.c",
        True,
        ok,
        "five in-memory mutations, none written to disk: "
        + "; ".join(f"{name} -> {digest[:12]}..." for name, digest in digests.items())
        + f" (all differ from baseline {baseline[:12]}...={all_changed}, all distinct="
        f"{all_distinct}). Negative control: member-reordered document keeps the digest "
        f"({reorder_stable}), so the digest is not merely always-different. On-disk artifact "
        f"byte-identical after the run={artifact_intact}; reloaded H(Gamma) still equals row 8="
        f"{row8_intact} ({reloaded}). Would have failed if any mutation left H(Gamma) unchanged",
    )


def g2_d1_minus_attenuation_admits(doc: dict) -> None:
    """(d) On the same attacking chain, full Gamma refuses what -attenuation admits."""
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)

    # F1-chain-tamper: the terminal holder appends a block trying to restore an
    # element that hop 1 narrowed away.
    tampered_bytes = append_raw(
        chain.prefix(2),
        keypair.public_key,
        f'right("{NARROWED_AWAY[0]}", "{NARROWED_AWAY[1]}");\n',
    )
    tampered = ev.Chain((*chain.hops, tampered_bytes), keypair.public_key)

    full = frozen_config.gamma(doc)
    ablated = frozen_config.gamma_ablation(doc, "minus_attenuation")

    c_full = ev.allowed(tampered, doc, context(), gamma=full)
    c_ablated = ev.allowed(tampered, doc, context(), gamma=ablated)

    full_refuses = NARROWED_AWAY not in c_full
    ablation_admits = NARROWED_AWAY in c_ablated
    c0 = ev.allowed(ev.Chain(chain.hops[:1], keypair.public_key), doc, context())
    ablation_is_p0 = c_ablated == c0
    gap = c_ablated - c_full

    ok = full_refuses and ablation_admits and ablation_is_p0
    record(
        "G-2.d1",
        True,
        ok,
        f"same tampered chain (hop 1 narrowed {NARROWED_AWAY} away; the terminal holder appended "
        f"right{NARROWED_AWAY} to restore it): full Gamma computes |C_n|={len(c_full)} and "
        f"REFUSES {NARROWED_AWAY} ({full_refuses}); -attenuation computes "
        f"|Allowed(P_0)|={len(c_ablated)} and ADMITS it ({ablation_admits}); the ablated set "
        f"equals the independently computed C_0={ablation_is_p0}; admitted-but-blocked gap = "
        f"{sorted(gap)}. Would have failed if the control blocked it too (no contrast) or if the "
        f"full form admitted it",
    )


def g2_d2_control_is_matched(doc: dict) -> None:
    """(d) The control differs from the full form in exactly `evaluation.prefix`."""
    full = frozen_config.gamma(doc)
    ablated = frozen_config.gamma_ablation(doc, "minus_attenuation")
    spec = doc["gamma_ablations"]["minus_attenuation"]

    def flatten(node, prefix=""):
        out = {}
        for key, value in node.items():
            path = f"{prefix}{key}"
            if isinstance(value, dict):
                out.update(flatten(value, f"{path}."))
            else:
                out[path] = repr(value)
        return out

    left, right = flatten(full), flatten(ablated)
    differing = sorted(k for k in left | right if left.get(k) != right.get(k))
    declared = sorted(spec["differs_in_exactly"])
    matched = differing == declared == ["evaluation.prefix"]
    datalog_identical = full["datalog"] == ablated["datalog"]

    # The loader rejects a delta that drifts (ADR 0016; the assertion is also pinned by
    # tests/test_omega_gamma_freeze.py::test_ablation_declaration_must_match_override).
    drifted = copy.deepcopy(doc)
    drifted["gamma_ablations"]["minus_attenuation"]["override"]["trust.block_scoping"] = "all"
    try:
        frozen_config._validate_ablations(drifted)
        drift_rejected = False
    except frozen_config.DocumentStructureError:
        drift_rejected = True

    ok = matched and datalog_identical and drift_rejected
    record(
        "G-2.d2",
        True,
        ok,
        f"materialized difference between the full and ablated forms = {differing}, declared "
        f"differs_in_exactly={declared}, matched={matched}; Datalog byte-identical="
        f"{datalog_identical} (so the outcome contrast in d1 is attributable to attenuation "
        f"alone, not to a second edit). A delta declaring one path but overriding two is rejected "
        f"by the loader={drift_rejected}. Would have failed if the forms differed anywhere else",
    )


def g2_e_evaluation_shape(doc: dict) -> None:
    """(informational) The evaluation actually performed, for the record."""
    keypair = KeyPair()
    chain = legitimate_chain(doc, keypair)
    omega = frozen_config.omega(doc)
    commitments = [chain.commitment(i).hex() for i in range(chain.length)]
    prefix_stable = all(
        chain.block_ids(chain.length - 1)[: i + 1] == chain.block_ids(i)
        for i in range(chain.length)
    )
    record(
        "G-2.E",
        False,
        prefix_stable,
        f"|Omega|={len(omega)} candidates x {chain.length} prefixes = "
        f"{len(omega) * chain.length} independent authorizer runs per chain; facts injected as "
        f"AUTHORIZER facts: operation(<action>, <resource>), time, request_audience, "
        f"request_task; H(P_i) via ADR 0003 commit_prefix (G-1's construction): "
        + ", ".join(f"H(P_{i})={c[:16]}..." for i, c in enumerate(commitments))
        + f"; each hop's BlockIDs are a verified prefix of the terminal hop's={prefix_stable}",
    )


def main() -> int:
    print("Gate G-2 spike — frozen Gamma under biscuit-python 0.4.0 (module biscuit_auth)")
    print("Frozen Omega/Gamma per ADR 0016; every C_i computed, never asserted.\n")

    doc = frozen_config.load_document()
    digest = frozen_config.h_gamma(doc)
    if digest != ROW8_H_GAMMA:
        print(f"ABORT: H(Gamma)={digest} does not match frozen_parameters row 8 {ROW8_H_GAMMA}")
        return 2
    print(f"loaded frozen artifact, H(Gamma)={digest} (matches row 8)")
    file_digest = hashlib.sha256(frozen_config.DOCUMENT_PATH.read_bytes()).hexdigest()
    print(f"artifact sha256(file bytes)={file_digest}\n")

    g2_a1_widening_append(doc)
    g2_a2_legitimate_narrowing(doc)
    g2_a3_fact_is_live_not_absent(doc)
    g2_a4_broadening_vectors(doc)
    g2_b1_third_party_block(doc)
    g2_b2_trusting_annotation(doc)
    g2_c_gamma_mutation_detected(doc)
    g2_d1_minus_attenuation_admits(doc)
    g2_d2_control_is_matched(doc)
    g2_e_evaluation_shape(doc)

    mandatory_failures = [c for c, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if mandatory_failures:
        print(f"GATE G-2: FAIL — mandatory check(s) failed: {', '.join(mandatory_failures)}")
        print(
            "Gate-outcome policy (Part G): G-1/G-2 fail -> Macaroon-style caveat chain "
            "(losing root-public-key verification) or FFI to the Rust biscuit-auth library. "
            "No fallback is implemented here; the decision rests with the author."
        )
        return 1
    print("GATE G-2: all mandatory checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
