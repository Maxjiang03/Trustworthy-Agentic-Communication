"""Regression suite for the frozen authorizer semantics (gate G-2, ADR 0016).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. What is under test is `src/harness/authorizer/allowed.py` computing
`Allowed(P_i; Gamma, kappa, Omega)` by running the pinned Biscuit authorizer
over the frozen `Omega`/`Gamma` — never an asserted authority set.

Unlike the effect-ledger suite (Windows-only per ADR 0014), these tests are
platform-independent: they run the authorizer, so they must pass on Linux CI
too.

The frozen vocabulary IS the ontology here — this suite deliberately uses
`Omega`, not pilot strings, because the frozen values are what G-2 adjudicates.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import (
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BlockBuilder,
    Fact,
    KeyPair,
)

from src.harness.authorizer import allowed as ev
from src.harness.authorizer import frozen_config
from src.harness.oracle import commitment

ROW8_H_GAMMA = "f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb"

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
EXPIRY = datetime(2027, 1, 1, tzinfo=timezone.utc)
AUDIENCE = "mcp-boundary"
TASK = "task-g2-pilot"

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
OUTSIDE_C0 = ("notes.delete", "notes/project")  # in Omega, never granted
NARROWED_AWAY = ("mail.send", "mail/outbox")  # in C_0, dropped at hop 1


@pytest.fixture
def doc():
    return frozen_config.load_document()


@pytest.fixture
def keypair():
    return KeyPair()


@pytest.fixture
def context():
    return ev.RequestContext(now=NOW, audience=AUDIENCE, task=TASK)


@pytest.fixture
def chain(doc, keypair):
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


def sets_along(chain, doc, context):
    return [
        ev.allowed(ev.Chain(chain.hops[: i + 1], chain.root_pub), doc, context)
        for i in range(chain.length)
    ]


def append_raw(token_bytes, root_pub, source):
    return bytes(Biscuit.from_bytes(token_bytes, root_pub).append(BlockBuilder(source)).to_bytes())


# --------------------------------------------------------------------------
# Criterion (a): monotone attenuation, computed
# --------------------------------------------------------------------------


def test_c0_equals_u_task(chain, doc, context):
    """C_0 = U_task exactly (SS A.0.1), and is a strict subset of Omega."""
    c0 = sets_along(chain, doc, context)[0]
    omega = frozen_config.omega(doc)
    assert c0 == frozenset(U_TASK)
    assert c0 < omega  # negative arm: the grant is not all of Omega
    assert OUTSIDE_C0 in omega - c0


def test_two_hop_attenuation_is_strict(chain, doc, context):
    """INV-2 computed, and strict at both hops so containment is not vacuous."""
    c0, c1, c2 = sets_along(chain, doc, context)
    assert c2 < c1 < c0
    assert NARROWED_AWAY in c0 and NARROWED_AWAY not in c1


def test_appended_widening_verifies_but_does_not_widen(chain, doc, context, keypair):
    """(a) The widening append is cryptographically valid AND changes no authority."""
    c1 = sets_along(chain, doc, context)[1]
    widened = append_raw(
        chain.prefix(1), keypair.public_key, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )

    # Positive arm: the token really is valid — the library verifies it and the
    # independent ADR 0003 extractor accepts it.
    verified = Biscuit.from_bytes(widened, keypair.public_key)
    assert verified.block_count() == 3
    assert len(commitment.block_ids_from_raw(widened, keypair.public_key)) == 3
    assert f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}")' in verified.block_source(2)

    # Negative arm: the authority set is unchanged and still contained.
    c2 = ev.allowed(ev.Chain((*chain.hops[:2], widened), keypair.public_key), doc, context)
    assert OUTSIDE_C0 not in c2
    assert c2 <= c1


def test_widening_fact_is_live_but_hidden_by_default_scoping(chain, doc, keypair):
    """(a) non-vacuity: the same check holds under `trusting previous` and fails by default."""
    widened = append_raw(
        chain.prefix(0), keypair.public_key, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )

    def check_holds(scope: str) -> bool:
        probe = append_raw(
            widened,
            keypair.public_key,
            f'check if right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}"){scope};\n',
        )
        authorizer = AuthorizerBuilder("allow if true;").build(
            Biscuit.from_bytes(probe, keypair.public_key)
        )
        try:
            authorizer.authorize()
            return True
        except AuthorizationError:
            return False

    assert check_holds(" trusting previous") is True  # the fact is present
    assert check_holds("") is False  # default scoping hides it


def authorizer_admits(token_bytes, root_pub, element, annotation):
    probe = AuthorizerBuilder(f"allow if operation($a, $r), right($a, $r){annotation};")
    probe.add_fact(Fact("operation({a}, {r})", {"a": element[0], "r": element[1]}))
    try:
        probe.build(Biscuit.from_bytes(token_bytes, root_pub)).authorize()
        return True
    except AuthorizationError:
        return False


@pytest.mark.parametrize("annotation", ["", " trusting authority", " trusting previous"])
def test_authorizer_cannot_reach_later_block_facts(chain, keypair, annotation):
    """(a) No scope annotation available to the authorizer imports a later-block fact."""
    widened = append_raw(
        chain.prefix(0), keypair.public_key, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )
    assert authorizer_admits(widened, keypair.public_key, OUTSIDE_C0, annotation) is False


@pytest.mark.parametrize("annotation", ["", " trusting authority"])
def test_authorizer_still_admits_authority_grants(chain, keypair, annotation):
    """(a) positive arm: the denial above is not blanket — granted elements authorize."""
    widened = append_raw(
        chain.prefix(0), keypair.public_key, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )
    assert authorizer_admits(widened, keypair.public_key, U_TASK[0], annotation) is True


def test_trusting_previous_reaches_no_token_facts_from_the_authorizer(chain, keypair):
    """Recorded library behaviour: from the authorizer, `trusting previous` REPLACES the
    default trust set and then resolves to nothing — it reaches neither the authority
    block nor a later block. Pinned so a library bump surfaces the change."""
    widened = append_raw(
        chain.prefix(0), keypair.public_key, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )
    assert authorizer_admits(widened, keypair.public_key, U_TASK[0], " trusting previous") is False
    assert authorizer_admits(widened, keypair.public_key, U_TASK[0], "") is True


BROADENING_VECTORS = {
    "derivation_rule": "right($a, $r) <- scope($a, $r);\n",
    "unconditional_rule": f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}") <- true;\n',
    "expiry_extension": "expiry(2099-01-01T00:00:00Z);\n",
    "audience_widening": 'token_audience("evil-audience");\n',
    "task_widening": 'token_task("other-task");\n',
    "scope_re_add": f'scope("{NARROWED_AWAY[0]}", "{NARROWED_AWAY[1]}");\n',
}


@pytest.mark.parametrize("name", sorted(BROADENING_VECTORS))
def test_appended_broadening_vector_does_not_widen(chain, doc, context, keypair, name):
    """(a) Widening is not only a `right/2` fact: no later-block fact or rule reaches
    Gamma's policy or its checks."""
    baseline = ev.allowed(chain, doc, context)
    assert baseline  # positive arm: the untampered chain admits something
    tampered = ev.Chain(
        (
            *chain.hops,
            append_raw(
                chain.prefix(chain.length - 1), keypair.public_key, BROADENING_VECTORS[name]
            ),
        ),
        keypair.public_key,
    )
    assert ev.allowed(tampered, doc, context) <= baseline


def test_appended_expiry_does_not_extend_lifetime(chain, doc, keypair):
    """(a) The expiry vector probed under the condition it was meant to unlock."""
    late = ev.RequestContext(now=EXPIRY + timedelta(days=180), audience=AUDIENCE, task=TASK)
    tampered = ev.Chain(
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
    assert ev.allowed(tampered, doc, late) == frozenset()
    # Positive arm: before the real expiry the same chain admits something.
    assert ev.allowed(tampered, doc, ev.RequestContext(now=NOW, audience=AUDIENCE, task=TASK))


def test_appended_audience_does_not_widen_audience(chain, doc, keypair):
    """(a) The audience vector probed with the widened audience requested."""
    evil = ev.RequestContext(now=NOW, audience="evil-audience", task=TASK)
    tampered = ev.Chain(
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
    assert ev.allowed(tampered, doc, evil) == frozenset()
    assert ev.allowed(tampered, doc, ev.RequestContext(now=NOW, audience=AUDIENCE, task=TASK))


# --------------------------------------------------------------------------
# Criterion (b): third-party blocks and `trusting` are out of profile
# --------------------------------------------------------------------------


def third_party_token(chain, keypair, attacker, source):
    base = Biscuit.from_bytes(chain.prefix(0), keypair.public_key)
    block = base.third_party_request().create_block(attacker.private_key, BlockBuilder(source))
    return bytes(base.append_third_party(attacker.public_key, block).to_bytes())


def test_third_party_block_rejected_before_evaluation(chain, keypair):
    """(b) The structural layer refuses the token; the library alone does not."""
    attacker = KeyPair()
    tp = third_party_token(
        chain, keypair, attacker, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )

    # The library accepts it: signature verification is NOT the rejection.
    token = Biscuit.from_bytes(tp, keypair.public_key)
    assert token.block_external_key(token.block_count() - 1) is not None

    # The project rejects it structurally, before any Datalog runs.
    with pytest.raises(commitment.TokenStructureError, match="external"):
        commitment.block_ids_from_raw(tp, keypair.public_key)
    with pytest.raises(commitment.TokenStructureError):
        ev.Chain((chain.hops[0], tp), keypair.public_key)


def test_frozen_gamma_denies_third_party_widening(chain, doc, context, keypair):
    """(b) Semantic backstop: even presented to the authorizer, the fact is trusted by nothing."""
    attacker = KeyPair()
    tp = third_party_token(
        chain, keypair, attacker, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )
    gamma = frozen_config.gamma(doc)
    permitted, _ = ev.authorize_candidate(tp, keypair.public_key, gamma, OUTSIDE_C0, context)
    assert permitted is False

    # Positive arm: a genuinely granted element still authorizes on the same token.
    granted, _ = ev.authorize_candidate(tp, keypair.public_key, gamma, U_TASK[0], context)
    assert granted is True


def test_trusting_authorizer_refused_but_would_have_admitted(chain, doc, context, keypair):
    """(b) The out-of-profile authorizer is refused pre-evaluation — and it does escalate."""
    attacker = KeyPair()
    tp = third_party_token(
        chain, keypair, attacker, f'right("{OUTSIDE_C0[0]}", "{OUTSIDE_C0[1]}");\n'
    )
    trusting = frozen_config.gamma(doc)
    trusting["datalog"]["authorizer"] = trusting["datalog"]["authorizer"].replace(
        "allow if operation($action, $resource), right($action, $resource);",
        "allow if operation($action, $resource), right($action, $resource) "
        "trusting authority, {attacker};",
    )

    with pytest.raises(ev.AuthorizerProfileError, match="trusting"):
        ev.check_profile(doc, trusting)

    # Negative arm: had it been evaluated, it would have admitted the widening.
    builder = AuthorizerBuilder()
    builder.add_code(trusting["datalog"]["authorizer"], None, {"attacker": attacker.public_key})
    builder.add_fact(Fact("operation({a}, {r})", {"a": OUTSIDE_C0[0], "r": OUTSIDE_C0[1]}))
    for fact in context.facts():
        builder.add_fact(fact)
    assert builder.build(Biscuit.from_bytes(tp, keypair.public_key)).authorize() == 0


def test_frozen_gamma_carries_no_trusting_annotation(doc):
    """(b) The frozen text itself is inside the profile."""
    assert all(
        "trusting" not in source
        for source in doc["gamma"]["datalog"].values()
        if isinstance(source, str)
    )
    ev.check_profile(doc)  # the frozen document passes its own profile check


@pytest.mark.parametrize(
    "path,value",
    [
        ("trusted_keys", ["kappa", "attacker"]),
        ("third_party_blocks", "accept"),
        ("trusting_annotations", "permitted"),
        ("block_scoping", "all"),
    ],
)
def test_profile_refuses_broadened_trust(doc, path, value):
    """(b) Each trust-broadening configuration is refused before evaluation."""
    broadened = frozen_config.gamma(doc)
    broadened["trust"][path] = value
    with pytest.raises(ev.AuthorizerProfileError):
        ev.check_profile(doc, broadened)


# --------------------------------------------------------------------------
# Criterion (c): H(Gamma) detects trust-broadening mutation
# --------------------------------------------------------------------------


def mutate(doc, fn):
    mutated = copy.deepcopy(doc)
    fn(mutated)
    return mutated


MUTATIONS = {
    "add_trusted_key": lambda d: d["gamma"]["trust"]["trusted_keys"].append("attacker"),
    "accept_third_party": lambda d: d["gamma"]["trust"].__setitem__("third_party_blocks", "accept"),
    "permit_trusting": lambda d: d["gamma"]["trust"].__setitem__(
        "trusting_annotations", "permitted"
    ),
    "edit_datalog": lambda d: d["gamma"]["datalog"].__setitem__(
        "authorizer", d["gamma"]["datalog"]["authorizer"].replace("allow if", "allow if true; //")
    ),
    "widen_omega": lambda d: d["omega"]["elements"].append(["notes.delete", "notes/meeting"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_changes_h_gamma(doc, name):
    """(c) Every trust-broadening or ontology-widening mutation changes the digest."""
    assert frozen_config.h_gamma(mutate(doc, MUTATIONS[name])) != frozen_config.h_gamma(doc)


def test_h_gamma_survives_member_reordering(doc):
    """(c) negative control: the digest is not merely always-different."""
    reordered = {key: doc[key] for key in reversed(list(doc))}
    assert frozen_config.h_gamma(reordered) == frozen_config.h_gamma(doc)


def test_artifact_matches_row_eight(doc):
    """(c) The on-disk frozen artifact still hashes to the recorded row-8 value."""
    assert frozen_config.h_gamma(doc) == ROW8_H_GAMMA


# --------------------------------------------------------------------------
# Criterion (d): the matched -attenuation control
# --------------------------------------------------------------------------


def test_minus_attenuation_admits_what_full_gamma_refuses(chain, doc, context, keypair):
    """(d) Same chain, opposite outcomes, difference attributable to attenuation."""
    tampered_bytes = append_raw(
        chain.prefix(2), keypair.public_key, f'right("{NARROWED_AWAY[0]}", "{NARROWED_AWAY[1]}");\n'
    )
    tampered = ev.Chain((*chain.hops, tampered_bytes), keypair.public_key)

    full = ev.allowed(tampered, doc, context, gamma=frozen_config.gamma(doc))
    ablated = ev.allowed(
        tampered, doc, context, gamma=frozen_config.gamma_ablation(doc, "minus_attenuation")
    )

    assert NARROWED_AWAY not in full
    assert NARROWED_AWAY in ablated
    assert ablated == sets_along(chain, doc, context)[0]  # the control is exactly Allowed(P_0)


def test_ablation_differs_only_in_evaluation_prefix(doc):
    """(d) The control is matched: one declared difference, identical Datalog."""
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
    assert sorted(k for k in left | right if left.get(k) != right.get(k)) == ["evaluation.prefix"]
    assert spec["differs_in_exactly"] == ["evaluation.prefix"]
    assert full["datalog"] == ablated["datalog"]


# --------------------------------------------------------------------------
# The evaluator's own guarantees
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", "other-audience"),
        ("task", "other-task"),
    ],
)
def test_context_mismatch_denies_everything(chain, doc, context, field, value):
    """Gamma's audience/task checks are live: a mismatch empties the authority set."""
    assert ev.allowed(chain, doc, context)  # positive arm: matching context admits something
    mismatched = ev.RequestContext(
        now=context.now,
        audience=value if field == "audience" else context.audience,
        task=value if field == "task" else context.task,
    )
    assert ev.allowed(chain, doc, mismatched) == frozenset()


def test_expired_capability_denies_everything(chain, doc, context):
    """Gamma's expiry check is live."""
    expired = ev.RequestContext(now=EXPIRY + timedelta(days=1), audience=AUDIENCE, task=TASK)
    assert ev.allowed(chain, doc, expired) == frozenset()
    assert ev.allowed(chain, doc, context) != frozenset()


def test_unverifiable_prefix_fails_closed(chain):
    """crypto_chain_ok is a conjunct: a wrong root key raises, never returns a set."""
    with pytest.raises(Exception):  # noqa: B017 — library error type is the point of the guard
        ev.Chain(chain.hops, KeyPair().public_key)


def test_chain_rejects_a_non_extending_hop(chain, doc, keypair):
    """A `Chain` verifies the prefix relation from signatures, not from call order."""
    other = ev.build_chain(
        doc,
        keypair.private_key,
        keypair.public_key,
        U_TASK,
        [C1_ELEMENTS],
        audience=AUDIENCE,
        task=TASK,
        expiry=EXPIRY,
    )
    ev.Chain(chain.hops, keypair.public_key)  # positive arm
    with pytest.raises(ev.ChainStructureError, match="extension"):
        ev.Chain((chain.hops[0], other.hops[1]), keypair.public_key)


def test_prefix_commitment_is_the_adr_0003_construction(chain, keypair):
    """H(P_i) here is `commit_prefix` over BlockIDs — G-1's construction, not a second one."""
    for index in range(chain.length):
        block_ids = commitment.block_ids_from_raw(chain.prefix(index), keypair.public_key)
        assert chain.commitment(index) == commitment.commit_prefix(block_ids, index)
    # Prefix stability (G-1.F) holds across the hops this suite builds.
    terminal = commitment.block_ids_from_raw(chain.prefix(chain.length - 1), keypair.public_key)
    assert terminal[:1] == commitment.block_ids_from_raw(chain.prefix(0), keypair.public_key)


def test_render_block_instantiates_the_frozen_template(doc):
    """Blocks are rendered from the frozen templates, one fact per element."""
    template = doc["gamma"]["datalog"]["attenuation_block_template"]
    rendered = ev.render_block(template, C1_ELEMENTS)
    assert rendered.count('scope("') == len(C1_ELEMENTS)  # one fact per element
    assert rendered.count("check if") == 1  # the consuming check, emitted once
    assert "check if operation($action, $resource), scope($action, $resource);" in rendered
    assert "<action>" not in rendered and "<resource>" not in rendered

    authority = ev.render_block(
        doc["gamma"]["datalog"]["authority_block_template"],
        U_TASK,
        audience=AUDIENCE,
        task_id=TASK,
        instant=ev.datalog_instant(EXPIRY),
    )
    assert authority.count('right("') == len(U_TASK)
    assert f'token_audience("{AUDIENCE}")' in authority
    assert "<audience>" not in authority and "<instant>" not in authority
