"""Regression suite for the pinned experiment AS (gate G-4 Phase 2, ADR 0015).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. What is under test is `src/sut/oauth_as/` -- the token endpoint, the
RFC 8693 exchange, RFC 9396 RAR carriage and containment -- together with the
boundary-side verification in `src/sut/authz/boundary.py` that limb L2 needs.

Platform-independent: unlike the Windows-only effect-ledger suite (ADR 0014),
these tests drive a loopback TLS socket and must pass on Linux CI too.

The spike-local stand-ins come from `smoke/g4/campaign.py` (loaded by path,
because `smoke/` is not a package): the **C3 identity registry** and the
`may_act` **delegation policy**, both re-triggered at G-11 / by
`frozen_parameters` row 5. `Omega` is the **frozen** ontology -- ADR 0016 closed
conflict C1, so L2 uses no stand-in.

The AT profile is RFC 9068-**shaped** and deliberately **not** RFC
9068-conformant (DESIGN SS 8.3): the project signs Ed25519 with an explicit
allowlist and excludes RS256 by decision.
"""

import json
import sys
import time
import unicodedata
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPIKE_DIR = REPO_ROOT / "smoke" / "g4"
for entry in (str(REPO_ROOT), str(SPIKE_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import campaign as camp  # noqa: E402

from src.sut import dpop  # noqa: E402
from src.sut.authz import boundary  # noqa: E402
from src.sut.oauth_as import rar  # noqa: E402
from src.sut.oauth_as.errors import OAuthError  # noqa: E402
from src.sut.oauth_as.exchange import REQUESTED_EXPIRES_IN, parse_form  # noqa: E402
from src.sut.oauth_as.tokens import current_actor  # noqa: E402


@pytest.fixture(scope="module")
def run():
    """One AS on a loopback TLS 1.3 socket for the whole module."""
    server = camp.start()
    yield server
    server.stop()


@pytest.fixture
def config():
    return boundary.BoundaryConfig(
        issuer=camp.ISSUER,
        resource_server=camp.RESOURCE_SERVER,
        as_public_jwk=camp.public_jwk(),
        rar_type=camp.RAR_TYPE,
    )


def claims_of(token: str, config) -> dict:
    return boundary.verify_access_token(token, config, now=int(time.time()))


# ---------------------------------------------------------------------------
# L1 — a task-narrowed token issues
# ---------------------------------------------------------------------------


def test_narrowing_exchange_issues_and_echoes_granted_rar(run, config):
    """RFC 9396 SS 7 MUST: the response carries the granted authorization_details."""
    status, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    assert status == 200
    assert body["authorization_details"] == camp.C1_DETAILS
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert body["token_type"] == "Bearer"
    assert rar.elements(body["authorization_details"]) == frozenset(
        {
            ("notes.read", "notes/project"),
            ("notes.read", "notes/meeting"),
            ("notes.write", "notes/project"),
        }
    )


def test_scope_reported_only_when_it_differs_from_the_request(run):
    """RFC 8693 SS 2.2.1: OPTIONAL when identical, REQUIRED otherwise."""
    _, identical, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS, scope=camp.SCOPE_NARROW)
    )
    assert "scope" not in identical

    _, omitted, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS, scope=None)
    )
    assert omitted["scope"] == " ".join(sorted(camp.SCOPE_FULL.split()))


def test_expanded_authority_is_a_subset_of_the_frozen_omega(run, config):
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    allowed = boundary.allowed_authority(claims_of(body["access_token"], config), config)
    assert allowed <= camp.omega()
    assert allowed  # negative arm: not vacuously empty


# ---------------------------------------------------------------------------
# L1' — widening refused in all four planes, no token issued
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,overrides,expected",
    [
        ("extra_actions", {"details": "C1+delete"}, "invalid_authorization_details"),
        ("extra_datatypes", {"details": "C1+calendar"}, "invalid_authorization_details"),
        ("wider_resource", {"resource": camp.OTHER_RESOURCE_SERVER}, "invalid_target"),
        ("longer_exp", {REQUESTED_EXPIRES_IN: "99999"}, "invalid_authorization_details"),
    ],
)
def test_widening_is_an_error_with_no_token_issued(run, label, overrides, expected):
    """A silent clamp is the failure mode: assert the ABSENCE of a token."""
    overrides = dict(overrides)
    details = overrides.pop("details", None)
    payload = {
        "C1+delete": camp.C1_DETAILS + [camp.OUTSIDE_C0],
        "C1+calendar": camp.C1_DETAILS + [camp.OUTSIDE_C0_CALENDAR],
        None: camp.C1_DETAILS,
    }[details]
    status, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, payload, **overrides)
    )
    assert status == 400
    assert body["error"] == expected
    assert "access_token" not in body  # no clamp, no partial issuance


def test_the_same_request_narrowed_instead_of_widened_succeeds(run):
    """Positive arm for the four rejections above: the shape is fine, the widening is not."""
    status, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    assert status == 200 and "access_token" in body


def test_unrequested_default_lifetime_is_capped_not_refused(run, config):
    """The AS caps **its own** default at `exp_{i-1}`; only an explicit over-long
    request is a widening error. Without this, hop 2 would be impossible."""
    _, hop1, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    parent = claims_of(hop1["access_token"], config)
    status, hop2, _ = run.post_token(
        run.exchange_form(hop1["access_token"], camp.C1_DETAILS, actor=camp.WORKER),
        client=camp.SPECIALIST,
    )
    assert status == 200
    child = claims_of(hop2["access_token"], config)
    assert child["exp"] <= parent["exp"]  # the invariant still holds

    # Negative arm: asking explicitly for longer is still an error, not a clamp.
    status2, body2, _ = run.post_token(
        run.exchange_form(
            hop1["access_token"],
            camp.C1_DETAILS,
            actor=camp.WORKER,
            **{REQUESTED_EXPIRES_IN: "99999"},
        ),
        client=camp.SPECIALIST,
    )
    assert status2 == 400 and body2["error"] == "invalid_authorization_details"
    assert "access_token" not in body2


# ---------------------------------------------------------------------------
# L2 — both layers enforced
# ---------------------------------------------------------------------------


def test_request_inside_rar_but_outside_scope_is_denied(run, config):
    _, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS, scope="mcp.invoke")
    )
    claims = claims_of(body["access_token"], config)
    assert boundary.admits(
        claims, config, element=("notes.read", "notes/project"), required_scope="mcp.invoke"
    ).admitted
    denied = boundary.admits(
        claims, config, element=("notes.read", "notes/project"), required_scope="mcp.read"
    )
    assert not denied.admitted and "scope" in denied.reason


def test_request_inside_scope_but_outside_rar_is_denied(run, config):
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    claims = claims_of(body["access_token"], config)
    denied = boundary.admits(
        claims, config, element=("mail.send", "mail/outbox"), required_scope="mcp.invoke"
    )
    assert not denied.admitted and "authorization_details" in denied.reason


def test_token_for_another_resource_server_is_rejected(run):
    """RFC 9068 SS 4 MUST: reject a token whose `aud` does not name this RS."""
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    other = boundary.BoundaryConfig(
        camp.ISSUER, camp.OTHER_RESOURCE_SERVER, camp.public_jwk(), camp.RAR_TYPE
    )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_access_token(body["access_token"], other, now=int(time.time()))
    assert caught.value.reason == "aud"


def test_rar_objects_for_another_location_contribute_no_authority(config):
    """The capability plane is filtered to this RS (RFC 9396 SS 9.1)."""
    foreign = camp.rar(["notes.read"], ["notes/project"], location=camp.OTHER_RESOURCE_SERVER)
    assert boundary.capability_plane({"authorization_details": [foreign]}, config) == frozenset()
    local = camp.rar(["notes.read"], ["notes/project"])
    assert boundary.capability_plane({"authorization_details": [local]}, config)


@pytest.mark.parametrize(
    "reason,mutate",
    [
        ("typ", lambda t: t),  # replaced below by a non-at+jwt token
        ("iss", lambda t: t),
        ("exp", lambda t: t),
        ("signature", lambda t: t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB")),
    ],
)
def test_boundary_rejects_bad_tokens_as_invalid_token(run, config, reason, mutate):
    """RFC 9068 SS 4: every failure is `invalid_token`, with the check named."""
    at0 = run.issue_root()
    if reason == "signature":
        with pytest.raises(boundary.TokenRejected) as caught:
            boundary.verify_access_token(mutate(at0.value), config, now=int(time.time()))
        assert caught.value.error == "invalid_token"
        return
    if reason == "exp":
        expired = run.issue_root(lifetime=-10)
        with pytest.raises(boundary.TokenRejected) as caught:
            boundary.verify_access_token(expired.value, config, now=int(time.time()))
        assert caught.value.reason == "exp"
        return
    if reason == "iss":
        wrong = boundary.BoundaryConfig(
            "https://impostor.example", camp.RESOURCE_SERVER, camp.public_jwk(), camp.RAR_TYPE
        )
        with pytest.raises(boundary.TokenRejected) as caught:
            boundary.verify_access_token(at0.value, wrong, now=int(time.time()))
        assert caught.value.reason == "iss"
        return
    # typ: a JWT that is not an `at+jwt`
    from joserfc import jwt

    from src.sut.oauth_as.keys import ALGS, derive_signing_key

    signer = derive_signing_key(camp.SEED)
    wrong_typ = jwt.encode(
        {"alg": ALGS[0], "typ": "JWT"}, dict(at0.claims), signer.private, algorithms=ALGS
    )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_access_token(wrong_typ, config, now=int(time.time()))
    assert caught.value.reason == "typ"


# ---------------------------------------------------------------------------
# L3 / A1 — identity plane and delegation semantics
# ---------------------------------------------------------------------------


def test_actor_resolves_to_exactly_one_principal_and_holder_key(run, config):
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    claims = claims_of(body["access_token"], config)
    entry = run.config.resolve_actor(claims["act"]["sub"])
    assert entry is not None and entry.principal == "specialist"
    assert camp.holder_key(claims["act"]["sub"]).thumbprint()


def test_unmapped_actor_is_rejected(run):
    status, body, _ = run.post_token(
        run.exchange_form(
            run.issue_root().value,
            camp.C1_DETAILS,
            assertion=camp.actor_assertion(camp.UNMAPPED),
        )
    )
    assert status == 400 and body["error"] == "invalid_request"
    assert run.config.resolve_actor(camp.UNMAPPED) is None


def test_resource_owner_is_never_required_to_be_the_holder(run, config):
    """SS A.5.1 MUST NOT: delegation means the actor is *not* the resource owner."""
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    claims = claims_of(body["access_token"], config)
    assert claims["sub"] == camp.USER
    assert claims["sub"] != claims["act"]["sub"]
    assert (
        run.config.resolve_actor(claims["sub"]) is None
    )  # the owner is not in the holder registry


def test_nested_act_is_present_but_only_the_outermost_is_current(run, config):
    """RFC 8693 SS 4.1 MUST: prior actors are informational only."""
    _, hop1, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    status, hop2, _ = run.post_token(
        run.exchange_form(hop1["access_token"], camp.C1_DETAILS, actor=camp.WORKER),
        client=camp.SPECIALIST,
    )
    assert status == 200
    claims = claims_of(hop2["access_token"], config)
    assert claims["act"]["sub"] == camp.WORKER  # current
    assert claims["act"]["act"]["sub"] == camp.SPECIALIST  # history
    assert current_actor(claims) == camp.WORKER  # the decision reads the outermost only


def test_hop_zero_falls_back_to_client_id(run):
    at0 = run.issue_root()
    assert "act" not in at0.claims
    assert current_actor(at0.claims) == camp.SUPERVISOR


def test_subject_is_the_owner_never_the_actor(run, config):
    """The impersonation shape of RFC 8693 SS 1.1 must be absent."""
    _, body, _ = run.post_token(run.exchange_form(run.issue_root().value, camp.C1_DETAILS))
    claims = claims_of(body["access_token"], config)
    assert claims["sub"] == camp.USER
    assert claims["sub"] not in {camp.SUPERVISOR, camp.SPECIALIST, camp.WORKER}


def test_only_the_current_holder_may_exchange_the_token(run):
    """SS 5.3: the delegating agent *is* the client of the exchange.

    Client authentication alone does not imply it -- a different registered
    client that came to possess the token must not be able to exchange it on.
    """
    at0 = run.issue_root()  # issued to agent-supervisor
    status, body, _ = run.post_token(
        run.exchange_form(at0.value, camp.C1_DETAILS, actor=camp.WORKER), client=camp.SPECIALIST
    )
    assert status == 400 and body["error"] == "invalid_request"
    assert "access_token" not in body
    # Positive arm: the genuine holder exchanges the same token successfully.
    status2, body2, _ = run.post_token(run.exchange_form(at0.value, camp.C1_DETAILS))
    assert status2 == 200 and "access_token" in body2


def test_actor_not_permitted_by_may_act_is_rejected(run):
    """RFC 8693 SS 4.4 -- the spike-local policy stands in for frozen row 5."""
    status, body, _ = run.post_token(
        run.exchange_form(
            run.issue_root().value,
            camp.C1_DETAILS,
            actor=camp.SUPERVISOR,
            assertion=camp.actor_assertion(camp.SUPERVISOR),
        )
    )
    assert status == 400 and body["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# A2 — the rejection catalogue, exact code and status per row
# ---------------------------------------------------------------------------


def test_client_authentication_is_required(run):
    status, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS), client=None
    )
    assert status == 400 and body["error"] == "invalid_client"


def test_bad_client_secret_is_401_with_www_authenticate(run):
    """OAuth 2.1 SS 3.2.4: MUST be 401 with `WWW-Authenticate` if the client used the header."""
    status, body, headers = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS), secret="wrong"
    )
    assert status == 401 and body["error"] == "invalid_client"
    assert "WWW-Authenticate" in headers


@pytest.mark.parametrize(
    "label,expected",
    [
        ("grant_type", "unsupported_grant_type"),
        ("missing_parameter", "invalid_request"),
        ("duplicate_parameter", "invalid_request"),
        ("subject_token_tampered", "invalid_request"),
        ("subject_token_expired", "invalid_request"),
        ("actor_token_malformed", "invalid_request"),
        ("actor_token_type_missing", "invalid_request"),
    ],
)
def test_catalogue_row_exact_code(run, label, expected):
    form = run.exchange_form(run.issue_root().value, camp.C1_DETAILS)
    if label == "grant_type":
        form["grant_type"] = "authorization_code"
    elif label == "missing_parameter":
        form.pop("subject_token")
    elif label == "duplicate_parameter":
        status, body, _ = run.post_token({}, raw_body="grant_type=a&grant_type=b")
        assert status == 400 and body["error"] == expected
        return
    elif label == "subject_token_tampered":
        form["subject_token"] = form["subject_token"][:-4] + "AAAA"
    elif label == "subject_token_expired":
        form["subject_token"] = run.issue_root(lifetime=-10).value
    elif label == "actor_token_malformed":
        form["actor_token"] = "not.a.jwt"
    elif label == "actor_token_type_missing":
        form.pop("actor_token_type")
    status, body, _ = run.post_token(form)
    assert status == 400 and body["error"] == expected
    assert "access_token" not in body


@pytest.mark.parametrize(
    "label,details",
    [
        (
            "unknown_type",
            [
                {
                    "type": "https://evil.example/x",
                    "locations": [camp.RESOURCE_SERVER],
                    "actions": ["notes.read"],
                    "datatypes": ["notes/project"],
                }
            ],
        ),
        ("unknown_field", [dict(camp.C1_DETAILS[0], surprise="x")]),
        ("wrong_field_type", [dict(camp.C1_DETAILS[0], actions="notes.read")]),
        ("invalid_identifier", [dict(camp.C1_DETAILS[0], identifier="notes/absent")]),
        ("missing_field", [{"type": camp.RAR_TYPE, "locations": [camp.RESOURCE_SERVER]}]),
        ("forbidden_privileges", [dict(camp.C1_DETAILS[0], privileges=["admin"])]),
        ("outside_omega", [camp.rar(["notes.write"], ["notes/meeting"])]),
        (
            "multiple_locations",
            [
                dict(
                    camp.C1_DETAILS[0], locations=[camp.RESOURCE_SERVER, camp.OTHER_RESOURCE_SERVER]
                )
            ],
        ),
    ],
)
def test_rar_rejections_are_invalid_authorization_details(run, label, details):
    """RFC 9396 SS 5's five MUST-abort conditions plus the three profile additions."""
    status, body, _ = run.post_token(run.exchange_form(run.issue_root().value, details))
    assert status == 400 and body["error"] == "invalid_authorization_details"
    assert "access_token" not in body


@pytest.mark.parametrize(
    "resource",
    [camp.OTHER_RESOURCE_SERVER, "not-a-uri", "https://mcp.aasc.local/tools#frag"],
)
def test_target_rejections_are_invalid_target(run, resource):
    status, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS, resource=resource)
    )
    assert status == 400 and body["error"] == "invalid_target"


def test_multiple_targets_are_invalid_target(run):
    """RFC 8693 SS 2.1.1: one exchange targets exactly one audience."""
    status, body, _ = run.post_token(
        run.exchange_form(
            run.issue_root().value,
            camp.C1_DETAILS,
            resource=[camp.RESOURCE_SERVER, camp.OTHER_RESOURCE_SERVER],
        )
    )
    assert status == 400 and body["error"] == "invalid_target"


def test_token_this_as_did_not_issue_is_rejected(run):
    """SS 6 row 8: a foreign token, signed by a key this AS does not use."""
    from src.sut.oauth_as.exchange import issue_initial
    from src.sut.oauth_as.keys import derive_signing_key

    foreign = issue_initial(
        config=camp.build_config(token_endpoint=run.endpoint),
        signing_key=derive_signing_key(b"\x99" * 32),
        subject=camp.USER,
        client_id=camp.SUPERVISOR,
        audience=camp.RESOURCE_SERVER,
        scope=camp.SCOPE_FULL,
        authorization_details=camp.C0_DETAILS,
    )
    status, body, _ = run.post_token(run.exchange_form(foreign.value, camp.C1_DETAILS))
    assert status == 400 and body["error"] == "invalid_request"


def test_unrecognized_parameters_are_ignored(run):
    """OAuth 2.1 SS 3.2.2 MUST ignore unrecognized parameters."""
    form = run.exchange_form(run.issue_root().value, camp.C1_DETAILS)
    form["totally_unknown"] = "value"
    status, body, _ = run.post_token(form)
    assert status == 200 and "access_token" in body


def test_valueless_parameters_are_treated_as_omitted():
    """OAuth 2.1 SS 3.2.2, checked at the parser."""
    parsed = parse_form("grant_type=x&scope=")
    assert parsed == {"grant_type": "x"}
    with pytest.raises(OAuthError) as caught:
        parse_form("grant_type=x&grant_type=y")
    assert caught.value.code == "invalid_request"


def test_connection_is_reused_across_hops(run):
    """SS 8.2: HTTP keep-alive, one connection across hops.

    Per-hop TCP+TLS setup would inflate B2's measured delegation cost and bias
    the overhead comparison **toward B3** -- toward this study's own hypothesis.
    """
    connection = run.connect()
    try:
        sockets = []
        for _ in range(3):
            status, body, _ = run.post_token(
                run.exchange_form(run.issue_root().value, camp.C1_DETAILS), connection=connection
            )
            assert status == 200 and "access_token" in body
            sockets.append(id(connection.sock))
        assert len(set(sockets)) == 1  # the same socket served all three exchanges
        assert connection.sock.version() == "TLSv1.3"  # SS 5.1: TLS 1.3, not a downgrade
    finally:
        connection.close()


def test_no_discovery_or_jwks_endpoint(run):
    """SS 5.1: one endpoint. A GET must not reveal metadata or keys."""
    connection = run.connect()
    try:
        connection.request("GET", "/.well-known/oauth-authorization-server")
        first = connection.getresponse()
        assert first.status == 404
        first.read()
        connection.request("GET", "/jwks")
        second = connection.getresponse()
        assert second.status == 404
        second.read()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# A3 — RFC 9396 SS 12 string rule
# ---------------------------------------------------------------------------


def test_case_variant_is_not_equal_and_does_not_narrow_match(run):
    status, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, [camp.rar(["Notes.read"], ["notes/project"])])
    )
    assert status == 400 and body["error"] == "invalid_authorization_details"
    assert "Notes.read" != "notes.read"


def test_nfd_variant_is_not_equal_and_is_rejected(run):
    decomposed = "notes/projéct"  # 'e' + COMBINING ACUTE ACCENT
    composed = unicodedata.normalize("NFC", decomposed)
    assert decomposed != composed  # unequal as byte strings...
    assert unicodedata.normalize("NFC", decomposed) == composed  # ...but equal if normalized
    status, body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, [camp.rar(["notes.read"], [decomposed])])
    )
    assert status == 400 and body["error"] == "invalid_authorization_details"


def test_containment_uses_exact_string_equality():
    outer = [camp.rar(["notes.read"], ["notes/project"])]
    assert rar.contains(outer, [camp.rar(["notes.read"], ["notes/project"])])
    assert not rar.contains(outer, [camp.rar(["Notes.read"], ["notes/project"])])
    assert not rar.contains(outer, [camp.rar(["notes.read"], ["notes/Project"])])


def test_expansion_is_the_product_of_the_common_fields():
    """RFC 9396 SS 2.2: one object means all actions at all locations for all datatypes."""
    entry = camp.rar(["notes.read", "notes.write"], ["notes/project", "notes/meeting"])
    assert len(rar.expand([entry])) == 4
    assert rar.elements([entry]) == frozenset(
        {
            ("notes.read", "notes/project"),
            ("notes.read", "notes/meeting"),
            ("notes.write", "notes/project"),
            ("notes.write", "notes/meeting"),
        }
    )


def test_pairs_outside_omega_are_rejected_even_when_each_value_is_valid():
    """`C_i` is a subset of `Omega` (SS A.0.1), so membership is checked pairwise."""
    omega = camp.omega()
    assert ("notes.write", "notes/project") in omega
    assert ("notes.read", "notes/meeting") in omega
    assert ("notes.write", "notes/meeting") not in omega  # each value valid, the pair is not
    with pytest.raises(OAuthError) as caught:
        rar.validate_details(
            [camp.rar(["notes.read", "notes.write"], ["notes/project", "notes/meeting"])],
            rar_type=camp.RAR_TYPE,
            omega=omega,
        )
    assert caught.value.code == "invalid_authorization_details"
    # Split across two same-type objects, the same authority is accepted.
    rar.validate_details(
        [
            camp.rar(["notes.read"], ["notes/project", "notes/meeting"]),
            camp.rar(["notes.write"], ["notes/project"]),
        ],
        rar_type=camp.RAR_TYPE,
        omega=omega,
    )


# ---------------------------------------------------------------------------
# A4 — key isolation and the ADR 0015 import rules
# ---------------------------------------------------------------------------


def _import_hits(root: Path, exclude: str | None = None) -> list[str]:
    hits = []
    for path in root.rglob("*.py"):
        if exclude and exclude in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and (
                "sut.oauth_as" in stripped or "sut import oauth_as" in stripped
            ):
                hits.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    return hits


def test_harness_never_imports_the_as():
    """ADR 0015 rule 4 -- the instrument must not share implementation with what it judges."""
    assert _import_hits(REPO_ROOT / "src" / "harness") == []


def test_no_other_sut_module_imports_the_as():
    """ADR 0015 rule 3 -- agents reach the AS only over the wire."""
    assert _import_hits(REPO_ROOT / "src" / "sut", exclude="oauth_as") == []


def test_a_forged_token_is_rejected_by_the_boundary(run, config):
    """A principal without the sealed seed cannot mint an acceptable token."""
    from joserfc import jwt
    from joserfc.jwk import OKPKey

    attacker = OKPKey.generate_key("Ed25519")
    now = int(time.time())
    forged = jwt.encode(
        {"alg": "Ed25519", "typ": "at+jwt"},
        {
            "iss": camp.ISSUER,
            "sub": camp.USER,
            "aud": camp.RESOURCE_SERVER,
            "client_id": camp.SUPERVISOR,
            "iat": now,
            "exp": now + 600,
            "jti": "forged",
            "scope": camp.SCOPE_FULL,
            "authorization_details": [camp.OUTSIDE_C0],
        },
        attacker,
        algorithms=["Ed25519"],
    )
    with pytest.raises(boundary.TokenRejected):
        boundary.verify_access_token(forged, config, now=now)
    # Positive arm: the genuine token verifies under the same configuration.
    assert claims_of(run.issue_root().value, config)["sub"] == camp.USER


def test_the_as_signing_key_is_never_written_to_disk():
    """SS 5.4 / STEP 1 item 5: the private key exists only in process memory.

    Scans the project's own trees -- not `.venv`, which holds tens of thousands
    of third-party files and nothing this project wrote.
    """
    from src.sut.oauth_as.keys import derive_signing_key

    key = derive_signing_key(camp.SEED)
    private_d = key.private.as_dict(private=True)["d"]
    assert "d" not in key.public_jwk  # only the public half is exportable
    scanned = 0
    for tree in ("src", "tests", "smoke", "docs", "adr", "fixtures"):
        for path in (REPO_ROOT / tree).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".json", ".md", ".toml"}:
                assert private_d not in path.read_text(encoding="utf-8", errors="ignore")
                scanned += 1
    assert scanned > 50  # negative arm: the scan actually looked at something


# ---------------------------------------------------------------------------
# A5 / A6 / A7 — the G-5 hand-forwards
# ---------------------------------------------------------------------------


@pytest.fixture
def dpop_bound(run, config):
    from joserfc.jwk import OKPKey

    holder = OKPKey.generate_key("Ed25519")
    token = run.issue_root(cnf_jkt=holder.thumbprint())
    return holder, token, claims_of(token.value, config)


def test_valid_ath_proof_is_accepted(dpop_bound):
    holder, token, claims = dpop_bound
    proof = dpop.create_proof(
        holder, method="POST", url=camp.RESOURCE_URL, ath=dpop.access_token_hash(token.value)
    )
    assert (
        boundary.verify_dpop_request(
            token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
        )
        == holder.thumbprint()
    )


@pytest.mark.parametrize("variant", ["missing_ath", "wrong_ath", "wrong_key"])
def test_ath_failures_are_rejected_at_item_12(dpop_bound, variant):
    """RFC 9449 SS 4.3 item 12 and SS 7.1: MUST NOT grant access unless all checks pass."""
    from joserfc.jwk import OKPKey

    holder, token, claims = dpop_bound
    if variant == "missing_ath":
        proof = dpop.create_proof(holder, method="POST", url=camp.RESOURCE_URL)
    elif variant == "wrong_ath":
        proof = dpop.create_proof(
            holder, method="POST", url=camp.RESOURCE_URL, ath=dpop.access_token_hash("other-token")
        )
    else:
        proof = dpop.create_proof(
            OKPKey.generate_key("Ed25519"),
            method="POST",
            url=camp.RESOURCE_URL,
            ath=dpop.access_token_hash(token.value),
        )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_dpop_request(
            token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
        )
    assert caught.value.reason == "dpop-item-12"


def test_ath_is_not_h_jcs():
    """SS 9 C2's named trap: two digests over the same token must never be conflated."""
    from src.harness.oracle.jcs_digest import h_jcs

    token = "eyJhbGciOiJFZDI1NTE5In0.e30.sig"
    ath = dpop.access_token_hash(token)
    assert ath != h_jcs({"token": token})
    assert "=" not in ath  # base64url, unpadded -- not lowercase hex
    assert len(bytes.fromhex(h_jcs({"token": token}))) == 32


def test_more_than_one_dpop_header_is_rejected_at_item_1(dpop_bound):
    holder, token, claims = dpop_bound
    proof = dpop.create_proof(
        holder, method="POST", url=camp.RESOURCE_URL, ath=dpop.access_token_hash(token.value)
    )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_dpop_request(
            token.value,
            claims,
            [proof, proof],
            method="POST",
            url=camp.RESOURCE_URL,
            now=int(time.time()),
        )
    assert caught.value.reason == "dpop-item-1"


def test_a_private_key_in_the_proof_header_is_rejected_at_item_7(dpop_bound):
    """RFC 9449 SS 4.3 item 7."""
    from joserfc import jws
    from joserfc.jwk import OKPKey

    holder, token, claims = dpop_bound
    leaky = OKPKey.generate_key("Ed25519")
    header = {"typ": "dpop+jwt", "alg": "Ed25519", "jwk": leaky.as_dict(private=True)}
    payload = json.dumps(
        {
            "jti": "x",
            "htm": "POST",
            "htu": camp.RESOURCE_URL,
            "iat": int(time.time()),
            "ath": dpop.access_token_hash(token.value),
        }
    ).encode()
    proof = jws.serialize_compact(header, payload, leaky, algorithms=["Ed25519"])
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_dpop_request(
            token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
        )
    assert caught.value.reason == "dpop-item-7"


def test_nonce_challenge_then_retry_then_stale():
    """RFC 9449 SS 8: 400 `use_dpop_nonce` + header, retry succeeds, stale refused."""
    from joserfc.jwk import OKPKey

    nonce_run = camp.start(require_dpop=True, require_dpop_nonce=True)
    try:
        holder = OKPKey.generate_key("Ed25519")
        token = nonce_run.issue_root(cnf_jkt=holder.thumbprint())
        form = nonce_run.exchange_form(token.value, camp.C1_DETAILS)

        first = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint)
        status, body, headers = nonce_run.post_token(form, dpop=first)
        assert status == 400 and body["error"] == "use_dpop_nonce"
        nonce = headers["DPoP-Nonce"]

        retry = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint, nonce=nonce)
        status2, body2, _ = nonce_run.post_token(form, dpop=retry)
        assert status2 == 200 and body2["token_type"] == "DPoP"  # RFC 9449 SS 5 MUST

        nonce_run.server.nonce_store.retire(nonce)
        stale = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint, nonce=nonce)
        status3, body3, _ = nonce_run.post_token(
            nonce_run.exchange_form(nonce_run.issue_root().value, camp.C1_DETAILS), dpop=stale
        )
        assert status3 == 400 and body3["error"] == "use_dpop_nonce"
    finally:
        nonce_run.stop()


def test_as_and_rs_nonce_namespaces_are_distinct():
    """RFC 9449 SS 9: each nonce is only accepted by its issuer."""
    as_store, rs_store = dpop.NonceStore("as"), dpop.NonceStore("rs")
    as_nonce, rs_nonce = as_store.issue(), rs_store.issue()
    assert as_store.is_valid(as_nonce) and rs_store.is_valid(rs_nonce)
    assert not as_store.is_valid(rs_nonce)
    assert not rs_store.is_valid(as_nonce)


def test_missing_dpop_proof_when_required_is_invalid_dpop_proof():
    nonce_run = camp.start(require_dpop=True)
    try:
        status, body, _ = nonce_run.post_token(
            nonce_run.exchange_form(nonce_run.issue_root().value, camp.C1_DETAILS)
        )
        assert status == 400 and body["error"] == "invalid_dpop_proof"
    finally:
        nonce_run.stop()


@pytest.mark.parametrize(
    "variant",
    [
        "https://mcp.aasc.local:443/tools/invoke",
        "HTTPS://MCP.AASC.LOCAL/tools/invoke",
        "https://mcp.aasc.local/tools/./invoke",
        "https://mcp.aasc.local/tools/invoke?x=1#frag",
    ],
)
def test_htu_normalization_accepts_equivalent_forms(dpop_bound, variant):
    """RFC 3986 syntax- and scheme-based normalization; closes the G-5 residual."""
    holder, token, claims = dpop_bound
    proof = dpop.create_proof(
        holder, method="POST", url=variant, ath=dpop.access_token_hash(token.value)
    )
    assert boundary.verify_dpop_request(
        token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
    )


def test_htu_normalization_still_rejects_a_different_resource(dpop_bound):
    holder, token, claims = dpop_bound
    proof = dpop.create_proof(
        holder,
        method="POST",
        url="https://mcp.aasc.local/tools/other",
        ath=dpop.access_token_hash(token.value),
    )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_dpop_request(
            token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
        )
    assert caught.value.reason == "dpop-item-9"


def test_wrong_method_is_rejected_at_item_8(dpop_bound):
    holder, token, claims = dpop_bound
    proof = dpop.create_proof(
        holder, method="GET", url=camp.RESOURCE_URL, ath=dpop.access_token_hash(token.value)
    )
    with pytest.raises(boundary.TokenRejected) as caught:
        boundary.verify_dpop_request(
            token.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=int(time.time())
        )
    assert caught.value.reason == "dpop-item-8"


# ---------------------------------------------------------------------------
# L4 — PRECONDITION ONLY (SS 9 C2). The limb is not adjudicated here.
# ---------------------------------------------------------------------------


def test_presented_access_token_is_observable_and_stable(run):
    """The precondition a digest binding needs; NOT the INV construction (G-11)."""
    at0 = run.issue_root()
    assert at0.value == at0.value.encode("ascii").decode("ascii")
    assert dpop.access_token_hash(at0.value) == dpop.access_token_hash(at0.value)


def test_a_swapped_token_is_detectable(run):
    first, second = run.issue_root(), run.issue_root(details=camp.C1_DETAILS)
    assert first.value != second.value
    assert dpop.access_token_hash(first.value) != dpop.access_token_hash(second.value)
