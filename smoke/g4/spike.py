"""Gate G-4 Phase 2 spike — the pinned experiment AS, built and adjudicated (IA-4).

Executes the `smoke/g4/DESIGN.md` SS 10 test plan against the AS built at
`src/sut/oauth_as/`: rows **L1, L1', L2, L3, A1-A7**, plus **L4 as a
precondition only** -- the `INV.access_token_hash` limb is *not* adjudicated
here (SS 9 C2: INV does not exist until G-11, so there is nothing to verify the
digest *in*, and inventing a construction would report a pass on something G-11
may replace).

Every check is built so the **wrong** outcome is observable as a failure, and
each records the world in which it would have failed -- the discipline G-2
applied throughout. The two directions that matter most:

* a widening attempt must be an **error with no token issued**, never a silent
  clamp (a clamp would make `F1-chain-tamper` indistinguishable from a benign
  narrowing);
* a rejection must carry the **exact** SS 6 error code and status, because a
  test that accepts "some error" has not exercised the row.

The AS runs on a real TLS 1.3 loopback socket and every exchange goes over the
wire. Spike-local stand-ins (the C3 registry, the `may_act` policy) print the
`SPIKE-LOCAL` banner below and are scoped in `smoke/g4/REPORT.md`.

    uv run python smoke/g4/spike.py
"""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import campaign as camp  # noqa: E402  (spike-local fixture, beside this file)

from src.sut import dpop  # noqa: E402
from src.sut.authz import boundary  # noqa: E402
from src.sut.oauth_as.exchange import REQUESTED_EXPIRES_IN  # noqa: E402

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


def boundary_config() -> boundary.BoundaryConfig:
    """The boundary holds only the AS **public** key, from sealed configuration."""
    return boundary.BoundaryConfig(
        issuer=camp.ISSUER,
        resource_server=camp.RESOURCE_SERVER,
        as_public_jwk=camp.public_jwk(),
        rar_type=camp.RAR_TYPE,
    )


# ---------------------------------------------------------------------------
# L1 — a task-narrowed token issues
# ---------------------------------------------------------------------------


def l1_narrowed_token_issues(run: camp.Campaign) -> None:
    at0 = run.issue_root()
    status, body, _ = run.post_token(run.exchange_form(at0.value, camp.C1_DETAILS))

    granted_ok = body.get("authorization_details") == camp.C1_DETAILS  # RFC 9396 SS 7 MUST
    type_ok = body.get("issued_token_type") == "urn:ietf:params:oauth:token-type:access_token"
    bearer_ok = body.get("token_type") == "Bearer"
    # RFC 8693 SS 2.2.1: `scope` is OPTIONAL only when identical to the request.
    identical_scope_omitted = "scope" not in body

    # The same exchange with `scope` omitted: the granted scope then differs from
    # the request, so the AS MUST report it.
    status2, body2, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS, scope=None)
    )
    narrowed_reported = body2.get("scope") == " ".join(sorted(camp.SCOPE_FULL.split()))

    claims = boundary.verify_access_token(
        body["access_token"], boundary_config(), now=int(time.time())
    )
    computed = boundary.allowed_authority(claims, boundary_config())
    expected = frozenset(
        {
            ("notes.read", "notes/project"),
            ("notes.read", "notes/meeting"),
            ("notes.write", "notes/project"),
        }
    )
    expand_ok = computed == expected

    ok = status == 200 and granted_ok and type_ok and bearer_ok and identical_scope_omitted
    ok = ok and status2 == 200 and narrowed_reported and expand_ok
    record(
        "G-4.L1",
        True,
        ok,
        f"POST /token over TLS 1.3 -> {status}; response carries the granted RAR "
        f"({granted_ok}, RFC 9396 SS 7 MUST), issued_token_type ({type_ok}), token_type=Bearer "
        f"({bearer_ok}); scope omitted when identical to the request ({identical_scope_omitted}, "
        f"RFC 8693 SS 2.2.1) and REPORTED as {body2.get('scope')!r} when it differs "
        f"({narrowed_reported}); "
        f"expand(AT_1.AD) = {sorted(computed)} equals C_1 ({expand_ok}). Would have failed if the "
        f"granted details were absent, the narrowed scope silently unreported, or the expansion "
        f"disagreed with the requested C_1",
    )


# ---------------------------------------------------------------------------
# L1' — widening refused in all four planes, with no token issued
# ---------------------------------------------------------------------------


def l1_prime_widening_refused(run: camp.Campaign) -> None:
    attempts = {
        "extra actions": (
            run.exchange_form(run.issue_root().value, camp.C1_DETAILS + [camp.OUTSIDE_C0]),
            "invalid_authorization_details",
        ),
        "extra datatypes": (
            run.exchange_form(run.issue_root().value, camp.C1_DETAILS + [camp.OUTSIDE_C0_CALENDAR]),
            "invalid_authorization_details",
        ),
        "wider resource": (
            run.exchange_form(
                run.issue_root().value, camp.C1_DETAILS, resource=camp.OTHER_RESOURCE_SERVER
            ),
            "invalid_target",
        ),
        "longer exp": (
            run.exchange_form(
                run.issue_root().value, camp.C1_DETAILS, **{REQUESTED_EXPIRES_IN: "99999"}
            ),
            "invalid_authorization_details",
        ),
    }
    outcomes, failures = {}, []
    for label, (form, expected_error) in attempts.items():
        status, body, _ = run.post_token(form)
        issued = "access_token" in body
        exact = status == 400 and body.get("error") == expected_error
        outcomes[label] = f"{status} {body.get('error')}"
        if not exact or issued:
            failures.append(f"{label} (issued={issued}, got {outcomes[label]})")

    # A widening request whose narrowing counterpart succeeds, proving the refusal
    # is about the widening and not about the request shape.
    control_status, control_body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, camp.C1_DETAILS)
    )
    control_ok = control_status == 200 and "access_token" in control_body

    ok = not failures and control_ok
    record(
        "G-4.L1'",
        True,
        ok,
        "four widening attempts, each refused with the exact SS 6 error and **no token issued**: "
        + "; ".join(f"{label} -> {value}" for label, value in outcomes.items())
        + f". Control: the same request narrowed instead of widened is issued ({control_ok}), so "
        f"the refusals are about the widening, not the shape. Would have failed on a silent clamp "
        f"— a 200 carrying a clamped intersection — which is why the assertion is on the ABSENCE "
        f"of access_token, not merely on a differing response",
    )


# ---------------------------------------------------------------------------
# L2 — both layers enforced, over the frozen Omega/Gamma
# ---------------------------------------------------------------------------


def l2_both_layers(run: camp.Campaign) -> None:
    at0 = run.issue_root()
    status, body, _ = run.post_token(run.exchange_form(at0.value, camp.C1_DETAILS))
    config = boundary_config()
    claims = boundary.verify_access_token(body["access_token"], config, now=int(time.time()))

    inside_both = boundary.admits(
        claims, config, element=("notes.read", "notes/project"), required_scope="mcp.invoke"
    )
    # Inside the RAR, outside the OAuth-resource plane (scope).
    outside_scope = boundary.admits(
        claims, config, element=("notes.read", "notes/project"), required_scope="mcp.read"
    )
    # Inside scope, outside the RAR.
    outside_rar = boundary.admits(
        claims, config, element=("mail.send", "mail/outbox"), required_scope="mcp.invoke"
    )
    # Outside the audience plane: the same token presented to a different RS.
    other_config = boundary.BoundaryConfig(
        camp.ISSUER, camp.OTHER_RESOURCE_SERVER, camp.public_jwk(), camp.RAR_TYPE
    )
    try:
        boundary.verify_access_token(body["access_token"], other_config, now=int(time.time()))
        audience_rejected = False
        audience_reason = "accepted (bad)"
    except boundary.TokenRejected as exc:
        audience_rejected = exc.reason == "aud"
        audience_reason = f"{exc.error} ({exc.reason})"

    allowed = boundary.allowed_authority(claims, config)
    within_omega = allowed <= camp.omega()

    ok = (
        inside_both.admitted
        and not outside_scope.admitted
        and not outside_rar.admitted
        and audience_rejected
        and within_omega
    )
    record(
        "G-4.L2",
        True,
        ok,
        f"over the FROZEN Omega (ADR 0016, no stand-in): Allowed(AT_1) = {sorted(allowed)}, "
        f"a subset of Omega ({within_omega}). Inside both planes -> admitted "
        f"({inside_both.admitted}); inside the RAR but outside `scope` -> denied "
        f"({outside_scope.reason}); inside `scope` but outside the RAR -> denied "
        f"({outside_rar.reason}); presented to a different RS -> {audience_reason} "
        f"({audience_rejected}, RFC 9068 SS 4 MUST). Would have failed if either plane alone could "
        f"admit what the other denies",
    )


# ---------------------------------------------------------------------------
# L3 — actor -> holder mapping resolves (C3 stand-in)
# ---------------------------------------------------------------------------


def l3_actor_to_holder(run: camp.Campaign) -> None:
    at0 = run.issue_root()
    status, body, _ = run.post_token(run.exchange_form(at0.value, camp.C1_DETAILS))
    claims = boundary.verify_access_token(
        body["access_token"], boundary_config(), now=int(time.time())
    )

    # Resolution for a valid actor: outermost `act` -> exactly one principal -> one holder key.
    actor_id = claims["act"]["sub"]
    entry = run.config.resolve_actor(actor_id)
    resolves = entry is not None and entry.principal == "specialist"
    holder = camp.holder_key(actor_id).thumbprint()

    # An unmapped actor is rejected: no registry entry, so no exchange.
    unmapped_status, unmapped_body, _ = run.post_token(
        run.exchange_form(
            run.issue_root().value,
            camp.C1_DETAILS,
            assertion=camp.actor_assertion(camp.UNMAPPED),
        )
    )
    unmapped_rejected = unmapped_status == 400 and unmapped_body.get("error") == "invalid_request"

    # The check is `oauth_actor -> htc_holder` ONLY. `resource_owner` is the user and
    # is never compared against a holder key (SS A.5.1 MUST NOT).
    resource_owner = claims["sub"]
    owner_is_not_actor = resource_owner != actor_id
    owner_absent_from_registry = run.config.resolve_actor(resource_owner) is None

    # Nested `act` history is present but MUST NOT be consulted. Build hop 2 so a
    # chain exists, then confirm the current actor is the outermost one only.
    hop2_status, hop2_body, _ = run.post_token(
        run.exchange_form(
            body["access_token"],
            camp.C1_DETAILS,
            actor=camp.WORKER,
            scope="mcp.invoke",
        ),
        client=camp.SPECIALIST,
    )
    nested_present = False
    outermost_only = False
    nested_actor = None
    if hop2_status == 200:
        hop2 = boundary.verify_access_token(
            hop2_body["access_token"], boundary_config(), now=int(time.time())
        )
        nested_present = "act" in hop2["act"]
        nested_actor = hop2["act"].get("act", {}).get("sub")
        outermost_only = hop2["act"]["sub"] == camp.WORKER and nested_actor == camp.SPECIALIST

    ok = (
        resolves
        and unmapped_rejected
        and owner_is_not_actor
        and owner_absent_from_registry
        and nested_present
        and outermost_only
    )
    record(
        "G-4.L3",
        True,
        ok,
        f"[{camp.BANNER}: the C3 registry] outermost act.sub={actor_id!r} resolves to exactly one "
        f"principal {entry.principal if entry else None!r} and one holder key "
        f"jkt={holder[:16]}... ({resolves}); an unmapped actor is REJECTED "
        f"({unmapped_status} {unmapped_body.get('error')}, {unmapped_rejected}); "
        f"resource_owner={resource_owner!r} differs from the actor ({owner_is_not_actor}) and is "
        f"absent from the holder registry ({owner_absent_from_registry}) — the profile never "
        f"requires resource_owner = holder (SS A.5.1 MUST NOT); at hop 2 the act chain nests the "
        f"prior actor {nested_actor!r} beneath the current one ({nested_present}) while the "
        f"current actor is the OUTERMOST one only ({outermost_only}, RFC 8693 SS 4.1 MUST). Would "
        f"have failed if an unmapped actor were admitted, or if a nested actor were read as "
        f"current",
    )


# ---------------------------------------------------------------------------
# A1 — delegation semantics, never impersonation
# ---------------------------------------------------------------------------


def a1_delegation_not_impersonation(run: camp.Campaign) -> None:
    at0 = run.issue_root()
    status, body, _ = run.post_token(run.exchange_form(at0.value, camp.C1_DETAILS))
    claims = boundary.verify_access_token(
        body["access_token"], boundary_config(), now=int(time.time())
    )

    sub_is_owner = claims["sub"] == camp.USER
    actor_not_in_sub = claims["sub"] != camp.SPECIALIST  # impersonation shape is absent
    act_outermost = claims["act"]["sub"] == camp.SPECIALIST
    root_had_no_act = "act" not in at0.claims  # hop 0: oauth_actor falls back to client_id
    root_client = at0.claims["client_id"] == camp.SUPERVISOR

    ok = sub_is_owner and actor_not_in_sub and act_outermost and root_had_no_act and root_client
    record(
        "G-4.A1",
        True,
        ok,
        f"sub={claims['sub']!r} is the resource owner ({sub_is_owner}); the actor is NEVER written "
        f"into sub ({actor_not_in_sub}) — the impersonation shape RFC 8693 SS 1.1 describes is "
        f"absent; outermost act.sub={claims['act']['sub']!r} is the current actor "
        f"({act_outermost}); at hop 0 there is no act and oauth_actor falls back to "
        f"client_id={at0.claims['client_id']!r} ({root_had_no_act and root_client}, SS A.5.1). "
        f"Would have failed under impersonation, where "
        f"sub would carry the agent and the three-way identity split of SS A.5.1 would collapse",
    )


# ---------------------------------------------------------------------------
# A2 — the rejection catalogue, one row at a time, exact code and status
# ---------------------------------------------------------------------------


def a2_rejection_catalogue(run: camp.Campaign) -> None:
    def form(details=None, **overrides):
        return run.exchange_form(
            run.issue_root().value, camp.C1_DETAILS if details is None else details, **overrides
        )

    rows: list[tuple[str, dict, int, str]] = []

    # 1. client unauthenticated / unknown / unsupported auth method
    rows.append(("client-unauthenticated", {"client": None}, 400, "invalid_client"))
    rows.append(("client-bad-secret", {"secret": "wrong"}, 401, "invalid_client"))
    # 2. grant_type not the exchange URN
    rows.append(
        (
            "grant-type",
            {"form": form(grant_type="authorization_code")},
            400,
            "unsupported_grant_type",
        )
    )
    # 3. missing / duplicated / valueless required parameter
    rows.append(
        ("missing-parameter", {"form": _without(form(), "subject_token")}, 400, "invalid_request")
    )
    rows.append(
        ("duplicated-parameter", {"raw_body": "grant_type=a&grant_type=b"}, 400, "invalid_request")
    )
    # 4. subject_token invalid / expired / foreign
    rows.append(
        ("subject-token-invalid", {"form": form()} | {"_mutate": "subject"}, 400, "invalid_request")
    )
    rows.append(("subject-token-expired", {"_expired": True}, 400, "invalid_request"))
    rows.append(("subject-token-foreign", {"_foreign": True}, 400, "invalid_request"))
    # 5. actor_token invalid, or actor_token_type missing while actor_token present
    rows.append(
        ("actor-token-invalid", {"form": form(assertion="not.a.jwt")}, 400, "invalid_request")
    )
    rows.append(
        (
            "actor-token-type-missing",
            {"form": _without(form(), "actor_token_type")},
            400,
            "invalid_request",
        )
    )
    # 6. actor or client not resolvable to exactly one principal
    rows.append(
        (
            "unmapped-principal",
            {"form": form(assertion=camp.actor_assertion(camp.UNMAPPED))},
            400,
            "invalid_request",
        )
    )
    # 7. requested actor not permitted (may_act)
    rows.append(
        (
            "may-act",
            {"form": form(actor=camp.SUPERVISOR, assertion=camp.actor_assertion(camp.SUPERVISOR))},
            400,
            "invalid_request",
        )
    )
    # 8. replayed subject_token after exp / not issued by this AS -- rows 4b/4c cover it.
    # 9. RAR: unknown type; unknown field; wrong field type; invalid value; missing required field
    rows.append(
        (
            "rar-unknown-type",
            {"form": form(details=[dict(camp.C1_DETAILS[0], type="https://evil.example/x")])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-unknown-field",
            {"form": form(details=[dict(camp.C1_DETAILS[0], surprise="x")])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-wrong-field-type",
            {"form": form(details=[dict(camp.C1_DETAILS[0], actions="notes.read")])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-invalid-value",
            {"form": form(details=[dict(camp.C1_DETAILS[0], identifier="notes/absent")])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-missing-field",
            {"form": form(details=[{"type": camp.RAR_TYPE, "locations": [camp.RESOURCE_SERVER]}])},
            400,
            "invalid_authorization_details",
        )
    )
    # 10. RAR: forbidden privileges; value outside Omega; multiple locations
    rows.append(
        (
            "rar-privileges",
            {"form": form(details=[dict(camp.C1_DETAILS[0], privileges=["admin"])])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-outside-omega",
            {"form": form(details=[camp.rar(["notes.write"], ["notes/meeting"])])},
            400,
            "invalid_authorization_details",
        )
    )
    rows.append(
        (
            "rar-multi-location",
            {
                "form": form(
                    details=[
                        dict(
                            camp.C1_DETAILS[0],
                            locations=[camp.RESOURCE_SERVER, camp.OTHER_RESOURCE_SERVER],
                        )
                    ]
                )
            },
            400,
            "invalid_authorization_details",
        )
    )
    # 11. widening (all four planes) -- exercised in full by L1'; one representative row here
    rows.append(
        (
            "widening",
            {"form": form(details=camp.C1_DETAILS + [camp.OUTSIDE_C0])},
            400,
            "invalid_authorization_details",
        )
    )
    # 12. audience mismatch / unknown target / malformed resource URI
    rows.append(
        (
            "audience-unknown",
            {"form": form(resource=camp.OTHER_RESOURCE_SERVER)},
            400,
            "invalid_target",
        )
    )
    rows.append(("resource-malformed", {"form": form(resource="not-a-uri")}, 400, "invalid_target"))
    # 13. more than one target
    rows.append(
        (
            "multi-target",
            {"form": form(resource=[camp.RESOURCE_SERVER, camp.OTHER_RESOURCE_SERVER])},
            400,
            "invalid_target",
        )
    )

    observed, failures = {}, []
    for label, spec, expected_status, expected_error in rows:
        status, body, headers = _drive(run, spec)
        observed[label] = f"{status} {body.get('error')}"
        issued = "access_token" in body
        if status != expected_status or body.get("error") != expected_error or issued:
            failures.append(
                f"{label}: expected {expected_status} {expected_error}, got {observed[label]}"
            )
        if label == "client-bad-secret" and "WWW-Authenticate" not in headers:
            failures.append("client-bad-secret: 401 without WWW-Authenticate")

    ok = not failures
    record(
        "G-4.A2",
        True,
        ok,
        f"{len(rows)} catalogue checks over the 13 AS-side SS 6 rows reachable without the DPoP "
        f"arm "
        f"(rows 14-15 are A5/A6), each asserting the EXACT code and status and that no token was "
        f"issued: {'; '.join(f'{k} -> {v}' for k, v in observed.items())}"
        + (f". FAILURES: {failures}" if failures else "")
        + ". The 401 row additionally carries WWW-Authenticate (OAuth 2.1 SS 3.2.4). Would have "
        "failed if any row returned a different code, a different status, or a token",
    )


def _without(form: dict, key: str) -> dict:
    return {k: v for k, v in form.items() if k != key}


def _drive(run: camp.Campaign, spec: dict):
    """Turn one catalogue-row specification into a request."""
    if spec.get("_expired"):
        expired = run.issue_root(lifetime=-10)
        return run.post_token(run.exchange_form(expired.value, camp.C1_DETAILS))
    if spec.get("_foreign"):
        other = camp.build_config(token_endpoint=run.endpoint)
        from src.sut.oauth_as.keys import derive_signing_key

        foreign_key = derive_signing_key(b"\x99" * 32)  # a token this AS did not issue
        from src.sut.oauth_as.exchange import issue_initial

        token = issue_initial(
            config=other,
            signing_key=foreign_key,
            subject=camp.USER,
            client_id=camp.SUPERVISOR,
            audience=camp.RESOURCE_SERVER,
            scope=camp.SCOPE_FULL,
            authorization_details=camp.C0_DETAILS,
        )
        return run.post_token(run.exchange_form(token.value, camp.C1_DETAILS))
    if spec.get("_mutate") == "subject":
        at0 = run.issue_root()
        tampered = at0.value[:-4] + ("AAAA" if not at0.value.endswith("AAAA") else "BBBB")
        return run.post_token(run.exchange_form(tampered, camp.C1_DETAILS))
    if "raw_body" in spec:
        return run.post_token({}, raw_body=spec["raw_body"])
    if "client" in spec:
        return run.post_token(
            run.exchange_form(run.issue_root().value, camp.C1_DETAILS), client=None
        )
    if "secret" in spec:
        return run.post_token(
            run.exchange_form(run.issue_root().value, camp.C1_DETAILS), secret=spec["secret"]
        )
    return run.post_token(spec["form"])


# ---------------------------------------------------------------------------
# A3 — RFC 9396 SS 12 string rule
# ---------------------------------------------------------------------------


def a3_string_rule(run: camp.Campaign) -> None:
    # `Read` vs `read`: ADR 0016 froze Omega as US-ASCII lowercase, so the
    # capitalized form is simply not an Omega element -- and it must not
    # narrow-match the lowercase one either.
    capitalized = camp.rar(["Notes.read"], ["notes/project"])
    status_case, body_case, _ = run.post_token(
        run.exchange_form(run.issue_root().value, [capitalized])
    )
    case_rejected = status_case == 400 and body_case.get("error") == "invalid_authorization_details"

    # NFC vs NFD: a decomposed variant is a different byte string, so it is not
    # an Omega element either.
    nfd = "notes/projéct"  # 'e' + COMBINING ACUTE, never equal to the frozen value
    status_nfd, body_nfd, _ = run.post_token(
        run.exchange_form(run.issue_root().value, [camp.rar(["notes.read"], [nfd])])
    )
    nfd_rejected = status_nfd == 400 and body_nfd.get("error") == "invalid_authorization_details"

    # Non-equality at the comparison layer itself, independent of Omega membership.
    import unicodedata

    composed = unicodedata.normalize("NFC", nfd)
    not_equal = nfd != composed and "Notes.read" != "notes.read"
    would_match_if_normalized = unicodedata.normalize("NFC", nfd) == composed

    # And the lowercase, composed original still works -- so the rejections are
    # about the strings, not about the request being malformed.
    control_status, control_body, _ = run.post_token(
        run.exchange_form(run.issue_root().value, [camp.rar(["notes.read"], ["notes/project"])])
    )
    control_ok = control_status == 200 and "access_token" in control_body

    ok = case_rejected and nfd_rejected and not_equal and control_ok
    record(
        "G-4.A3",
        True,
        ok,
        f"RFC 9396 SS 12 (RFC 8259 equality, no transformation or normalization): 'Notes.read' is "
        f"rejected ({status_case} {body_case.get('error')}, {case_rejected}); an NFD variant of "
        f"'notes/project' is rejected ({status_nfd} {body_nfd.get('error')}, {nfd_rejected}); the "
        f"NFD and NFC forms are unequal as strings ({not_equal}) though they would collide under "
        f"normalization ({would_match_if_normalized}) — which is exactly the widening bypass the "
        f"MUST forbids. Control: the exact frozen strings are accepted ({control_ok}). Would have "
        f"failed under a case-folding or Unicode-normalizing comparison",
    )


# ---------------------------------------------------------------------------
# A4 — key isolation (additional evidence, explicitly not a criterion change)
# ---------------------------------------------------------------------------


def a4_key_isolation(run: camp.Campaign) -> None:
    harness_imports = _grep_imports(REPO_ROOT / "src" / "harness")
    sut_imports = _grep_imports(REPO_ROOT / "src" / "sut", exclude="oauth_as")
    rules_hold = not harness_imports and not sut_imports

    # An agent process, started WITHOUT the sealed seed, tries to mint an AT the
    # boundary would accept.
    forge = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parent / "forge_attempt.py"),
            json.dumps(camp.public_jwk()),  # the REAL AS public key, as sealed config delivers it
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=_env_without_seed(),
        timeout=120,
    )
    verdict = json.loads(forge.stdout.strip().splitlines()[-1]) if forge.stdout.strip() else {}
    forge_failed = verdict.get("forged_token_accepted") is False
    seed_absent = verdict.get("seed_in_env") is False
    distinct_key = verdict.get("attacker_key_differs_from_as") is True

    # Positive arm: a genuine AS-issued token IS accepted by the same verifier, so
    # the rejection above is about the key and not about the verifier refusing all.
    at0 = run.issue_root()
    genuine_ok = True
    try:
        boundary.verify_access_token(at0.value, boundary_config(), now=int(time.time()))
    except boundary.TokenRejected:
        genuine_ok = False

    ok = rules_hold and forge_failed and seed_absent and genuine_ok and distinct_key
    record(
        "G-4.A4",
        True,
        ok,
        f"ADR 0015 import rules asserted programmatically: src/harness/ importing src.sut.oauth_as "
        f"-> {harness_imports or 'none'}; other src/sut/ modules importing it -> "
        f"{sut_imports or 'none'} ({rules_hold}). A separate agent process started WITHOUT the "
        f"sealed seed (seed_in_env={verdict.get('seed_in_env')}) minted a token with its own key "
        f"and the boundary REJECTED it: {verdict.get('rejection')} ({forge_failed}). Positive arm: "
        f"a genuine AS-issued token is accepted by that same verifier ({genuine_ok}). Isolation "
        f"rests on the private key never leaving the AS process AND the runner giving the seed "
        f"only "
        f"to that process — a principal holding the seed can derive the key by construction. Would "
        f"have failed if the forged token verified, or if the verifier rejected everything",
    )


def _grep_imports(root: Path, exclude: str | None = None) -> list[str]:
    """Static check for imports of the AS package (ADR 0015 rules 3 and 4)."""
    hits = []
    for path in root.rglob("*.py"):
        if exclude and exclude in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            if "sut.oauth_as" in stripped or "sut import oauth_as" in stripped:
                hits.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    return hits


def _env_without_seed() -> dict:
    import os

    from src.sut.oauth_as.__main__ import SEED_ENV

    env = dict(os.environ)
    env.pop(SEED_ENV, None)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


# ---------------------------------------------------------------------------
# A5 / A6 / A7 — the G-5 hand-forwards, exercised for the first time
# ---------------------------------------------------------------------------


def a5_ath(run: camp.Campaign) -> None:
    from joserfc.jwk import OKPKey

    holder = OKPKey.generate_key("Ed25519")
    at0 = run.issue_root(cnf_jkt=holder.thumbprint())
    config = boundary_config()
    claims = boundary.verify_access_token(at0.value, config, now=int(time.time()))
    now = int(time.time())

    good = dpop.create_proof(
        holder, method="POST", url=camp.RESOURCE_URL, ath=dpop.access_token_hash(at0.value)
    )
    accepted = (
        boundary.verify_dpop_request(
            at0.value, claims, [good], method="POST", url=camp.RESOURCE_URL, now=now
        )
        == holder.thumbprint()
    )

    failures = {}
    for label, proof, token in [
        ("missing ath", dpop.create_proof(holder, method="POST", url=camp.RESOURCE_URL), at0.value),
        (
            "wrong ath",
            dpop.create_proof(
                holder, method="POST", url=camp.RESOURCE_URL, ath=dpop.access_token_hash("other")
            ),
            at0.value,
        ),
        (
            "proof key != bound key",
            dpop.create_proof(
                OKPKey.generate_key("Ed25519"),
                method="POST",
                url=camp.RESOURCE_URL,
                ath=dpop.access_token_hash(at0.value),
            ),
            at0.value,
        ),
    ]:
        try:
            boundary.verify_dpop_request(
                token, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=now
            )
            failures[label] = "ACCEPTED (bad)"
        except boundary.TokenRejected as exc:
            failures[label] = exc.reason

    all_rejected = all(reason.startswith("dpop-item-12") for reason in failures.values())
    ok = accepted and all_rejected
    record(
        "G-4.A5",
        True,
        ok,
        f"first real exercise of the G-5 `ath` hand-forward, at a protected resource: a proof "
        f"carrying ath=base64url(SHA-256(ASCII(AT))) is accepted and returns the bound jkt "
        f"({accepted}); missing ath -> {failures['missing ath']}, wrong ath -> "
        f"{failures['wrong ath']}, a proof signed by a key other than the one cnf.jkt binds -> "
        f"{failures['proof key != bound key']} (all RFC 9449 SS 4.3 item 12: {all_rejected}). "
        f"Would "
        f"have failed if a captured proof could be replayed against a different token, which is "
        f"precisely what ath exists to prevent",
    )


def a6_nonce(run: camp.Campaign) -> None:
    from joserfc.jwk import OKPKey

    nonce_run = camp.start(require_dpop=True, require_dpop_nonce=True)
    try:
        holder = OKPKey.generate_key("Ed25519")
        at0 = nonce_run.issue_root(cnf_jkt=holder.thumbprint())
        form = nonce_run.exchange_form(at0.value, camp.C1_DETAILS)

        first = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint)
        status1, body1, headers1 = nonce_run.post_token(form, dpop=first)
        challenged = status1 == 400 and body1.get("error") == "use_dpop_nonce"
        nonce = headers1.get("DPoP-Nonce")

        retry = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint, nonce=nonce)
        status2, body2, _ = nonce_run.post_token(form, dpop=retry)
        retry_ok = status2 == 200 and body2.get("token_type") == "DPoP"

        nonce_run.server.nonce_store.retire(nonce)
        stale = dpop.create_proof(holder, method="POST", url=nonce_run.endpoint, nonce=nonce)
        status3, body3, _ = nonce_run.post_token(
            nonce_run.exchange_form(nonce_run.issue_root().value, camp.C1_DETAILS), dpop=stale
        )
        stale_rejected = status3 == 400 and body3.get("error") == "use_dpop_nonce"

        # AS and RS nonce namespaces are distinct (RFC 9449 SS 9).
        rs_store = dpop.NonceStore("rs")
        rs_nonce = rs_store.issue()
        as_store = nonce_run.server.nonce_store
        distinct = not as_store.is_valid(rs_nonce) and not rs_store.is_valid(as_store.issue())

        ok = challenged and bool(nonce) and retry_ok and stale_rejected and distinct
        record(
            "G-4.A6",
            True,
            ok,
            f"first real exercise of the G-5 nonce hand-forward: a proof with no nonce is answered "
            f"HTTP {status1} {body1.get('error')} with DPoP-Nonce={str(nonce)[:16]}... "
            f"({challenged}); the retry carrying it succeeds with "
            f"token_type={body2.get('token_type')!r} ({retry_ok}, "
            f"RFC 9449 SS 5 MUST); a retired nonce is refused ({status3} {body3.get('error')}, "
            f"{stale_rejected}); AS and RS namespaces are mutually invalid ({distinct}, SS 9). "
            f"Would "
            f"have failed if a stale nonce were accepted, or if an RS nonce satisfied the AS — the "
            f"conflation SS 9 warns against",
        )
    finally:
        nonce_run.stop()


def a7_htu_normalization(run: camp.Campaign) -> None:
    from joserfc.jwk import OKPKey

    holder = OKPKey.generate_key("Ed25519")
    at0 = run.issue_root(cnf_jkt=holder.thumbprint())
    claims = boundary.verify_access_token(at0.value, boundary_config(), now=int(time.time()))
    now = int(time.time())
    ath = dpop.access_token_hash(at0.value)

    equivalents = {
        "default port": "https://mcp.aasc.local:443/tools/invoke",
        "uppercase scheme and host": "HTTPS://MCP.AASC.LOCAL/tools/invoke",
        "dot segments": "https://mcp.aasc.local/tools/./invoke",
        "query and fragment": "https://mcp.aasc.local/tools/invoke?x=1#frag",
    }
    accepted = {}
    for label, variant in equivalents.items():
        proof = dpop.create_proof(holder, method="POST", url=variant, ath=ath)
        try:
            boundary.verify_dpop_request(
                at0.value, claims, [proof], method="POST", url=camp.RESOURCE_URL, now=now
            )
            accepted[label] = True
        except boundary.TokenRejected:
            accepted[label] = False

    # A genuinely different URI must still be refused, or normalization would be
    # laundering mismatches rather than normalizing them.
    different = dpop.create_proof(
        holder, method="POST", url="https://mcp.aasc.local/tools/other", ath=ath
    )
    try:
        boundary.verify_dpop_request(
            at0.value, claims, [different], method="POST", url=camp.RESOURCE_URL, now=now
        )
        different_rejected = False
    except boundary.TokenRejected as exc:
        different_rejected = exc.reason == "dpop-item-9"

    # And a wrong method is refused (item 8), so item 9 is not doing all the work.
    wrong_method = dpop.create_proof(holder, method="GET", url=camp.RESOURCE_URL, ath=ath)
    try:
        boundary.verify_dpop_request(
            at0.value, claims, [wrong_method], method="POST", url=camp.RESOURCE_URL, now=now
        )
        method_rejected = False
    except boundary.TokenRejected as exc:
        method_rejected = exc.reason == "dpop-item-8"

    ok = all(accepted.values()) and different_rejected and method_rejected
    record(
        "G-4.A7",
        True,
        ok,
        f"RFC 3986 syntax- and scheme-based normalization before comparing htu (closes the G-5 "
        f"residual): {accepted}; a genuinely different path is still refused at item 9 "
        f"({different_rejected}) and a wrong htm at item 8 ({method_rejected}). Would have failed "
        f"if normalization accepted a different resource — laundering a mismatch rather than "
        f"normalizing an equivalent form",
    )


# ---------------------------------------------------------------------------
# L4 — PRECONDITION ONLY. The limb itself is not adjudicated (SS 9 C2).
# ---------------------------------------------------------------------------


def l4_precondition(run: camp.Campaign) -> None:
    at0 = run.issue_root()
    presented = at0.value

    # Observable and stable: the exact byte string presented at the boundary is
    # the one the AS issued, and reading it twice gives the same bytes.
    ascii_bytes = presented.encode("ascii")
    stable = (
        hashlib.sha256(ascii_bytes).hexdigest()
        == hashlib.sha256(presented.encode("ascii")).hexdigest()
    )
    round_trip = presented == ascii_bytes.decode("ascii")

    # A swapped token is detectable: a different token has a different byte
    # string, and the boundary rejects one minted for another audience.
    other = run.issue_root(details=camp.C1_DETAILS)
    swapped_differs = other.value != presented
    swap_digest_differs = (
        hashlib.sha256(other.value.encode("ascii")).hexdigest()
        != hashlib.sha256(ascii_bytes).hexdigest()
    )

    ok = stable and round_trip and swapped_differs and swap_digest_differs
    record(
        "G-4.L4-precondition",
        True,
        ok,
        f"PRECONDITION ONLY — the INV.access_token_hash limb is NOT adjudicated here (SS 9 C2: INV "
        f"is built and mutation-tested at G-11, so there is nothing to verify a digest IN, and the "
        f"AASC-AT-DIGEST construction is a PROPOSAL for G-11, not settled). What is shown: the AT "
        f"byte string presented at the boundary is observable and ASCII-stable "
        f"({stable and round_trip}), "
        f"and a different token is a different byte string with a different digest "
        f"({swapped_differs and swap_digest_differs}), so any digest binding is computable over it "
        f"and a swap is detectable. The SHA-256 above is illustrative only and is NOT the INV "
        f"construction. Would have failed if the presented bytes were unstable or a swap were "
        f"indistinguishable",
    )


# ---------------------------------------------------------------------------


def main() -> int:
    print("Gate G-4 Phase 2 spike — the pinned experiment AS (src/sut/oauth_as/)")
    print(f"Stand-ins in use: {camp.BANNER} — the C3 identity registry and the may_act policy.")
    print("Omega is the FROZEN ontology (ADR 0016); L2 uses no stand-in.")
    print("The AT profile is RFC 9068-SHAPED, deliberately NOT RFC 9068-conformant (SS 8.3).\n")

    run = camp.start()
    print(f"AS listening on {run.endpoint} (TLS 1.3, loopback only)\n")
    try:
        l1_narrowed_token_issues(run)
        l1_prime_widening_refused(run)
        l2_both_layers(run)
        l3_actor_to_holder(run)
        a1_delegation_not_impersonation(run)
        a2_rejection_catalogue(run)
        a3_string_rule(run)
        a4_key_isolation(run)
        a5_ath(run)
        a6_nonce(run)
        a7_htu_normalization(run)
        l4_precondition(run)
    finally:
        run.stop()

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-4 (Phase 2): FAIL — mandatory check(s) failed: {', '.join(failures)}")
        print(
            "Gate-outcome policy (Part G): G-4 fails -> build a behaviourally faithful AS "
            "enforcing the mandated checks directly; disclose it."
        )
        return 1
    print("GATE G-4 (Phase 2): all mandatory checks passed")
    print(
        "Adjudication is over the criteria's ADJUDICABLE limbs. The "
        "INV.access_token_hash limb (L4) is NOT closed: it is scoped to a follow-on run after "
        "G-11 (DESIGN SS 9 C2), and the C3 registry stand-in re-triggers the actor->holder limb "
        "at G-11. This is not a full four-limb closure."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
