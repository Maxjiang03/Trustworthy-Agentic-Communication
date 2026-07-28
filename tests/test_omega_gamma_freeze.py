"""Regression suite for the frozen Omega/Gamma configuration and H(Gamma) (ADR 0016).

Scope discipline: these tests are **structural**. They check that the frozen
artifact loads, that its string encoding and no-phantom-element rules hold, that
the `-attenuation` ablation is matched, that the H(Gamma) construction is
domain-separated / versioned / encoding-invariant, and that the digest recorded
in `docs/frozen_parameters.md` still matches the artifact.

They are **not** gate G-2. Nothing here mints a token, appends a block, or runs
an authorizer over a capability, so nothing here says anything about Biscuit
monotonicity under the frozen Gamma - that is assumption IA-2, still
[UNVERIFIED-IA], and G-2's to adjudicate.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest
import rfc8785
from biscuit_auth import AuthorizerBuilder, BiscuitBuilder, BlockBuilder

from src.harness.authorizer.frozen_config import (
    DOCUMENT_PATH,
    DocumentStructureError,
    UnsupportedVersionError,
    gamma,
    gamma_ablation,
    h_gamma,
    load_document,
    omega,
)
from src.harness.oracle.jcs_digest import h_jcs

REPO_ROOT = Path(__file__).resolve().parents[1]

# The frozen ontology, restated here as a known answer so a silent edit to the
# artifact fails a test rather than passing unnoticed (ADR 0016 SS Omega).
EXPECTED_OMEGA = frozenset(
    {
        ("calendar.read", "calendar/work"),
        ("calendar.read", "calendar/personal"),
        ("notes.read", "notes/project"),
        ("notes.read", "notes/meeting"),
        ("notes.write", "notes/project"),
        ("notes.delete", "notes/project"),
        ("mail.send", "mail/outbox"),
    }
)

# Illustrative witness for the two-hop strict-attenuation constraint. NOT a
# frozen scenario and NOT a policy: it only shows the chain is expressible over
# the frozen vocabulary (SS A.6.1 INV-2; task STEP 3 constraint 3).
WITNESS_C0 = frozenset(
    {
        ("calendar.read", "calendar/work"),
        ("notes.read", "notes/project"),
        ("notes.read", "notes/meeting"),
        ("notes.write", "notes/project"),
        ("mail.send", "mail/outbox"),
    }
)
WITNESS_C1 = frozenset(
    {
        ("calendar.read", "calendar/work"),
        ("notes.read", "notes/project"),
        ("notes.read", "notes/meeting"),
    }
)
WITNESS_C2 = frozenset({("notes.read", "notes/project"), ("notes.read", "notes/meeting")})


@pytest.fixture(scope="module")
def doc() -> dict:
    return load_document()


# --------------------------------------------------------------------------
# 1. The artifact loads, and is exactly what was frozen
# --------------------------------------------------------------------------


def test_document_loads_and_pins_its_version(doc: dict) -> None:
    assert doc["config_version"] == 1
    assert doc["fixing_adr"] == "0016"


def test_omega_is_the_frozen_set_with_the_frozen_type(doc: dict) -> None:
    result = omega(doc)
    assert result == EXPECTED_OMEGA
    assert isinstance(result, frozenset)
    assert all(isinstance(x, tuple) and len(x) == 2 for x in result)
    assert all(isinstance(s, str) for x in result for s in x)


def test_omega_string_encoding_is_enforced(tmp_path: Path, doc: dict) -> None:
    """Positive: the frozen strings pass. Negative: a cased or Unicode variant fails."""
    for action, resource in omega(doc):
        assert action == action.lower() and resource == resource.lower()
        assert action.isascii() and resource.isascii()
        assert action.count(".") == 1 and resource.count("/") == 1

    for bad in (["Notes.read", "notes/project"], ["notes.read", "notes∕project"]):
        mutated = json.loads(DOCUMENT_PATH.read_text(encoding="utf-8"))
        mutated["omega"]["elements"].append(bad)
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(mutated), encoding="utf-8")
        with pytest.raises(DocumentStructureError):
            load_document(path)


def test_no_phantom_element_every_action_is_a_declared_tool(tmp_path: Path, doc: dict) -> None:
    """Constraint 5: no element exists only on paper."""
    tools = set(doc["omega"]["tools"])
    assert {action for action, _ in omega(doc)} <= tools

    mutated = json.loads(DOCUMENT_PATH.read_text(encoding="utf-8"))
    mutated["omega"]["elements"].append(["ghost.read", "notes/project"])
    path = tmp_path / "phantom.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(DocumentStructureError):
        load_document(path)


def test_unsupported_config_version_fails_closed(tmp_path: Path) -> None:
    mutated = json.loads(DOCUMENT_PATH.read_text(encoding="utf-8"))
    mutated["config_version"] = 2
    path = tmp_path / "v2.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(UnsupportedVersionError):
        load_document(path)


# --------------------------------------------------------------------------
# 2. Omega carries the vocabulary every retained construct needs
# --------------------------------------------------------------------------


def test_two_hop_strict_attenuation_is_expressible(doc: dict) -> None:
    """C_0 superset C_1 superset C_2, every step dropping real authority."""
    universe = omega(doc)
    assert WITNESS_C2 < WITNESS_C1 < WITNESS_C0 <= universe


def test_amplification_is_expressible(doc: dict) -> None:
    """At least one element the tool surface exposes lies outside the grant."""
    outside = omega(doc) - WITNESS_C0
    assert outside
    assert {action for action, _ in outside} <= set(doc["omega"]["tools"])


def test_invocation_substitution_fixtures_are_expressible(doc: dict) -> None:
    """T-tool needs two actions inside one C_n; T-args needs one action with two
    resources inside one C_n - otherwise containment, not invocation binding,
    would block the SS E.6 -invoke fixture, and it would stop being matched."""
    assert len({action for action, _ in WITNESS_C1}) >= 2
    by_action: dict[str, set[str]] = {}
    for action, resource in WITNESS_C1:
        by_action.setdefault(action, set()).add(resource)
    assert any(len(resources) >= 2 for resources in by_action.values())


def test_egress_and_high_risk_elements_are_distinct(doc: dict) -> None:
    """SS E.6 orthogonality: if F4's sink were also F5's high-risk action, the
    -context and -approval fixtures would each trip the other's conjunct."""
    universe = omega(doc)
    egress = {(a, r) for a, r in universe if a == "mail.send"}
    destructive = {(a, r) for a, r in universe if a == "notes.delete"}
    assert egress and destructive
    assert not (egress & destructive)


# --------------------------------------------------------------------------
# 3. Gamma: profile restrictions, and the matched ablation
# --------------------------------------------------------------------------


def test_gamma_declares_the_msc_profile_restrictions(doc: dict) -> None:
    trust = gamma(doc)["trust"]
    assert trust["trusted_keys"] == ["kappa"]
    assert trust["trusted_key_count"] == 1
    assert trust["third_party_blocks"] == "reject"
    assert trust["trusting_annotations"] == "forbidden"
    assert trust["block_scoping"] == "default"


def test_minus_attenuation_ablation_differs_in_exactly_one_respect(doc: dict) -> None:
    full = gamma(doc)
    ablated = gamma_ablation(doc, "minus_attenuation")
    differing = _diff_paths(full, ablated)
    assert differing == ["evaluation.prefix"]
    assert full["evaluation"]["prefix"] == "P_n"
    assert ablated["evaluation"]["prefix"] == "P_0"
    # Same Datalog, byte for byte: the control is the same authorizer applied to
    # a different prefix, not a different authorizer.
    assert full["datalog"] == ablated["datalog"]


def test_ablation_declaration_must_match_its_override(tmp_path: Path) -> None:
    mutated = json.loads(DOCUMENT_PATH.read_text(encoding="utf-8"))
    mutated["gamma_ablations"]["minus_attenuation"]["override"]["trust.third_party_blocks"] = (
        "accept"
    )
    path = tmp_path / "drifted.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(DocumentStructureError):
        load_document(path)


def test_frozen_datalog_parses_under_the_pinned_library(doc: dict) -> None:
    """Syntax only. This asserts nothing about authorization semantics: no token
    is minted, no block appended, no authorizer run - that is gate G-2."""
    datalog = gamma(doc)["datalog"]
    assert AuthorizerBuilder(datalog["authorizer"]) is not None

    substitutions = {
        "<action>": "calendar.read",
        "<resource>": "calendar/work",
        "<audience>": "mcp://example",
        "<task_id>": "task-0001",
        "<instant>": "2026-12-31T23:59:59Z",
    }

    def fill(template: str) -> str:
        for placeholder, value in substitutions.items():
            template = template.replace(placeholder, value)
        return template

    assert BiscuitBuilder(fill(datalog["authority_block_template"])) is not None
    assert BlockBuilder(fill(datalog["attenuation_block_template"])) is not None


# --------------------------------------------------------------------------
# 4. H(Gamma): construction, domain separation, fail-closed, and no drift
# --------------------------------------------------------------------------


def test_h_gamma_known_answer() -> None:
    """Worked example from ADR 0016, reproducible by hand."""
    example = {"config_version": 1, "gamma": {"profile": "msc"}}
    canonical = rfc8785.dumps(example)
    assert canonical == b'{"config_version":1,"gamma":{"profile":"msc"}}'
    assert len(canonical) == 46
    assert h_gamma(example) == "80a0f13f95b7be7c16f54d051c5da0d9882e343bdecb5eea47f1aacc0b0bb7d1"


def test_h_gamma_is_domain_separated(doc: dict) -> None:
    """Non-vacuous against a bare digest and against the two sibling constructions."""
    canonical = rfc8785.dumps(doc)
    assert h_gamma(doc) != hashlib.sha256(canonical).hexdigest()
    assert h_gamma(doc) != h_jcs(doc)


def test_h_gamma_is_encoding_invariant(doc: dict) -> None:
    """Member order and insignificant whitespace cannot change the digest."""
    reserialized = json.loads(json.dumps(doc, sort_keys=True, indent=4))
    assert h_gamma(reserialized) == h_gamma(doc)


def test_h_gamma_unsupported_version_fails_closed(doc: dict) -> None:
    with pytest.raises(UnsupportedVersionError):
        h_gamma(doc, version=2)


def test_h_gamma_output_shape(doc: dict) -> None:
    digest = h_gamma(doc)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_frozen_parameters_row_8_records_the_current_digest(doc: dict) -> None:
    """Anti-drift: editing Omega or Gamma without re-recording H(Gamma) fails here."""
    row = _row_8(REPO_ROOT / "docs" / "frozen_parameters.md")
    assert h_gamma(doc) in row
    assert "0016" in row


def test_digest_is_not_written_into_the_document_it_covers(doc: dict) -> None:
    """Part H step 6's detached-manifest rule, applied to H(Gamma)."""
    assert h_gamma(doc) not in DOCUMENT_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------


def _diff_paths(left: dict, right: dict, prefix: str = "") -> list[str]:
    paths: list[str] = []
    for key in sorted(set(left) | set(right)):
        path = f"{prefix}{key}"
        lhs, rhs = left.get(key), right.get(key)
        if isinstance(lhs, dict) and isinstance(rhs, dict):
            paths.extend(_diff_paths(lhs, rhs, f"{path}."))
        elif lhs != rhs:
            paths.append(path)
    return paths


def _row_8(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("| 8 |"):
            return line
    raise AssertionError("row 8 not found in docs/frozen_parameters.md")
