"""RFC 9396 Rich Authorization Requests: how `C_i` is carried, expanded, contained.

`smoke/g4/DESIGN.md` SS 5.2. `C_i` travels as a single-type `authorization_details`
array. The **meaning** of an object is RFC 9396 SS 2.2's product rule -- all its
`actions`, at all its `locations`, for all its `datatypes` -- so containment is
computed on the **expansion**, never on the JSON objects (SS 6.1: "an AS should
not rely on simple object comparison").

Two rules here are load-bearing and easy to get quietly wrong:

* **String comparison is RFC 8259 equality with no transformation or
  normalization** [VERIFIED, RFC 9396 SS 12]. No case folding, no Unicode
  normalization, no trimming. A case-insensitive or NFC-normalizing comparison
  is a real widening bypass (SS 8.1 item 5), so equality here is plain `==` on
  `str` and every value is additionally required to be a member of the frozen
  `Omega`, which ADR 0016 fixed as US-ASCII lowercase.
* **The expansion must be a subset of `Omega`**, checked at the level of the
  expanded `(action, resource)` **pair**, not merely value by value. `C_i` is by
  definition a subset of `Omega` (SS A.0.1), and an object pairing two
  individually-valid strings could otherwise manufacture a pair that is not an
  `Omega` element. Splitting such a request across several same-type objects is
  the RFC-sanctioned way to express it (SS 2 allows several entries of one type).

`Omega` arrives as **start-up configuration** supplied by the runner, never by
importing the harness (`src/sut/` must never import `src/harness/`, PROJECT_RULES.md
red line 6; ADR 0016's data-not-code discipline).
"""

from typing import Any

from src.sut.oauth_as.errors import INVALID_AUTHORIZATION_DETAILS, OAuthError

# SS 5.2: the only fields a profile RAR object may carry. `privileges` is
# forbidden because RFC 9396 SS 6.1's own example shows `privileges: admin`
# subsuming both `read` and `write` -- API-defined subsumption is exactly the
# widening hazard this gate exists to catch.
_ALLOWED_FIELDS = {"type", "locations", "actions", "datatypes", "identifier"}
_REQUIRED_FIELDS = {"type", "locations", "actions", "datatypes"}
FORBIDDEN_FIELDS = {"privileges"}

# (location, action, datatype) -- the RFC 9396 SS 2.2 product.
Triple = tuple[str, str, str]


def _reject(description: str, row: str = "rar-malformed") -> OAuthError:
    return OAuthError(INVALID_AUTHORIZATION_DETAILS, row, description)


def validate_details(
    details: Any, *, rar_type: str, omega: frozenset[tuple[str, str]]
) -> list[dict[str, Any]]:
    """Validate an `authorization_details` array, or raise the catalogue error.

    Implements RFC 9396 SS 5's five MUST-abort conditions (unknown `type`;
    unknown field in a known type; wrong field type; invalid value; missing
    required field) plus this profile's three additions (forbidden `privileges`;
    a value outside `Omega`; more than one `locations` entry) -- SS 6 rows 9
    and 10. Every failure is `invalid_authorization_details`.
    """
    if not isinstance(details, list) or not details:
        raise _reject("authorization_details must be a non-empty JSON array", "rar-wrong-type")
    for entry in details:
        if not isinstance(entry, dict):
            raise _reject(
                "each authorization_details entry must be a JSON object", "rar-wrong-type"
            )

        if "type" not in entry:
            raise _reject("missing required field: type", "rar-missing-field")
        if entry["type"] != rar_type:
            # RFC 9396 SS 5: unknown type MUST be refused.
            raise _reject(
                f"unknown authorization_details type {entry['type']!r}", "rar-unknown-type"
            )

        forbidden = FORBIDDEN_FIELDS & set(entry)
        if forbidden:
            raise _reject(
                f"forbidden field(s) in the MSc profile: {sorted(forbidden)}", "rar-forbidden-field"
            )
        unknown = set(entry) - _ALLOWED_FIELDS
        if unknown:
            raise _reject(f"unknown field(s) for this type: {sorted(unknown)}", "rar-unknown-field")
        missing = _REQUIRED_FIELDS - set(entry)
        if missing:
            raise _reject(f"missing required field(s): {sorted(missing)}", "rar-missing-field")

        for field in ("locations", "actions", "datatypes"):
            value = entry[field]
            if not isinstance(value, list) or not value:
                raise _reject(f"{field} must be a non-empty JSON array", "rar-wrong-type")
            if not all(isinstance(item, str) for item in value):
                raise _reject(f"{field} must contain only JSON strings", "rar-wrong-type")
        if len(entry["locations"]) != 1:
            # SS 5.2 profile restriction: one location per object, so the
            # expansion maps bijectively onto Omega (ADR 0016).
            raise _reject("exactly one locations value is allowed per object", "rar-multi-location")
        if "identifier" in entry:
            if not isinstance(entry["identifier"], str):
                raise _reject("identifier must be a JSON string", "rar-wrong-type")
            if entry["identifier"] not in entry["datatypes"]:
                # `identifier` names a specific resource of this object; allowing
                # it to name anything else would be a second, unexpanded
                # authority channel. It may narrow or restate, never widen.
                raise _reject(
                    "identifier must be one of this object's datatypes", "rar-invalid-value"
                )

        for action, resource in _object_pairs(entry):
            if (action, resource) not in omega:
                # SS 5.2: an out-of-Omega value is a rejection, never an
                # implicitly new authority element. Checked pairwise because
                # C_i is a subset of Omega (SS A.0.1).
                raise _reject(
                    f"({action!r}, {resource!r}) is not an element of the frozen ontology",
                    "rar-outside-omega",
                )
    return list(details)


def _object_pairs(entry: dict[str, Any]) -> set[tuple[str, str]]:
    return {(a, d) for a in entry["actions"] for d in entry["datatypes"]}


def expand(details: list[dict[str, Any]]) -> set[Triple]:
    """`expand(AD)` -- the RFC 9396 SS 2.2 product, as a set of triples."""
    return {
        (location, action, datatype)
        for entry in details
        for location in entry["locations"]
        for action in entry["actions"]
        for datatype in entry["datatypes"]
    }


def elements(details: list[dict[str, Any]]) -> frozenset[tuple[str, str]]:
    """The `Omega` projection of the expansion: `(l, a, d)` |-> `(a, d)`.

    With exactly one `locations` value per object the mapping is a bijection
    (ADR 0016), so this is `C_i` as the SS F.1 type.
    """
    return frozenset((action, datatype) for _, action, datatype in expand(details))


def contains(outer: list[dict[str, Any]], inner: list[dict[str, Any]]) -> bool:
    """`expand(inner)` subset-of `expand(outer)`, by byte-exact string equality.

    Python `str` equality is codepoint equality with no normalization, which is
    exactly RFC 8259 / RFC 9396 SS 12 string comparison.
    """
    return expand(inner) <= expand(outer)


def filter_to_audience(details: list[dict[str, Any]], audience: str) -> list[dict[str, Any]]:
    """The granted details filtered to one audience (RFC 9396 SS 9.1).

    Objects whose single location is not this audience are dropped entirely.
    """
    return [dict(entry) for entry in details if entry["locations"] == [audience]]
