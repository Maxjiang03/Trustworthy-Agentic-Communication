"""Expected frozen-parameter values, read from `docs/frozen_parameters.md`.

The document is the single record of every frozen parameter and this module is
its single reader, so **no second copy of a frozen value exists in code**.
Rows 8 and 11 record `H(Gamma)` (ADR 0016) and `H(R)` (ADR 0019); rows 4/6/10
record `H(Lambda)` (ADR 0022/0023). The runner verifies all three against the
frozen artifacts at start-up and fails closed on a mismatch, before any
scenario runs; the pilot corpus generator performs the same check at
generation time.

Rows 1, 2, 3 and 7 are **scalars, not documents** (ADR 0025/0026/0027): there
is no artifact to hash and no new digest. Each is recorded in the document as
an explicit `name = value` token -- the same idiom the digest rows use -- and
read here.

**Fail-closed rules, and the distinction between the two ways a row can be
absent.** A missing or unparseable row is an error, never a default; and if a
value appears more than once in the document every occurrence must be
identical, because a divergent duplicate means the document contradicts itself
and nothing should run on top of it. Beyond that:

* **row 9** is genuinely **not yet chosen** -- it is read off the measurement
  box at seal time -- and raises `RowUnset`;
* **row 5** is **deferred by decision** (ADR 0028) and will never be filled.
  It raises `RowDeferred`, a distinct type, so a caller can tell "nobody has
  decided this yet" from "this was decided not to exist". Collapsing the two
  would invite someone to fill row 5 later to make an error go away.
"""

import re
from pathlib import Path

DOCUMENT_PATH = Path(__file__).resolve().parents[2] / "docs" / "frozen_parameters.md"

# The document spells the symbols with the Greek capital gamma; match the
# recorded `<symbol> = <64 lowercase hex>` form.
_H_GAMMA_RE = re.compile(r"H\(Γ\)\s*=\s*([0-9a-f]{64})")
_H_REGISTRY_RE = re.compile(r"H\(R\)\s*=\s*([0-9a-f]{64})")
_H_POLICY_RE = re.compile(r"H\(Λ\)\s*=\s*([0-9a-f]{64})")


class FrozenParametersError(Exception):
    """Base: the frozen-parameters reader failed closed."""


class RowUnset(FrozenParametersError):
    """The row has no value yet. Nothing may be compared against it."""


class RowDeferred(FrozenParametersError):
    """The row was deliberately NOT frozen, and never will be (ADR 0028)."""


def _single_value(pattern: re.Pattern[str], text: str, name: str) -> str:
    values = set(pattern.findall(text))
    if not values:
        raise FrozenParametersError(f"{name} is not recorded in {DOCUMENT_PATH.name}")
    if len(values) > 1:
        raise FrozenParametersError(f"{name} appears with conflicting values: {sorted(values)}")
    return values.pop()


def expected_h_gamma(path: Path = DOCUMENT_PATH) -> str:
    """Row 8's recorded `H(Gamma)` (ADR 0016)."""
    return _single_value(_H_GAMMA_RE, path.read_text(encoding="utf-8"), "H(Gamma)")


def expected_h_registry(path: Path = DOCUMENT_PATH) -> str:
    """Row 11's recorded `H(R)` (ADR 0019)."""
    return _single_value(_H_REGISTRY_RE, path.read_text(encoding="utf-8"), "H(R)")


def expected_h_policy(path: Path = DOCUMENT_PATH) -> str:
    """Rows 4/6/10's recorded `H(Lambda)` (ADR 0022)."""
    return _single_value(_H_POLICY_RE, path.read_text(encoding="utf-8"), "H(Lambda)")


# ---------------------------------------------------------------------------
# The scalar rows (ADR 0025/0026/0027). No artifact, no hash -- a token.
# ---------------------------------------------------------------------------
def _scalar(name: str, path: Path = DOCUMENT_PATH) -> int:
    """Read one `name = <integer>` token, or fail closed.

    Deliberately not tolerant: no default, no unit inference, and a row that
    still reads `<UNSET` raises rather than matching a stray digit elsewhere
    in the document.
    """
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(rf"\b{re.escape(name)}\s*=\s*(\d+)\b")
    values = set(pattern.findall(text))
    if not values:
        raise RowUnset(
            f"{name} is not recorded in {path.name}: the row is unset, and a comparison "
            "against an unset frozen parameter must fail closed rather than default"
        )
    if len(values) > 1:
        raise FrozenParametersError(f"{name} appears with conflicting values: {sorted(values)}")
    return int(values.pop())


def equivalence_margin_ms(path: Path = DOCUMENT_PATH) -> int:
    """Row 1 (ADR 0026). The margin the "lightweight" claim is retracted against.

    The value alone is not the decision rule: the claim stands iff the **upper
    bound of the 95% bootstrap CI** on `median(B3) - median(B0)` over the
    measured segment is below it. Row 1 records that rule; this returns the
    number it uses.
    """
    return _scalar("equivalence_margin_ms", path)


def g3_threshold_ms(path: Path = DOCUMENT_PATH) -> int:
    """Row 2 (ADR 0025). Fixed BEFORE row 1 and independently of it.

    A G-3 run that counts toward the gate must execute on the row 9 sealed
    measurement platform; a Linux CI run of the spike is regression protection
    only and is never adjudicative.
    """
    return _scalar("g3_threshold_ms", path)


def delta_seconds(path: Path = DOCUMENT_PATH) -> int:
    """Row 3 (ADR 0027). ONE window, three consumers, no exceptions.

    The `jti` cache TTL, the DPoP proof `iat` acceptance window and INV
    freshness at the boundary all use this value, so G-14's two arms cannot
    differ in window and any difference it reports is attributable to the
    mechanisms rather than to the clock.
    """
    return _scalar("delta_seconds", path)


def replay_cache_capacity(path: Path = DOCUMENT_PATH) -> int:
    """Row 3's G-9 budget (ADR 0027): 2^16 entries, fail-closed on overflow."""
    return _scalar("replay_cache_capacity", path)


def llm_turn_denominators(path: Path = DOCUMENT_PATH) -> tuple[int, int]:
    """Row 7 (ADR 0025): `(T_full_ms, T_ttft_ms)`.

    A **secondary interpretive aid only** -- no hypothesis, gate criterion or
    retraction rule depends on it except through row 2 -- and never re-fitted
    to observed data.
    """
    return _scalar("T_full_ms", path), _scalar("T_ttft_ms", path)


def task_authorization_policy(path: Path = DOCUMENT_PATH) -> None:
    """Row 5 (ADR 0028). Always raises: the row is deferred BY DECISION.

    Not an oversight and not a to-do. `F2 wrong_principal` is unscored because
    row 5 has no anchor outside the author's judgement, so any value would make
    that family measure conformance to an invented artifact. The other three
    `F2` subfamilies are retained and scored in full.
    """
    raise RowDeferred(
        "frozen_parameters row 5 (task_authorization_policy) is DEFERRED BY DECISION "
        "(ADR 0028) and will never be set: the F2 wrong_principal subfamily is unscored. "
        "This is not a row awaiting a value -- filling it would require a new ADR, an update "
        "to PRE_REGISTRATION.md, and re-opening G-4's may_act limb."
    )


def sealed_measurement_platform(path: Path = DOCUMENT_PATH) -> str:
    """Row 9. Raises until the exact build is read off the box at seal time."""
    text = path.read_text(encoding="utf-8")
    match = re.search(r"sealed_platform\s*=\s*(\S.*?)\s*\|", text)
    if match is None:
        raise RowUnset(
            "frozen_parameters row 9 (sealed measurement platform) is unset: it is read off "
            "the measurement box at Part H step 3, and no G-3 adjudication may be attributed "
            "to a platform that has not been recorded"
        )
    return match.group(1)
