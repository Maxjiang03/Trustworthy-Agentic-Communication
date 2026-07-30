"""Expected frozen-parameter digests, read from `docs/frozen_parameters.md`.

`docs/frozen_parameters.md` rows 8 and 11 record `H(Gamma)` (ADR 0016) and
`H(R)` (ADR 0019). The runner verifies both against the frozen artifacts at
start-up and fails closed on a mismatch, before any scenario runs (EXP1
STEP 8 item 2); the pilot corpus generator performs the same check at
generation time. This module is the single reader of those recorded values,
so no second copy of either digest exists in code.

Fail-closed rules: a missing row is an error, and if a digest string appears
more than once in the document every occurrence must be identical -- a
divergent duplicate means the document contradicts itself and nothing should
run on top of it.
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
