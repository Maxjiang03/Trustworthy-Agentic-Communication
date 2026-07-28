"""Loader and `H(Gamma)` for the frozen Omega/Gamma configuration (ADR 0016).

`omega_gamma_v1.json` beside this module is the frozen artifact named by
`docs/frozen_parameters.md` row 8: the finite action/resource ontology `Omega`
(SS A.0.1) and the project authorizer configuration `Gamma` (SS A.6.1), plus the
matched `-attenuation` ablation of `Gamma` (SS E.6). It is **data, not code** —
deliberately, because two sides must evaluate the same frozen bytes with two
independent implementations (D13/D21, the discipline ADR 0009 applies to
`H_JCS`): the SUT boundary authorizes with it, and the harness verifier and the
oracle recompute `Allowed(P_i; Gamma, kappa, Omega)` over it. The SUT receives
the document as start-up configuration (bytes/path supplied by the runner),
never by importing this package - `src/sut/` must never import `src/harness/`
(CLAUDE.md red line 6).

`H(Gamma)` construction (frozen by ADR 0016; the same tagged, versioned,
length-delimited family as ADR 0003 `commitment.py` and ADR 0009
`jcs_digest.py`, with its own tag so the three can never be confused):

    C        = RFC 8785 canonical UTF-8 bytes of the whole document
               (rfc8785==0.1.4, ADR 0005)
    H(Gamma) = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )

It covers the whole document - `Omega`, `Gamma`, and the ablation delta - so a
mutation that broadens trust, that widens the ontology (which would widen every
`C_i`, since `C_i` is a subset of `Omega`), or that lets the ablation drift away
from "identical except the one named respect" all change the digest (gate G-2
criterion (c)). What it does NOT cover: the *value* of `kappa`, which is a
per-campaign key derived from a sealed seed (ADR 0007) and sealed at Part H
step 3; `Gamma` freezes the cardinality and role of the trusted-key set, not the
key bytes.

The digest is never written into the document it covers (Part H step 6's
detached-manifest rule); it is recorded in `docs/frozen_parameters.md` row 8 and
in ADR 0016, and recomputed here.

**Nothing here evaluates a token.** Whether the frozen `Gamma` actually yields
`C_i` a subset of `C_{i-1}` under `biscuit-python==0.4.0` is assumption IA-2,
**[UNVERIFIED-IA]**, and is gate **G-2**'s to adjudicate.
"""

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import rfc8785

TAG = b"AASC-GAMMA-DIGEST"  # fixed ASCII tag; != AASC-JCS-DIGEST, != AASC-CAP-COMMIT
VERSION = 0x01  # any other value fails closed
CONFIG_VERSION = 1  # any other document version fails closed

DOCUMENT_PATH = Path(__file__).with_name("omega_gamma_v1.json")

_ACTION_RE = re.compile(r"^[a-z0-9]+\.[a-z0-9]+$")
_RESOURCE_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+$")


class FrozenConfigError(Exception):
    """Base: the frozen-configuration layer failed closed."""


class UnsupportedVersionError(FrozenConfigError):
    """Document `config_version`, or `H(Gamma)` version, other than the pinned one."""


class DocumentStructureError(FrozenConfigError):
    """The document violates an invariant the freeze guarantees."""


def load_document(path: Path = DOCUMENT_PATH) -> dict[str, Any]:
    """Read, validate, and return the frozen document. Fails closed.

    Validation is structural only: version, the `Omega` string encoding, the
    no-phantom-element rule (every action is a declared tool), and the
    matched-ablation rule (the override touches exactly the declared paths).
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("config_version") != CONFIG_VERSION:
        raise UnsupportedVersionError(f"unsupported config_version {doc.get('config_version')!r}")
    _validate_omega(doc)
    _validate_ablations(doc)
    return doc


def _validate_omega(doc: dict[str, Any]) -> None:
    tools = doc["omega"]["tools"]
    if len(set(tools)) != len(tools):
        raise DocumentStructureError("duplicate tool in the declared tool surface")
    seen: set[tuple[str, str]] = set()
    for element in doc["omega"]["elements"]:
        if len(element) != 2:
            raise DocumentStructureError(
                f"omega element is not an (action, resource) pair: {element!r}"
            )
        action, resource = element
        if not _ACTION_RE.match(action):
            raise DocumentStructureError(f"action {action!r} violates the frozen string encoding")
        if not _RESOURCE_RE.match(resource):
            raise DocumentStructureError(
                f"resource {resource!r} violates the frozen string encoding"
            )
        if action not in tools:
            # No phantom elements: every element must be producible by a real tool,
            # so the effect ledger can record it and the oracle can score it.
            raise DocumentStructureError(f"action {action!r} is not a declared tool")
        if (action, resource) in seen:
            raise DocumentStructureError(f"duplicate omega element {element!r}")
        seen.add((action, resource))
    if not seen:
        raise DocumentStructureError("omega is empty")


def _validate_ablations(doc: dict[str, Any]) -> None:
    for name, spec in doc["gamma_ablations"].items():
        if spec["derived_from"] != "gamma":
            raise DocumentStructureError(f"ablation {name!r} is not derived from gamma")
        if sorted(spec["override"]) != sorted(spec["differs_in_exactly"]):
            # A matched leave-one-out must differ in exactly the one respect it is
            # named for; anything else is not a matched control (SS E.6).
            raise DocumentStructureError(
                f"ablation {name!r} override does not match its declaration"
            )
        for path in spec["override"]:
            _resolve(doc["gamma"], path)  # the overridden path must already exist


def _resolve(node: Any, dotted: str) -> Any:
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            raise DocumentStructureError(f"path {dotted!r} does not exist in gamma")
        node = node[key]
    return node


def h_gamma(doc: dict[str, Any], *, version: int = 1) -> str:
    """Frozen `H(Gamma)` of the whole document (ADR 0016): lowercase-hex SHA-256
    over TAG || version || u32be(len(C)) || C, with C the RFC 8785 canonical
    bytes of `doc`.

    Raises UnsupportedVersionError on any version other than VERSION;
    propagates rfc8785 canonicalization errors unchanged (fail closed).
    """
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported H(Gamma) version {version}")
    canonical = rfc8785.dumps(doc)
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(len(canonical).to_bytes(4, "big"))
    digest.update(canonical)
    return digest.hexdigest()


def omega(doc: dict[str, Any]) -> frozenset[tuple[str, str]]:
    """`Omega` as the SS F.1 type: `frozenset[tuple[str, str]]` of (action, resource)."""
    return frozenset((action, resource) for action, resource in doc["omega"]["elements"])


def gamma(doc: dict[str, Any]) -> dict[str, Any]:
    """The operative authorizer configuration (the full form)."""
    return copy.deepcopy(doc["gamma"])


def gamma_ablation(doc: dict[str, Any], name: str) -> dict[str, Any]:
    """Materialize a matched ablation of `Gamma` by applying its declared override.

    `minus_attenuation` is the SS E.6 unsafe control: identical to the full form
    except that it authorizes against `Allowed(P_0; ...)`, ignoring every
    attenuation block. It is a control, never a deployable authorizer.
    """
    spec = doc["gamma_ablations"][name]
    ablated = gamma(doc)
    for path, value in spec["override"].items():
        keys = path.split(".")
        node = ablated
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return ablated
