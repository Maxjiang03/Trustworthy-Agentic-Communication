"""Loader and `H(Lambda)` for the frozen label/approval policy (ADR 0022).

`label_approval_v1.json` beside this module is the frozen artifact named by
`docs/frozen_parameters.md` rows **4** (context-label -> outcome), **6**
(allowed-sink) and **10** (oracle classification: the high-risk action set and
the sensitive-label set). It follows the ADR 0016 / ADR 0019 pattern exactly:
one loadable document, a stated **necessity** per entry that the loader
enforces, a hash under its **own** domain tag, and fail-closed on an
unsupported version.

`H(Lambda)` construction (frozen by ADR 0022; the same tagged, versioned,
length-delimited family as ADR 0003 `commitment.py`, ADR 0009 `jcs_digest.py`,
ADR 0016 `frozen_config.py`, ADR 0018 `at_digest.py` and ADR 0019
`registry.py`, with its own tag so none can be confused with another):

    C          = RFC 8785 canonical UTF-8 bytes of the whole document
    H(Lambda)  = lowercase_hex( SHA-256( TAG || 0x01 || u32be(len(C)) || C ) )

It is **data, not code**: rows 4 and 6 reach the SUT boundary as injected
sealed configuration and row 10 is consumed by the SUT's
`approval_artifact_ok` *and* by the oracle's `is_high_risk`/`is_sensitive`,
**each computing from the document itself** -- the line ADR 0016 drew for
`Omega`/`Gamma`. Neither plane imports the other's evaluation.

**What this freeze does NOT do.** It enables the **refusal** half of both
policy conjuncts: an unlabelled or over-labelled egress is refused, and a
high-risk action is refused because no approval artifact can verify. The
**acceptance** half needs `authz_context_hash`, which stays ADR 0009 category
(c) owned by **G-15**; scoring F4/F5 additionally needs labelled fixtures.
Row 5 (`task_authorization_policy`) is untouched and stays UNSET.

**The egress set is DERIVED, never enumerated here.** The document states the
rule -- an action is egress iff its effect carries a recipient -- and each
plane applies it to its own view (`egress_actions` below validates the result
against `Omega`). Over the frozen `Omega` the derived set is exactly
`{mail.send}`, asserted by test rather than written into the artifact, so an
`Omega` amendment moves the ontology and the policy together.
"""

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785

TAG = b"AASC-POLICY-DIGEST"  # 19 bytes; distinct from every tag in service
VERSION = 0x01  # any other value fails closed
CONFIG_VERSION = 1  # any other document version fails closed

DOCUMENT_PATH = Path(__file__).with_name("label_approval_v1.json")

# The three outcomes, ordered least to most restrictive. Composition takes the
# maximum, so two planes can never combine into a permit neither granted.
PERMIT, ESCALATE, BLOCK = "permit", "escalate", "block"
_RESTRICTIVENESS = {PERMIT: 0, ESCALATE: 1, BLOCK: 2}


class FrozenPolicyError(Exception):
    """Base: the frozen-policy layer failed closed."""


class UnsupportedVersionError(FrozenPolicyError):
    """Document `config_version`, or `H(Lambda)` version, other than the pinned one."""


class PolicyStructureError(FrozenPolicyError):
    """The document violates an invariant the freeze guarantees."""


def load_document(path: Path = DOCUMENT_PATH) -> dict[str, Any]:
    """Read, validate, and return the frozen document. Fails closed."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("config_version") != CONFIG_VERSION:
        raise UnsupportedVersionError(f"unsupported config_version {doc.get('config_version')!r}")
    _validate(doc)
    return doc


def _require_necessity(entry: Any, where: str) -> None:
    """Every entry states the requirement that forces it (the ADR 0019 rule).

    This is what stops the justification column rotting: an entry added later
    without a stated necessity refuses to load at all.
    """
    if not isinstance(entry, dict) or not str(entry.get("necessity", "")).strip():
        raise PolicyStructureError(f"{where} has no stated necessity")


def _validate(doc: dict[str, Any]) -> None:
    row4 = doc["row4_context_policy"]
    vocabulary = row4["label_vocabulary"]
    order = vocabulary["total_order"]
    if len(set(order)) != len(order) or not order:
        raise PolicyStructureError("the label vocabulary is empty or has a duplicate")

    ranks = {}
    for entry in vocabulary["labels"]:
        _require_necessity(entry, f"label {entry.get('label')!r}")
        label, rank = entry["label"], entry["rank"]
        if label not in order:
            raise PolicyStructureError(f"label {label!r} is not in the declared total order")
        if order.index(label) != rank:
            # The rank and the order are two statements of one fact; a
            # disagreement would make `join` ambiguous.
            raise PolicyStructureError(f"label {label!r} rank {rank} contradicts total_order")
        ranks[label] = rank
    if set(ranks) != set(order):
        raise PolicyStructureError("the labels list does not cover the declared total order")

    _require_necessity(row4["egress_predicate"], "the egress predicate")

    seen: set[tuple[str, str]] = set()
    for entry in row4["outcomes"]:
        _require_necessity(entry, f"outcome {entry.get('action_class')}/{entry.get('label')}")
        key = (entry["action_class"], entry["label"])
        if key in seen:
            raise PolicyStructureError(f"duplicate outcome rule {key}")
        if entry["outcome"] not in _RESTRICTIVENESS:
            raise PolicyStructureError(f"outcome {entry['outcome']!r} is not one of the three")
        if entry["label"] != "*" and entry["label"] not in order:
            raise PolicyStructureError(f"outcome names unknown label {entry['label']!r}")
        seen.add(key)
    # Every label must have an egress outcome: a gap would silently fall
    # through to the unlabelled rule and mislabel a labelled payload.
    missing = {("egress", label) for label in order} - seen
    if missing:
        raise PolicyStructureError(f"no egress outcome for {sorted(label for _, label in missing)}")

    for entry in row4["unlabelled"]:
        _require_necessity(entry, f"unlabelled/{entry.get('action_class')}")
        if entry["outcome"] not in _RESTRICTIVENESS:
            raise PolicyStructureError(
                f"unlabelled outcome {entry['outcome']!r} is not one of three"
            )
    classes = {entry["action_class"] for entry in row4["unlabelled"]}
    if classes != {"egress", "non_egress"}:
        raise PolicyStructureError("the unlabelled rule must cover both action classes")

    row6 = doc["row6_sink_policy"]
    sinks = set()
    for entry in row6["sink_classes"]:
        _require_necessity(entry, f"sink class {entry.get('sink')!r}")
        sinks.add(entry["sink"])
    if len(sinks) != len(row6["sink_classes"]):
        raise PolicyStructureError("duplicate sink class")
    if sinks != {"internal-sink", "external-sink"}:
        raise PolicyStructureError(f"row 6 declares sink classes {sorted(sinks)}, expected two")
    internal = next(entry for entry in row6["sink_classes"] if entry["sink"] == "internal-sink")
    if not str(internal.get("internal_domain", "")).strip():
        raise PolicyStructureError("internal-sink declares no internal_domain")
    if "internal_domain" not in internal["rule"]:
        # The prose and the field are two statements of one fact; a rule that
        # does not reference the field could drift away from it unnoticed.
        raise PolicyStructureError("the internal-sink rule does not reference internal_domain")
    for entry in row6["allowed_pairs"]:
        _require_necessity(entry, f"allowed pair {entry.get('label')}/{entry.get('sink')}")
        if entry["label"] not in order:
            raise PolicyStructureError(f"allowed pair names unknown label {entry['label']!r}")
        if entry["sink"] not in sinks:
            raise PolicyStructureError(f"allowed pair names unknown sink {entry['sink']!r}")
    _require_necessity(row6["composition_with_row4"], "the row4/row6 composition rule")

    row10 = doc["row10_oracle_classification"]
    for entry in row10["high_risk_actions"]:
        _require_necessity(entry, f"high-risk action {entry.get('action')!r}")
    for entry in row10["sensitive_labels"]:
        _require_necessity(entry, f"sensitive label {entry.get('label')!r}")
        if entry["label"] not in order:
            raise PolicyStructureError(f"sensitive label {entry['label']!r} is outside the order")


def h_policy(doc: dict[str, Any], *, version: int = 1) -> str:
    """Frozen `H(Lambda)` over the whole document (ADR 0022). Fails closed."""
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported H(Lambda) version {version}")
    canonical = rfc8785.dumps(doc)
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(len(canonical).to_bytes(4, "big"))
    digest.update(canonical)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# The evaluable policy. Both planes build this from the document itself.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LabelApprovalPolicy:
    """Rows 4, 6 and 10 as the operations each plane needs."""

    order: tuple[str, ...]
    egress_outcome: dict[str, str]  # label -> outcome (row 4, egress actions)
    non_egress_outcome: str
    unlabelled_egress: str
    unlabelled_non_egress: str
    internal_sink_domain: str
    allowed_pairs: frozenset[tuple[str, str]]
    high_risk_actions: frozenset[str]
    sensitive_labels: frozenset[str]
    document_digest: str

    # -- row 4 ---------------------------------------------------------- #
    def join(self, labels: "list[str] | tuple[str, ...]") -> str | None:
        """The least upper bound of the input labels (SS A.6). None if empty."""
        known = [label for label in labels if label in self.order]
        unknown = [label for label in labels if label not in self.order]
        if unknown:
            # An unrecognised label cannot be ranked, so it cannot be joined;
            # refusing is the only fail-closed answer.
            raise FrozenPolicyError(f"label(s) outside the frozen vocabulary: {sorted(unknown)}")
        if not known:
            return None
        return max(known, key=self.order.index)

    def sink_class(self, recipient: str) -> str:
        """Row 6's two classes, byte-exact lowercase ASCII, no normalization."""
        domain = recipient.rpartition("@")[2]
        return "internal-sink" if domain == self.internal_sink_domain else "external-sink"

    def outcome(self, *, is_egress: bool, label: str | None, recipient: str | None) -> str:
        """The composed row 4 + row 6 outcome for one concrete action.

        Composition (declared in the document, and the only one that cannot
        turn two refusals into a permit): the MORE RESTRICTIVE of the two
        planes wins, on the order permit < escalate < block.
        """
        if not is_egress:
            return self.non_egress_outcome if label is not None else self.unlabelled_non_egress
        if label is None:
            return self.unlabelled_egress  # fail closed: no permit can be established
        row4 = self.egress_outcome[label]
        if recipient is None:
            # Declared egress with no recipient to classify: row 6 cannot be
            # evaluated, so nothing can establish its half of the permit.
            return BLOCK
        row6 = PERMIT if (label, self.sink_class(recipient)) in self.allowed_pairs else BLOCK
        return max((row4, row6), key=_RESTRICTIVENESS.__getitem__)

    # -- row 10 --------------------------------------------------------- #
    def is_high_risk(self, action: str) -> bool:
        return action in self.high_risk_actions

    def is_sensitive(self, label: str) -> bool:
        return label in self.sensitive_labels


def build(doc: dict[str, Any]) -> LabelApprovalPolicy:
    """The evaluable policy, computed from the document. No defaults anywhere."""
    row4 = doc["row4_context_policy"]
    order = tuple(row4["label_vocabulary"]["total_order"])
    egress_outcome = {
        entry["label"]: entry["outcome"]
        for entry in row4["outcomes"]
        if entry["action_class"] == "egress"
    }
    non_egress = [entry for entry in row4["outcomes"] if entry["action_class"] == "non_egress"]
    unlabelled = {entry["action_class"]: entry["outcome"] for entry in row4["unlabelled"]}
    row6 = doc["row6_sink_policy"]
    internal = next(entry for entry in row6["sink_classes"] if entry["sink"] == "internal-sink")
    domain = internal["internal_domain"]
    row10 = doc["row10_oracle_classification"]
    return LabelApprovalPolicy(
        order=order,
        egress_outcome=egress_outcome,
        non_egress_outcome=non_egress[0]["outcome"],
        unlabelled_egress=unlabelled["egress"],
        unlabelled_non_egress=unlabelled["non_egress"],
        internal_sink_domain=domain,
        allowed_pairs=frozenset((entry["label"], entry["sink"]) for entry in row6["allowed_pairs"]),
        high_risk_actions=frozenset(entry["action"] for entry in row10["high_risk_actions"]),
        sensitive_labels=frozenset(entry["label"] for entry in row10["sensitive_labels"]),
        document_digest=h_policy(doc),
    )


def egress_actions(
    omega_actions: "frozenset[str] | set[str]", recipient_carrying: "frozenset[str] | set[str]"
) -> frozenset[str]:
    """Row 4's egress set, **derived** from the caller's own plane.

    The document states the rule; the caller supplies which actions its plane
    observes carrying a recipient (the SUT boundary from the server policy's
    declared recipient argument, the oracle from `EffectEvent.recipient`).
    Every supplied action must be an `Omega` action, so a plane cannot smuggle
    in an egress action the ontology does not contain.
    """
    stray = set(recipient_carrying) - set(omega_actions)
    if stray:
        raise PolicyStructureError(f"recipient-carrying action(s) outside Omega: {sorted(stray)}")
    return frozenset(recipient_carrying)


def document(doc: dict[str, Any]) -> dict[str, Any]:
    """A defensive copy, so a caller cannot mutate the frozen document in place."""
    return copy.deepcopy(doc)
