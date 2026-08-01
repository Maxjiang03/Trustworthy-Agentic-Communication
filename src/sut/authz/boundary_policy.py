"""The frozen rows 4/6/10 policy, as any boundary consumes it (ADR 0022/0023).

**Deliberately in its own module, and the reason is structural.** This loader
started life inside `capability_path.py`, which was fine while only `B3` read
it. ADR 0030's reference monitor is shared by an OAuth arm and a capability arm
alike, and an OAuth arm reaching into `capability_path` to load a policy would
import the capability plane to answer a question that has nothing to do with
capabilities -- and `tests/test_b2_exchange_task.py` rightly fails a B2 arm that
does. The policy belongs to **neither** plane, so it lives in neither.

`capability_path` re-exports it, so nothing that already imported it there
breaks; the canonical home is here.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

PERMIT, ESCALATE, BLOCK = "permit", "escalate", "block"


class PolicyConfigurationError(Exception):
    """The injected label/approval policy is missing or not the frozen shape."""


@dataclass(frozen=True)
class BoundaryPolicy:
    """Rows 4/6/10 as the boundary consumes them (ADR 0022).

    Built from the **frozen document itself**, injected as sealed
    configuration by the runner -- the SUT never imports the harness loader
    (red line 6), it evaluates the same bytes independently, exactly the line
    ADR 0016 drew for `Omega`/`Gamma`. There is one policy source: the
    PILOT-PROVISIONAL stand-in is gone.

    This supplies the POLICY both conjuncts evaluate. Whether an artifact may
    be believed is a separate question, answered by the ADR 0030 monitor over
    the same document; rows 4/6 are then re-evaluated over the labels that
    verified, so a declassification is an acceptance path and never a bypass.
    """

    order: tuple[str, ...]
    egress_outcome: dict[str, str]
    non_egress_outcome: str
    unlabelled_egress: str
    unlabelled_non_egress: str
    internal_sink_domain: str
    allowed_pairs: frozenset[tuple[str, str]]
    high_risk_actions: frozenset[str]
    sensitive_labels: frozenset[str]

    @classmethod
    def load(cls, document: Mapping[str, Any] | None) -> "BoundaryPolicy":
        """Build from the frozen document. A missing document fails closed."""
        if document is None:
            raise PolicyConfigurationError(
                "no label/approval policy was injected; defaulting is forbidden (ADR 0022)"
            )
        try:
            row4 = document["row4_context_policy"]
            order = tuple(row4["label_vocabulary"]["total_order"])
            egress = {
                entry["label"]: entry["outcome"]
                for entry in row4["outcomes"]
                if entry["action_class"] == "egress"
            }
            non_egress = next(
                entry["outcome"]
                for entry in row4["outcomes"]
                if entry["action_class"] == "non_egress"
            )
            unlabelled = {entry["action_class"]: entry["outcome"] for entry in row4["unlabelled"]}
            row6 = document["row6_sink_policy"]
            internal = next(
                entry for entry in row6["sink_classes"] if entry["sink"] == "internal-sink"
            )
            row10 = document["row10_oracle_classification"]
            return cls(
                order=order,
                egress_outcome=egress,
                non_egress_outcome=non_egress,
                unlabelled_egress=unlabelled["egress"],
                unlabelled_non_egress=unlabelled["non_egress"],
                internal_sink_domain=internal["internal_domain"],
                allowed_pairs=frozenset(
                    (entry["label"], entry["sink"]) for entry in row6["allowed_pairs"]
                ),
                high_risk_actions=frozenset(
                    entry["action"] for entry in row10["high_risk_actions"]
                ),
                sensitive_labels=frozenset(entry["label"] for entry in row10["sensitive_labels"]),
            )
        except (KeyError, StopIteration, TypeError) as exc:
            raise PolicyConfigurationError(
                f"the injected policy document is not the frozen shape: {exc!r}"
            ) from exc

    def sink_class(self, recipient: str) -> str:
        domain = recipient.rpartition("@")[2]
        return "internal-sink" if domain == self.internal_sink_domain else "external-sink"

    def join(self, labels) -> "str | None":
        """The least upper bound of several labels in row 4's **total order**.

        One request may carry several labelled payloads, and one egress carries
        all of them, so the label that governs is the **most restrictive**
        present -- `join(public, sensitive) = sensitive`. Taking the least would
        let a sensitive payload ride out under a public one's label, which is
        `F4-label-confusion` performed by the boundary itself. ADR 0022 froze
        the vocabulary as a *total order* precisely so this join always exists.
        """
        ranked = [label for label in labels if label is not None]
        if not ranked:
            return None
        for label in ranked:
            if label not in self.order:
                raise PolicyConfigurationError(f"label {label!r} is outside the frozen vocabulary")
        return max(ranked, key=self.order.index)

    def egress_decision(self, label: str | None, recipient: str | None) -> str:
        """The row 4 + row 6 verdict for one egress (ADR 0023).

        **Row 6 is the permit whitelist; row 4 supplies the severity.** One
        verdict per cell, never two combined -- the rows answer different
        questions, so composing them as two verdicts over one cell was the
        category error ADR 0023 corrects.
        """
        if label is None:
            return self.unlabelled_egress  # fail closed
        if label not in self.order:
            raise PolicyConfigurationError(f"label {label!r} is outside the frozen vocabulary")
        if recipient is None:
            return BLOCK  # declared egress with no classifiable recipient
        if (label, self.sink_class(recipient)) in self.allowed_pairs:
            return PERMIT
        return self.egress_outcome[label]  # row 4 as the severity of the refusal
