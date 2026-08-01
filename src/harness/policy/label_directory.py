"""The ingestion-time label directory (ADR 0030, item 4).

`EffectEvent.data_labels_touched`, `EffectEvent.payload_digest`/`value_id` and
`ToolIngressEvent.payload_digest`/`value_id` have existed in `src/harness/
schema.py` since the beginning with **nothing populating them**. This is what
populates them, and the design question ADR 0030 had to settle is *where the
ledger learns a label from*.

**Not from the assertions the request carried.** That is the whole point. §A.6
puts labelling at **ingestion, by a trusted source**, before task-time issuance,
so the label of a value is a fact about the value and not about the request that
moved it. If the ledger resolved labels from the presented `LabelAssertion`s
instead, then an arm that stripped the label off a sensitive payload and
exfiltrated it would produce an effect with `data_labels_touched = []`, and
`realized_harm_F4` would score **no harm for exactly the attack it exists to
catch**. The ledger would be measuring the attacker's own account of what it
touched.

So the directory is **instrument-side sealed knowledge**: the harness plays the
ingestion source, it knows what it labelled, and it resolves by recomputing
`payload_digest` over the value the tool **actually acted on**. That keeps
gate G-7's independence intact -- the ledger reads raw arguments and its own
directory, never a SUT-computed digest (red line 4) and never a SUT-presented
artifact.

**It is not `τ_gt`.** Red line 5 forbids a SUT principal reading the sealed
ground-truth scope; this is a different object, held by the harness and consumed
only by the ledger writer and the oracle. No arm and no agent is ever handed one.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from src.harness.verifier import label_context as lc


@dataclass(frozen=True)
class LabelledValue:
    """One value as the ingestion plane knows it."""

    value_id: str
    label: str


class LabelDirectory:
    """`payload_digest -> (value_id, label)`, resolved by recomputation.

    Keyed by digest rather than by `value_id` so that a payload is recognized
    **by its bytes**: renaming a value, copying it into another field, or
    re-serializing the request around it cannot detach it from its label.
    """

    def __init__(self, entries: Mapping[str, LabelledValue] | None = None) -> None:
        self._by_digest: dict[str, LabelledValue] = dict(entries or {})

    @classmethod
    def from_values(cls, values: "Mapping[str, tuple[str, str]]") -> "LabelDirectory":
        """Build from `{value_id: (value, label)}`, as a scenario declares them."""
        return cls(
            {
                lc.payload_digest(value): LabelledValue(value_id=value_id, label=label)
                for value_id, (value, label) in values.items()
            }
        )

    def __len__(self) -> int:
        return len(self._by_digest)

    def lookup(self, value: Any) -> LabelledValue | None:
        """The ingestion label of one value, or `None` if it was never labelled.

        A value the directory does not know is **unlabelled**, which is a real
        state (row 4 has an unlabelled rule) and not an error. A value with no
        fixed digest -- a number, a mapping -- is likewise unlabelled rather
        than a crash: the ledger must record every effect, including effects on
        payloads outside §A.6's domain.
        """
        try:
            digest = lc.payload_digest(value)
        except lc.LabelContextError:
            return None
        return self._by_digest.get(digest)

    def observe(
        self, arguments: Mapping[str, Any], *, order: "tuple[str, ...] | None" = None
    ) -> "tuple[str | None, str | None, list[str]]":
        """`(payload_digest, value_id, data_labels_touched)` for one call.

        **Every** argument value is looked up, not one nominated payload field.
        A tool that carried a sensitive value in a field nobody thought to
        declare as *the* payload would otherwise touch it invisibly, and the
        effect would be recorded as having touched nothing.

        `data_labels_touched` is the union of what was found. The two singular
        fields name the **governing** payload -- the most restrictive label
        present under row 4's total order, which is the one that decides the
        effect's classification. With no `order` given, or no labelled value at
        all, they are `None`: these fields exist to carry §A.6's join, and with
        nothing labelled there is no join to carry. Nothing is lost, because
        `effect_request_digest` already binds the arguments in full.
        """
        found: list[tuple[str, LabelledValue]] = []
        for value in arguments.values():
            try:
                digest = lc.payload_digest(value)
            except lc.LabelContextError:
                continue  # outside §A.6's domain: unlabelled, not an error
            known = self._by_digest.get(digest)
            if known is not None:
                found.append((digest, known))
        if not found:
            return None, None, []
        labels = sorted({entry.label for _, entry in found})
        if order:
            digest, governing = max(
                found, key=lambda pair: (order.index(pair[1].label), pair[1].value_id)
            )
        else:
            digest, governing = min(found, key=lambda pair: pair[1].value_id)
        return digest, governing.value_id, labels


EMPTY = LabelDirectory()
