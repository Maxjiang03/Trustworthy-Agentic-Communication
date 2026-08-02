"""The security side of the pre-registered analysis — **exact counts, no CI** (STEP 9).

§E.5, in the words this module must not paraphrase away:

> **Security and blocking outcomes** are reported as **exact counts and rates
> only** … **No confidence interval** is placed on any security/blocking
> proportion (a fixed author-constructed suite has no random-sampling
> population; verdicts are deterministic). Repetition of a security verdict is
> used **only** to detect nondeterminism.

So this module computes counts, rates, and a **nondeterminism check** — and
**there is no interval estimator in it at all.** That is deliberate and is
asserted by test: the absence is the enforcement. A confidence interval on
`blocked/total` would invite a reader to treat this suite as a sample from a
population of attacks, which it is not; it is a fixed set the author
constructed, and the honest statement of uncertainty about it is *"these are
the instances, here is what happened to each"*.

**What repetition is for.** Running a sealed scenario twice must give the same
verdict. If it does not, the apparatus is nondeterministic and the difference
is a **defect**, not variance to be averaged: Part H's *"what once means"* rule
says each sealed scenario is evaluated once for its verdict, and a second
evaluation exists to check that the first was reproducible. `nondeterminism`
below reports every disagreement rather than summarising them, because one
disagreeing cell invalidates the run it is in.

Granularity, per §E.5: **class-macro** (per family) and **instance-micro** (per
instance) are both reported, with template-derived variants clustered.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class AnalysisError(Exception):
    """The analysis refused. Never returns a number it cannot justify."""


@dataclass(frozen=True)
class Verdict:
    """One scored cell, as the oracle produced it.

    `quantities` holds the Part I values **separately** — the analysis never
    receives a collapsed "did it go wrong" flag, because the two it would
    collapse (a decision property and an effect property) answer different
    questions.
    """

    scenario_id: str
    arm: str
    family: str
    template: str  # the clustering key for template-derived variants
    quantities: Mapping[str, bool | None]

    def key(self) -> tuple[str, str]:
        return (self.scenario_id, self.arm)


@dataclass(frozen=True)
class Disagreement:
    """One cell that produced different values across repetitions."""

    scenario_id: str
    arm: str
    quantity: str
    values: tuple[Any, ...]

    def __str__(self) -> str:  # pragma: no cover - display only
        return (
            f"{self.scenario_id}/{self.arm}: {self.quantity} took values {list(self.values)} "
            "across repetitions"
        )


def nondeterminism(repetitions: Sequence[Iterable[Verdict]]) -> list[Disagreement]:
    """Every cell whose verdict was not reproduced across repetitions.

    **This is not a significance test and produces no p-value or interval.** A
    disagreement is a defect in the apparatus: the same sealed scenario, the
    same sealed configuration and the same arm must yield the same verdict, and
    where they do not, the run is invalid rather than uncertain.

    A cell present in one repetition and absent from another is also a
    disagreement — a silently-dropped cell would otherwise read as agreement
    among the repetitions that did produce it.
    """
    if len(repetitions) < 2:
        raise AnalysisError(
            "nondeterminism needs at least two repetitions; one repetition cannot disagree "
            "with itself and reporting 'no disagreement' from it would be vacuous"
        )
    seen: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for repetition in repetitions:
        for verdict in repetition:
            seen[verdict.key()].append(dict(verdict.quantities))

    disagreements: list[Disagreement] = []
    for (scenario_id, arm), observations in sorted(seen.items()):
        if len(observations) != len(repetitions):
            disagreements.append(
                Disagreement(
                    scenario_id,
                    arm,
                    "cell-present",
                    tuple([True] * len(observations) + [False]),
                )
            )
            continue
        for quantity in sorted({name for row in observations for name in row}):
            values = tuple(row.get(quantity) for row in observations)
            if len(set(values)) > 1:
                disagreements.append(Disagreement(scenario_id, arm, quantity, values))
    return disagreements


@dataclass(frozen=True)
class Counts:
    """Exact counts and the rate derived from them. **No interval.**

    `rate` is `count / total` and nothing more — a descriptive proportion of a
    fixed set, not an estimate of a population parameter.
    """

    count: int
    total: int

    @property
    def rate(self) -> float:
        if self.total == 0:
            raise AnalysisError("a rate over zero cells is undefined, not 0.0")
        return self.count / self.total

    def as_dict(self) -> dict[str, Any]:
        return {"count": self.count, "total": self.total, "rate": self.rate}


def class_macro(verdicts: Iterable[Verdict], quantity: str) -> dict[str, Counts]:
    """Per-family counts (§E.5's class-macro granularity)."""
    buckets: dict[str, list[Verdict]] = defaultdict(list)
    for verdict in verdicts:
        buckets[verdict.family].append(verdict)
    return {
        family: Counts(
            count=sum(1 for v in rows if v.quantities.get(quantity) is True),
            total=sum(1 for v in rows if v.quantities.get(quantity) is not None),
        )
        for family, rows in sorted(buckets.items())
    }


def instance_micro(verdicts: Iterable[Verdict], quantity: str) -> Counts:
    """Per-instance counts over every scored cell (§E.5's instance-micro).

    Cells the oracle could not score are **excluded from the denominator**, not
    counted as negatives: `None` means *not scored*, and folding it into the
    `False` bucket would report an unscorable cell as a clean result.
    """
    rows = list(verdicts)
    return Counts(
        count=sum(1 for v in rows if v.quantities.get(quantity) is True),
        total=sum(1 for v in rows if v.quantities.get(quantity) is not None),
    )


def clustered_by_template(verdicts: Iterable[Verdict], quantity: str) -> dict[str, Counts]:
    """§E.5: *template-derived variants clustered*.

    Variants generated from one template are not independent instances, so they
    are reported as their template's cluster rather than inflating a count.
    """
    buckets: dict[str, list[Verdict]] = defaultdict(list)
    for verdict in verdicts:
        buckets[verdict.template].append(verdict)
    return {
        template: Counts(
            count=sum(1 for v in rows if v.quantities.get(quantity) is True),
            total=sum(1 for v in rows if v.quantities.get(quantity) is not None),
        )
        for template, rows in sorted(buckets.items())
    }


__all__ = [
    "AnalysisError",
    "Counts",
    "Disagreement",
    "Verdict",
    "class_macro",
    "clustered_by_template",
    "instance_micro",
    "nondeterminism",
]
