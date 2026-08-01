"""How §E.4 groups arms — **per family**, because the families do not group alike.

Replaces the hardcoded `STRONG` tuple the F1 matrix used (EXP4 STEP 12). That
tuple was right for F1 and wrong as a general shape, and the difference is not
cosmetic:

**F1's grouping is a LADDER PROPERTY.** Whether an arm blocks scope amplification
follows from where it sits on §E.1's ladder — it either receives per-hop `C_i`
or it does not. Nothing about a run changes it.

**F4/F5's grouping is a CONFIGURATION CONDITION.** §E.4 marks the OAuth arms
`A†`, glossed *"admitted **absent** the shared monitor"*; with the shared
boundary-owned monitor attached they block instead. The same arm produces
different cells under different configurations, so a recorded F4/F5 cell that
does not say which configuration produced it **is not a result**. Reporting one
as though it were would present a reference-monitor-configuration difference as
a capability-versus-OAuth advantage — precisely the error gate **G-15** exists to
prevent.

So a cell is a `Cell`, and for F4/F5 the `monitor_attached` field is mandatory.
`MatrixError` on a cell recorded without it: the type system carries the rule
rather than a reviewer having to remember it.
"""

from collections.abc import Mapping
from dataclasses import dataclass

# §E.1's ladder, in its own order.
ARMS: tuple[str, ...] = (
    "B0",
    "B1",
    "B2-broad-noexchange",
    "B2-exchange-broad",
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
    "B-cap",
    "B3",
    "B3+",
)

# The arms whose ladder position gives them per-hop `C_i` (F1's grouping).
STRONG: tuple[str, ...] = (
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
    "B-cap",
    "B3",
    "B3+",
)

# The arms whose §E.5 bitmask selects the two policy conjuncts. Attaching a
# monitor to an arm outside this set changes nothing -- the arm never runs the
# conjuncts the monitor answers for. `B-cap` is the case that matters: it is a
# capability arm and it is NOT here, because `context = 0` and `approval = 0`
# are its ladder position (a bearer capability with no policy plane).
POLICY_PLANE: tuple[str, ...] = ("B3", "B3+")

# The arms whose DECISION PATH can reach an attached monitor without changing
# the arm's bitmask -- i.e. the arms whose F4/F5 cell actually flips with
# `monitor_attached`, and therefore the only arms entitled to wear `A-dagger`
# (ADR 0032).
#
# Three groups are excluded and for three different reasons, which is why this
# cannot be derived from the bitmask alone:
#
#   B0, B1     run no boundary check at all; there is nothing to attach to.
#   B-cap      shares `B3`'s decision path, in which the monitor's verdicts
#              arrive THROUGH `context_policy_ok` and `approval_artifact_ok` --
#              the very conjuncts its bitmask gates off. Setting them to 1 is
#              not a configuration change, it is `B3`.
#   B3, B3+    always run the conjuncts; their cell is B in both
#              configurations, so it never flips either.
#
# The four OAuth arms have no SS A.5 conjunct plane, so the monitor sits beside
# their decision path and `monitor_attached` is genuinely a property of the run.
MONITOR_REACHABLE: tuple[str, ...] = (
    "B2-broad-noexchange",
    "B2-exchange-broad",
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
)

# Which families group which way. Data, so a new family must choose.
LADDER_FAMILIES = frozenset({"F1", "F2", "F3"})
CONFIGURATION_FAMILIES = frozenset({"F4", "F5"})


class MatrixError(Exception):
    """A cell was recorded in a way that cannot be reported. Fail closed."""


@dataclass(frozen=True)
class Cell:
    """One measured cell: the outcome, and the conditions it was measured under.

    `monitor_attached` is `None` for a family whose grouping is a ladder
    property, and **required** for one whose grouping is a configuration
    condition. `validate` is what refuses; nothing here guesses a default.
    """

    family: str
    subcase: str
    arm: str
    admitted: bool
    reason_code: str
    monitor_attached: bool | None = None

    def __post_init__(self) -> None:
        if self.family not in LADDER_FAMILIES | CONFIGURATION_FAMILIES:
            raise MatrixError(
                f"family {self.family!r} declares no grouping; add it to LADDER_FAMILIES or "
                "CONFIGURATION_FAMILIES rather than letting it default"
            )
        if self.arm not in ARMS:
            raise MatrixError(f"{self.arm!r} is not an §E.1 arm")
        if self.family in CONFIGURATION_FAMILIES and self.monitor_attached is None:
            raise MatrixError(
                f"{self.family} cell ({self.subcase!r}, {self.arm!r}) was recorded without its "
                "monitor configuration. §E.4 marks these cells A-dagger -- 'admitted ABSENT the "
                "shared monitor' -- so the same arm produces different cells under different "
                "configurations and a cell without its configuration is not a result (G-15)"
            )
        if self.family in LADDER_FAMILIES and self.monitor_attached is not None:
            raise MatrixError(
                f"{self.family} cell ({self.subcase!r}, {self.arm!r}) carries a monitor "
                "configuration, but this family's grouping is a LADDER property. Recording one "
                "would suggest the cell could move with configuration, which it cannot"
            )

    @property
    def outcome(self) -> str:
        return "A" if self.admitted else "B"


def comparison_is_sound(cells: "Mapping[str, Cell] | list[Cell]") -> tuple[bool, str]:
    """May these cells be compared **across arms** in one claim?

    The G-15 predicate, stated once and used by both the matrix suite and the
    gate. A cross-arm claim over a configuration family is sound only if every
    cell in it was measured under the **same** `monitor_attached`. Mixing them
    is the exact failure the gate must catch: "B3 blocks and the OAuth arm does
    not" is a statement about monitors, not about mechanisms, when one arm had
    a monitor and the other did not.
    """
    rows = list(cells.values()) if isinstance(cells, Mapping) else list(cells)
    if not rows:
        return False, "an empty comparison supports nothing"
    families = {cell.family for cell in rows}
    if families - CONFIGURATION_FAMILIES:
        # A ladder family carries no configuration, so there is nothing to mix.
        if families & CONFIGURATION_FAMILIES:
            return False, (
                f"the comparison mixes ladder families {sorted(families - CONFIGURATION_FAMILIES)} "
                f"with configuration families {sorted(families & CONFIGURATION_FAMILIES)}; they "
                "are grouped by different things and cannot share one claim"
            )
        return True, ""
    configurations = {cell.monitor_attached for cell in rows}
    if len(configurations) != 1:
        by_config: dict[bool | None, list[str]] = {}
        for cell in rows:
            by_config.setdefault(cell.monitor_attached, []).append(cell.arm)
        detail = "; ".join(
            f"monitor_attached={key}: {sorted(arms)}"
            for key, arms in sorted(by_config.items(), key=lambda item: str(item[0]))
        )
        return False, (
            "a cross-arm F4/F5 claim mixes monitor configurations "
            f"({detail}). The difference it would report is a reference-monitor-configuration "
            "difference, not a capability-vs-OAuth advantage (§E.4 footnote; G-15)"
        )
    return True, ""


def label(cell: Cell, *, monitored: "Cell | None" = None) -> str:
    """The cell as it must appear in any report: never a bare `A` or `B`.

    A configuration-family cell always renders with its configuration, so the
    annotation cannot be flattened away by a copy-paste into a table.

    **The dagger is narrower than "admitted without a monitor", twice over**,
    and gate G-15 caught this renderer applying it too widely on both counts.
    `A†` means *admitted ABSENT the shared monitor -- **and blocks WITH it***, so:

    1. it belongs only to an arm whose decision can actually reach a monitor
       (ADR 0032): an `A` from `B-cap`, `B0` or `B1` is a plain `A`, because
       attaching a monitor to them moves nothing; and
    2. it belongs only to a cell that actually **flips**. Pass the companion
       `monitored` cell and the dagger is decided by the measured pair rather
       than by the arm alone -- which matters for the benign controls, where an
       OAuth arm is admitted under BOTH configurations because the artifact is
       valid, not because the monitor is absent. Daggering those would claim a
       monitor would block them, which is false.

    Without `monitored` the arm-level rule applies, which is correct for §E.4's
    own rows (all attacks) and deliberately conservative elsewhere.
    """
    if cell.family not in CONFIGURATION_FAMILIES:
        return cell.outcome
    if monitored is not None:
        flips = monitored.admitted is False
    else:
        flips = cell.arm in MONITOR_REACHABLE
    dagger = "†" if cell.admitted and not cell.monitor_attached and flips else ""
    return f"{cell.outcome}{dagger} (monitor_attached={str(cell.monitor_attached).lower()})"
