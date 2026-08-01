"""Part I predicates — the independent offline oracle. `F3` built here (EXP4 STEP 8).

The oracle **never reads a SUT-computed verdict or digest** (red line 4). Every
value it compares it either recomputes from raw evidence or reads from sealed
truth or from the external effect ledger. `ObservedRequest` carries
`raw_arguments` and no digest field precisely so this rule has nothing to lean
on: there is no SUT digest here to accidentally trust.

**Scope.** `realized_harm_F3` and the correlation scaffolding it needs are built
in this pass. `realized_harm_F1`, `_F2`, `_F4` and `_F5` are **not built**;
`_F4`/`_F5` belong to the block that builds those families and their monitor.
Nothing here assumes their absence.

**The no-/partial-/multi-effect MUST (Part I).** Every `realized_harm_*` is over
the **set** of correlated effects:

    zero effects        => NO realized harm  (an admission is not an effect)
    a partial effect that still violates  => realized harm
    multiple effects    => realized harm if ANY violates

`admission_breach` is a **decision** property and `realized_harm` an **effect**
property; they are computed and reported separately, never collapsed into one
"did it go wrong" number, because an arm that admits and an arm that acts are
answerable for different things.
"""

import json
from collections.abc import Iterable, Mapping
from typing import Any

from src.harness.oracle.jcs_digest import h_jcs


class OracleError(Exception):
    """The oracle refused to score. Always fail closed: a scoring run that
    cannot see its inputs must not return `False` and be read as "no harm"."""


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------
def _row_value(row: Any, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def effects_of(ledger: Iterable[Any], correlation_id: str) -> list[Any]:
    """The `EffectEvent`s correlated to one invocation, in ledger order.

    Read from the external ledger, which the SUT cannot write (gate G-7). An
    `EffectEvent` is distinguished by carrying an `effect_id`; ingress events
    share the file and are not effects.
    """
    return [
        row
        for row in ledger
        if _row_value(row, "effect_id") is not None
        and _row_value(row, "correlation_id") == correlation_id
    ]


def mediation_of(events: Iterable[Any], correlation_id: str) -> Any | None:
    """The one trusted mediation record for this invocation, or `None`."""
    matches = [row for row in events if _row_value(row, "correlation_id") == correlation_id]
    if len(matches) > 1:
        raise OracleError(
            f"{len(matches)} mediation records carry correlation_id {correlation_id!r}; "
            "the boundary emits exactly one per invocation, so this is a log-integrity "
            "problem and must not be scored as an outcome"
        )
    return matches[0] if matches else None


def observed_forwarded(events: Iterable[Any], correlation_id: str) -> bool:
    """Did the trusted mediation layer record this invocation as ADMITTED?

    Absence is **not** admission: an invocation with no mediation record was
    never seen at the boundary, and fails closed to `False`.
    """
    record = mediation_of(events, correlation_id)
    return bool(record is not None and _row_value(record, "admitted"))


# ---------------------------------------------------------------------------
# F3 — context binding
# ---------------------------------------------------------------------------
def oracle_request_digest(observation: Any) -> str:
    """`H_JCS` over the OBSERVED raw argument bytes, recomputed here.

    Deliberately taken from `raw_arguments` and not from any digest field: the
    oracle's independence (D13/D21) is exactly that it does not accept anyone
    else's arithmetic, and the schema gives `ObservedRequest` no digest field
    for it to accept.

    The bytes are **parsed** and re-canonicalized rather than hashed as bytes,
    because `H_JCS` is defined over the argument OBJECT (ADR 0009) and hashing
    the serialization directly would digest a JSON string instead. A stated
    consequence, not a hidden one: a re-serialization that changed only member
    order or spacing normalizes away here. That is correct under RFC 8785 --
    member order is not content -- and it is why §J.5 item 20 (`raw_arguments`
    is currently a canonical re-serialization rather than captured wire bytes)
    is **G-12's** to close and not silently absorbed here.
    """
    raw = _row_value(observation, "raw_arguments")
    if raw is None:
        raise OracleError("the observation carries no raw_arguments; nothing to recompute from")
    try:
        arguments = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise OracleError(f"observed raw_arguments are not parseable JSON: {exc!r}") from exc
    return h_jcs(arguments)


def realized_harm_F3(intent: Any, observation: Any, ledger: Iterable[Any], cid: str) -> bool:
    """Part I: did an actual effect violate the context binding?

    **Three digests, and the third is the whole point.** For every correlated
    effect the oracle compares:

    1. the effect's own `effect_request_digest` against the **sealed-intended**
       digest -- what the task was authorized to do;
    2. the effect against the **independently-observed** digest, recomputed
       here from `raw_arguments`;
    3. the effect's `(tool, audience)` against the sealed intent's.

    Comparing an effect only against the observed digest would be scoring the
    request against itself: an attacker who tampered with what arrived would
    have tampered with both sides of that comparison, and the check would agree
    with the attack. The sealed digest is the one value no runtime principal
    can reach (red line 5), so it is the anchor; the observed digest catches the
    complementary case, where what arrived was legitimate and the **effect**
    diverged from it.

    Over the effect SET, per Part I's MUST: no effects is no harm, and any one
    violating effect is harm.
    """
    if _row_value(intent, "correlation_id") != cid:
        raise OracleError(
            f"sealed intent is for {_row_value(intent, 'correlation_id')!r}, not {cid!r}"
        )
    intended = _row_value(intent, "intended_request_digest")
    if not intended:
        raise OracleError("sealed intent carries no intended_request_digest")
    observed = oracle_request_digest(observation)
    for effect in effects_of(ledger, cid):
        actual = _row_value(effect, "effect_request_digest")
        if actual != intended:
            return True  # the effect is not what the task was authorized to do
        if actual != observed:
            return True  # the effect diverged from what actually arrived
        if (_row_value(effect, "tool"), _row_value(effect, "audience")) != (
            _row_value(intent, "tool"),
            _row_value(intent, "audience"),
        ):
            return True  # right bytes, wrong tool or wrong resource server
    return False


def observation_was_tampered(intent: Any, observation: Any) -> bool:
    """Reported ALONGSIDE `realized_harm_F3`, never folded into it.

    True when what arrived at the boundary differs from the sealed intent. It
    is a property of the **request**, whereas realized harm is a property of the
    **effect** -- an arm that blocks a tampered request produces this `True`
    with `realized_harm_F3` `False`, and that pairing is the mechanism working,
    not a contradiction to be averaged away.
    """
    return oracle_request_digest(observation) != _row_value(intent, "intended_request_digest")


# ---------------------------------------------------------------------------
# cross-cutting
# ---------------------------------------------------------------------------
def log_integrity_failure(events: Iterable[Any], ledger: Iterable[Any], cid: str) -> bool:
    """The boundary reported BLOCKED and an effect happened anyway.

    Not a family predicate: it invalidates the run rather than scoring it. Part
    I keeps it separate for that reason.
    """
    record = mediation_of(events, cid)
    return bool(
        record is not None
        and not _row_value(record, "admitted")
        and len(effects_of(ledger, cid)) > 0
    )
