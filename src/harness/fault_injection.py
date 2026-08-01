"""Gate G-12's fault injectors: the instrument's own faults, applied to records.

Two families, injected at two different places, because the two things G-12
tests are different:

**SUT-side faults** live in the child (`src/sut/sut_process/__main__.py`) and
make the system under test *lie about itself*. They are the SUT's to commit.

**Record-side faults** live here and corrupt the LINKAGE the harness itself
maintains — the harness-minted `correlation_id` bound into the sealed intent,
the `MediationEvent`, the `ToolIngressEvent` and the INV `jti` (§F.1). The SUT
cannot forge that linkage, so simulating swap / drop / duplicate requires the
instrument to damage its own records deliberately.

**These are applied to COPIES, after a run, never to the live ledger.** The
ledger is append-only under an exclusive-share handle (G-7, ADR 0014), and a
fault injector that could write to it would be a hole in the property G-7
established. So the run happens honestly, the records are read back, and the
corruption is applied to the read-back copy that the oracle is then asked to
judge. The oracle cannot tell the difference — it sees records, not their
provenance — which is exactly why this is a valid injection.

**Nothing here weakens a check to make a gate pass** (EXP5 forbidden action 3).
Each function damages records in one named way and the gate asserts the oracle
notices. A fault the oracle cannot detect is a finding to report.
"""

from collections.abc import Iterable
from typing import Any


def _rows(ledger: Iterable[Any]) -> list[dict]:
    return [dict(row) for row in ledger]


def drop_effect_records(ledger: Iterable[Any], cid: str) -> list[dict]:
    """**DROP.** Delete the effect rows and leave everything else standing.

    The dangerous fault: the result is *zero effects*, which Part I reads as no
    realized harm. What distinguishes it from an unreached tool is that the
    ingress row survives — see `predicates.linkage_of`.
    """
    return [
        row
        for row in _rows(ledger)
        if not (row.get("effect_id") is not None and row.get("correlation_id") == cid)
    ]


def drop_all_records(ledger: Iterable[Any], cid: str) -> list[dict]:
    """DROP, harder: the ingress rows go too, so the ledger is silent.

    Detected against the `MediationEvent`, which lives in the harness process
    and is not in this file's reach: admitted-with-no-ingress is a break in the
    chain even when the ledger itself looks internally tidy.
    """
    return [row for row in _rows(ledger) if row.get("correlation_id") != cid]


def duplicate_effect_records(ledger: Iterable[Any], cid: str) -> list[dict]:
    """**DUPLICATE.** One invocation recorded twice: one intent, two effects."""
    out = _rows(ledger)
    for row in list(out):
        if row.get("effect_id") is not None and row.get("correlation_id") == cid:
            copy = dict(row)
            copy["effect_id"] = str(copy.get("effect_id", "")) + "-dup"
            out.append(copy)
    return out


def swap_correlation_ids(ledger: Iterable[Any], one: str, other: str) -> list[dict]:
    """**SWAP.** Two invocations' records crossed.

    Every row carrying `one` gets `other` and vice versa, so each effect is
    correlated to the wrong intent while the ledger stays well-formed.
    """
    out = []
    for row in _rows(ledger):
        cid = row.get("correlation_id")
        if cid == one:
            row["correlation_id"] = other
        elif cid == other:
            row["correlation_id"] = one
        out.append(row)
    return out


def drop_mediation_record(events: Iterable[Any], cid: str) -> list[Any]:
    """DROP applied to the trusted record rather than the ledger."""
    return [row for row in events if getattr(row, "correlation_id", None) != cid]


def inject_effect_for_a_blocked_call(ledger: Iterable[Any], template: Any, cid: str) -> list[dict]:
    """The world `log_integrity_failure` exists for: BLOCKED, yet an effect.

    **Why the effect row is injected rather than produced by a real bypass.**
    Gate G-6 established complete mediation for `mcp==1.28.1`: every SDK
    dispatch path converges on the wrapped tool function, and with the
    interposition in place a denied call reaches neither the recorder nor the
    tool. There is therefore no bypass path left to drive — which is the
    *result* of G-6, not a gap here. So the failure mode is reproduced at the
    record level: the records that a bypass WOULD leave behind, handed to the
    oracle, which must flag them.

    What this does and does not establish: it shows the predicate fires on the
    evidence a bypass leaves, and (with its negative arm) that it stays silent
    on an honest block. It does not re-establish complete mediation — that is
    G-6's, and this gate does not reopen it.
    """
    out = _rows(ledger)
    row = dict(template)
    row["correlation_id"] = cid
    row["effect_id"] = "injected-by-g12-bypass-world"
    out.append(row)
    return out
