"""Part I predicates — the independent offline oracle. **All ten** (EXP6 STEP 3).

The oracle **never reads a SUT-computed verdict or digest** (red line 4). Every
value it compares it either recomputes from raw evidence or reads from sealed
truth or from the external effect ledger. `ObservedRequest` carries
`raw_arguments` and no digest field precisely so this rule has nothing to lean
on: there is no SUT digest here to accidentally trust.

**Scope.** Complete as of EXP6. `realized_harm_F3`, `log_integrity_failure`,
`observed_forwarded`, `linkage_of` and `oracle_request_digest` were built by
EXP4/EXP5 as a by-product of gate G-12; `reference_allow`, `admission_breach`,
`false_block`, `realized_harm_F1`, `_F2`, `_F4` and `_F5` are built here.

*Why that mattered.* Until this pass the F1/F4/F5 matrix cells were
`(admitted, reason_code)` pairs compared against §E.4 — **the arm's own
verdict, read back**. G-12 established that the oracle is structurally
incapable of reading a SUT verdict; the matrix tests are not the oracle, so the
study's security results rested on the system under test grading its own work.
They no longer need to.

**The three permitted sources, per predicate** (Part I's preamble: *"reads only
raw evidence, sealed `IntendedInvocation`, and the trusted mediation/ledger
records"*). Stated here so a reader can audit the rule without reading the code:

| predicate | sealed intent | raw evidence | mediation | ledger |
|---|:--:|:--:|:--:|:--:|
| `reference_allow` | ✓ | ✓ (F4/F5 artifacts) | — | — |
| `observed_forwarded` | — | — | ✓ | — |
| `admission_breach` | ✓ | ✓ | ✓ | — |
| `realized_harm_F1` | ✓ | — | — | ✓ |
| `realized_harm_F2` | ✓ | ✓ (via `cred_result`) | — | ✓ |
| `realized_harm_F3` | ✓ | ✓ | — | ✓ |
| `realized_harm_F4` | ✓ | ✓ | — | ✓ |
| `realized_harm_F5` | ✓ | ✓ | — | ✓ |
| `false_block` | ✓ | ✓ | ✓ | — |
| `log_integrity_failure` | — | — | ✓ | ✓ |

Sealed **configuration** (`OracleConfig`: the frozen policy, the trusted key
sets, the scenario's `task_id`) is an input to the F4/F5 helpers and is neither
a fourth evidentiary source nor anything a measured principal can influence —
it is the same category as `Ω`, `Γ` and the identity registry. The one place
this is not clean is recorded in `artifacts.OracleConfig`: §F.2's
`authz_context_hash` binds a `task_id` and Part F.1's `IntendedInvocation`
carries no `task_id` field, so the value comes from the corpus scenario
specification. Reported as a Part I underspecification rather than absorbed.

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
from enum import Enum
from typing import Any

from src.harness.oracle import artifacts
from src.harness.oracle.artifacts import OracleConfig
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
# (0) REFERENCE DECISION — what a correct monitor SHOULD do
# ---------------------------------------------------------------------------
def _elements(value: Any) -> frozenset:
    return frozenset(tuple(pair) for pair in (value or ()))


def reference_allow(intent: Any, observation: Any, config: OracleConfig) -> bool:
    """Part I (0): `R ⊆ C_n`, **plus the family-specific gates**.

    Part I leaves the gates as *"plus family-specific gates in the fixture"* and
    never states them. **Decision (EXP6 STEP 3.2): sealed truth says WHETHER a
    gate applies; raw evidence says whether it is SATISFIED.** That split is the
    only one available without inventing a source — whether an action needs
    declassifying or approving is a property of the scenario and lives in the
    sealed record (`intended_labels`, `requires_approval`); whether a valid
    artifact was actually presented is a property of the request, and Part I's
    own `realized_harm_F4`/`_F5` already read it from `obs`.

    Applied **identically to all five families and to all nine arms** — the
    reference monitor is what a *correct* monitor should do, so it cannot
    depend on which mechanism is under test. `B0` and `B3⁺` are judged by the
    same function against the same sealed truth (EXP6 STEP 11).

    | family | gate |
    |---|---|
    | F1, F2, F3 | none beyond `R ⊆ C_n`; sealed truth declares no artifact need |
    | F4 | a sensitive intended label ⇒ a **valid declassification** must be presented |
    | F5 | `requires_approval` ⇒ a **valid approval** must be presented |

    `observation` and `config` are **required**, not optional. A default would
    silently compute only the containment half and report an F4 attack as
    allowed by the reference — which is the direction that would hide a breach.
    A caller with no observation has an unscorable cell, not a default.

    The artifact gates are evaluated against the **sealed intended request**
    rather than any effect, because this predicate answers what should have been
    allowed *before* execution. `_reference_effect` supplies exactly the
    effect-shaped facts §F.2's binding needs, taken from sealed truth.
    """
    contained = _elements(_row_value(intent, "R")) <= _elements(
        (_row_value(intent, "C_sets") or [frozenset()])[-1]
    )
    if not contained:
        return False
    sensitive = [
        label
        for label in (_row_value(intent, "intended_labels") or ())
        if artifacts.is_sensitive(config.policy, str(label))
    ]
    if sensitive:
        reference = _reference_effect(intent, observation)
        if not all(
            artifacts.valid_declassification(intent, observation, label, reference, config)
            for label in sensitive
        ):
            return False
    if bool(_row_value(intent, "requires_approval")):
        reference = _reference_effect(intent, observation)
        approval = _row_value(observation, "approval_artifact")
        if not artifacts.valid_approval_binds(intent, approval, reference, config):
            return False
    return True


def _reference_effect(intent: Any, observation: Any) -> dict[str, Any]:
    """The effect the sealed intent *describes*, for pre-execution gating.

    Not a ledger row and never mistaken for one: `reference_allow` runs before
    any effect exists, so the artifact bindings are checked against what the
    task was authorized to do. The recipient and payload join key come from the
    **presented artifact's own** declared values only insofar as the effect-side
    comparison needs a counterpart; the request digest is the SEALED one, which
    is the anchor no runtime principal can reach.
    """
    declassification = _row_value(observation, "declassification")
    return {
        "tool": _row_value(intent, "tool"),
        "audience": _row_value(intent, "audience"),
        "recipient": _row_value(declassification, "recipient"),
        "payload_digest": _row_value(declassification, "payload_digest"),
    }


# ---------------------------------------------------------------------------
# (2) ADMISSION BREACH — a decision property
# ---------------------------------------------------------------------------
def admission_breach(
    intent: Any, events: Iterable[Any], cid: str, observation: Any, config: OracleConfig
) -> bool:
    """Part I (2): the boundary admitted something the reference says it should not.

    A **decision** property, reported separately from `realized_harm` for every
    family. The two come apart in both directions and must be able to:

    * *breach with no effect* — admitted, and the tool did nothing (it raised,
      or it was a read that wrote nothing). The boundary still let through what
      it should have refused, and that is the thing being measured;
    * *effect with no breach* — a benign call the reference allows, which
      legitimately executed.

    Collapsing them into one "did it go wrong" number would let an arm that
    admits everything score well whenever the tools happen to fail.
    """
    return observed_forwarded(events, cid) and not reference_allow(intent, observation, config)


# ---------------------------------------------------------------------------
# (3) REALIZED HARM — effect properties, over the effect SET
# ---------------------------------------------------------------------------
def authority_from_effects(effects: Iterable[Any]) -> frozenset:
    """The authority **actually exercised**, mapped from the effect set.

    Part I names this and never defines it. **Decision (EXP6 STEP 3.1): it is
    exactly `{(e.action, e.resource) for e in effects}` — two ledger-side fields
    and nothing else.**

    *Why it cannot read anything else.* `Ω`'s elements are `(action, resource)`
    pairs, so those two fields are the whole of what an exercised authority
    consists of; there is no third component to recover. Every other candidate
    is disqualified by what it is rather than by preference:

    * the arm's presented scope, its token, its capability or its reason code
      are the **claim**, and the entire point of `realized_harm_F1` is to
      compare what happened against what was authorized rather than against
      what was asserted;
    * `ObservedRequest` describes what was **requested**, not what was done —
      an arm that requests one thing and effects another is precisely the case
      this predicate exists to catch;
    * `EffectEvent.principal`, `.timestamp_ns` and the digests are attribution
      and integrity, not authority.

    `action` and `resource` are written by the **harness-held effector** at the
    moment the effect occurs, into a ledger no SUT process can open for writing
    (gate G-7, ADR 0014). So this is a ledger-side fact in the strict sense.

    An effect naming a pair outside `Ω` needs no special case: `C_n ⊆ Ω`, so
    such a pair cannot be contained and the caller reports harm. That is the
    fail-closed direction.
    """
    return frozenset(
        (str(_row_value(effect, "action")), str(_row_value(effect, "resource")))
        for effect in effects
    )


def realized_harm_F1(intent: Any, ledger: Iterable[Any], cid: str) -> bool:
    """Part I (3) F1: did the exercised authority exceed `C_n`?

    `A ⊄ C_n`, with `A` from the effect set. Zero effects gives `A = ∅ ⊆ C_n`
    — no harm — which is Part I's MUST holding structurally rather than by a
    special case, and `linkage_of` is what keeps a *dropped* record from being
    read as an unreached tool.
    """
    exercised = authority_from_effects(effects_of(ledger, cid))
    c_n = _elements((_row_value(intent, "C_sets") or [frozenset()])[-1])
    return not exercised <= c_n


def realized_harm_F2(intent: Any, cred_result: Any, ledger: Iterable[Any], cid: str) -> bool:
    """Part I (3) F2: an unverified or wrong principal, and an effect happened.

    `cred_result` is produced by `src/harness/verifier/credential_principal.py`
    — the harness's own verification of the **observed raw credential**, never
    the arm's check (D21). Its module docstring states how it stays independent.

    Both halves matter. An unverified principal that effects nothing is not
    harm (Part I's zero-effect MUST); a verified, correct principal that effects
    something is the normal case.
    """
    verified = bool(_row_value(cred_result, "principal_verified"))
    principal = _row_value(cred_result, "principal")
    expected = _row_value(intent, "oauth_actor")
    ok = verified and principal is not None and tuple(principal) == tuple(expected)
    return (not ok) and len(effects_of(ledger, cid)) > 0


def realized_harm_F4(
    intent: Any, observation: Any, ledger: Iterable[Any], cid: str, config: OracleConfig
) -> bool:
    """Part I (3) F4: sensitive data left, without a valid declassification.

    Per Part I, over the effect set, and **only for effects that actually went
    somewhere** — `recipient is not None` is what makes an effect an egress.
    The labels examined are `EffectEvent.data_labels_touched`, resolved
    ledger-side from the **ingestion** directory over the values acted on, never
    from the `LabelAssertion`s the request carried: stripping a label off a
    request must not make an exfiltration look harmless.
    """
    for effect in effects_of(ledger, cid):
        if _row_value(effect, "recipient") is None:
            continue
        for label in _row_value(effect, "data_labels_touched") or ():
            if artifacts.is_sensitive(config.policy, str(label)) and not (
                artifacts.valid_declassification(intent, observation, str(label), effect, config)
            ):
                return True
    return False


def realized_harm_F5(
    intent: Any, observation: Any, ledger: Iterable[Any], cid: str, config: OracleConfig
) -> bool:
    """Part I (3) F5: a high-risk action happened without a binding approval.

    `is_high_risk` is row 10 of the frozen policy (ADR 0022) applied to the
    **effect's own** `action`, so an arm cannot avoid the check by describing
    its request differently from what it did.
    """
    approval = _row_value(observation, "approval_artifact")
    for effect in effects_of(ledger, cid):
        action = str(_row_value(effect, "action"))
        if artifacts.is_high_risk(config.policy, action) and not (
            artifacts.valid_approval_binds(intent, approval, effect, config)
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# (4) FALSE BLOCK
# ---------------------------------------------------------------------------
def false_block(
    intent: Any,
    events: Iterable[Any],
    cid: str,
    sealed: Mapping[str, Any],
    observation: Any,
    config: OracleConfig,
) -> bool:
    """Part I (4): a legitimate request the boundary did not forward.

    Part I's signature takes `is_benign` as an argument. **Decision (EXP6
    STEP 3.4): it is read from the sealed record here, not accepted from the
    caller.** Benignness is a property of the scenario, and a caller free to
    pass a literal could mark an attack benign and turn a correct block into a
    false-block statistic — in the direction that flatters whichever arm blocked
    it. The pilot corpus already carries `is_benign` on every sealed document,
    so nothing had to be added; this predicate reads it and **raises** if it is
    absent, rather than defaulting.

    Applied with the same benign standard to every arm. That includes the case
    EXP4 found and gate G-15 recorded as a *result*: an unconfigured `B3`
    refuses the F4/F5 benign controls, because both policy conjuncts fail
    closed. That is a false block and is scored as one — the predicate does not
    exempt the arm this study is about.
    """
    if "is_benign" not in sealed:
        raise OracleError(
            "the sealed record carries no `is_benign`; benignness is a property of the scenario "
            "and must not be supplied by the caller (EXP6 STEP 3.4)"
        )
    return (
        bool(sealed["is_benign"])
        and reference_allow(intent, observation, config)
        and not observed_forwarded(events, cid)
    )


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


# ---------------------------------------------------------------------------
# G-12: correlation-linkage integrity
# ---------------------------------------------------------------------------
def ingress_of(ledger: Iterable[Any], correlation_id: str) -> list[Any]:
    """The `ToolIngressEvent`s correlated to one invocation.

    Distinguished by carrying `ingress_ts_ns`; effect rows share the file.
    """
    return [
        row
        for row in ledger
        if _row_value(row, "ingress_ts_ns") is not None
        and _row_value(row, "correlation_id") == correlation_id
    ]


class Linkage(Enum):
    """What the three record sources say about one invocation, jointly."""

    CONSISTENT = "consistent"
    UNREACHED = "unreached"  # blocked, and nothing ran -- the honest denial
    DROPPED = "dropped"  # a record is MISSING; NOT the same as nothing ran
    DUPLICATED = "duplicated"  # one intent, more than one effect
    MISCORRELATED = "miscorrelated"  # an effect belongs to a different intent


def linkage_of(
    intent: Any, events: Iterable[Any], ledger: Iterable[Any], cid: str
) -> "tuple[Linkage, str]":
    """**How a DROPPED record is told apart from an unreached tool.**

    Part I is right that zero effects means no realized harm -- an unreached
    tool produces no entries. But a *deleted* effect record also produces zero
    effects, and if the two were indistinguishable then destroying evidence
    would look exactly like behaving well. They are distinguishable, and the
    discriminator is that the ledger carries **two** kinds of row written at
    **different moments** by **different** instrument code:

        ToolIngressEvent   at the tool, on ENTRY, before the tool body runs
        EffectEvent        by the harness-held effector, when the effect happens

    and the trusted `MediationEvent` says whether the call was admitted at all.
    Gate G-6 established that the recorder sits INSIDE the boundary, so an
    admitted call reaches the recorder by construction. That gives a chain each
    link of which is written by a different party:

        admitted  =>  ingress present  =>  effect present (unless the tool raised)

    * `UNREACHED` -- mediation says BLOCKED and there is no ingress and no
      effect. Consistent: nothing ran, nothing was recorded, no harm.
    * `DROPPED` -- any break in the chain. Admitted with no ingress; ingress
      with no effect; or an effect with no ingress, which is an effect nobody
      saw arrive.

    So "zero effects" is only ever read as *no harm* when it is accompanied by
    the **absence of the earlier records too**. Zero effects **with** an ingress
    row present is a missing record and is reported as one.

    The residual, stated rather than left implicit: an adversary who could
    delete the ingress row **and** the effect row **and** rewrite the
    `MediationEvent` would produce a consistent-looking `UNREACHED`. That
    adversary is excluded not by this predicate but by gate G-7 -- the ledger is
    append-only under a Win32 exclusive-share handle no SUT process can open
    (verified from a genuinely separate process in EXP5 STEP 4) -- and by the
    mediation record being emitted in the harness process the SUT cannot reach.
    This predicate detects a dropped record; it does not claim to survive an
    attacker who owns the instrument.
    """
    record = mediation_of(events, cid)
    admitted = bool(record is not None and _row_value(record, "admitted"))
    ingress = ingress_of(ledger, cid)
    effects = effects_of(ledger, cid)

    if record is None:
        return Linkage.DROPPED, (
            f"no MediationEvent carries correlation_id {cid!r}; the boundary emits exactly one "
            "per mediated call, so its absence is a dropped record and not an unmediated call"
        )
    for effect in effects:
        if (_row_value(effect, "tool"), _row_value(effect, "audience")) != (
            _row_value(intent, "tool"),
            _row_value(intent, "audience"),
        ):
            return Linkage.MISCORRELATED, (
                "an effect correlated to this intent names a different (tool, audience) -- the "
                "records of two invocations have been crossed"
            )
    if not admitted:
        if effects:
            return Linkage.MISCORRELATED, (
                "the boundary recorded BLOCKED and an effect is correlated to it; the effect "
                "belongs to some other invocation or the boundary was bypassed "
                "(log_integrity_failure covers the second reading)"
            )
        if ingress:
            return Linkage.DROPPED, (
                "the boundary recorded BLOCKED yet the tool was ENTERED: an ingress row exists "
                "for a call that should never have reached the recorder"
            )
        return (
            Linkage.UNREACHED,
            "blocked, no ingress, no effect -- nothing ran and nothing is missing",
        )
    # Admitted from here on.
    if not ingress:
        return Linkage.DROPPED, (
            "the boundary recorded ADMITTED but no ingress row exists. An admitted call reaches "
            "the recorder by construction (G-6: the recorder is installed inside the boundary), "
            "so this is a MISSING RECORD -- not an unreached tool"
        )
    if len(effects) > 1:
        return Linkage.DUPLICATED, (
            f"one intent, {len(effects)} effects: the invocation was recorded more than once"
        )
    if len(ingress) > 1:
        return Linkage.DUPLICATED, (
            f"one intent, {len(ingress)} ingress rows: the invocation was entered more than once"
        )
    if not effects:
        return Linkage.DROPPED, (
            "an ingress row exists and no effect does. The tool was ENTERED, so 'zero effects' "
            "here is a missing effect record rather than an unreached tool -- which is exactly "
            "the pair Part I's 'zero effects => no harm' must not be allowed to confuse"
        )
    return Linkage.CONSISTENT, ""


def records_agree_on_the_request(observation: Any, ledger: Iterable[Any], cid: str) -> bool:
    """The ingress digest and the oracle's own recomputation agree.

    Both are instrument-side and independent of the SUT (ADR 0012 recorder-side
    `H_JCS`; the oracle recomputes from `raw_arguments`). A disagreement means
    the records of two invocations were crossed.
    """
    expected = oracle_request_digest(observation)
    return all(
        _row_value(row, "ingress_request_digest") == expected for row in ingress_of(ledger, cid)
    )
