"""One entry point for the whole matrix — nine arms × every scenario (EXP6 STEP 6–7).

Each gate has its own fixture, which is right for a gate and wrong for a
campaign: a gate isolates one property and builds the smallest world that shows
it, while a campaign must run **every** cell through **one** path so the cells
are comparable. This is that path.

**Its output is EVIDENCE, not verdicts read back.** For every cell it records
the sealed intent, the trusted mediation record, the ledger entries, the
harness's observation, and each Part I quantity **separately** —
`reference_allow`, `observed_forwarded`, `admission_breach`, `realized_harm`,
`false_block`, `log_integrity_failure`. The arm's `reason_code` is recorded
**for diagnosis only**; nothing in the scoring path reads one, and G-12's L2
scan is what makes that structural rather than a promise. The scoring path is
`src/harness/oracle/`, which imports no SUT module and names no verdict field.

**Built OVER the existing stack, never beside it.** `GoldenThreadRunner` builds
the MCP server, the mediation boundary, the ingress recorder and the effector
once; EXP5 established that one stack is what makes the two SUT modes
comparable, and a campaign that assembled its own would be a third.
`the_stack_is_not_duplicated()` asserts that structurally, the way EXP5 STEP 3
asserted it for the modes.

**Preconditions fail closed, with named errors** (STEP 7). A campaign that
silently runs in a wrong configuration produces results nobody can trust, and
the failure would surface as a table rather than as an exception.

**This module runs a campaign; it does not seal one.** `fixtures/confirmatory/`
stays empty, `run_mode` stays `"pilot"`, and nothing here writes to `results/`.
Building the entry point is not running the confirmatory campaign (red lines
1–2).
"""

import base64
import binascii
import json
import os
import platform
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.harness import credential_faults, frozen_parameters, key_material, matrix_grouping
from src.harness.authorizer import frozen_config
from src.harness.oracle import predicates as P
from src.harness.oracle.artifacts import OracleConfig
from src.harness.policy import frozen_policy, label_artifacts
from src.harness.runner import GoldenThreadRunner, RunnerError
from src.harness.verifier import registry as reg
from src.harness.verifier.credential_principal import CredentialResult, credential_result
from src.harness.verifier.matched_authority import TokenVerifierConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
PILOT_CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"

# The rows a campaign needs before it may run (STEP 7). Row 5 is DEFERRED by
# decision (ADR 0028) and is deliberately absent: requiring it would refuse
# every run for a row that will never be filled. Row 9 is the sealed
# measurement platform, needed at Part H step 3 rather than to run the pilot.
REQUIRED_ROWS = (
    "equivalence_margin_ms",
    "g3_threshold_ms",
    "delta_seconds",
    "llm_turn_denominators",
)


def corpus_scenarios(corpus_root: Path = PILOT_CORPUS) -> tuple[str, ...]:
    """Every scenario the corpus holds, **derived, never listed**.

    The gap this closes: `scenarios` was supplied by the caller, the only caller
    passed four of thirteen, and nine rows had never run through this entry
    point. Nothing was wrong — every one had been read and verified in its own
    module — but the confirmatory campaign calls `run_campaign`, so the single
    sealed run would have produced `F1` results only and the absence would have
    looked like a corpus that never had the other families.

    A longer literal would have fixed today and not tomorrow. Deriving the set
    from the sealed records makes an incomplete run **impossible to write**: a
    scenario that exists is reachable without anyone editing a tuple.
    """
    sealed = corpus_root / "sealed"
    return tuple(sorted(path.stem for path in sealed.glob("*.json")))


def configuration_scenarios(corpus_root: Path = PILOT_CORPUS) -> tuple[str, ...]:
    """The scenarios whose family is grouped by CONFIGURATION (§E.4's `A†`).

    Read from each sealed record's `attack_subcase`, so a new F4/F5 scenario
    joins this set by existing rather than by being remembered.
    """
    return tuple(
        scenario_id
        for scenario_id in corpus_scenarios(corpus_root)
        if _family_of(str(_sealed_document(corpus_root, scenario_id).get("attack_subcase", "")))
        in matrix_grouping.CONFIGURATION_FAMILIES
    )


class CampaignError(Exception):
    """A precondition refused. The campaign never runs in a configuration it
    cannot describe: an unrunnable configuration must raise, not produce a
    table that looks like a result."""


class PreconditionFailed(CampaignError):
    """A named precondition (STEP 7). Which one is in the message."""


# ---------------------------------------------------------------------------
# the per-run record — what Part H step 6 will hash
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RunRecord:
    """Everything needed to say *which* run produced a table.

    Part H step 6 emits a **detached** manifest; this is what it will hash. It
    is assembled from the environment and the frozen documents at run time, so
    a table can never be attributed to a commit or a platform it did not come
    from.
    """

    git_commit: str
    git_dirty: bool
    h_gamma: str
    h_registry: str
    h_policy: str
    frozen_rows: Mapping[str, Any]
    sut_mode: str
    run_mode: str
    platform: str
    python: str
    corpus: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "git_commit": self.git_commit,
            "git_dirty": self.git_dirty,
            "h_gamma": self.h_gamma,
            "h_registry": self.h_registry,
            "h_policy": self.h_policy,
            "frozen_rows": dict(self.frozen_rows),
            "sut_mode": self.sut_mode,
            "run_mode": self.run_mode,
            "platform": self.platform,
            "python": self.python,
            "corpus": self.corpus,
        }


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - defensive
        return ""


def build_run_record(*, sut_mode: str, run_mode: str, corpus: str) -> RunRecord:
    """The run's identity, resolved from the environment and the frozen docs."""
    rows: dict[str, Any] = {}
    for name in REQUIRED_ROWS:
        rows[name] = getattr(frozen_parameters, name)()
    rows["replay_cache_capacity"] = frozen_parameters.replay_cache_capacity()
    return RunRecord(
        git_commit=_git("rev-parse", "HEAD"),
        git_dirty=bool(_git("status", "--porcelain")),
        h_gamma=frozen_parameters.expected_h_gamma(),
        h_registry=frozen_parameters.expected_h_registry(),
        h_policy=frozen_parameters.expected_h_policy(),
        frozen_rows=rows,
        sut_mode=sut_mode,
        run_mode=run_mode,
        platform=f"{platform.system()} {platform.release()} {platform.version()}",
        python=platform.python_version(),
        corpus=corpus,
    )


# ---------------------------------------------------------------------------
# STEP 7 — the preconditions, each refusing with a named error
# ---------------------------------------------------------------------------
def check_frozen_rows() -> None:
    """Refuse if a row the campaign needs is unset, or a hash has drifted.

    The hashes are recomputed from the artifacts and compared against the
    values `docs/frozen_parameters.md` records. A drift means the document and
    the artifact disagree, and a campaign run under that disagreement could not
    say which of the two its numbers were produced under.
    """
    for name in REQUIRED_ROWS:
        try:
            getattr(frozen_parameters, name)()
        except frozen_parameters.FrozenParametersError as exc:
            raise PreconditionFailed(
                f"frozen_parameters row {name!r} is not usable: {exc}. A campaign may not run "
                "under a row it cannot resolve"
            ) from exc
    checks = (
        (
            "H(Gamma)",
            frozen_parameters.expected_h_gamma(),
            frozen_config.h_gamma(frozen_config.load_document()),
        ),
        ("H(R)", frozen_parameters.expected_h_registry(), reg.h_registry(reg.load_document())),
        (
            "H(Lambda)",
            frozen_parameters.expected_h_policy(),
            frozen_policy.h_policy(frozen_policy.load_document()),
        ),
    )
    for label, expected, actual in checks:
        if expected != actual:
            raise PreconditionFailed(
                f"{label} mismatch: docs/frozen_parameters.md records {expected!r} but the "
                f"artifact hashes to {actual!r}. The document and the artifact disagree, so no "
                "run can say which it was performed under"
            )


def check_run_mode(*, run_mode: str, corpus_root: Path, arms: Sequence[Any]) -> None:
    """Refuse a confirmatory run carrying any pilot-provisional artifact.

    Three ways a provisional artifact reaches a run, and all three refuse:
    a fixture from `fixtures/pilot/`, an §E.6 ablation variant (which
    `ArmIdentity.check_disabled` already refuses at provisioning and is refused
    here too, earlier and by name), and a policy document still marked
    `PILOT-PROVISIONAL`.
    """
    if run_mode not in ("pilot", "confirmatory"):
        raise PreconditionFailed(f"unknown run_mode {run_mode!r} (pilot | confirmatory)")
    if run_mode != "confirmatory":
        return
    if "pilot" in corpus_root.parts:
        raise PreconditionFailed(
            f"run_mode='confirmatory' with a corpus under {corpus_root}: a confirmatory campaign "
            "may not read fixtures/pilot/ (Part H step 5 requires the two corpora disjoint)"
        )
    ablations = [
        getattr(arm, "name", str(arm))
        for arm in arms
        if getattr(getattr(arm, "identity", None), "is_ablation", False)
    ]
    if ablations:
        raise PreconditionFailed(
            f"run_mode='confirmatory' with §E.6 ablation variant(s) {ablations}: an ablation is a "
            "matched control for the pilot, not a confirmatory arm"
        )
    document = json.dumps(frozen_policy.load_document())
    if "PILOT-PROVISIONAL" in document:
        raise PreconditionFailed(
            "run_mode='confirmatory' with a PILOT-PROVISIONAL policy document still in play"
        )


def ladder_reaches_the_arbiter() -> bool:
    """Does any §E.1 baseline reach G-9's arbiter (`RemoteJtiCache`)?

    Keyed on the **seam** rather than on a constant, so the refusal below
    encodes *the reason* and not *the current answer*: a later block that wires
    a ladder arm to the arbiter makes this `True` and the constraint lifts by
    itself (ADR 0034).
    """
    baselines = REPO_ROOT / "src" / "sut" / "baselines"
    return any(
        "RemoteJtiCache" in path.read_text(encoding="utf-8") for path in baselines.glob("*.py")
    )


def check_single_process_campaign(*, run_mode: str, sut_mode: str) -> None:
    """ADR 0034: a **confirmatory** campaign runs single-process.

    Gate G-9 established that the §F.5 check-and-insert is atomic across
    processes — **on the arbiter**. The ladder's `B3⁺` carries its own
    in-process `JtiCache`, one per arm instance, so two SUT processes hold two
    caches and a replay landing in the second is admitted. Those are two claims
    about two different objects, and a green G-9 does not license the second.

    So a confirmatory run may not be multi-process while that is still true.
    The pilot is exempt: it is where the configuration is *explored*, and EXP5
    STEP 13 measured the cross-process behaviour deliberately in order to find
    this. What must not happen is a **sealed** campaign producing an F3 replay
    row under a configuration §E.4 never predicted a cell for.

    Not keyed on which arms this particular call was handed: a confirmatory
    campaign runs the whole ladder by definition, and a check that could be
    satisfied by omitting `B3⁺` would be a check on the caller rather than on
    the configuration.
    """
    if run_mode != "confirmatory" or sut_mode == "in-process":
        return
    if ladder_reaches_the_arbiter():
        return
    raise PreconditionFailed(
        f"run_mode='confirmatory' with sut_mode={sut_mode!r}: ADR 0034 fixes the campaign as "
        "SINGLE-PROCESS while the ladder's replay cache is in-process. `B3PlusArm` builds one "
        "`JtiCache` per arm instance, so across two SUT processes the bit-identical replay §E.4 "
        "predicts BLOCKED would be ADMITTED — a cell measured under a configuration the matrix "
        "never predicted one for. Gate G-9 adjudicated multi-process atomicity on the ARBITER, "
        "which no baseline reaches (`RemoteJtiCache` is absent from src/sut/baselines/); wiring "
        "one lifts this refusal, and would also put a loopback round trip inside ADR 0026's "
        "measured segment for exactly one arm"
    )


def check_configuration_families(
    *, scenarios: Sequence[str], monitor_attached: bool | None, corpus_root: Path
) -> None:
    """**Decision: a configuration-free campaign REFUSES to run F4/F5.**

    §E.4 marks those cells `A†` — *admitted **absent** the shared monitor* — so
    the same arm produces different cells under different configurations, and a
    cell recorded without its configuration **is not a result** (gate G-15).
    Running them once under whichever configuration happened to be in force
    would be **worse than not running them**: it would produce a number that
    looks like a result.

    So the campaign refuses rather than guessing, and full coverage of those
    families is **two runs**, one per configuration — which is what
    `tests/test_f45_matrix.py` already does and what G-15 adjudicated on. The
    alternative, running both configurations inside one call, was rejected
    because `monitor_attached` is baked into each arm's provisioning material:
    one call would need two setup sets and would hide that fact behind a
    parameter.
    """
    if monitor_attached is not None:
        return
    present = sorted(set(scenarios) & set(configuration_scenarios(corpus_root)))
    if present:
        raise PreconditionFailed(
            f"scenarios {present} belong to a CONFIGURATION family (§E.4's `A†`) and this campaign "
            "was given no `monitor_attached`. Those cells are meaningless without it -- the same "
            "arm produces a different cell under each configuration -- so running them once would "
            "produce a number that looks like a result (G-15). Pass monitor_attached=False and "
            "again with True, or narrow the scenario set"
        )


def artifact_instants(artifacts: Mapping[str, Any]) -> tuple[tuple[str, int], ...]:
    """Every **Δ-bound** `iat` the harness minted into one cell, by name.

    Two of the three ADR 0030 artifacts are judged against Δ — the boundary
    calls `freshness.is_fresh(now, iat)` on the declassification and on the
    approval, symmetrically (`|now - iat| <= Δ`). The third, a `LabelAssertion`,
    is deliberately **not**: §A.6 puts labels at ingestion, *before* task-time
    issuance, so `mint_for_scenario` gives them `iat = now - 86_400` on purpose
    and only their own `iat`/`exp` window binds them. Including them here would
    refuse every labelled cell for a property the boundary never checks.

    Read from the minted objects rather than from whatever instant a caller
    thought it minted at: what the guard must compare is the artifact this cell
    actually carried.
    """
    found: list[tuple[str, int]] = []
    declassification = artifacts.get("declassification")
    if isinstance(declassification, Mapping) and "iat" in declassification:
        found.append(("declassification", int(declassification["iat"])))
    approval = artifacts.get("approval_artifact")
    if approval:
        try:
            payload = json.loads(bytes(approval).decode("utf-8"))["payload"]
            found.append(("approval_artifact", int(payload["iat"])))
        except (ValueError, KeyError, TypeError):  # pragma: no cover - defensive
            # An artifact whose instant cannot be read is not evidence that it
            # is fresh. Naming it with a sentinel makes the guard refuse the
            # cell rather than score it on an unread window.
            found.append(("approval_artifact", -(2**62)))
    return tuple(found)


# A window that nothing can be inside, used when a credential announces itself
# as time-bound and then cannot be read. Absence of a readable window is not
# evidence of a valid one — the approval path already fails closed the same way.
UNREADABLE = (2**62, -(2**62))


def _jwt_window(value: Any) -> "tuple[int | None, int | None] | None":
    """`(nbf, exp)` from a JWT payload, **UNVERIFIED**, or `None` if not a JWT.

    Deliberately no signature check (forbidden action 4). This guard decides
    **scorability**, never **admission**: verifying here would gate the
    measurement on the very verifier under measurement, and a harness that
    accepted the SUT's arithmetic about its own credential would be reading the
    thing it is supposed to bound. `nbf` is optional exactly as the SUT's
    verifier treats it (`claims.get("nbf")`); `exp` is not — a token that
    announces no expiry cannot be shown to cover anything.
    """
    if not isinstance(value, str) or value.count(".") != 2:
        return None
    header_b64, payload_b64, signature_b64 = value.split(".")
    if not (header_b64 and payload_b64 and signature_b64):
        return None
    # Decide JWT-or-not on the HEADER, then fail closed on the payload. Counting
    # dots is not enough: `https://as.aasc.local` has exactly two, and treating
    # every issuer URL and endpoint in the setup as an unreadable credential
    # would have refused every cell in the healthy case -- a guard that refuses
    # everything measures nothing. Found by running STEP 1's enumeration rather
    # than by reasoning about it, which is why the spec asked for it as a test.
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    except (ValueError, TypeError, binascii.Error):
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
        if not isinstance(claims, dict):
            raise ValueError("a JWT payload that is not an object")
        return (
            int(claims["nbf"]) if "nbf" in claims else None,
            int(claims["exp"]),
        )
    except (ValueError, KeyError, TypeError, binascii.Error):
        return UNREADABLE


def _x509_window(value: Any) -> "tuple[int, int] | None":
    """`(notBefore, notAfter)` from a PEM certificate, **UNVERIFIED**.

    No chain building and no trust decision — the same rule as above. Included
    because STEP 1's enumeration found it: the AS's self-signed TLS certificate
    is minted at start-up with a one-day window and handed to every `B2` arm,
    which makes it a **second** time-bound credential and therefore the same
    defect, however much longer its window is.
    """
    if not isinstance(value, str) or "-----BEGIN CERTIFICATE-----" not in value:
        return None
    try:
        from cryptography import x509

        certificate = x509.load_pem_x509_certificate(value.encode("ascii"))
        return (
            int(certificate.not_valid_before_utc.timestamp()),
            int(certificate.not_valid_after_utc.timestamp()),
        )
    except Exception:  # noqa: BLE001 - unreadable is not evidence of valid
        return UNREADABLE


def credential_windows(
    credentials: Mapping[str, Any],
) -> "tuple[tuple[str, int | None, int | None], ...]":
    """Every **time-bound** credential in a setup dict, as `(name, nbf, exp)`.

    **Found, not listed.** A hardcoded field name would cover today's
    enumeration and silently miss tomorrow's: the whole failure this closes was
    a credential nobody had enumerated. Detection is by shape — JWT-shaped, or
    PEM-certificate-shaped — so a third time-bound credential added to any
    setup is picked up by existing code, and
    `tests/test_credential_enumeration.py` pins the resulting set so that
    growth is visible rather than absorbed.

    Everything else the harness injects is untimed by construction: frozen JSON
    documents, raw Ed25519 key material, derived secrets, ports, strings and
    booleans. HTC, INV and DPoP proofs carry windows but are minted **inside**
    the cell at its own instant and never appear here.
    """
    found: list[tuple[str, int | None, int | None]] = []
    for name in sorted(credentials):
        value = credentials[name]
        window = _jwt_window(value)
        if window is None:
            window = _x509_window(value)
        if window is not None:
            found.append((name, window[0], window[1]))
    return tuple(found)


def clock_refusal(
    *,
    artifacts: Mapping[str, Any],
    judged_at: int,
    delta: int,
    credentials: Mapping[str, Any] | None = None,
) -> str:
    """`""` if this cell may be scored, else the reason it may not.

    **The straddle, fail-closed.** A cell whose artifact was minted at one
    instant and judged at another more than Δ away is not a measurement of the
    mechanism: it measures how long the campaign took to reach that cell. The
    defect this closes was silent in both directions — the arm blocks with its
    own conjunct's reason code, which is what a working mechanism looks like,
    and the oracle was judged at the same stale instant, so `reference_allow`
    agreed and nothing contradicted anything.

    A refused cell is **unscorable**, exactly as an `NA` cell is: not a `B`,
    not a `false_block`, not a result at all.

    **The second check: validity coverage.** Δ is the wrong instrument for a
    credential the harness did not mint at task time. Phase-1 access tokens are
    minted **once, at AS start-up**, live 300 s by a configuration default that
    no frozen row bounds, and are reused by every cell of a pass — so the
    exposure clock starts *earlier than the campaign's own start*. An expired
    one produced two different behaviours and only one of them was visible:
    the capability arms denied through `ConjunctFailed` and were **scored
    `false_block = True` on the benign control**, with `unscorable = 0` and
    `reference_allow` still `True`; the `B2` arms raised `B2ConfigurationError`
    out of `provision` and aborted the pass. One defect, two behaviours, one of
    them silent — and a strong arm that blocks the benign control leaves the F1
    headline with no contrast at all.

    So a cell whose credential does not **cover** the instant it is judged at is
    refused, and one expired token now produces one outcome for every arm.

    **This check must run BEFORE the cell runs**, which is why the caller
    passes the instant it is about to hand the runner rather than reading one
    back off the finished run: the `B2` half raises inside `provision`, so a
    post-run guard would never see it. There is still no second clock — the
    value passed is the same one `run_scenario` is given as `now`, and
    `run.observed.iat` is that value.
    """
    for name, not_before, expires_at in credential_windows(credentials or {}):
        if (not_before is not None and judged_at < not_before) or (
            expires_at is not None and judged_at >= expires_at
        ):
            return (
                f"the {name} is valid over [{not_before}, {expires_at}) and the cell is judged "
                f"at {judged_at}, which that window does not cover. The credential is minted "
                "ONCE, before the pass, so this records how long the campaign has been running "
                "and not what the mechanism did -- and it is asymmetric across arms, scored "
                "silently by the capability arms and raised loudly by the OAuth ones. "
                "UNSCORABLE, never scored"
            )
    for name, iat in artifact_instants(artifacts):
        separation = abs(judged_at - iat)
        if separation > delta:
            # ASCII, as the boundary's own refusals are: this string is read
            # off consoles whose code page is not UTF-8.
            return (
                f"the {name} was minted at {iat} and the cell was judged at {judged_at}, "
                f"{separation}s apart, which exceeds the frozen freshness window Delta="
                f"{delta}s "
                "(frozen_parameters row 3, ADR 0027). The boundary checks that artifact with "
                "`is_fresh(now, iat)`, so this cell would record how long the campaign took to "
                "reach it and not what the mechanism did. UNSCORABLE, never scored"
            )
    return ""


def check_ledger_available(*, ledger_backed: bool, ledger_dir: Path | None) -> None:
    """ADR 0014: the effect ledger does **not** degrade.

    A run that needs effect evidence and cannot open the ledger must refuse. It
    must never fall back to a run without one, because the absence of effect
    records would then be indistinguishable from the absence of effects — and
    every `realized_harm_*` would read `False`.
    """
    if not ledger_backed:
        return
    if os.name != "nt":
        raise PreconditionFailed(
            "a ledger-backed campaign needs the Win32 exclusive-share effect ledger (ADR 0014); "
            f"this platform is {os.name!r}. The ledger does not degrade and there is no POSIX "
            "stand-in: refusing rather than producing effect columns nothing enforced"
        )
    if ledger_dir is None or not Path(ledger_dir).is_dir():
        raise PreconditionFailed(
            f"a ledger-backed campaign needs a ledger directory; got {ledger_dir!r}"
        )


def the_stack_is_not_duplicated() -> None:
    """Structural, exactly as EXP5 STEP 3 asserted it for the two SUT modes.

    The campaign must drive `GoldenThreadRunner`'s stack rather than assemble a
    second one. A second stack would make campaign cells incomparable with
    every gate result already adjudicated on the first.
    """
    import inspect

    source = inspect.getsource(GoldenThreadRunner.run_scenario)
    for symbol in ("install_boundary(", "install_ingress_recorder(", "build_server("):
        if source.count(symbol) != 1:
            raise PreconditionFailed(
                f"{symbol} appears {source.count(symbol)} times in run_scenario; the campaign "
                "requires exactly one stack"
            )
    campaign_source = Path(__file__).read_text(encoding="utf-8")
    for symbol in ("install_boundary(", "install_ingress_recorder(", "build_server("):
        # ...and the campaign must not build one of its own. Matched on the
        # call syntax so this check does not find its own name.
        if f".{symbol}" in campaign_source or f"\n    {symbol}" in campaign_source:
            raise PreconditionFailed(
                f"the campaign builds its own {symbol}: that is a second stack"
            )


# ---------------------------------------------------------------------------
# one cell
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CellVerdict:
    """One cell: the evidence, and every Part I quantity **separately**.

    `reason_code` is recorded for **diagnosis** and is never an input to any
    field above it. Part I keeps `admission_breach` (a decision property) and
    `realized_harm` (an effect property) apart, and so does this record — an
    arm that admits and an arm that acts are answerable for different things.
    """

    scenario_id: str
    arm: str
    family: str
    subcase: str
    monitor_attached: bool | None
    correlation_id: str
    # -- Part I quantities, each computed by the oracle from evidence -------- #
    reference_allow: bool
    observed_forwarded: bool
    admission_breach: bool
    realized_harm: bool | None  # None when the family is unscorable; see `note`
    false_block: bool
    log_integrity_failure: bool
    linkage: str
    # -- evidence references ------------------------------------------------ #
    effect_count: int
    ledger_backed: bool
    note: str = ""
    # -- diagnosis ONLY. Never read by any field above. ---------------------- #
    reason_code: str = ""
    # WHICH seams captured a span, never the durations. `TimingSeams.recorded()`
    # returns names for exactly this reason, and the campaign keeps the rule:
    # EXP6 forbidden action 1 forbids *producing* a latency number, not merely
    # reporting one, and G-3 has not run on a locked row 9 platform. So the
    # campaign carries the evidence that the segment was instrumented and
    # correlated, and no duration reaches this artifact.
    timing_seams: tuple[str, ...] = ()

    @property
    def oracle_outcome(self) -> str:
        """`A`/`B` **from the trusted mediation record**, not from the arm.

        This is what makes the matrix an oracle product: `observed_forwarded`
        reads the `MediationEvent` the harness emitted, and the arm's own
        verdict never enters.
        """
        return "A" if self.observed_forwarded else "B"


def _family_of(subcase: str) -> str:
    """The §E.3 family, read from the sealed `attack_subcase`."""
    head = subcase.split(":", 1)[0]
    if head in ("F1", "F2", "F3", "F4", "F5"):
        return head
    # A benign control belongs to the family whose gate it controls, which the
    # subcase names after the `benign:` prefix (e.g. `benign:F5-control:...`).
    for part in subcase.split(":"):
        if part[:2] in ("F1", "F2", "F3", "F4", "F5") and len(part) >= 2:
            return part[:2]
    return "F1"  # the golden thread's benign control; F1 is its ladder family


def score_cell(
    run: Any,
    sealed: Mapping[str, Any],
    *,
    family: str,
    config: OracleConfig,
    cred: CredentialResult,
    monitor_attached: bool | None,
    ledger_backed: bool,
) -> CellVerdict:
    """Every Part I quantity for one run, computed from evidence alone.

    `realized_harm` is dispatched by **family**, because Part I defines a
    different predicate per family and there is no generic one. A family whose
    predicate needs evidence this run does not have yields `None` with a `note`
    — never `False`, which a reader would take for *no harm*.
    """
    cid = run.correlation_id
    intent, observation, events = run.intent, run.observed, run.mediation_events
    ledger: list[Any] = []
    note = ""
    if ledger_backed:
        ledger = run.ledger_entries()
    else:
        note = (
            "no effect ledger on this run (ADR 0014): realized_harm is NOT scored, because "
            "zero effect records would be indistinguishable from zero effects"
        )

    reference = P.reference_allow(intent, observation, config, sealed)
    forwarded = P.observed_forwarded(events, cid)
    breach = P.admission_breach(intent, events, cid, observation, config, sealed)
    false_block = P.false_block(intent, events, cid, sealed, observation, config)
    integrity = P.log_integrity_failure(events, ledger, cid) if ledger_backed else False
    linkage, _detail = P.linkage_of(intent, events, ledger, cid) if ledger_backed else (None, "")

    harm: bool | None = None
    if ledger_backed:
        if family == "F1":
            harm = P.realized_harm_F1(intent, ledger, cid)
        elif family == "F2":
            harm = P.realized_harm_F2(intent, cred, ledger, cid)
        elif family == "F3":
            harm = P.realized_harm_F3(intent, observation, ledger, cid)
        elif family == "F4":
            harm = P.realized_harm_F4(intent, observation, ledger, cid, config)
        elif family == "F5":
            harm = P.realized_harm_F5(intent, observation, ledger, cid, config)
        else:  # pragma: no cover - _family_of never returns another value
            note = f"no Part I predicate for family {family!r}"

    return CellVerdict(
        scenario_id=run.scenario_id,
        arm=run.arm_name,
        family=family,
        subcase=str(sealed.get("attack_subcase", "")),
        monitor_attached=monitor_attached,
        correlation_id=cid,
        reference_allow=reference,
        observed_forwarded=forwarded,
        admission_breach=breach,
        realized_harm=harm,
        false_block=false_block,
        log_integrity_failure=integrity,
        linkage=linkage.value if linkage is not None else "not-scored",
        effect_count=len(P.effects_of(ledger, cid)),
        ledger_backed=ledger_backed,
        note=note,
        # Recorded, never read. The `MediationEvent` carries it because §F.1
        # puts it there; the oracle above computed every quantity without it.
        reason_code=str(
            next((getattr(m, "reason_code", "") for m in events if m.correlation_id == cid), "")
        ),
        timing_seams=run.timing.recorded() if run.timing is not None else (),
    )


# ---------------------------------------------------------------------------
# the campaign
# ---------------------------------------------------------------------------
@dataclass
class CampaignResult:
    """The whole matrix, plus the record of the run that produced it."""

    record: RunRecord
    cells: list[CellVerdict]
    unscorable: list[tuple[str, str, str]] = field(default_factory=list)

    def by_cell(self) -> dict[tuple[str, str], CellVerdict]:
        return {(cell.scenario_id, cell.arm): cell for cell in self.cells}

    def matrix(self) -> dict[tuple[str, str], str]:
        """`A`/`B` per cell, **from the oracle**, never from a reason code."""
        return {(cell.scenario_id, cell.arm): cell.oracle_outcome for cell in self.cells}

    def as_dict(self) -> dict[str, Any]:
        return {
            "run": self.record.as_dict(),
            "cells": [
                {
                    "scenario_id": c.scenario_id,
                    "arm": c.arm,
                    "family": c.family,
                    "subcase": c.subcase,
                    "monitor_attached": c.monitor_attached,
                    "correlation_id": c.correlation_id,
                    "reference_allow": c.reference_allow,
                    "observed_forwarded": c.observed_forwarded,
                    "admission_breach": c.admission_breach,
                    "realized_harm": c.realized_harm,
                    "false_block": c.false_block,
                    "log_integrity_failure": c.log_integrity_failure,
                    "linkage": c.linkage,
                    "effect_count": c.effect_count,
                    "ledger_backed": c.ledger_backed,
                    "note": c.note,
                    "reason_code_FOR_DIAGNOSIS_ONLY": c.reason_code,
                    "timing_seams_recorded": list(c.timing_seams),
                }
                for c in self.cells
            ],
            "unscorable": [list(entry) for entry in self.unscorable],
        }


def run_campaign(
    *,
    runner: GoldenThreadRunner,
    factories: Mapping[str, tuple[Any, Mapping[str, Any]]],
    scenarios: Sequence[str] | None = None,
    seed: bytes,
    as_issuer: str,
    as_public_jwk: Mapping[str, str],
    resource_server: str,
    rar_type: str,
    monitor_attached: bool | None = None,
    sut_mode: str = "in-process",
    run_mode: str = "pilot",
    ledger_backed: bool = False,
    corpus_root: Path = PILOT_CORPUS,
    artifact_instant: int | None = None,
    wrong_audience_token: str | None = None,
) -> CampaignResult:
    """Run every applicable cell once and score it from evidence.

    One callable, over `GoldenThreadRunner`. Preconditions are checked **before**
    any arm is provisioned, so a misconfigured campaign costs nothing and
    produces no partial table.

    `monitor_attached` is the run's configuration for the F4/F5 families. It is
    **required** whenever a configuration family is in the scenario set, and
    every such cell is routed through `matrix_grouping.Cell`, which refuses one
    recorded without it — the rule lives there, and this goes through it rather
    than around it (§E.4's `A†` footnote, gate G-15).

    **One clock per cell.** This module used to read `int(time.time())` once for
    the whole pass and mint every scenario's artifacts, build every
    `OracleConfig` and evaluate every credential at it, while `run_scenario`
    read its own `run_epoch` per cell and never received it. The separation grew
    with the pass, and at 61 s — one cell running a minute into a run — twelve
    of eighteen F4/F5 control cells flipped from admitted to blocked, six of
    them scored `false_block`. It could not surface: the oracle was judged at
    the stale instant too, so `reference_allow` agreed with itself.

    So the campaign now **adopts the cell's clock rather than imposing its own**.
    The wall clock is read once per cell, immediately before the run, and handed
    to `run_scenario` as `now`, so the cell is judged at the instant its
    artifacts were built at. Everything computed *after* the run —
    `OracleConfig` and `credential_result` — reads `run.observed.iat`, the
    runner's own epoch, rather than a campaign copy of it: not a convention that
    they agree, but no second value to disagree with. The rejected alternative
    was freezing the cell to a campaign-wide instant, which `run_scenario`'s
    one-clock-per-run invariant forbids for a good reason — the AS mints against
    the real wall clock, and a cell frozen behind it would make a live token
    look unexpired, the same straddle in the plane where F3 lives.

    `artifact_instant` pins the instant the artifacts are minted at while the
    cell still runs on its own clock. **Nothing in production passes it**: it
    reconstructs precisely the defect above, so that `clock_refusal` — the
    fail-closed guard that routes a straddled cell to `unscorable` — has a world
    in which it is watched refusing real cells rather than asserted to work.
    """
    import time

    # DEFAULT TO EVERYTHING. A caller that needs a subset must narrow this
    # explicitly; the campaign never runs a short list because someone forgot a
    # scenario existed.
    scenarios = corpus_scenarios(corpus_root) if scenarios is None else tuple(scenarios)
    the_stack_is_not_duplicated()
    check_frozen_rows()
    check_configuration_families(
        scenarios=scenarios, monitor_attached=monitor_attached, corpus_root=corpus_root
    )
    check_run_mode(
        run_mode=run_mode,
        corpus_root=corpus_root,
        arms=[factory for factory, _ in factories.values()],
    )
    check_single_process_campaign(run_mode=run_mode, sut_mode=sut_mode)
    check_ledger_available(ledger_backed=ledger_backed, ledger_dir=runner._ledger_dir)

    delta = frozen_parameters.delta_seconds()  # frozen row 3, never a literal
    label_issuers, approvers = label_artifacts.trusted_sets(seed)
    policy = frozen_policy.build(frozen_policy.load_document())
    token_config = TokenVerifierConfig(
        issuer=as_issuer,
        resource_server=resource_server,
        as_public_jwk=dict(as_public_jwk),
        rar_type=rar_type,
        required_scope="mcp.invoke",
    )

    cells: list[CellVerdict] = []
    unscorable: list[tuple[str, str, str]] = []
    for scenario_id in scenarios:
        sealed = _sealed_document(corpus_root, scenario_id)
        visible = _visible_document(corpus_root, scenario_id)
        family = _family_of(str(sealed.get("attack_subcase", "")))
        # SEALED, never SUT-visible: the arm sees only a credential that
        # happens not to verify, never a flag saying it is under attack.
        fault = credential_faults.validate(str(sealed.get("credential_fault", "none")))
        not_applicable = set(sealed.get("not_applicable", {}).get("arms", ()))
        for arm_name, (factory, setup) in factories.items():
            if arm_name in not_applicable:
                # NA is read from the sealed record and the cell is NOT run: an
                # NA cell is not a result and must never be scored as one.
                unscorable.append((scenario_id, arm_name, "NA per the sealed record"))
                continue
            # ONE clock for this cell, read immediately before it runs and
            # handed to the runner, so the cell is JUDGED at the instant its
            # artifacts were BUILT at. Minting has to happen first -- the
            # artifacts travel into the invocation -- which is exactly why
            # `run_scenario` takes the instant rather than reading its own.
            cell_instant = int(time.time())
            artifacts = label_artifacts.mint_for_scenario(
                seed,
                visible,
                now=cell_instant if artifact_instant is None else int(artifact_instant),
                resource_owner=tuple(sealed["resource_owner"]),
                oauth_actor=tuple(sealed["oauth_actor"]),
                policy_version=frozen_parameters.expected_h_policy(),
            )
            # BEFORE the run, and it has to be. The credential half of this
            # guard catches an arm that raises out of `provision`, which happens
            # inside `run_scenario`, so a post-run check would never see it --
            # and the whole point is that one expired credential produces ONE
            # outcome regardless of which arm holds it. `cell_instant` is the
            # value handed to the runner below as `now`, and `run.observed.iat`
            # IS that value, so this is the instant the cell is judged at and
            # not a second reading of the clock.
            refusal = clock_refusal(
                artifacts=artifacts,
                credentials=setup,
                judged_at=cell_instant,
                delta=delta,
            )
            if refusal:
                unscorable.append((scenario_id, arm_name, refusal))
                continue
            try:
                run = runner.run_scenario(
                    scenario_id,
                    factory(),
                    setup=dict(setup),
                    ledger_backed=ledger_backed,
                    sut_mode=sut_mode,
                    artifacts=artifacts,
                    credential_fault=fault,
                    wrong_audience_token=wrong_audience_token,
                    now=cell_instant,
                )
            except RunnerError as exc:
                unscorable.append((scenario_id, arm_name, f"the run did not complete: {exc}"))
                continue
            # The RUNNER's own epoch, not the campaign's copy of it. Everything
            # judged after the run reads it, so there is no second value that
            # could disagree -- construction, not convention.
            judged_at = int(run.observed.iat)
            config = OracleConfig(
                policy=policy,
                trusted_label_issuers=label_issuers,
                trusted_approvers=approvers,
                task_id=visible["task_id"],
                now=judged_at,
            )
            cred = credential_result(run.observed, token_config, now=judged_at)
            verdict = score_cell(
                run,
                sealed,
                family=family,
                config=config,
                cred=cred,
                monitor_attached=monitor_attached,
                ledger_backed=ledger_backed,
            )
            # Route the F4/F5 configuration rule through `matrix_grouping`
            # rather than reimplementing it: a cell recorded without its
            # configuration is refused THERE, and this call is what makes the
            # campaign subject to that refusal.
            matrix_grouping.Cell(
                family=verdict.family,
                subcase=verdict.subcase,
                arm=arm_name,
                admitted=verdict.observed_forwarded,
                reason_code=verdict.reason_code,
                monitor_attached=(
                    monitor_attached
                    if verdict.family in matrix_grouping.CONFIGURATION_FAMILIES
                    else None
                ),
            )
            cells.append(verdict)

    return CampaignResult(
        record=build_run_record(sut_mode=sut_mode, run_mode=run_mode, corpus=str(corpus_root)),
        cells=cells,
        unscorable=unscorable,
    )


def _sealed_document(corpus_root: Path, scenario_id: str) -> dict[str, Any]:
    path = corpus_root / "sealed" / f"{scenario_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _visible_document(corpus_root: Path, scenario_id: str) -> dict[str, Any]:
    path = corpus_root / "sut_visible" / f"{scenario_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = [
    "CampaignError",
    "CampaignResult",
    "CellVerdict",
    "PreconditionFailed",
    "RunRecord",
    "artifact_instants",
    "build_run_record",
    "clock_refusal",
    "credential_windows",
    "check_configuration_families",
    "check_frozen_rows",
    "configuration_scenarios",
    "corpus_scenarios",
    "check_ledger_available",
    "check_run_mode",
    "check_single_process_campaign",
    "ladder_reaches_the_arbiter",
    "key_material",
    "run_campaign",
    "score_cell",
    "the_stack_is_not_duplicated",
]
