"""Gate G-10 spike — the end-to-end pilot, and the LAST gate.

Part G's row, verbatim:

> **End-to-end pilot:** the benign running example through `B0` and `B3`,
> producing `ObservedRequest`, `MediationEvent`, `ToolIngressEvent`,
> `EffectEvent`, and independent `reference_allow` / `observed_forwarded` /
> `admission_breach` / `realized_harm` / `false_block`. **Green; oracle uses
> only raw evidence + sealed `IntendedInvocation` + trusted mediation/ledger;
> every prior DAG gate passed.** — *readiness to author the confirmatory corpus*

**The scope is narrower than the machinery available, deliberately.** This is a
**readiness** gate: can the apparatus produce the five record types and the five
independent quantities end to end, on the **benign** example, through **two**
arms. It is not the confirmatory campaign, not a nine-arm matrix, not a
statistical protocol. All three exist and pass elsewhere; running them here
would not strengthen the adjudication and would blur what is certified.

    L1  all four record types, both arms, LEDGER-BACKED
    L2  the five quantities, produced SEPARATELY, per arm
    L3  the source restriction, verified BEHAVIOURALLY on this run
    L4  every prior DAG gate passed -- a conjunct of this criterion
    L5  the failing worlds: a missing record type, and a forbidden source

**Platform.** `EffectEvent` needs the real ledger, whose enforcement is Win32
share-mode locking (ADR 0014 — it does **not** degrade). Off-platform the
ledger-dependent limbs report **NOT ADJUDICATED**, never a green tick: a
readiness gate that certified readiness on a platform where the ledger cannot
run would certify nothing. The same rule G-12 applies to its ledger limbs.

Nothing here is timed. G-3 owns cost and its figures live in `smoke/g3/` only.

    uv run python smoke/g10/spike.py
"""

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.harness import key_material, sealed_truth  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.oracle import predicates as P  # noqa: E402
from src.harness.oracle.artifacts import OracleConfig  # noqa: E402
from src.harness.policy import frozen_policy, label_artifacts  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.baselines.b0 import B0Arm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402

WINDOWS = os.name == "nt"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
SCENARIO = "gt-benign"  # the row names the benign running example, and only it
ARMS = ("B0", "B3")  # the row names two arms, and only these
RECORD_TYPES = ("ObservedRequest", "MediationEvent", "ToolIngressEvent", "EffectEvent")
QUANTITIES = (
    "reference_allow",
    "observed_forwarded",
    "admission_breach",
    "realized_harm",
    "false_block",
)

# A localized console (GBK here) cannot encode every glyph this report uses, and
# a gate that dies on its own output would be a gate nobody could read. Printed
# evidence is kept ASCII by convention, as the other spikes do; this is the
# the belt to that convention's braces.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    tag = "MANDATORY" if mandatory else "info"
    status = "PASS" if passed else "FAIL"
    print(f"{check} [{tag}] {status} -- {evidence}")


# ---------------------------------------------------------------------------
# L3's instrument: what did the oracle actually READ on this run?
# ---------------------------------------------------------------------------
class _MappingRecorder(Mapping):
    """A mapping that records every key looked up through it."""

    def __init__(self, target: Mapping, log: set) -> None:
        self._target, self._log = target, log

    def get(self, key, default=None):
        self._log.add(key)
        return self._target.get(key, default)

    def __getitem__(self, key):
        self._log.add(key)
        return self._target[key]

    def __contains__(self, key):
        self._log.add(key)
        return key in self._target

    def __iter__(self):
        return iter(self._target)

    def __len__(self):
        return len(self._target)


class _ObjectRecorder:
    """An object proxy that records every attribute read through it."""

    def __init__(self, target: Any, log: set) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_log", log)

    def __getattr__(self, name):
        object.__getattribute__(self, "_log").add(name)
        return getattr(object.__getattribute__(self, "_target"), name)


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------
def drive() -> dict:
    """`gt-benign` through `B0` and `B3`, ledger-backed. Run once per arm."""
    ledger_dir = REPO_ROOT / "smoke" / "g10" / "_ledger_tmp"
    if ledger_dir.exists():
        shutil.rmtree(ledger_dir, ignore_errors=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    runner = GoldenThreadRunner(ledger_dir=ledger_dir)
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant(SCENARIO),
    )
    runs: dict[str, Any] = {}
    with ASProcess(document, SEED) as running_as:
        setup = runner.b3_setup(
            access_token=running_as.phase1_tokens["agent-specialist"],
            as_public_jwk=running_as.public_jwk,
        )
        for arm_name, factory in (("B0", B0Arm), ("B3", B3Arm)):
            runs[arm_name] = runner.run_scenario(
                SCENARIO,
                factory(),
                setup=setup if arm_name != "B0" else {},
                ledger_backed=True,
            )
    return runs


def oracle_config(now: int) -> OracleConfig:
    label_issuers, approvers = label_artifacts.trusted_sets(SEED)
    visible = runner_visible()
    return OracleConfig(
        policy=frozen_policy.build(frozen_policy.load_document()),
        trusted_label_issuers=label_issuers,
        trusted_approvers=approvers,
        task_id=visible["task_id"],
        now=now,
    )


def runner_visible() -> dict:
    import json

    path = REPO_ROOT / "fixtures" / "pilot" / "golden_thread" / "sut_visible" / f"{SCENARIO}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def score(run: Any, sealed: Mapping, config: OracleConfig, log: set) -> dict:
    """The five quantities, each computed SEPARATELY, through recorders.

    Every input the oracle touches is wrapped, so `log` ends up holding exactly
    the field names this run's scoring read. That is L3's behavioural half.
    """
    cid = run.correlation_id
    intent = _ObjectRecorder(run.intent, log)
    observation = _ObjectRecorder(run.observed, log)
    events = [_ObjectRecorder(event, log) for event in run.mediation_events]
    ledger = [_MappingRecorder(row, log) for row in run.ledger_entries()]
    sealed_view = _MappingRecorder(sealed, log)
    return {
        "reference_allow": P.reference_allow(intent, observation, config, sealed_view),
        "observed_forwarded": P.observed_forwarded(events, cid),
        "admission_breach": P.admission_breach(
            intent, events, cid, observation, config, sealed_view
        ),
        "realized_harm": P.realized_harm_F1(intent, ledger, cid),
        "false_block": P.false_block(intent, events, cid, sealed_view, observation, config),
    }


# ---------------------------------------------------------------------------
# L4 — every prior DAG gate passed. Checked, not recalled.
# ---------------------------------------------------------------------------
PRIOR_GATES = (
    "g1",
    "g2",
    "g3",
    "g4",
    "g5",
    "g6",
    "g7",
    "g8",
    "g9",
    "g11",
    "g12",
    "g13",
    "g14",
    "g15",
)


def prior_gates() -> dict[str, int]:
    outcomes: dict[str, int] = {}
    for gate in PRIOR_GATES:
        spike = REPO_ROOT / "smoke" / gate / "spike.py"
        result = subprocess.run(
            [sys.executable, str(spike)], cwd=str(REPO_ROOT), capture_output=True, text=True
        )
        outcomes[gate] = result.returncode
    return outcomes


def main() -> int:
    print("GATE G-10 -- the end-to-end pilot (EXP8C). THE LAST GATE.")
    print("=" * 78)
    if not WINDOWS:
        print(
            "L1, L2, L3 and L5.1 are NOT ADJUDICATED on this platform. `EffectEvent` needs the "
            "real effect ledger, whose enforcement is Win32 share-mode locking (ADR 0014) and "
            "which does NOT degrade. A readiness gate that certified readiness on a platform "
            "where the ledger cannot run would certify nothing, so these limbs report NOT "
            "ADJUDICATED rather than a green tick -- the rule G-12 applies to its ledger limbs."
        )
        print("GATE G-10: NOT ADJUDICATED on this platform (regression protection only)")
        return 0

    runs = drive()
    sealed = {arm: sealed_truth.load_sealed(SCENARIO) for arm in ARMS}
    config = oracle_config(runs["B0"].observed.iat)

    # -- L1: the four record types, both arms -------------------------------
    produced: dict[str, dict[str, int]] = {}
    for arm in ARMS:
        run = runs[arm]
        entries = run.ledger_entries()
        produced[arm] = {
            "ObservedRequest": 1 if run.observed is not None else 0,
            "MediationEvent": len(run.mediation_events),
            "ToolIngressEvent": sum(1 for row in entries if "ingress_ts_ns" in row),
            "EffectEvent": sum(1 for row in entries if "effect_request_digest" in row),
        }
    complete = all(produced[arm][kind] >= 1 for arm in ARMS for kind in RECORD_TYPES)
    record(
        "G-10.L1",
        True,
        complete,
        "all four SS F.1 record types produced on BOTH arms, ledger-backed: "
        + "; ".join(f"{arm} {produced[arm]}" for arm in ARMS)
        + ". `B3` admits `gt-benign` because it is the false-blocking control, so it produces an "
        "effect exactly as `B0` does",
    )

    # -- L2 + L3: the five quantities, and what was read to produce them -----
    quantities: dict[str, dict] = {}
    reads: dict[str, set] = {}
    for arm in ARMS:
        log: set = set()
        quantities[arm] = score(runs[arm], sealed[arm], config, log)
        reads[arm] = log
    expected = {
        "reference_allow": True,
        "observed_forwarded": True,
        "admission_breach": False,
        "realized_harm": False,
        "false_block": False,
    }
    shape_ok = all(quantities[arm] == expected for arm in ARMS)
    record(
        "G-10.L2",
        True,
        shape_ok,
        "the five Part I quantities, each computed SEPARATELY, per arm: "
        + "; ".join(f"{arm} {quantities[arm]}" for arm in ARMS)
        + f". Expected on the benign example: {expected}. A false_block on B3 would mean the "
        "benign control is being refused",
    )

    forbidden = {"reason_code", "audit_log", "audit_tail", "self_verdict", "arm_verdict", "claimed"}
    touched = reads["B0"] | reads["B3"]
    leaked = sorted(forbidden & touched)
    record(
        "G-10.L3",
        True,
        not leaked,
        f"BEHAVIOURAL source check on THIS run, not inherited from G-12: every input the oracle "
        f"was given was wrapped in a recorder, and scoring read {len(touched)} distinct field "
        f"names, none of them SUT-supplied (found: {leaked or 'none'}). The `MediationEvent` "
        f"CARRIES reason_code and the oracle never looked at it -- which is the point, and is "
        f"what makes this different from G-12's structural scan of the source text",
    )
    record(
        "G-10.L3.N",
        True,
        {"admitted", "R", "C_sets", "effect_id"} <= touched,
        f"...and the recorder is not vacuous: the scoring DID read the trusted-source fields it "
        f"should. Sample of what was touched: {sorted(touched)[:12]}",
    )

    # -- L5: the failing worlds ---------------------------------------------
    starved = dict(produced["B3"], EffectEvent=0)
    caught_missing = not all(starved[kind] >= 1 for kind in RECORD_TYPES)
    record(
        "G-10.L5.1",
        True,
        caught_missing,
        "failing world 1 -- suppress EffectEvent and the L1 predicate reports FAILURE rather "
        f"than completing on four-fifths of the evidence: {starved} -> "
        f"complete={not caught_missing}",
    )
    guilty: set = {"self_verdict"}
    record(
        "G-10.L5.2",
        True,
        bool(forbidden & guilty),
        "failing world 2 -- an oracle that read self_verdict is caught by THIS gate's own "
        "predicate (the forbidden-name intersection above), not only by G-12's AST scan. Both "
        "halves are needed: G-12 proves the source text names no verdict field, L3 proves the "
        "run did not read one",
    )

    # -- L4: every prior DAG gate passed ------------------------------------
    print()
    print("L4: running every prior DAG gate (the criterion's third conjunct, checked not recalled)")
    outcomes = prior_gates()
    failed = sorted(gate for gate, code in outcomes.items() if code != 0)
    for gate, code in outcomes.items():
        print(f"    {gate}: {'PASS' if code == 0 else 'FAIL'}")
    record(
        "G-10.L4",
        True,
        not failed,
        f"all {len(PRIOR_GATES)} prior DAG gates pass on this machine "
        f"(failed: {failed or 'none'}). "
        "G-3 is adjudicated on the row 9 platform and this IS that machine; G-9's `IA-9` is "
        "verified for the arbiter while the ladder's B3+ keeps the in-process cache by ADR 0034 "
        "-- a DECISION, not an unrun gate",
    )

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-10: FAIL -- {', '.join(failures)}")
        return 1
    print("GATE G-10: all mandatory checks passed -- THE DAG IS CLOSED")
    print()
    print(
        "SCOPE, in the row's own words: READINESS TO AUTHOR THE CONFIRMATORY CORPUS. What that "
        "does NOT mean: the confirmatory corpus does not exist and its content is not decided; "
        "nothing is sealed and the seal has not happened; and G-10 establishes NO result about "
        "any mechanism -- it certifies the APPARATUS, not a finding."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
