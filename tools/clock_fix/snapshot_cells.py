"""Record every campaign cell, so a harness change can be shown to move none.

**Not a gate.** It lives in `tools/` and is not named `spike.py`: in this
repository those two things together mean *a gate*, and this adjudicates
nothing. It produces the before/after evidence for the one-clock-per-cell ADR
and can produce it again for any later harness change.

Three passes, because one is not enough to say a cell did not move:

* the **F1 ladder chain** — nine arms over the four F1 scenarios;
* the **F4/F5 chain**, `monitor_attached=False`;
* the **F4/F5 chain**, `monitor_attached=True`.

F4/F5 needs both configurations because §E.4 marks those cells `A†` — admitted
*absent* the shared monitor — so one column cannot say whether a cell moved.
They also run on their own authority chain: on the F1 chain `containment_ok`
would refuse these actions **before** the conjuncts under test ran.

`correlation_id` is dropped (minted per run) and so are the run record's
`git_commit`, `git_dirty` and `platform`, which change between two runs of the
same code. What remains is **verdicts**, so an identical pair of snapshots is a
statement about the measurement and not about the machine.

    uv run python tools/clock_fix/snapshot_cells.py out.json
    uv run python tools/clock_fix/snapshot_cells.py out.json --stale 61

`--stale N` mints every artifact N seconds before the cell's own clock, which
is the defect the ADR records. With the guard in place the cells are refused;
with it removed they are scored, twelve of them wrongly.
"""

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.harness import campaign as C  # noqa: E402
from src.harness import frozen_parameters, key_material  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.baselines.b0 import B0Arm  # noqa: E402
from src.sut.baselines.b1 import B1Arm  # noqa: E402
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm  # noqa: E402
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm  # noqa: E402
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.b3_plus import B3PlusArm  # noqa: E402
from src.sut.baselines.b_cap import BCapArm  # noqa: E402

CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
F1_SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
F45_SCENARIOS = (
    "gt-f4-declassified",
    "gt-f4-sensitive-egress",
    "gt-f5-approved",
    "gt-f5-unapproved-high-risk",
)
CONTROLS = ("gt-f4-declassified", "gt-f5-approved")

# Minted per run; identical code produces different values, so a diff over them
# would report a change every time and say nothing about verdicts.
VOLATILE = ("correlation_id",)


def as_document(runner: GoldenThreadRunner, task_grant_scenario: str) -> dict:
    registry_document = reg.load_document()
    return golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant(task_grant_scenario),
    )


def factories(runner, running_as, document, *, monitor_attached, scenario_id) -> dict:
    """Every arm under ONE configuration, so it is a property of the run."""
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
        "scenario_id": scenario_id,
    }
    b3_extra = {}
    if monitor_attached is not None:
        common["monitor_attached"] = monitor_attached
        b3_extra["monitor_attached"] = monitor_attached
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
        **b3_extra,
    )
    broad = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor:broad"],
        ladder_grant="broad",
        **common,
    )
    task = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        ladder_grant="task",
        **common,
    )
    dpop = runner.b2_dpop_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_token_endpoint=document["token_endpoint"],
        **common,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B2-broad-noexchange": (B2BroadNoExchangeArm, broad),
        "B2-exchange-broad": (B2ExchangeBroadArm, broad),
        "B2-exchange-task": (B2ExchangeTaskArm, task),
        "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, dpop),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
        "B3+": (B3PlusArm, b3_setup),
    }


def comparable(payload: dict) -> dict:
    """The verdicts, with the per-run values removed."""
    return {
        "cells": [
            {key: value for key, value in cell.items() if key not in VOLATILE}
            for cell in sorted(payload["cells"], key=lambda c: (c["scenario_id"], c["arm"]))
        ],
        "unscorable": sorted(payload["unscorable"]),
        "frozen_rows": payload["run"]["frozen_rows"],
        "sut_mode": payload["run"]["sut_mode"],
        "run_mode": payload["run"]["run_mode"],
    }


def main() -> int:
    out_path = Path(sys.argv[1])
    stale = int(sys.argv[sys.argv.index("--stale") + 1]) if "--stale" in sys.argv else 0
    pinned = {"artifact_instant": int(time.time()) - stale} if stale else {}

    runner = GoldenThreadRunner()
    snapshot: dict = {}

    document = as_document(runner, "gt-benign")
    with ASProcess(document, SEED) as running_as:
        result = C.run_campaign(
            runner=runner,
            factories=factories(
                runner, running_as, document, monitor_attached=None, scenario_id="gt-benign"
            ),
            scenarios=F1_SCENARIOS,
            seed=SEED,
            as_issuer=ISSUER,
            as_public_jwk=running_as.public_jwk,
            resource_server=AUDIENCE,
            rar_type="urn:aasc:mcp-invoke",
            sut_mode="in-process",
            run_mode="pilot",
            ledger_backed=False,
            corpus_root=CORPUS,
            **pinned,
        )
        snapshot["F1"] = comparable(result.as_dict())
        print("F1 ladder chain done", flush=True)

    document = as_document(runner, "gt-f4-sensitive-egress")
    with ASProcess(document, SEED) as running_as:
        for configured in (False, True):
            result = C.run_campaign(
                runner=runner,
                factories=factories(
                    runner,
                    running_as,
                    document,
                    monitor_attached=configured,
                    scenario_id="gt-f4-sensitive-egress",
                ),
                scenarios=F45_SCENARIOS,
                seed=SEED,
                as_issuer=ISSUER,
                as_public_jwk=running_as.public_jwk,
                resource_server=AUDIENCE,
                rar_type="urn:aasc:mcp-invoke",
                monitor_attached=configured,
                sut_mode="in-process",
                run_mode="pilot",
                ledger_backed=False,
                corpus_root=CORPUS,
                **pinned,
            )
            snapshot[f"F45-monitor-{configured}"] = comparable(result.as_dict())
            print(f"F4/F5 chain, monitor_attached={configured} done", flush=True)

    out_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

    admitted = blocked = false_blocked = 0
    for pass_name in ("F45-monitor-False", "F45-monitor-True"):
        for cell in snapshot[pass_name]["cells"]:
            if cell["scenario_id"] not in CONTROLS:
                continue
            if cell["observed_forwarded"]:
                admitted += 1
            else:
                blocked += 1
            false_blocked += bool(cell["false_block"])
    print(f"Delta (frozen row 3) = {frozen_parameters.delta_seconds()}s; stale offset = {stale}s")
    print(
        f"F4/F5 CONTROL cells: admitted={admitted} blocked={blocked} false_block={false_blocked} "
        "(a control carries a VALID artifact and must be admitted)"
    )
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
