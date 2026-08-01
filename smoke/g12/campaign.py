"""G-12's ledger-backed limbs: the lying SUT, and real cross-process concurrency.

Windows-only, because they need the real effect ledger (ADR 0014 — a recorded
platform decision; the ledger does not degrade). Imported by `spike.py` only on
Windows; on POSIX those limbs are reported NOT ADJUDICATED rather than passed.

**The lying SUT runs in the SEPARATED mode**, which is what makes the lie
meaningful: the self-report is produced in a process that holds no reference
into harness memory, so the records the oracle reads cannot have been touched
by the liar. Before EXP5 STEP 3 the same test would have been a program lying
to itself.

**Concurrency is real.** N SUT child processes, each a separate OS process,
each driving its own scenario through the same parent stack — not interleaved
callbacks in one thread, which is what the fault class stopped meaning the
moment the process boundary existed.
"""

import concurrent.futures
import json
import tempfile
from pathlib import Path

from src.harness import fault_injection as fi
from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.oracle import predicates as P
from src.harness.oracle.predicates import Linkage
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.baselines.b3 import B3Arm

SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"


def _campaign():
    runner_dir = Path(tempfile.mkdtemp(prefix="g12-ledger-"))
    runner = GoldenThreadRunner(ledger_dir=runner_dir)
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )
    return runner, document


def _entries(run):
    return [
        json.loads(line)
        for line in Path(run.ledger_path).read_text("utf-8").splitlines()
        if line.strip()
    ]


def run(record) -> None:
    runner, document = _campaign()
    with ASProcess(document, SEED) as process:
        setup = runner.b3_setup(
            access_token=process.phase1_tokens["agent-specialist"],
            as_public_jwk=process.public_jwk,
        )

        # -- L1: the lying SUT, BOTH directions ---------------------------- #
        honest = runner.run_scenario(
            "gt-benign", B3Arm(), setup=setup, sut_mode="separate", fault="none"
        )
        hides = runner.run_scenario(
            "gt-benign",
            B3Arm(),
            setup=setup,
            sut_mode="separate",
            fault="claim-blocked-while-executing",
        )
        invents = runner.run_scenario(
            "gt-benign",
            B3Arm(),
            setup=setup,
            sut_mode="separate",
            fault="claim-admitted-while-nothing-runs",
        )

        # Direction 1 -- the SUT claims BLOCKED while the tool executes. The
        # oracle, reading only the trusted record and the ledger, says ADMITTED
        # and finds the effect. It never consulted the claim.
        hides_events = _entries(hides)
        hides_forwarded = P.observed_forwarded(hides.mediation_events, hides.correlation_id)
        hides_effects = len(P.effects_of(hides_events, hides.correlation_id))

        # Direction 2 -- the SUT claims ADMITTED while nothing runs. Zero
        # effects, and the oracle must NOT read that as a successful call.
        invents_events = _entries(invents)
        invents_forwarded = P.observed_forwarded(invents.mediation_events, invents.correlation_id)
        invents_effects = len(P.effects_of(invents_events, invents.correlation_id))
        invents_linkage, _ = P.linkage_of(
            invents.intent, invents.mediation_events, invents_events, invents.correlation_id
        )

        both_directions = (
            hides_forwarded
            and hides_effects == 1
            and not invents_forwarded
            and invents_effects == 0
        )
        record(
            "G-12.L1",
            True,
            both_directions,
            f"direction 1 (claims BLOCKED, tool executes): the trusted record says admitted="
            f"{hides_forwarded} and the ledger holds {hides_effects} effect -- the lie is "
            f"invisible to the oracle because the oracle never asked. direction 2 (claims "
            f"ADMITTED, nothing runs): trusted record admitted={invents_forwarded}, effects="
            f"{invents_effects}, linkage={invents_linkage.value!r} -- an unreached tool, NOT a "
            f"successful call. A gate testing only direction 1 would have tested half of it",
        )

        # The self-report really did diverge -- otherwise L1 passes vacuously.
        record(
            "G-12.L1.W1",
            True,
            honest.mediation_events[-1].admitted and not invents.mediation_events[-1].admitted,
            f"non-vacuity: the honest run admits ({honest.mediation_events[-1].admitted}) and the "
            f"direction-2 fault denies ({invents.mediation_events[-1].admitted}), so the injected "
            "faults genuinely changed what happened rather than only what was claimed",
        )

        # -- L5.C: drop, on records produced by a REAL run ------------------ #
        honest_entries = _entries(honest)
        real_drop, real_why = P.linkage_of(
            honest.intent,
            honest.mediation_events,
            fi.drop_effect_records(honest_entries, honest.correlation_id),
            honest.correlation_id,
        )
        real_unreached, _ = P.linkage_of(
            invents.intent, invents.mediation_events, invents_events, invents.correlation_id
        )
        record(
            "G-12.L5.C",
            True,
            real_drop is Linkage.DROPPED and real_unreached is Linkage.UNREACHED,
            f"on records from REAL runs, not constructed ones: a dropped effect reads "
            f"{real_drop.value!r} ({real_why[:70]}...) and a genuinely unreached tool reads "
            f"{real_unreached.value!r}. Both have zero effects",
        )

        # -- L4.C: REAL cross-process concurrency --------------------------- #
        def one(index: int):
            return runner.run_scenario(
                "gt-benign", B3Arm(), setup=setup, sut_mode="separate", fault="none"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            runs = list(pool.map(one, range(4)))

        ids = [r.correlation_id for r in runs]
        distinct = len(set(ids)) == len(ids)
        each_clean = []
        for r in runs:
            entries = _entries(r)
            linkage, _ = P.linkage_of(r.intent, r.mediation_events, entries, r.correlation_id)
            each_clean.append(linkage is Linkage.CONSISTENT)
        # No interleaving produced a mis-correlation: every effect landed under
        # its own invocation, and none under anyone else's.
        no_cross_talk = all(
            len(P.effects_of(_entries(r), other.correlation_id)) == 0
            for r in runs
            for other in runs
            if other is not r
        )
        record(
            "G-12.L4.C",
            True,
            distinct and all(each_clean) and no_cross_talk,
            f"{len(runs)} scenarios driven concurrently, each in its OWN SUT child process "
            f"(real processes, not interleaved callbacks in one thread): {len(set(ids))} distinct "
            f"correlation ids, every linkage CONSISTENT ({all(each_clean)}), and no invocation's "
            f"ledger holds another's effect ({no_cross_talk})",
        )
