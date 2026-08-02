"""Gate G-3 spike — boundary-verification cost. **The first timing number.**

Part G's row: *"Sign/verify 1,000 HTC+INV pairs (Ed25519); time boundary
verification."* Criterion, `frozen_parameters` row 2: *G-3 passes iff the
**median single boundary-verification cost** is `≤ 5 ms` on the row 9 sealed
measurement platform. A Linux CI run of the spike is regression protection only
and is **never adjudicative**.*

**The quantity is `boundary_verification` ALONE — `arm.decide(...)` and nothing
else.** It is **not** row 1's estimand. ADR 0026 separated them deliberately:

    row 2 (here)   boundary_verification            median            <= 5 ms
    row 1 (later)  presentation + boundary_verif.   median(B3)-median(B0),
                                                    95% bootstrap CI upper < 20 ms

The two bars differ on purpose — a gate threshold wants headroom, an
equivalence margin encodes what the field tolerates — and reporting one where
the other belongs would misstate the result in the direction of whichever
happens to look better. This spike computes row 2 and says nothing about row 1.

**5 ms was fixed by ADR 0025 before any measurement existed**, on three
arguments, precisely so this gate could fail. Nothing here may move it.

**Three hardware hazards, handled rather than hoped away** (EXP8B STEP 4):

1. the process is **pinned to the detected performance cores** — Thread
   Director would otherwise scatter repetitions across E-cores and the spread
   would be the scheduler's, not the mechanism's;
2. **AC power is asserted**, because a laptop on battery throttles whatever the
   power plan says;
3. the run is **batched**, and the per-batch medians are reported so thermal
   drift is visible rather than averaged away.

    uv run python smoke/g3/spike.py
"""

import os
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.harness import key_material  # noqa: E402
from src.harness import measurement_platform as mp  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.frozen_parameters import g3_threshold_ms  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.base import HopContext, InvocationContext  # noqa: E402

WINDOWS = os.name == "nt"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# Part G's row names 1,000 pairs. Split into batches so thermal drift is
# VISIBLE: an H-series laptop chip gets slower late, and a single pooled median
# would hide that inside the number the criterion reads.
BATCHES = 4
PER_BATCH = 250  # 4 x 250 = the 1,000 pairs Part G names
# Discarded before the first timed pair. 100 is ~10% of the sample and well past
# the first-call effects that dominate early iterations here -- lazy imports in
# the crypto and Biscuit paths, first-touch allocation, and cold branch
# predictors. It is fixed in advance rather than chosen after looking at where
# the curve flattens, which would be fitting the warm-up to the data.
WARMUP = 100

RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    tag = "MANDATORY" if mandatory else "info"
    status = "PASS" if passed else "FAIL"
    print(f"{check} [{tag}] {status} -- {evidence}")


def _visible() -> dict:
    import json

    path = REPO_ROOT / "fixtures" / "pilot" / "golden_thread" / "sut_visible" / "gt-benign.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _percentile(ordered: list[float], fraction: float) -> float:
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def measure() -> "tuple[list[float], list[list[float]]]":
    """Sign an HTC+INV pair and time the boundary verification, 1,000 times.

    Each iteration re-runs `delegate` (the HTC chain) and `present` (the INV
    signature) so a **fresh pair is signed**, then times `decide` alone. Only
    `decide` is inside the timed span: the signing is what Part G's row means by
    *"sign/verify 1,000 pairs"*, and the quantity is the **verification**.
    """
    runner = GoldenThreadRunner()
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )
    visible = _visible()
    intent = visible["delegation_intent"]
    with ASProcess(document, SEED) as running_as:
        setup = runner.b3_setup(
            access_token=running_as.phase1_tokens["agent-specialist"],
            as_public_jwk=running_as.public_jwk,
        )
        arm = B3Arm()
        arm.provision(dict(setup))
        now = int(time.time())
        hop = HopContext(
            task_id=visible["task_id"],
            audience=visible["audience"],
            from_agent=visible["supervisor"],
            to_agent=visible["specialist"],
            authority_elements=tuple(map(tuple, visible["authority_elements"])),
            attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
            widening_elements=tuple(map(tuple, visible["widening_elements"])),
            now_epoch=now,
            expiry_epoch=now + int(visible["validity_seconds"]),
        )

        def one_pair(index: int) -> float:
            credentials = arm.delegate(hop)  # signs the HTC chain
            arm.present(  # signs the INV
                credentials,
                InvocationContext(
                    tool=intent["tool"],
                    arguments=dict(intent["arguments"]),
                    method=visible["method"],
                    task_id=visible["task_id"],
                    audience=visible["audience"],
                    invocation_id=f"g3-{index:05d}",
                    now_epoch=now,
                ),
            )
            start = time.perf_counter_ns()
            admitted, reason = arm.decide(intent["tool"], dict(intent["arguments"]))
            elapsed = time.perf_counter_ns() - start
            if not admitted:
                raise SystemExit(
                    f"G-3's benign pair was REFUSED at {reason!r}. The gate times a SUCCESSFUL "
                    "verification -- a refusal short-circuits the conjuncts and would time a "
                    "cheaper path than the one being measured"
                )
            return elapsed / 1e6  # ms

        for index in range(WARMUP):
            one_pair(index)
        batches: list[list[float]] = []
        for batch in range(BATCHES):
            batches.append([one_pair(WARMUP + batch * PER_BATCH + i) for i in range(PER_BATCH)])
    return [value for batch in batches for value in batch], batches


def main() -> int:
    threshold = g3_threshold_ms()
    print("GATE G-3 -- boundary-verification cost (EXP8B)")
    print("=" * 78)
    print(f"criterion: median boundary_verification <= {threshold} ms on the row 9 platform")

    if not WINDOWS:
        print()
        print(
            "G-3 is NOT ADJUDICATED on this platform. `frozen_parameters` row 2 names the row 9 "
            "SEALED MEASUREMENT PLATFORM, which is Windows; a Linux CI run of this spike is "
            "REGRESSION PROTECTION ONLY and is never adjudicative. Running the timing here and "
            "reporting it as a result would launder a Windows-platform criterion into a green "
            "Linux tick -- the same rule G-12 applies to its ledger-backed limbs."
        )
        values, _ = measure()
        print(f"regression check only: {len(values)} pairs completed, no verdict recorded")
        return 0

    mp.require_ac_power()
    pinned = mp.pin_to_performance_cores()
    platform = mp.read_platform()
    record(
        "G-3.H1",
        True,
        len(pinned) > 0,
        f"pinned to the DETECTED performance cores {list(pinned)} (efficiency classes "
        f"{list(mp.cpu_topology().classes)}); the mask was read from GetSystemCpuSetInformation, "
        "not assumed from a logical-processor range",
    )
    record("G-3.H2", True, platform.on_ac, f"on AC power: {platform.on_ac}")

    values, batches = measure()
    ordered = sorted(values)
    median = statistics.median(ordered)
    p95 = _percentile(ordered, 0.95)
    iqr = _percentile(ordered, 0.75) - _percentile(ordered, 0.25)
    batch_medians = [statistics.median(sorted(batch)) for batch in batches]
    drift = (
        (batch_medians[-1] - batch_medians[0]) / batch_medians[0] * 100 if batch_medians else 0.0
    )

    print()
    print(
        f"pairs timed: {len(values)} ({BATCHES} batches x {PER_BATCH}), warm-up discarded: {WARMUP}"
    )
    print(f"median {median:.4f} ms | p95 {p95:.4f} ms | IQR {iqr:.4f} ms")
    print("per-batch medians (ms): " + ", ".join(f"{m:.4f}" for m in batch_medians))
    print(f"last-vs-first batch median drift: {drift:+.1f}%")

    record(
        "G-3.C",
        True,
        median <= threshold,
        f"MEDIAN boundary_verification = {median:.4f} ms against the ADR 0025 threshold of "
        f"{threshold} ms, fixed before any measurement existed. This is row 2's quantity -- "
        f"`decide` alone -- and NOT row 1's `presentation + boundary_verification` segment",
    )
    record(
        "G-3.T",
        False,
        True,
        f"thermal: per-batch medians {[round(m, 4) for m in batch_medians]}, drift {drift:+.1f}%. "
        "Reported rather than averaged away; a systematically slower late batch is thermal and "
        "belongs in the report",
    )

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-3: FAIL -- {', '.join(failures)}")
        print(
            "Per EXP8B STEP 7: adjust NOTHING. The threshold was fixed in advance precisely so "
            "this outcome was reachable, and a failing G-3 is a finding about the mechanism's "
            "cost on this platform. IA-3 does NOT move."
        )
        return 1
    print(f"GATE G-3: PASS -- median {median:.4f} ms <= {threshold} ms")
    print(
        "IA-3 moves to VERIFIED. Fixing a threshold was never verifying an assumption (ADR 0025); "
        "measuring against it on the sealed platform is."
    )
    print(
        f"Headroom: the median is {threshold / median:.0f}x below the bar. A failing world is "
        f"therefore not marginal -- it would need the per-invocation verification to cost "
        f"{threshold / median:.0f}x more than it does, which the harness would report as a FAIL "
        "because the comparison is a plain `median <= threshold` on the same number printed above."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
