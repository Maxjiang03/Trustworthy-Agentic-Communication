"""Gate G-9 spike — the multi-process replay cache under concurrency and failure.

Part G's row: *fire N concurrent bit-identical requests at the replay cache
**across processes**; induce a backend error.* Criterion: *exactly one proceeds;
no double-admission; fail-closed observed; frozen `(mechanism_tag, jti)`/TTL/
capacity budget.* What rides on it: **IA-9; B3⁺ and the replay layer.**

    L1  EXACTLY ONE of N concurrent, across real processes -- asserted as a COUNT
    L2  the lock-removed world genuinely DOUBLE-ADMITS
    L3  the induced backend error produces a DENIAL, never an admission
    L4  overflow is REACHED and fails closed, evicting no unexpired entry
    L5  the frozen budget is unchanged and unmovable

"Exactly one" is a count, not "at least one blocked": a cache admitting two of
five has failed even though four were blocked. And L2 is what makes L1 a
measurement rather than a race that happened not to occur.

The clock is injected and **nothing sleeps** (ADR 0027): sixty seconds of real
waiting per repetition would make this suite's runtime a function of `Δ`.

Cross-platform -- loopback sockets, no effect ledger (ADR 0033).

    uv run python smoke/g9/spike.py
"""

import concurrent.futures
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.harness.replay_arbiter import ReplayArbiter  # noqa: E402
from src.sut import freshness  # noqa: E402
from src.sut.authz.jti_cache import Consumption, JtiCache  # noqa: E402
from src.sut.authz.replay_client import RemoteJtiCache  # noqa: E402

N = 8  # concurrent bit-identical requests
NOW = 1_800_000_000
# A TIMEOUT BUDGET, NOT A PERFORMANCE BASELINE -- nothing here is measured, and
# 900 is not a claim that anything takes 900 s. Generous on purpose: the cost is
# a fixed function of the FROZEN capacity (see `l4_overflow_is_reached`), so the
# only two ways to make the limb reliable are to give it time or to shrink the
# capacity -- and the second is forbidden. A gate that errors on a slow machine
# is not a gate.
FILL_TIMEOUT = 900
RESULTS: list[tuple[str, bool, bool, str]] = []


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} -- {evidence}")


def _fire(consume, jti: str, count: int) -> list[Consumption]:
    """`count` bit-identical requests, genuinely in flight together."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(consume, "inv", jti, now=NOW) for _ in range(count)]
        return [f.result(timeout=30) for f in futures]


def l1_exactly_one(arbiter) -> None:
    """Across processes, through one arbiter: exactly one ADMITTED."""
    client = RemoteJtiCache(arbiter.port)
    outcomes = _fire(client.consume, "g9-exactly-one", N)
    admitted = sum(1 for o in outcomes if o is Consumption.ADMITTED)
    duplicate = sum(1 for o in outcomes if o is Consumption.DUPLICATE)
    record(
        "G-9.L1",
        True,
        admitted == 1 and duplicate == N - 1,
        f"{N} bit-identical requests in flight together -> ADMITTED={admitted}, "
        f"DUPLICATE={duplicate}. The criterion is EXACTLY ONE as a count: a cache admitting two "
        f"of {N} has failed even though {N - 2} were blocked, and 'at least one blocked' would "
        f"not have caught it",
    )


def l1_repeated(arbiter) -> None:
    """A single trial could be a race that happened not to occur. Repeat it."""
    client = RemoteJtiCache(arbiter.port)
    counts = []
    for trial in range(20):
        outcomes = _fire(client.consume, f"g9-repeat-{trial}", N)
        counts.append(sum(1 for o in outcomes if o is Consumption.ADMITTED))
    record(
        "G-9.L1.R",
        True,
        set(counts) == {1},
        f"20 trials x {N} concurrent requests: admitted counts = {sorted(set(counts))}. Any trial "
        f"admitting 2 would show here",
    )


def l2_the_lock_removed_world() -> None:
    """**The world in which L1 fails**, and it must genuinely double-admit.

    The lock is not removed from the arbiter -- that would test a mutilated
    arbiter. It is removed by putting the cache back where it was: one
    `JtiCache` PER CALLER, which is exactly what N separate SUT processes each
    holding their own in-process cache amounts to. That is the configuration
    §F.5 rules out, and it must admit N times.
    """
    per_caller = [JtiCache() for _ in range(N)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
        futures = [
            pool.submit(cache.consume, "inv", "g9-lock-removed", now=NOW) for cache in per_caller
        ]
        outcomes = [f.result(timeout=30) for f in futures]
    admitted = sum(1 for o in outcomes if o is Consumption.ADMITTED)
    record(
        "G-9.L2",
        True,
        admitted == N,
        f"with a per-process cache instead of the shared arbiter, the SAME {N} bit-identical "
        f"requests are ADMITTED {admitted} times. So L1's 'exactly one' is a MEASUREMENT of the "
        f"arbiter and not a race that happened not to occur",
    )


def l3_induced_backend_error() -> None:
    """A backend error is a DENIAL. Two shapes: answered `error`, and gone."""
    with ReplayArbiter(fail_mode=True) as failing:
        answered = RemoteJtiCache(failing.port).consume("inv", "g9-fail", now=NOW)
    dead = ReplayArbiter()
    port = dead.port
    dead.kill()
    unreachable = RemoteJtiCache(port).consume("inv", "g9-gone", now=NOW)
    # ...and the same client against a HEALTHY arbiter admits, so the denials
    # above are the failure and not a client that always denies.
    with ReplayArbiter() as healthy:
        healthy_outcome = RemoteJtiCache(healthy.port).consume("inv", "g9-healthy", now=NOW)
    record(
        "G-9.L3",
        True,
        answered is Consumption.CAPACITY
        and unreachable is Consumption.CAPACITY
        and healthy_outcome is Consumption.ADMITTED,
        f"arbiter answering `error` -> {answered.value}; arbiter killed and unreachable -> "
        f"{unreachable.value}; a HEALTHY arbiter -> {healthy_outcome.value}. ADR 0027: reject "
        f"rather than admit on doubt. Never an admission, and never a silent eviction",
    )


def l4_overflow_is_reached(arbiter) -> None:
    """**Overflow must be REACHED**, at the real frozen capacity.

    The budget exists so the fail-closed path can be exercised, not so the
    campaign stays below it. Filled through the SAME `consume` path -- the bulk
    op loops over the real check-and-insert rather than writing entries behind
    it -- so what is exercised is the real critical section.
    """
    client = RemoteJtiCache(arbiter.port)
    filler = RemoteJtiCache(arbiter.port)
    # Fill to exactly capacity.
    import json
    import socket

    def raw(message: dict) -> dict:
        # FILL_TIMEOUT, not 120 s. Found by EXP5 STEP 13's standing check, and
        # recorded here rather than quietly patched: reaching the frozen 2^16
        # through the real `consume` path is QUADRATIC in the capacity, because
        # `JtiCache._evict_expired` scans every entry on every call --
        # 2,147,450,880 scan steps, counted exactly, not estimated. The limb
        # therefore takes minutes on a slow machine and finished inside 120 s
        # only on the machines it happened to be adjudicated on; on a slower one
        # the socket read timed out and the gate errored with every OTHER limb
        # green. That is a flaky gate, which is worse than a failing one.
        #
        # The tempting fix is to fill to a smaller capacity. That is EXP5
        # forbidden action 6 -- moving a frozen parameter to suit a test -- and
        # it would mean overflow was never REACHED, which is the whole point of
        # this limb. So the budget stays at 2^16 and the limb is simply given
        # the time that budget costs.
        with socket.create_connection(("127.0.0.1", arbiter.port), timeout=FILL_TIMEOUT) as conn:
            conn.sendall((json.dumps(message) + "\n").encode())
            return json.loads(conn.makefile("r", encoding="utf-8").readline())

    print(
        f"    ...filling the cache to the frozen capacity {arbiter.capacity} through the real "
        f"check-and-insert; this is quadratic in the capacity and takes minutes"
    )

    filled = raw({"op": "fill", "count": arbiter.capacity, "now": NOW, "mechanism_tag": "fill"})
    size = raw({"op": "size"})
    # The next distinct id must be REFUSED -- fail closed, not evicted-for.
    overflowed = client.consume("inv", "g9-past-capacity", now=NOW)
    # An entry inserted BEFORE the cache filled is still there: nothing
    # unexpired was evicted to make room (the flooding bypass ADR 0027 rejects).
    survivor = filler.consume("fill", "fill-0", now=NOW)
    record(
        "G-9.L4",
        True,
        filled["admitted"] == arbiter.capacity
        and size["size"] == arbiter.capacity
        and overflowed is Consumption.CAPACITY
        and survivor is Consumption.DUPLICATE,
        f"filled to the frozen capacity {arbiter.capacity} ({filled['admitted']} admitted, size "
        f"now {size['size']}); the next distinct id -> {overflowed.value} (fail closed); and an "
        f"entry inserted before the cache filled is still present ({survivor.value}), so no "
        f"unexpired entry was evicted to make room -- the flooding bypass ADR 0027 rejects",
    )


def l5_the_frozen_budget_is_unmovable(arbiter) -> None:
    """The parameters are ADR 0027's, and the arbiter exposes no way to change
    them (EXP5 forbidden action 6 enforced by absence, not by discipline)."""
    source = (REPO_ROOT / "src" / "sut" / "replay_arbiter" / "__main__.py").read_text("utf-8")
    no_flags = "--capacity" not in source and "--ttl" not in source
    record(
        "G-9.L5",
        True,
        arbiter.capacity == freshness.REPLAY_CACHE_CAPACITY == 2**16
        and arbiter.ttl_seconds == freshness.DELTA_SECONDS == 60
        and no_flags,
        f"the arbiter reports capacity={arbiter.capacity} (frozen 2^16) and ttl="
        f"{arbiter.ttl_seconds}s (frozen Delta), taken from `JtiCache`'s defaults; and it accepts "
        f"no capacity or TTL flag ({no_flags}), so neither can be moved to suit a test",
    )


def l5_ttl_uses_the_injected_clock(arbiter) -> None:
    """No test sleeps: the window is crossed by advancing a logical instant."""
    client = RemoteJtiCache(arbiter.port)
    first = client.consume("inv", "g9-ttl", now=NOW)
    inside = client.consume("inv", "g9-ttl", now=NOW + freshness.DELTA_SECONDS - 1)
    outside = client.consume("inv", "g9-ttl", now=NOW + freshness.DELTA_SECONDS + 1)
    record(
        "G-9.L5.C",
        True,
        first is Consumption.ADMITTED
        and inside is Consumption.DUPLICATE
        and outside is Consumption.ADMITTED,
        f"first={first.value}; inside Delta={inside.value}; past Delta={outside.value}. The "
        f"window was crossed by ADVANCING THE INJECTED INSTANT -- no wall clock is read and "
        f"nothing slept, so this suite's runtime is not a function of Delta",
    )


def main() -> int:
    print("GATE G-9 -- the multi-process replay cache (EXP5 STEP 9-10)")
    print("=" * 78)
    l2_the_lock_removed_world()
    l3_induced_backend_error()
    with ReplayArbiter() as arbiter:
        l1_exactly_one(arbiter)
        l1_repeated(arbiter)
        l5_the_frozen_budget_is_unmovable(arbiter)
        l5_ttl_uses_the_injected_clock(arbiter)
    # Overflow gets its own arbiter: filling one to capacity is terminal for it.
    with ReplayArbiter() as overflow_arbiter:
        l4_overflow_is_reached(overflow_arbiter)

    failures = [name for name, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if failures:
        print(f"GATE G-9: FAIL -- mandatory check(s) failed: {', '.join(failures)}")
        print("Per STEP 10: do NOT mark PASS; IA-9 does not move.")
        return 1
    print("GATE G-9: all mandatory checks passed")
    print()
    print(
        "IA-9 MOVES TO VERIFIED. The check-and-insert is atomic ACROSS PROCESSES because the "
        "arbiter serves one request at a time -- atomicity is a property of the shape, not of a "
        "lock that could be mis-scoped. The frozen budget is unchanged and the arbiter exposes no "
        "flag that could change it."
    )
    print(
        "Scope: this gate establishes MULTI-PROCESS REPLAY DETECTION. It does not establish cost "
        "(IA-3 stays [UNVERIFIED-IA] for G-3) or the DPoP taxonomy (G-14). `B3+`'s SS E.5 bitmask "
        "is unchanged: where the cache runs is not a ladder property."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
