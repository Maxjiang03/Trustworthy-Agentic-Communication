"""Repeat-runner for the pre-seal flake hunt. **Not a gate.**

It lives in `tools/` and is not named `spike.py` deliberately: in this
repository a `spike.py` under `smoke/` means *a gate*, and this adjudicates
nothing. It exists to make one specific failure impossible to repeat — the
sighting whose **second failing test's name was never observed**, because the
output was not captured.

So the rule this tool enforces is: **every run's complete output goes to its own
file, before anything is summarised.** A summary that loses a name is the defect
this tool was built after.

What it varies and records, per condition:

* **CPU contention** — N busy-loop child processes competing for the scheduler.
  Both sightings appeared under load, one of them on a single-CPU container.
* **Gate-spike preamble** — whether the fourteen prior gate spikes ran as
  subprocesses immediately before the suite, which is exactly what happened
  before Sighting A.
* **Ordering** — `-p no:randomly` versus the default. Recorded even though
  `pytest-randomly` is **not installed** here, so ordering is deterministic and
  this knob is currently a no-op; it is recorded rather than dropped so a later
  environment that does install it produces comparable rows.

Reproduction rate is reported as a **fraction with both numbers**, never a
percentage alone: 0/20 and 0/2 are different claims.

    uv run python tools/repeat_runner.py --runs 10 --contention 3 --target tests/test_f45_matrix.py
"""

import argparse
import datetime
import json
import multiprocessing
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIOR_SPIKES = (
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


def _burn(stop_after: float) -> None:  # pragma: no cover - child process
    """A busy loop. Contention, not a benchmark: nothing here is timed."""
    while time.time() < stop_after:
        pow(7, 7777, 1000003)


class Contention:
    """N processes competing for the CPU, for the life of the block."""

    def __init__(self, workers: int, budget_seconds: float) -> None:
        self.workers, self.budget = workers, budget_seconds
        self._procs: list = []

    def __init__pin(self, cpu):  # pragma: no cover - set via attribute
        self.cpu = cpu

    def __enter__(self) -> "Contention":
        deadline = time.time() + self.budget
        for _ in range(self.workers):
            proc = multiprocessing.Process(target=_burn, args=(deadline,), daemon=True)
            proc.start()
            if getattr(self, "cpu", None) is not None:
                _pin(proc.pid, self.cpu)
            self._procs.append(proc)
        return self

    def __exit__(self, *exc) -> None:
        for proc in self._procs:
            proc.terminate()
        for proc in self._procs:
            proc.join(timeout=10)


FAILED = re.compile(r"^(FAILED|ERROR) (\S+)", re.M)
SUMMARY = re.compile(r"(\d+) (passed|failed|skipped|error)", re.I)


def _pin(pid: int, cpu: int) -> None:
    """Confine a live process to ONE logical CPU (Win32).

    Sighting B was measured in a container reporting **one CPU**, so contention
    there was total: every competing process fought for the same core. Six
    busy loops on a twenty-CPU laptop is not that condition, and reporting a
    null result from it would be answering a different question. This makes the
    machine look like the container the sighting came from.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
    PROCESS_SET_INFORMATION = 0x0200
    handle = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
    if not handle:
        raise OSError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    try:
        if not kernel32.SetProcessAffinityMask(handle, ctypes.c_size_t(1 << cpu)):
            raise OSError(f"SetProcessAffinityMask failed: {ctypes.get_last_error()}")
    finally:
        kernel32.CloseHandle(handle)


def run_once(target: str, log_path: Path, *, no_randomly: bool, pin_cpu: int | None = None) -> dict:
    """One suite run. The COMPLETE output is written before anything is parsed."""
    command = [sys.executable, "-m", "pytest", target, "-q", "-rA"]
    if no_randomly:
        command += ["-p", "no:randomly"]
    started = time.time()
    proc = subprocess.Popen(
        command, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    if pin_cpu is not None:
        _pin(proc.pid, pin_cpu)
    stdout, _ = proc.communicate()
    result = subprocess.CompletedProcess(command, proc.returncode, stdout, "")
    output = (result.stdout or "") + (result.stderr or "")
    log_path.write_text(output, encoding="utf-8", errors="replace")
    counts = {kind.lower(): int(number) for number, kind in SUMMARY.findall(output)}
    return {
        "returncode": result.returncode,
        "failures": sorted({name for _kind, name in FAILED.findall(output)}),
        "counts": counts,
        # Wall-clock RUN METADATA, not a latency figure: it records how long a
        # condition took to exercise, never how fast the mechanism is. G-3 owns
        # cost and its figures live in smoke/g3/ only.
        "wall_seconds": round(time.time() - started, 1),
        "log": log_path.name,
    }


def run_spikes() -> dict:
    """The fourteen prior gate spikes, as subprocesses. A CONDITION, not a verdict.

    Sighting A appeared immediately after exactly this, so it is reproducible
    as a condition. No gate verdict is recorded or moved by running them here.
    """
    outcomes = {}
    for gate in PRIOR_SPIKES:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "smoke" / gate / "spike.py")],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        outcomes[gate] = result.returncode
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description="pre-seal flake hunt repeat-runner")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--contention", type=int, default=0, help="busy-loop workers")
    parser.add_argument("--target", default="tests")
    parser.add_argument("--spikes-first", action="store_true")
    parser.add_argument("--no-randomly", action="store_true")
    parser.add_argument("--label", default=None)
    parser.add_argument("--budget", type=float, default=3600.0)
    parser.add_argument(
        "--pin-cpu",
        type=int,
        default=None,
        help="confine the suite AND the burners to one logical CPU, as Sighting B's container was",
    )
    args = parser.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    label = args.label or f"c{args.contention}{'-spikes' if args.spikes_first else ''}"
    out = REPO_ROOT / "results" / "flake_hunt" / f"{stamp}-{label}"
    out.mkdir(parents=True, exist_ok=True)

    condition = {
        "target": args.target,
        "runs": args.runs,
        "contention_workers": args.contention,
        "spikes_first": args.spikes_first,
        "no_randomly": args.no_randomly,
        "pytest_randomly_installed": False,
        "platform": sys.platform,
        "cpu_count": os.cpu_count(),
        "pinned_to_cpu": args.pin_cpu,
    }
    print(f"condition: {json.dumps(condition)}")
    print(f"logs: {out}")

    runs = []
    for index in range(args.runs):
        spikes = run_spikes() if args.spikes_first else None
        load = Contention(args.contention, args.budget) if args.contention else _Null()
        if args.contention and args.pin_cpu is not None:
            load.cpu = args.pin_cpu
        with load:
            record = run_once(
                args.target,
                out / f"run-{index:03d}.log",
                no_randomly=args.no_randomly,
                pin_cpu=args.pin_cpu,
            )
        record["spikes"] = spikes
        runs.append(record)
        status = "RED" if record["failures"] or record["returncode"] else "green"
        print(
            f"  run {index:03d}: {status} {record['counts']} "
            f"{record['failures'] if record['failures'] else ''}"
        )

    red = [r for r in runs if r["failures"] or r["returncode"] != 0]
    every_name = sorted({name for r in runs for name in r["failures"]})
    summary = {
        "condition": condition,
        "reproductions": f"{len(red)}/{len(runs)}",
        "reproduced": len(red),
        "total_runs": len(runs),
        "every_failure_named": every_name,
        "runs": runs,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"REPRODUCTION RATE: {len(red)}/{len(runs)}")
    if every_name:
        print("every failure named:")
        for name in every_name:
            print(f"  {name}")
    else:
        print("no failures observed -- this is a BOUNDED NULL CLAIM, not a resolution")
    return 0


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
