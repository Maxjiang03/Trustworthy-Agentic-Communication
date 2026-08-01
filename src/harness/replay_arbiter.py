"""Spawn the replay arbiter and hold its start-up line (ADR 0033, gate G-9).

The pattern `as_process.py` and `sut_process.py` already prove: **spawn, never
import**. The module path is duplicated here as a wire-level fact.

The arbiter is SUT infrastructure -- it is the arm's replay cache, and the
mechanism under measurement -- so it lives in `src/sut/`. The harness starts it
because the harness owns the composition root, exactly as it starts the AS.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ARBITER_MODULE = "src.sut.replay_arbiter"  # spawned, never imported
REPO_ROOT = Path(__file__).resolve().parents[2]


class ReplayArbiterError(Exception):
    """The arbiter failed to start or to report its start-up line."""


class ReplayArbiter:
    """One out-of-process replay arbiter and the port it listens on."""

    def __init__(self, *, fail_mode: bool = False) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        command = [sys.executable, "-m", ARBITER_MODULE]
        if fail_mode:
            command.append("--fail-mode")
        self._proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
        )
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            self.stop()
            raise ReplayArbiterError(f"arbiter emitted no start-up line: {stderr.strip()[:400]}")
        startup = json.loads(line)
        self.port: int = startup["port"]
        self.pid: int = startup["pid"]
        self.capacity: int = startup["capacity"]
        self.ttl_seconds: int = startup["ttl_seconds"]
        self.fail_mode: bool = startup["fail_mode"]

    def stop(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                self._proc.kill()
                self._proc.wait(timeout=10)

    def kill(self) -> None:
        """Terminate abruptly, for the induced-backend-error world."""
        self._proc.kill()
        self._proc.wait(timeout=10)

    def __enter__(self) -> "ReplayArbiter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()
