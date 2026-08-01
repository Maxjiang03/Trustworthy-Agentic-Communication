"""Spawn the SUT out-of-process and hold its pipe (EXP5 STEP 3).

The pattern `as_process.py` already proves, applied to the rest of the system
under test: **spawn, never import**. The module path and the JSON codec are
duplicated here as **wire-level facts**, exactly as `as_process.py` duplicates
the AS module path rather than importing the AS package (ADR 0015 rule 4).
Importing `src.sut.sut_process` to reach its codec would put SUT code in the
harness process and undo the separation this module exists to create.

**What this closes.** Gates G-6 and G-7 each carry a residual naming SUT process
separation and deferring it to G-12: *"in-process raw-reference/introspection
paths excluded by SUT process separation"* and *"in-process reachability inside
the harness process excluded by SUT process separation"*. Until now those were
excluded by assumption. With this module they are excluded by **address space**,
and `gc_sweep` lets a test measure it instead of asserting it.

**What stays here, in the parent:** the runner, the mediation record, the ledger
writer, the effector, the oracle and every sealed object. The child receives
provisioning material and scenario arguments; it receives no handle, no callable
and no sealed field.

**Key material crosses the pipe, never a file.** `stdin`, in memory, for the
lifetime of the process — the same rule ADR 0021 applies to the AS's Phase-1
tokens and red line 8 applies to everything.

**Failure is a denial, never a hang.** Every call is deadline-bounded; a child
that dies, stalls or answers unparseably yields a recorded error outcome, which
the runner turns into a fail-closed denial. That is STEP 4's fourth test.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

SUT_MODULE = "src.sut.sut_process"  # spawned, never imported
BYTES_TAG = "__bytes__"  # the wire codec's one tagged form; see sut_process/wire.py
DEFAULT_TIMEOUT_SECONDS = 60

REPO_ROOT = Path(__file__).resolve().parents[2]


class SutProcessError(Exception):
    """The SUT process failed to start, answer, or stay alive."""


# --- the codec, duplicated on purpose (see the module docstring) ------------ #
def encode(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {BYTES_TAG: bytes(value).hex()}
    if isinstance(value, dict):
        return {str(key): encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value


def decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {BYTES_TAG} and isinstance(value[BYTES_TAG], str):
            return bytes.fromhex(value[BYTES_TAG])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value


class SutProcess:
    """One out-of-process SUT and the line-delimited JSON channel to it."""

    def __init__(self, *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        self._timeout = timeout_seconds
        self._proc = subprocess.Popen(
            [sys.executable, "-m", SUT_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # DEVNULL, not PIPE. An unread stderr pipe is a latent DEADLOCK:
            # once the OS buffer fills (64 KiB on Linux, larger on Windows --
            # which is why this bit CI and not the local suite), the child
            # blocks writing stderr, stops reading stdin, and the parent blocks
            # writing stdin. Nothing here consumes the child's stderr, so it
            # must not be a pipe. Diagnostics travel on the JSON channel as an
            # `error` reply, which the parent DOES read.
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
        )
        assert self._proc.stdout is not None and self._proc.stdin is not None
        line = self._proc.stdout.readline()
        if not line:
            self.stop()
            raise SutProcessError(
                f"SUT process emitted no start-up line (exit code {self._proc.poll()}); "
                "stderr is DEVNULL by design -- see the constructor"
            )
        startup = json.loads(line)
        self.pid: int = startup["pid"]
        self.operations: list[str] = startup.get("operations", [])

    # -- the channel -------------------------------------------------------- #
    def call(self, op: str, **message: Any) -> dict[str, Any]:
        """One request, one reply. Never raises on a SUT-side error.

        A child error comes back as `{"error": ...}` for the caller to turn
        into a fail-closed denial -- the harness decides what a SUT failure
        means, and the SUT does not get to decide it by crashing.
        """
        if self._proc.poll() is not None:
            return {"error": "sut-process-dead", "detail": f"exit code {self._proc.returncode}"}
        payload = json.dumps(encode(dict(message, op=op)), ensure_ascii=True, separators=(",", ":"))
        try:
            self._proc.stdin.write(payload + "\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, OSError) as exc:
            return {"error": "sut-pipe-broken", "detail": str(exc)[:200]}
        line = self._proc.stdout.readline()  # type: ignore[union-attr]
        if not line:
            # The child died mid-invocation. A RECORDED outcome, not a hang and
            # not a silent pass (STEP 4).
            return {
                "error": "sut-process-died-mid-invocation",
                "detail": f"exit code {self._proc.poll()}",
            }
        try:
            return decode(json.loads(line))
        except json.JSONDecodeError as exc:
            return {"error": "sut-reply-unparseable", "detail": str(exc)[:200]}

    def run_task(self, *, visible: dict, now_epoch: int, invocation_id: str, on_invoke) -> dict:
        """Drive one scenario in the child, servicing its nested tool calls.

        The child runs both agents and the A2A hop and emits an `invoke` event
        per tool call; `on_invoke(message)` is the PARENT's handler -- it emits
        the `MediationEvent`, gates execution and writes the ledger, none of
        which the child can see or reach. Its return value goes back as the
        tool result.

        The loop ends on the child's final reply or on any error, so a child
        that dies mid-invocation yields a recorded outcome rather than a hang.
        """
        payload = json.dumps(
            encode(
                {
                    "op": "run_task",
                    "visible": visible,
                    "now_epoch": now_epoch,
                    "invocation_id": invocation_id,
                }
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        try:
            self._proc.stdin.write(payload + "\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, OSError) as exc:
            return {"error": "sut-pipe-broken", "detail": str(exc)[:200]}
        while True:
            line = self._proc.stdout.readline()  # type: ignore[union-attr]
            if not line:
                return {
                    "error": "sut-process-died-mid-invocation",
                    "detail": f"exit code {self._proc.poll()}",
                }
            try:
                message = decode(json.loads(line))
            except json.JSONDecodeError as exc:
                return {"error": "sut-reply-unparseable", "detail": str(exc)[:200]}
            if not isinstance(message, dict):
                return {"error": "sut-reply-not-an-object"}
            if message.get("event") != "invoke":
                return message  # the final reply, or an error
            reply = on_invoke(message)
            try:
                self._proc.stdin.write(  # type: ignore[union-attr]
                    json.dumps(encode(reply), ensure_ascii=True, separators=(",", ":")) + "\n"
                )
                self._proc.stdin.flush()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError) as exc:
                return {"error": "sut-pipe-broken", "detail": str(exc)[:200]}

    def send_raw(self, raw: str) -> dict[str, Any]:
        """Send bytes that are NOT a well-formed message (STEP 4).

        Exists so a test can drive the malformed/oversized path from the
        parent side; the child must answer with an error and stay alive.
        """
        if self._proc.poll() is not None:
            return {"error": "sut-process-dead"}
        try:
            self._proc.stdin.write(raw + "\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, OSError) as exc:
            return {"error": "sut-pipe-broken", "detail": str(exc)[:200]}
        line = self._proc.stdout.readline()  # type: ignore[union-attr]
        if not line:
            return {"error": "sut-process-died-mid-invocation"}
        try:
            return decode(json.loads(line))
        except json.JSONDecodeError as exc:
            return {"error": "sut-reply-unparseable", "detail": str(exc)[:200]}

    @property
    def alive(self) -> bool:
        return self._proc.poll() is None

    def kill(self) -> None:
        """Terminate abruptly, for the child-dies-mid-invocation test."""
        self._proc.kill()
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            pass

    def stop(self) -> None:
        if self._proc.poll() is None:
            try:
                if self._proc.stdin is not None:
                    self._proc.stdin.close()
            except OSError:  # pragma: no cover - defensive
                pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                self._proc.kill()
                self._proc.wait(timeout=10)

    def __enter__(self) -> "SutProcess":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


# The harness types a co-resident SUT could reach by introspection. `gc_sweep`
# counts them INSIDE the child, where the answer must be zero.
HARNESS_TYPES_A_CORESIDENT_SUT_COULD_REACH = (
    "LedgerWriter",
    "LedgerEffector",
    "MediationBoundary",
    "GoldenThreadRunner",
    "IntendedInvocation",
)
