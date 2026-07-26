"""Immutable external effect ledger + ToolIngressEvent recorder (gate G-7).

Mechanism (Windows, [VERIFIED empirically by gate G-7]): the ledger file is
held open by a SEPARATE ledger process that creates it via Win32
``CreateFileW`` with ``dwShareMode = FILE_SHARE_READ`` -- read sharing only.
While that handle is open, every other attempt to open the file for write,
append, truncate, or delete fails at the OS level with a sharing violation,
regardless of file attributes or ``chmod`` -- including attempts from the
harness process itself. Reads are allowed. The ledger process appends
validated JSON lines it receives on stdin and acks each one; its stdin/stdout
pipes are held by the harness-side ``LedgerWriter`` and are the ONLY write
path into the file.

Trust argument (D21, SS F.1): the SUT is handed neither the ``LedgerWriter``
nor the child's pipes; every filesystem route to the ledger is closed by the
sharing mode, so no SUT code path can write, amend, or delete an entry. The
recorder and effector interfaces that DO append are installed harness-side at
the tool. Remaining residual: in-process Python object reachability inside
the harness process (stressed adversarially at G-12; excluded
architecturally by SUT process separation). Windows-only enforcement in this
pass; a POSIX variant is a disclosed residual.

`ingress_request_digest` is H_JCS over the arguments mapping the tool is
invoked with (ADR 0012), computed recorder-side, independent of the SUT.
"""

import json
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools.base import Tool
from pydantic import BaseModel

from src.harness.oracle.jcs_digest import h_jcs
from src.harness.schema import ToolIngressEvent

CorrelationFn = Callable[[], str]

_RECORDED_MARKER = "__aasc_ingress_recorded__"

_CHILD_CODE = r"""
import ctypes, json, msvcrt, os, sys

path = sys.argv[1]
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
OPEN_ALWAYS = 4
FILE_ATTRIBUTE_NORMAL = 0x80

CreateFileW = ctypes.windll.kernel32.CreateFileW
CreateFileW.restype = ctypes.c_void_p
handle = CreateFileW(
    path, GENERIC_WRITE, FILE_SHARE_READ, None, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
)
if handle in (None, ctypes.c_void_p(-1).value):
    sys.exit(2)
fd = msvcrt.open_osfhandle(handle, os.O_APPEND)
out = os.fdopen(fd, "ab", buffering=0)

sys.stdout.write("ready\n")
sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        record = json.loads(line)
        if not (isinstance(record, dict) and record.get("correlation_id")):
            raise ValueError("not a correlated record")
    except Exception:
        sys.stdout.write("rejected\n")
        sys.stdout.flush()
        continue
    out.write(line.encode("utf-8") + b"\n")
    os.fsync(out.fileno())
    sys.stdout.write("ok\n")
    sys.stdout.flush()
"""


class LedgerError(Exception):
    """Base: the ledger layer failed closed."""


class LedgerWriteRejected(LedgerError):
    """The ledger process refused a record (invalid or uncorrelated)."""


class LedgerWriter:
    """Harness-held writer around the exclusive ledger process.

    The only write path into the ledger file. Appends are synchronous and
    acked; a rejected record raises (fail closed). Use as a context manager
    so the child exits and releases the exclusive handle deterministically.
    """

    def __init__(self, path: str):
        if sys.platform != "win32":  # enforcement mechanism is Win32 sharing
            raise LedgerError("exclusive-share ledger enforcement is Windows-only in this pass")
        self.path = str(path)
        self._proc = subprocess.Popen(
            [sys.executable, "-c", _CHILD_CODE, self.path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self._proc.stdout is not None and self._proc.stdin is not None
        if self._proc.stdout.readline().strip() != "ready":
            raise LedgerError("ledger process failed to acquire the exclusive handle")

    def append(self, event: BaseModel) -> None:
        """Append one schema event (ToolIngressEvent / EffectEvent) and await the ack."""
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(event.model_dump_json() + "\n")
        self._proc.stdin.flush()
        ack = self._proc.stdout.readline().strip()
        if ack != "ok":
            raise LedgerWriteRejected(ack or "ledger process gave no ack")

    def close(self) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        self._proc.wait(timeout=30)

    def __enter__(self) -> "LedgerWriter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def read_ledger(path: str) -> list[dict[str, Any]]:
    """Read the ledger (read sharing is allowed; never opens for write)."""
    with open(path, "rb") as handle:
        return [json.loads(line) for line in handle.read().splitlines() if line.strip()]


def install_ingress_recorder(
    server: FastMCP,
    *,
    audience: str,
    correlation_provider: CorrelationFn,
    writer: LedgerWriter,
) -> None:
    """Wrap every registered tool so entry emits a ToolIngressEvent.

    Install BEFORE the mediation boundary so the boundary wrapper stays
    outermost: a denied call never reaches the recorder (no ingress event).
    The digest is computed recorder-side over the arguments mapping the tool
    is invoked with, excluding the SDK-injected context parameter (ADR 0012).
    """
    for tool in server._tool_manager._tools.values():
        _wrap_with_recorder(tool, audience, correlation_provider, writer)


def _wrap_with_recorder(
    tool: Tool, audience: str, correlation_provider: CorrelationFn, writer: LedgerWriter
) -> None:
    original = tool.fn
    if getattr(original, _RECORDED_MARKER, False):
        return
    tool_name, context_kwarg = tool.name, tool.context_kwarg

    def record_ingress(kwargs: dict[str, Any]) -> None:
        arguments = {k: v for k, v in kwargs.items() if k != context_kwarg}
        writer.append(
            ToolIngressEvent(
                correlation_id=correlation_provider(),
                tool=tool_name,
                audience=audience,
                ingress_request_digest=h_jcs(arguments),
                payload_digest=None,
                value_id=None,
                ingress_ts_ns=time.time_ns(),
            )
        )

    if tool.is_async:

        async def recorded(**kwargs: Any) -> Any:
            record_ingress(kwargs)
            return await original(**kwargs)

    else:

        def recorded(**kwargs: Any) -> Any:
            record_ingress(kwargs)
            return original(**kwargs)

    setattr(recorded, _RECORDED_MARKER, True)
    tool.fn = recorded
