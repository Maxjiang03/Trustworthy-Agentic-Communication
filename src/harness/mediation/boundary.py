"""Trusted mediation boundary for MCP tool calls (gate G-6, harness-side).

Interposition point [VERIFIED, mcp 1.28.1]: the registered tool FUNCTION
OBJECTS. Every SDK dispatch path converges on `Tool.fn` -- the documented
protocol path (lowlevel `Server.run` -> `_handle_request` ->
`request_handlers[CallToolRequest]` -> `FastMCP.call_tool` ->
`ToolManager.call_tool` -> `Tool.run` -> `fn`), the server-side convenience
calls (`FastMCP.call_tool`, `ToolManager.call_tool`, `Tool.run`), and a
directly invoked `tool.fn`. The installer therefore (a) wraps the `fn` of
every already-registered tool and (b) replaces the manager's registry dict
with one that wraps on insertion, so tools registered later -- via
`@server.tool()`, `FastMCP.add_tool`, `ToolManager.add_tool`, or direct
registry assignment -- are wrapped the moment they enter the registry.

The boundary emits exactly one `MediationEvent` per mediated call, before
the tool runs (it is the admission-decision record). A denied call raises
`MediationDenied` and the tool function is never invoked.

This layer carries NO policy: the admission decision, the correlation-id
supply, and the event sink are all callables injected by the harness
(pilot policies live in the spike/tests; the frozen vocabulary and the real
conjuncts are arm/oracle territory). D21/red-line discipline: harness-side
and trusted; `src/sut/` must never import it.
"""

import time
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools.base import Tool

from src.harness.schema import MediationEvent

DecideFn = Callable[[str, dict[str, Any]], tuple[bool, str]]
CorrelationFn = Callable[[], str]
EmitFn = Callable[[MediationEvent], None]

_MEDIATED_MARKER = "__aasc_mediated__"


class MediationError(Exception):
    """Base: the mediation layer failed closed."""


class MediationDenied(MediationError):
    """The boundary denied the call; the tool function was never invoked."""


class MediationBoundary:
    """Wraps tool functions so every dispatch passes decide -> emit -> run."""

    def __init__(self, decide: DecideFn, correlation_provider: CorrelationFn, emit: EmitFn):
        self._decide = decide
        self._correlation_provider = correlation_provider
        self._emit = emit

    def _mediate(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Decide + emit exactly one MediationEvent; raise on deny."""
        admitted, reason_code = self._decide(tool_name, arguments)
        self._emit(
            MediationEvent(
                correlation_id=self._correlation_provider(),
                admitted=bool(admitted),
                reason_code=reason_code,
                boundary_ts_ns=time.time_ns(),
            )
        )
        if not admitted:
            raise MediationDenied(f"mediation denied: {tool_name}: {reason_code}")

    def wrap_tool(self, tool: Tool) -> None:
        """Replace tool.fn with a mediated wrapper (idempotent).

        fn_metadata/parameters/is_async derive from the ORIGINAL function and
        are untouched, so argument validation and the advertised schema are
        unchanged; the wrapper matches the original's sync/async nature.
        """
        original = tool.fn
        if getattr(original, _MEDIATED_MARKER, False):
            return
        tool_name = tool.name

        if tool.is_async:

            async def mediated(**kwargs: Any) -> Any:
                self._mediate(tool_name, kwargs)
                return await original(**kwargs)

        else:

            def mediated(**kwargs: Any) -> Any:
                self._mediate(tool_name, kwargs)
                return original(**kwargs)

        setattr(mediated, _MEDIATED_MARKER, True)
        # Deliberately no functools.wraps: the wrapper must not expose the
        # unmediated function via __wrapped__.
        tool.fn = mediated


class _MediatingToolRegistry(dict):
    """Registry that wraps every Tool on insertion (any insertion path)."""

    def __init__(self, boundary: MediationBoundary):
        super().__init__()
        self._boundary = boundary

    def __setitem__(self, name: str, tool: Tool) -> None:
        self._boundary.wrap_tool(tool)
        super().__setitem__(name, tool)

    def update(self, *args: Any, **kwargs: Any) -> None:  # defensive: route via __setitem__
        for key, value in dict(*args, **kwargs).items():
            self[key] = value

    def setdefault(self, name: str, default: Any = None) -> Any:  # defensive
        if name not in self:
            self[name] = default
        return self[name]


def install_boundary(
    server: FastMCP,
    *,
    decide: DecideFn,
    correlation_provider: CorrelationFn,
    emit: EmitFn,
) -> MediationBoundary:
    """Install the mediation boundary on a FastMCP server.

    Wraps every currently registered tool and replaces the tool registry so
    every future registration is wrapped on insertion. Returns the boundary.
    The interposition targets `mcp==1.28.1` internals (`_tool_manager._tools`);
    any SDK version bump re-triggers gate G-6 (ADR 0013).
    """
    boundary = MediationBoundary(decide, correlation_provider, emit)
    manager = server._tool_manager
    registry = _MediatingToolRegistry(boundary)
    for name, tool in manager._tools.items():
        registry[name] = tool
    manager._tools = registry
    return boundary
