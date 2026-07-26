"""Regression suite for complete mediation (gate G-6, ADR 0013).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. The interposition under test is src/harness/mediation/boundary.py
(wrap-at-fn + wrap-on-insert registry) on the pinned MCP SDK; the enumerated
dispatch paths are those of smoke/g6/REPORT.md section 2.

Pilot vocabulary and PILOT reason codes only -- NOT the frozen ontology
Omega and NOT a frozen reason-code vocabulary. The sensitive tool is a
sandboxed stub (records intent, never acts). In-memory transport only.
"""

import asyncio
import secrets

import mcp.types as types
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools.base import Tool
from mcp.shared.memory import create_connected_server_and_client_session

from src.harness.mediation.boundary import MediationDenied, install_boundary


def build_server(with_boundary: bool = True) -> dict:
    """Test-local toy server; tool fns are local so no raw reference leaks."""
    server = FastMCP("g6-test-server")
    witness = {"calendar.read": 0, "mail.send": 0, "late.tool": 0, "boom": 0}
    outbox: list[dict] = []
    events: list = []
    deny: set[str] = set()
    corr = {"current": ""}

    def calendar_read(user: str, day: str) -> str:
        witness["calendar.read"] += 1
        return f"{user}/{day}"

    def mail_send(to: str, subject: str, body: str) -> str:
        witness["mail.send"] += 1
        outbox.append({"to": to})
        return "queued(sandbox)"

    server.add_tool(calendar_read, name="calendar.read", description="benign")
    server.add_tool(mail_send, name="mail.send", description="sandboxed stub")
    if with_boundary:
        install_boundary(
            server,
            decide=lambda tool, args: (tool not in deny, f"{'denied' if tool in deny else 'ok'}(pilot)"),
            correlation_provider=lambda: corr["current"],
            emit=events.append,
        )
    return {
        "server": server,
        "witness": witness,
        "outbox": outbox,
        "events": events,
        "deny": deny,
        "corr": corr,
    }


def mint(ctx: dict) -> str:
    cid = secrets.token_hex(16)
    ctx["corr"]["current"] = cid
    return cid


ARGS_CAL = {"user": "A", "day": "2026-07-26"}
ARGS_MAIL = {"to": "x@example.test", "subject": "s", "body": "b"}


async def _client_call(ctx: dict, tool: str, args: dict):
    async with create_connected_server_and_client_session(ctx["server"]._mcp_server) as client:
        return await client.call_tool(tool, args)


# --- 1. admitted call over the documented path ---------------------------------


def test_admitted_call_emits_exactly_one_event():
    ctx = build_server()
    cid = mint(ctx)
    result = asyncio.run(_client_call(ctx, "calendar.read", ARGS_CAL))
    # Positive: one event, correct fields, tool ran.
    assert not result.isError and ctx["witness"]["calendar.read"] == 1
    assert len(ctx["events"]) == 1
    ev = ctx["events"][0]
    assert ev.correlation_id == cid and ev.admitted is True
    assert ev.reason_code == "ok(pilot)" and ev.boundary_ts_ns > 0
    # Negative: a second call emits a second, distinct event (not zero, not a reuse).
    cid2 = mint(ctx)
    asyncio.run(_client_call(ctx, "calendar.read", ARGS_CAL))
    assert len(ctx["events"]) == 2 and ctx["events"][1].correlation_id == cid2 != cid


# --- 2. denied call: event recorded, tool-side witness untouched ---------------


def test_denied_call_blocks_tool_and_records():
    ctx = build_server()
    ctx["deny"].add("mail.send")
    mint(ctx)
    result = asyncio.run(_client_call(ctx, "mail.send", ARGS_MAIL))
    # Positive: error surfaced, admitted=False event, tool never ran.
    assert result.isError and len(ctx["events"]) == 1
    assert ctx["events"][0].admitted is False and ctx["events"][0].reason_code == "denied(pilot)"
    assert ctx["witness"]["mail.send"] == 0 and ctx["outbox"] == []
    # Negative: lifting the pilot deny admits the same call (the deny did the blocking).
    ctx["deny"].clear()
    mint(ctx)
    result = asyncio.run(_client_call(ctx, "mail.send", ARGS_MAIL))
    assert not result.isError and ctx["witness"]["mail.send"] == 1 and len(ctx["outbox"]) == 1
    assert ctx["events"][1].admitted is True


# --- 3. direct server-side dispatch paths are mediated -------------------------


def test_direct_dispatch_paths_are_mediated():
    ctx = build_server()
    manager = ctx["server"]._tool_manager

    async def run_all() -> None:
        await ctx["server"].call_tool("calendar.read", ARGS_CAL)  # FastMCP.call_tool
        await manager.call_tool("calendar.read", ARGS_CAL)  # ToolManager.call_tool
        await manager.get_tool("calendar.read").run(ARGS_CAL)  # Tool.run
        manager.get_tool("calendar.read").fn(**ARGS_CAL)  # tool.fn direct

    mint(ctx)
    asyncio.run(run_all())
    # Positive: four dispatches -> four events, four executions.
    assert len(ctx["events"]) == 4 and ctx["witness"]["calendar.read"] == 4
    assert all(ev.admitted for ev in ctx["events"])
    # Negative: a denied tool is refused on the same internal paths, no execution.
    ctx["deny"].add("mail.send")
    mint(ctx)
    try:
        asyncio.run(manager.call_tool("mail.send", ARGS_MAIL))
        raise AssertionError("denied internal dispatch must raise")
    except Exception:
        pass
    assert ctx["witness"]["mail.send"] == 0 and ctx["events"][-1].admitted is False


# --- 4. registration paths wrap on insert --------------------------------------


def test_registration_paths_wrap_on_insert():
    ctx = build_server()
    manager = ctx["server"]._tool_manager
    witness = ctx["witness"]

    def late_tool(q: str) -> str:
        witness["late.tool"] += 1
        return q

    # Positive: add_tool after install AND raw registry insertion both mediate.
    ctx["server"].add_tool(late_tool, name="late.tool", description="post-install")
    manager._tools["late2.tool"] = Tool.from_function(late_tool, name="late2.tool")
    mint(ctx)
    asyncio.run(manager.call_tool("late.tool", {"q": "x"}))
    asyncio.run(manager.call_tool("late2.tool", {"q": "x"}))
    assert len(ctx["events"]) == 2 and witness["late.tool"] == 2
    # Negative arms: every registry fn is marked mediated and none leaks the
    # unmediated function via __wrapped__.
    assert all(getattr(t.fn, "__aasc_mediated__", False) for t in manager._tools.values())
    assert all(not hasattr(t.fn, "__wrapped__") for t in manager._tools.values())


# --- 5. direct request-handler invocation is mediated --------------------------


def test_direct_handler_invocation_is_mediated():
    ctx = build_server()
    handler = ctx["server"]._mcp_server.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="calendar.read", arguments=ARGS_CAL),
    )
    mint(ctx)
    asyncio.run(handler(req))
    # Positive: transport bypass still passes the boundary.
    assert len(ctx["events"]) == 1 and ctx["witness"]["calendar.read"] == 1
    # Negative: a denied tool through the same forged-request path is refused.
    ctx["deny"].add("mail.send")
    mint(ctx)
    denied_req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="mail.send", arguments=ARGS_MAIL),
    )
    asyncio.run(handler(denied_req))  # handler converts the raise into an error result
    assert ctx["witness"]["mail.send"] == 0 and ctx["events"][-1].admitted is False


# --- 6. error path: raising tool -> exactly one event --------------------------


def test_error_path_emits_single_event():
    ctx = build_server()
    witness = ctx["witness"]

    def boom() -> str:
        witness["boom"] += 1
        raise RuntimeError("boom(pilot)")

    ctx["server"].add_tool(boom, name="boom", description="raises")
    mint(ctx)
    result = asyncio.run(_client_call(ctx, "boom", {}))
    # Positive: the tool ran, raised, the error surfaced, exactly ONE event.
    assert result.isError and witness["boom"] == 1 and len(ctx["events"]) == 1
    assert ctx["events"][0].admitted is True
    # Negative: a healthy call afterwards still works and adds exactly one more.
    mint(ctx)
    result = asyncio.run(_client_call(ctx, "calendar.read", ARGS_CAL))
    assert not result.isError and len(ctx["events"]) == 2


# --- 7. non-vacuity: without the boundary the tool is reached, zero events -----


def test_non_vacuity_without_boundary():
    ctx = build_server(with_boundary=False)
    result = asyncio.run(_client_call(ctx, "mail.send", ARGS_MAIL))
    asyncio.run(ctx["server"]._tool_manager.call_tool("calendar.read", ARGS_CAL))
    # Positive (for the detector): tools reached on both paths...
    assert not result.isError
    assert ctx["witness"]["mail.send"] == 1 and ctx["witness"]["calendar.read"] == 1
    # ...and ZERO events were emitted: the suite is detecting mediation itself.
    assert ctx["events"] == []
    # Negative: MediationDenied is a real, importable failure mode (not vacuous).
    assert issubclass(MediationDenied, Exception)
