"""Gate G-6 spike: complete mediation in the MCP SDK tool-call path.

Tests IA-6 (docs/EXPERIMENT_ARCHITECTURE_FINAL.md SS F.4): the MCP Python SDK
exposes tool-call handling where the boundary can mediate EVERY call and emit
a MediationEvent. Pass criterion (Part G): no tool call executes without
passing the boundary and emitting a MediationEvent.

Interposition (src/harness/mediation/boundary.py): wrap every registered
tool's fn + a wrap-on-insert registry. Bypass checks G-6.C exercise one
attempt per SDK dispatch path enumerated in smoke/g6/REPORT.md section 2.

Pilot vocabulary and PILOT reason codes only -- NOT the frozen ontology
Omega and NOT a frozen reason-code vocabulary (deferred to arm
implementation). The mail.send tool is a SANDBOXED STUB: it records an
intent to act and returns; it never sends anything. In-memory transport
only; no sockets.
"""

import asyncio
import json
import secrets
import sys
from pathlib import Path

import mcp.types as types
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools.base import Tool
from mcp.shared.memory import create_connected_server_and_client_session

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root, for src.*

from src.harness.mediation.boundary import install_boundary  # noqa: E402
from src.harness.schema import MediationEvent  # noqa: E402

RESULTS = []


def record(check: str, ok: bool, evidence: str) -> None:
    RESULTS.append((check, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {check}: {evidence}")


def build_server(with_boundary: bool) -> dict:
    """Toy FastMCP server; tool functions are LOCAL to this scope, so no
    module-level raw (unmediated) reference survives installation."""
    server = FastMCP("g6-toy-server")
    witness = {"calendar.read": 0, "mail.send": 0, "notes.read": 0, "evil.tool": 0, "boom": 0}
    outbox: list[dict] = []  # sandboxed stub: recorded intents, never sent
    events: list[MediationEvent] = []
    deny: set[str] = set()  # pilot policy: deny-by-tool-name
    corr = {"current": ""}

    def calendar_read(user: str, day: str) -> str:
        witness["calendar.read"] += 1
        return json.dumps({"user": user, "day": day, "events": ["standup"]})

    def mail_send(to: str, subject: str, body: str) -> str:
        witness["mail.send"] += 1
        outbox.append({"to": to, "subject": subject, "body": body})
        return "queued(sandbox; nothing sent)"

    server.add_tool(calendar_read, name="calendar.read", description="benign pilot tool")
    server.add_tool(
        mail_send, name="mail.send", description="sensitive pilot tool (sandboxed stub)"
    )

    boundary = None
    if with_boundary:
        boundary = install_boundary(
            server,
            decide=lambda tool, args: (
                tool not in deny,
                f"{'denied' if tool in deny else 'ok'}(pilot)",
            ),
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
        "boundary": boundary,
    }


def mint_correlation(corr: dict) -> str:
    cid = secrets.token_hex(16)  # harness-minted 128-bit
    corr["current"] = cid
    return cid


async def main() -> None:
    ctx = build_server(with_boundary=True)
    server, witness, outbox = ctx["server"], ctx["witness"], ctx["outbox"]
    events, deny, corr = ctx["events"], ctx["deny"], ctx["corr"]
    args_cal = {"user": "A", "day": "2026-07-26"}
    args_mail = {"to": "x@example.test", "subject": "s", "body": "b"}

    async with create_connected_server_and_client_session(server._mcp_server) as client:
        # ---- G-6.A: documented protocol path, admitted -----------------------
        cid = mint_correlation(corr)
        result = await client.call_tool("calendar.read", args_cal)
        ev = events[-1]
        record(
            "G-6.A documented path emits exactly one MediationEvent",
            len(events) == 1
            and not result.isError
            and witness["calendar.read"] == 1
            and ev.correlation_id == cid
            and ev.admitted is True
            and ev.reason_code == "ok(pilot)"
            and ev.boundary_ts_ns > 0,
            f"events=1 admitted=True correlation_id={cid[:16]}.. reason={ev.reason_code} "
            f"ts_ns={ev.boundary_ts_ns} witness={witness['calendar.read']}",
        )

        # ---- G-6.B: denied call -> event(admitted=False), tool did NOT run ---
        deny.add("mail.send")
        cid = mint_correlation(corr)
        before = len(events)
        result = await client.call_tool("mail.send", args_mail)
        ev = events[-1]
        record(
            "G-6.B denied call: admitted=False event, tool-side witness untouched",
            result.isError
            and len(events) == before + 1
            and ev.admitted is False
            and ev.correlation_id == cid
            and ev.reason_code == "denied(pilot)"
            and witness["mail.send"] == 0
            and outbox == [],
            f"isError={result.isError} events+1 reason={ev.reason_code} "
            f"witness={witness['mail.send']} outbox={len(outbox)}",
        )

        # ---- G-6.C: one bypass attempt per enumerated non-documented path ----
        manager = server._tool_manager
        attempts = []

        async def attempt(name: str, coro_or_call, expect_witness_key: str) -> None:
            mint_correlation(corr)
            before_ev, before_w = len(events), witness[expect_witness_key]
            outcome = "raised"
            try:
                r = coro_or_call()
                if asyncio.iscoroutine(r):
                    await r
                outcome = "returned"
            except Exception as exc:  # denied or blocked paths raise
                outcome = f"raised {type(exc).__name__}"
            mediated = len(events) == before_ev + 1
            attempts.append((name, mediated, outcome))
            after_w = witness[expect_witness_key]
            print(
                f"    bypass[{name}]: {outcome}; mediated={mediated} "
                f"(events {before_ev}->{len(events)}, witness {before_w}->{after_w})"
            )

        # C1 FastMCP.call_tool (server-side convenience API)
        await attempt(
            "C1 FastMCP.call_tool",
            lambda: server.call_tool("calendar.read", args_cal),
            "calendar.read",
        )
        # C2 ToolManager.call_tool (internal dispatch API)
        await attempt(
            "C2 ToolManager.call_tool",
            lambda: manager.call_tool("calendar.read", args_cal),
            "calendar.read",
        )
        # C3 Tool.run (terminal SDK dispatch step)
        await attempt(
            "C3 Tool.run", lambda: manager.get_tool("calendar.read").run(args_cal), "calendar.read"
        )
        # C4 direct tool.fn invocation (the registered function object)
        await attempt(
            "C4 tool.fn direct",
            lambda: manager.get_tool("calendar.read").fn(**args_cal),
            "calendar.read",
        )

        # C5 post-install registration via FastMCP.add_tool (wrap-on-insert)
        def notes_read(q: str) -> str:
            witness["notes.read"] += 1
            return f"notes({q})"

        server.add_tool(notes_read, name="notes.read", description="registered after install")
        await attempt(
            "C5 post-install add_tool",
            lambda: manager.call_tool("notes.read", {"q": "x"}),
            "notes.read",
        )

        # C6 direct registry insertion (bypassing add_tool)
        def evil_tool(q: str) -> str:
            witness["evil.tool"] += 1
            return "evil"

        manager._tools["evil.tool"] = Tool.from_function(evil_tool, name="evil.tool")
        await attempt(
            "C6 direct registry insertion",
            lambda: manager.call_tool("evil.tool", {"q": "x"}),
            "evil.tool",
        )
        # C7 direct request-handler invocation (skip the transport)
        handler = server._mcp_server.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="calendar.read", arguments=args_cal),
        )
        await attempt("C7 request_handlers direct", lambda: handler(req), "calendar.read")
        # C8 denied tool via internal dispatch (transport bypass cannot un-deny)
        mint_correlation(corr)
        before_ev, before_w = len(events), witness["mail.send"]
        try:
            await manager.call_tool("mail.send", args_mail)
            c8_blocked = False
        except Exception:
            c8_blocked = True
        attempts.append(
            ("C8 denied via ToolManager", c8_blocked and len(events) == before_ev + 1, "raised")
        )
        print(
            f"    bypass[C8 denied via ToolManager]: blocked={c8_blocked}; "
            f"event={len(events) == before_ev + 1}; witness {before_w}->{witness['mail.send']}"
        )
        # C9 no unmediated reference reachable from the SDK surface
        no_wrapped_attr = all(
            not hasattr(t.fn, "__wrapped__") and getattr(t.fn, "__aasc_mediated__", False)
            for t in manager._tools.values()
        )
        attempts.append(
            ("C9 no __wrapped__/unmediated fn in registry", no_wrapped_attr, "inspected")
        )
        print(f"    bypass[C9 registry fns]: all mediated, no __wrapped__ = {no_wrapped_attr}")

        record(
            "G-6.C every enumerated bypass path is mediated or blocked",
            all(ok for _, ok, *_ in attempts) and witness["mail.send"] == 0,
            "; ".join(f"{n}:{'ok' if ok else 'FAIL'}" for n, ok, *_ in attempts),
        )

        # ---- G-6.E: raising tool -> exactly one event, error result ----------
        def boom() -> str:
            witness["boom"] += 1
            raise RuntimeError("boom(pilot)")

        server.add_tool(boom, name="boom", description="raises after entry")
        cid = mint_correlation(corr)
        before = len(events)
        result = await client.call_tool("boom", {})
        record(
            "G-6.E raising tool: exactly one event, error surfaced, no duplicate",
            result.isError
            and len(events) == before + 1
            and events[-1].admitted is True
            and events[-1].correlation_id == cid
            and witness["boom"] == 1,
            f"isError={result.isError} events {before}->{len(events)} witness={witness['boom']}",
        )

    # ---- G-6.D: non-vacuity -- interposition removed --------------------------
    bare = build_server(with_boundary=False)
    async with create_connected_server_and_client_session(bare["server"]._mcp_server) as client:
        result = await client.call_tool("mail.send", args_mail)
    await bare["server"]._tool_manager.call_tool("calendar.read", args_cal)
    record(
        "G-6.D interposition removed: tool reached, ZERO events (non-vacuity)",
        not result.isError
        and bare["witness"]["mail.send"] == 1
        and len(bare["outbox"]) == 1
        and bare["witness"]["calendar.read"] == 1
        and len(bare["events"]) == 0,
        f"witness(mail)={bare['witness']['mail.send']} outbox={len(bare['outbox'])} "
        f"witness(cal)={bare['witness']['calendar.read']} events={len(bare['events'])}",
    )


if __name__ == "__main__":
    asyncio.run(main())
    failed = [c for c, ok in RESULTS if not ok]
    print(f"\nG-6 spike: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)
    sys.exit(0)
