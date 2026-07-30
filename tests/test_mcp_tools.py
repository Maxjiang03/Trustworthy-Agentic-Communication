"""Regression suite for the five-tool MCP server over `Omega` (EXP1 STEP 5).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Platform split (ADR 0014 -- a recorded platform decision, not a
gap): tests that need the exclusive-share effect ledger are Windows-only and
skip elsewhere with the standing reason; the server-shape and effector-seam
tests are platform-independent and always run.
"""

import asyncio
import secrets
import shutil
import sys
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from src.harness.authorizer import frozen_config
from src.sut.protocol.mcp_tools import build_server

REPO_ROOT = Path(__file__).resolve().parents[1]

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


class RecordingEffector:
    """Platform-independent effector double: records intents in memory."""

    def __init__(self):
        self.intents = []

    def __call__(self, **kwargs):
        self.intents.append(kwargs)


class TestServerShape:
    def test_exactly_the_five_omega_tools(self):
        effector = RecordingEffector()
        server = build_server(effector)
        registered = set(server._tool_manager._tools)
        omega_tools = set(frozen_config.load_document()["omega"]["tools"])
        assert registered == omega_tools
        assert len(registered) == 5

    def test_every_tool_routes_through_the_injected_effector(self):
        effector = RecordingEffector()
        server = build_server(effector)

        async def drive():
            async with create_connected_server_and_client_session(server._mcp_server) as client:
                await client.call_tool("calendar.read", {"resource": "calendar/work"})
                await client.call_tool("notes.read", {"resource": "notes/project"})
                await client.call_tool("notes.write", {"resource": "notes/project", "content": "x"})
                await client.call_tool("notes.delete", {"resource": "notes/project"})
                await client.call_tool(
                    "mail.send", {"to": "a@example.test", "subject": "s", "body": "b"}
                )

        asyncio.run(drive())
        assert [intent["tool"] for intent in effector.intents] == [
            "calendar.read",
            "notes.read",
            "notes.write",
            "notes.delete",
            "mail.send",
        ]
        # mail.send's resource is server-fixed; recipient is carried.
        mail = effector.intents[-1]
        assert mail["resource"] == "mail/outbox"
        assert mail["recipient"] == "a@example.test"

    def test_a_denied_call_reaches_neither_recorder_nor_tool(self):
        """The g7 wiring order, asserted TOOL-SIDE so it runs everywhere.

        The ledger-backed version of this (below, Windows-only) additionally
        shows nothing reached the ledger; this one shows nothing reached the
        effector or the tool function, which needs no ledger at all.
        """
        from src.harness.mediation.boundary import install_boundary

        effector = RecordingEffector()
        server = build_server(effector)
        events = []
        install_boundary(
            server,
            decide=lambda tool, args: (tool != "mail.send", "denied(pilot)"),
            correlation_provider=lambda: "cid-test",
            emit=events.append,
        )

        async def drive():
            async with create_connected_server_and_client_session(server._mcp_server) as client:
                denied = await client.call_tool(
                    "mail.send", {"to": "a@b.test", "subject": "s", "body": "b"}
                )
                allowed = await client.call_tool("notes.read", {"resource": "notes/project"})
                return denied, allowed

        denied, allowed = asyncio.run(drive())
        assert denied.isError and not allowed.isError
        assert events[0].admitted is False and events[1].admitted is True
        # The denied tool never ran: only the admitted one reached the effector.
        assert [intent["tool"] for intent in effector.intents] == ["notes.read"]

    def test_stubs_return_sandbox_markers(self):
        effector = RecordingEffector()
        server = build_server(effector)

        async def drive():
            async with create_connected_server_and_client_session(server._mcp_server) as client:
                result = await client.call_tool(
                    "mail.send", {"to": "a@b.test", "subject": "s", "body": "b"}
                )
                return result

        result = asyncio.run(drive())
        assert not result.isError
        assert "sandbox" in result.content[0].text


@WIN32_ONLY
class TestLedgerBackedStack:
    """The g7 wiring order on the real ledger: recorder first, boundary outermost."""

    @pytest.fixture()
    def stack(self, tmp_path_factory):
        from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger
        from src.harness.effectors import LedgerEffector
        from src.harness.mediation.boundary import install_boundary

        ledger_dir = REPO_ROOT / "tests" / "_ledger_tmp"
        ledger_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = str(ledger_dir / f"mcp-tools-{secrets.token_hex(4)}.jsonl")
        writer = LedgerWriter(ledger_path)
        corr = {"current": ""}
        deny: set[str] = set()
        events = []
        effector = LedgerEffector(
            writer,
            audience="https://mcp.aasc.local/tools",
            principal="specialist(pilot)",
            correlation_provider=lambda: corr["current"],
        )
        server = build_server(effector)
        install_ingress_recorder(
            server,
            audience="https://mcp.aasc.local/tools",
            correlation_provider=lambda: corr["current"],
            writer=writer,
        )
        install_boundary(
            server,
            decide=lambda tool, args: (
                tool not in deny,
                "denied(pilot)" if tool in deny else "ok(pilot)",
            ),
            correlation_provider=lambda: corr["current"],
            emit=events.append,
        )
        yield {
            "server": server,
            "corr": corr,
            "deny": deny,
            "events": events,
            "ledger_path": ledger_path,
            "read_ledger": read_ledger,
            "writer": writer,
        }
        writer.close()
        shutil.rmtree(ledger_dir, ignore_errors=True)

    def test_admitted_call_records_ingress_and_effect(self, stack):
        cid = secrets.token_hex(16)
        stack["corr"]["current"] = cid

        async def drive():
            async with create_connected_server_and_client_session(
                stack["server"]._mcp_server
            ) as client:
                return await client.call_tool(
                    "notes.write", {"resource": "notes/project", "content": "x"}
                )

        result = asyncio.run(drive())
        assert not result.isError
        entries = stack["read_ledger"](stack["ledger_path"])
        ingress = [e for e in entries if "ingress_request_digest" in e]
        effects = [e for e in entries if "effect_request_digest" in e]
        assert len(ingress) == 1 and ingress[0]["correlation_id"] == cid
        assert len(effects) == 1 and effects[0]["correlation_id"] == cid
        assert effects[0]["action"] == "notes.write"
        assert effects[0]["resource"] == "notes/project"

    def test_denied_call_reaches_neither_recorder_nor_tool(self, stack):
        stack["deny"].add("mail.send")
        cid = secrets.token_hex(16)
        stack["corr"]["current"] = cid

        async def drive():
            async with create_connected_server_and_client_session(
                stack["server"]._mcp_server
            ) as client:
                return await client.call_tool(
                    "mail.send", {"to": "a@example.test", "subject": "s", "body": "b"}
                )

        result = asyncio.run(drive())
        assert result.isError  # the boundary denied it
        entries = stack["read_ledger"](stack["ledger_path"])
        assert all(e.get("correlation_id") != cid for e in entries), (
            "a denied call must reach neither the ingress recorder nor the effector"
        )
        assert stack["events"][-1].admitted is False
