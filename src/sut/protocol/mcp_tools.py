"""The MCP tool server over the frozen `Omega`: five sandboxed stub tools.

Exactly the five tools the frozen ontology names (`omega.tools`, ADR 0016) --
`calendar.read`, `notes.read`, `notes.write`, `notes.delete`, `mail.send` --
each a **sandboxed stub** whose only observable act is calling the injected
effector with what it is about to (not) do. Nothing is sent, nothing is
written anywhere, no socket is opened; the smoke/g7 mail stub is the worked
example this generalizes.

**The effector is injected, harness-held.** The SUT defines the seam (a
callable taking tool/action/resource/recipient/arguments) and never sees the
ledger writer behind it: the ledger process owns the only write path into the
ledger file (gate G-7), so a SUT that lies in its self-report still cannot
amend or delete what was recorded. This module imports nothing from
`src/harness/` (CLAUDE.md red line 6).

Interposition wiring (recorder, then mediation boundary outermost, so a
denied call reaches neither the recorder nor the tool) is the HARNESS's job
at composition time, in the order `smoke/g7/spike.py` establishes; this
module only builds the bare server.
"""

from collections.abc import Callable
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

SERVER_NAME = "aasc-tools(pilot)"


class Effector(Protocol):
    """The injected effect seam: record an INTENT to act, and nothing else."""

    def __call__(
        self,
        *,
        tool: str,
        action: str,
        resource: str,
        recipient: str | None,
        arguments: dict[str, Any],
    ) -> None: ...


def build_server(effector: Effector, *, name: str = SERVER_NAME) -> FastMCP:
    """The five-tool FastMCP server, every effector call routed via injection.

    Each tool's action is its own name (Omega's actions are tools) and its
    resource follows `src/sut/protocol/required_authority.SERVER_POLICY`:
    read from the designated argument, or fixed (`mail.send` -> `mail/outbox`).
    """
    server = FastMCP(name)

    def calendar_read(resource: str) -> str:
        effector(
            tool="calendar.read",
            action="calendar.read",
            resource=resource,
            recipient=None,
            arguments={"resource": resource},
        )
        return "read-intent recorded (sandbox; no calendar exists)"

    def notes_read(resource: str) -> str:
        effector(
            tool="notes.read",
            action="notes.read",
            resource=resource,
            recipient=None,
            arguments={"resource": resource},
        )
        return "read-intent recorded (sandbox; no notebook exists)"

    def notes_write(resource: str, content: str) -> str:
        effector(
            tool="notes.write",
            action="notes.write",
            resource=resource,
            recipient=None,
            arguments={"resource": resource, "content": content},
        )
        return "write-intent recorded (sandbox; nothing written)"

    def notes_delete(resource: str) -> str:
        effector(
            tool="notes.delete",
            action="notes.delete",
            resource=resource,
            recipient=None,
            arguments={"resource": resource},
        )
        return "delete-intent recorded (sandbox; nothing deleted)"

    def mail_send(to: str, subject: str, body: str) -> str:
        effector(
            tool="mail.send",
            action="mail.send",
            resource="mail/outbox",  # fixed by server policy; not caller-addressable
            recipient=to,
            arguments={"to": to, "subject": subject, "body": body},
        )
        return "send-intent recorded (sandbox; nothing sent)"

    stubs: dict[str, Callable[..., str]] = {
        "calendar.read": calendar_read,
        "notes.read": notes_read,
        "notes.write": notes_write,
        "notes.delete": notes_delete,
        "mail.send": mail_send,
    }
    for tool_name, fn in stubs.items():
        server.add_tool(fn, name=tool_name, description=f"sandboxed stub for {tool_name}")
    return server
