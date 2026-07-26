# 0013 — MCP SDK pin: adopt mcp 1.28.1 for the G-6/G-7-verified mediation surface

## Context

Gates G-6 (complete mediation) and G-7 (independent effect ledger) exercise the MCP Python
SDK's tool-call handling (§F.4 IA-6/IA-7). Per the build-vs-reuse rule (ADR 0004) the SDK is
pinned only after its gates pass; both passed in this pass (`smoke/g6/REPORT.md`,
`smoke/g7/REPORT.md`). The official SDK (`mcp` on PyPI, `modelcontextprotocol/python-sdk`) is
the only candidate: it is the reference implementation the architecture document's MCP claims
are stated against, and no alternative Python server SDK implements the current protocol
revision. A pin never asserts more than its gate verified (ADR 0006 precedent).

## Decision

[DESIGN] **Adopt `mcp==1.28.1`, pinned exactly**, for **exactly the surface G-6/G-7
verified**:

- the **FastMCP tool-call dispatch path** — lowlevel `Server.run` → `_handle_request` →
  `request_handlers[CallToolRequest]` → `FastMCP.call_tool` → `ToolManager.call_tool` →
  `Tool.run` → `tool.fn` — enumerated file-and-symbol in `smoke/g6/REPORT.md` §2;
- the **interposition point**: wrapping registered tool-function objects plus the
  wrap-on-insert registry (`src/harness/mediation/boundary.py`) and the tool-entry ingress
  recorder (`src/harness/effect_ledger.py`), both of which reach into the SDK internals
  `FastMCP._tool_manager` / `ToolManager._tools` / `Tool.fn` / `Tool.context_kwarg`;
- the **in-memory client-server session** (`mcp.shared.memory
  .create_connected_server_and_client_session`) used to drive the documented path.

[VERIFIED, gates G-6/G-7] For exactly `mcp==1.28.1` and exactly what ran: every enumerated
dispatch path mediated or blocked; denied calls never execute the tool; raising tools emit
exactly one `MediationEvent`; ingress and effect events recorded through the exclusive-share
ledger with the harness-minted correlation id.

**Everything else about the SDK remains `[UNVERIFIED-IA]`**: A2A integration (`a2a-python`
stays unpinned — its gate has not run), the stdio/SSE/streamable-HTTP transports, the auth
surface, resources/prompts/completions, the experimental task support, and every client-side
surface beyond the in-memory session. None of these is claimed by this pin.

## Status

accepted — 2026-07-26

## Consequences

- **The pin is exact; any version bump of `mcp` re-triggers G-6 and G-7** — the interposition
  targets private internals (`_tool_manager._tools`), so even a patch release can move the
  choke point. The regression suites are the re-trigger harness.
- `uv.lock` regenerated; `uv sync --frozen` verified. The SDK's transitive dependencies
  (anyio, starlette, httpx, uvicorn, …) enter the lock but are not independently claimed.
- §F.4 IA-6/IA-7 → verified-by-gate with residuals; smoke board rows G-6/G-7 → PASS (same
  pass).
- The arms (B0–B3⁺) must build their MCP servers through the harness installers
  (`install_ingress_recorder` then `install_boundary`) so the mediation claim carries over;
  registering tools outside the installers voids it.
