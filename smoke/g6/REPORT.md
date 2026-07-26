# Gate G-6 Report — complete mediation in the MCP SDK tool-call path

## 1. Gate

- **Gate:** G-6 (construct-validity tier of the Part G DAG: `G-1 / G-5 / G-8 → G-6 / G-7 → …`)
- **Assumption tested:** IA-6 — *"The MCP Python SDK exposes tool-call handling where the
  boundary can mediate **every** call (complete mediation) and emit a `MediationEvent`"*
  (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4). Pass criterion (Part G): no tool call
  executes without passing the boundary and emitting a `MediationEvent`. The load-bearing word
  is **every**: the gate asks whether a path exists that *skips* the boundary.
- **Date:** 2026-07-26.
- **Blocks on failure:** IA-6; construct validity of every result (Part G failure policy:
  re-architect interposition before any confirmatory work).

## 2. Call-path enumeration (the gate's central evidence)

SDK: `mcp==1.28.1` (official `modelcontextprotocol/python-sdk`), source inspected, not the
README. Every path by which a registered tool function can be reached:

| # | Path | Route (file:symbol) | Dominated by the interposition? |
|---|---|---|---|
| P1 | **Documented protocol path** | `ClientSession.call_tool` → JSON-RPC → `Server.run` **[VERIFIED, mcp-sdk 1.28.1, server/lowlevel/server.py:646]** → `Server._handle_message` (:698) → `Server._handle_request` (:725) → `request_handlers[CallToolRequest]` — the closure built by `Server.call_tool()` (:498–595), registered once by `FastMCP._setup_handlers` **[VERIFIED, server/fastmcp/server.py:302–308, `validate_input=False`]** → `FastMCP.call_tool` (:343) → `ToolManager.call_tool` **[VERIFIED, server/fastmcp/tools/tool_manager.py:81–93]** → `Tool.run` **[VERIFIED, server/fastmcp/tools/base.py:93–117]** → `FuncMetadata.call_fn_with_arg_validation` **[VERIFIED, server/fastmcp/utilities/func_metadata.py:75–96]** → `tool.fn(**args)` | **Yes** — `tool.fn` *is* the boundary wrapper (spike G-6.A) |
| P2 | `FastMCP.call_tool(name, args)` direct (server-side convenience) | server/fastmcp/server.py:343 → P1 tail | **Yes** (bypass C1) |
| P3 | `ToolManager.call_tool` direct (internal dispatch) | tool_manager.py:81 → `Tool.run` → fn | **Yes** (bypass C2) |
| P4 | `Tool.run(arguments)` direct (terminal SDK dispatch step) | base.py:93 → fn | **Yes** (bypass C3) |
| P5 | `tool.fn(...)` direct (the registered function object) | base.py:27 `Tool.fn` | **Yes** — the stored fn is the wrapper (bypass C4) |
| P6 | **Registration paths**: `@FastMCP.tool()` decorator **[VERIFIED, server/fastmcp/server.py:446; the decorator body (:493) calls `self.add_tool` and returns the RAW fn to the definer]**; `FastMCP.add_tool` (:397); `ToolManager.add_tool` (tool_manager.py:45–73); direct registry insertion `manager._tools[name] = Tool` | all end in `dict.__setitem__` on `ToolManager._tools` | **Yes** — the installer replaces `_tools` with a wrap-on-insert registry (`update`/`setdefault` routed through `__setitem__` too); bypasses C5/C6 confirm post-install `add_tool` and raw insertion are both wrapped |
| P7 | Direct invocation of `request_handlers[CallToolRequest]` with a forged `CallToolRequest` (transport bypass) | lowlevel server.py:592 | **Yes** — the handler still runs P1's tail (bypass C7) |
| P8 | **Handler replacement**: re-invoking `Server.call_tool()` overwrites `request_handlers[CallToolRequest]` (:592) | a replacement handler can only reach tool functions it can obtain; every fn reachable from the SDK surface is wrapped, and none exposes `__wrapped__` (bypass C9) | **Yes, conditionally** — see the in-process limit below |
| P9 | **Experimental task-augmented execution** | `server/lowlevel/experimental.py:88 enable_tasks`; `shared/experimental/tasks/*` | **Opt-in; never enabled by the harness.** Even enabled, tool execution originates in the same `CallToolRequest` handler (the registered func may return `CreateTaskResult`, server.py:548–550); the auto-registered `tasks/get`·`tasks/result`·`tasks/list`·`tasks/cancel` handlers do not invoke tool functions **[VERIFIED, experimental.py:155–239]** |
| P10 | **Error/retry re-entry** | the handler calls `func` exactly once per request (server.py:541) and converts exceptions via `_make_error_result` (:589–590); `Tool.run` wraps tool exceptions in `ToolError` (base.py:116–117) | **No retry/re-entry path exists**; G-6.E confirms exactly one event for a raising tool |
| P11 | **Streaming/batched variants** | none for tool calls: no JSON-RPC batch handling in 1.28.1 (batching removed by the 2025-06-18 MCP revision); progress notifications dispatch no tools; `list_tools` (fastmcp/server.py:315) reads metadata only | n/a — no such dispatch exists |

Resources, prompts, and completions are separate request families (separate handlers), not
tool calls; the toy and pilot servers register none. `remove_tool` deletes only.

**In-process limit (stated, not hidden).** Two things no SDK interposition can dominate:
(i) the `@tool()` decorator hands the RAW function back to the *defining* module (P6), so the
definer always holds an unmediated reference — the harness convention (enforced in the spike,
tests, and later the arms) defines tool functions in installer-managed local scope so no raw
reference survives installation; (ii) arbitrary in-process Python (closure introspection,
re-assigning `tool.fn`) is raw interpreter power, outside any SDK's mediation. Both are
excluded architecturally: the SUT never executes inside the tool-server process `[DESIGN]`;
adversarial SUT reporting is stressed further at G-12.

## 3. Interposition point

Wrap-at-fn plus wrap-on-insert registry (`src/harness/mediation/boundary.py`): the installer
replaces every registered `Tool.fn` with a mediated wrapper (decide → emit exactly one
`MediationEvent` → run or raise `MediationDenied`) and swaps `ToolManager._tools` for a
registry that wraps on insertion. All P1–P8 converge on `tool.fn`, which is why this single
point dominates every dispatch path; `fn_metadata`/`parameters`/`is_async` derive from the
original function, so the advertised schema and argument validation are unchanged. The
boundary carries **no policy** — decision, correlation supply, and event sink are injected
callables (pilot policy lives in the spike/tests; the frozen vocabulary is arm territory).

## 4. Results

Passing run: `uv run python smoke/g6/spike.py` → **exit code 0** (5/5), in-memory transport
only (no sockets). Permanent suite `tests/test_complete_mediation.py`: **7 tests, 7 passed**,
each with positive and negative arms.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-6.A documented path | yes | **PASS** | one client call → exactly one `MediationEvent` carrying the harness-minted 128-bit `correlation_id`, `admitted=True`, pilot `reason_code="ok(pilot)"`, `boundary_ts_ns>0`; tool witness = 1 |
| G-6.B denied call | yes | **PASS** | `admitted=False` event; client sees `isError`; **tool-side witness untouched** (a counter inside the tool body the boundary cannot write) = 0; sandbox outbox empty |
| G-6.C bypass attempts | yes | **PASS** | one attempt per enumerated non-documented path: C1 `FastMCP.call_tool`, C2 `ToolManager.call_tool`, C3 `Tool.run`, C4 `tool.fn`, C5 post-install `add_tool`, C6 direct registry insertion, C7 forged-request handler invocation — **all mediated** (event emitted); C8 denied tool via internal dispatch — **blocked** with `admitted=False`; C9 registry inspection — every fn mediated, none exposes `__wrapped__` |
| G-6.D non-vacuity | yes | **PASS** | interposition removed → the same calls **reach the tool** (witness=1, sandbox outbox=1) and **zero events** are emitted: the checks detect mediation, not an unrelated failure |
| G-6.E error path | yes | **PASS** | a raising tool produces exactly **one** event (no zero, no duplicate); error surfaces as `isError`; a subsequent healthy call works |

## 5. Outcome

**PASS** — all five mandatory checks and all seven regression tests green; `mcp==1.28.1`
pinned for exactly this surface (ADR 0013).

## 6. Consequences for the design

- `mcp==1.28.1` pinned; `uv.lock` regenerated; `uv sync --frozen` verified (ADR 0013).
- §F.4 IA-6 → verified-by-gate with residuals; smoke board G-6 → PASS (same pass).
- The arms must build their MCP servers through the harness installer; tools registered
  outside it void the mediation claim (ADR 0013 consequence).

## 7. Reproduction

```
uv run python smoke/g6/spike.py                 # after the ADR 0013 pin
make gate GATE=g6                               # equivalent, via the venv
uv run pytest tests/test_complete_mediation.py -q
```

## 8. Residual risks

- The interposition targets **private SDK internals** (`_tool_manager._tools`, `Tool.fn`);
  the pin is exact and **any `mcp` bump re-triggers G-6**.
- The completeness claim is scoped to **FastMCP servers built by the harness installer**; a
  lowlevel-`Server` user registering its own `call_tool` handler is a different construction
  (enumerated as P8) and would need its own installation.
- In-process raw-reference/introspection paths are excluded by process separation of the SUT,
  not by the SDK (§2, in-process limit); G-12 stresses the adjacent adversarial-reporting
  surface.

## 9. What this gate does NOT establish

- **Not** that the boundary's **policy** is correct — only that the boundary is
  **unavoidable**. The pilot allow/deny function is a placeholder; the real conjuncts
  (§A.5) are arm/oracle territory (G-2, G-11, G-13).
- **Not** the effect ledger or ingress recording — that is **G-7**.
- **Not** oracle correctness (Part I) or fault detection under adversarial correlation
  swap/drop/duplicate — **G-12**.
- **Not** any baseline arm, A2A hop, capability check, or OAuth flow; no `Ω`, no `Γ`, no
  frozen reason-code vocabulary (pilot codes only, exactly as G-1 used a pilot vocabulary).
- **Not** the stdio/SSE/streamable-HTTP transports, auth, resources/prompts, experimental
  tasks, or any client-side surface beyond the in-memory session (ADR 0013 scope).
