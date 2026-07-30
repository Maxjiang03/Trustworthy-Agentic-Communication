"""The Specialist: a deterministic mock receiving the hop and calling the tool.

Registered as the transport handler for its agent name; on receipt it stages
the envelope's credentials with the arm (`arm.present`) and issues the MCP
tool call named by the scripted intent. No LLM, no sampling, no wall-clock
branch: everything it does is a function of the envelope, the SUT-visible
scenario fields it was constructed with, and the injected invocation id.

This agent never reads sealed truth and never computes `R` -- the required
authority is the server's to compute (SS A.5), and the admission decision is
the arm's. It imports nothing from `src/harness/` (red line 6).

`invocation_id_provider` is injected by the composition root and yields the
harness-minted correlation id for the current invocation (SS F.1: the id is
bound into the sealed intent, the records, and -- in B3 -- the INV `jti`).
The SUT receives it; it never mints one. `clock` is likewise injected: the
run's instant comes from the composition root, so the INV window and the
live OAuth token are judged on one clock (see `supervisor.py`).
"""

from collections.abc import Callable, Mapping
from typing import Any

from src.sut.baselines.base import Arm, InvocationContext
from src.sut.protocol.a2a import DelegationEnvelope

ToolCaller = Callable[[str, Mapping[str, Any]], Any]


class Specialist:
    """Receives the delegation; presents credentials; makes the tool call."""

    def __init__(
        self,
        *,
        arm: Arm,
        tool_caller: ToolCaller,
        method: str,
        audience: str,
        clock: Callable[[], int],
        invocation_id_provider: Callable[[], str],
    ) -> None:
        self._arm = arm
        self._tool_caller = tool_caller
        self._method = method
        self._audience = audience
        self._clock = clock
        self._invocation_id_provider = invocation_id_provider

    def receive(self, envelope: DelegationEnvelope) -> Any:
        """The transport handler: one scripted tool call per delegation."""
        tool = envelope.intent["tool"]
        arguments = dict(envelope.intent["arguments"])
        self._arm.present(
            envelope.credentials,
            InvocationContext(
                tool=tool,
                arguments=arguments,
                method=self._method,
                task_id=envelope.task_id,
                audience=self._audience,
                invocation_id=self._invocation_id_provider(),
                now_epoch=self._clock(),
            ),
        )
        return self._tool_caller(tool, arguments)
