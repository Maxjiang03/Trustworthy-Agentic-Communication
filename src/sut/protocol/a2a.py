"""The A2A delegation port: envelope, one-operation transport protocol, in-process adapter.

ADR 0020. The official `a2a-python` SDK is **not** used here: ADR 0004's rule is
that a pin never precedes its gate, the SDK's gate has not run, and Part G
defines no A2A gate (an enumeration gap recorded in ADR 0020, not resolved by
inventing one). What exists instead is a **port**: the arms and the agents
depend on `DelegationEnvelope` and `DelegationTransport` only, and the concrete
adapter is **injected** by the composition root (the harness runner or a test).
Swapping in an SDK-backed adapter later must touch no arm, no agent, and no
boundary code -- that seam is the point of the port.

Field names and message shape follow A2A v1.0 message semantics as closely as
an in-process adapter can `[VERIFIED basis: A2A v1.0 defines Message
{taskId, contextId, parts, messageId, role} and an in-task authorization
workflow via TASK_STATE_AUTH_REQUIRED with out-of-band credential acquisition
-- SS A.1]`. Every divergence is listed in ADR 0020 and summarized here:

* **No wire, no serialization.** Delivery is a synchronous in-process call;
  there is no HTTP/JSON-RPC transport, no serialized message, no AgentCard
  discovery, no streaming, no push notifications.
* **No task lifecycle.** No task states and no `TASK_STATE_AUTH_REQUIRED`
  transition; `credentials` ride **in the envelope** (filled by the arm),
  where A2A v1.0 acquires secondary credentials out of band mid-task.
* **Error semantics.** Exceptions propagate in-process; no A2A error codes.
* **Addressing.** `from_agent`/`to_agent` are envelope fields; A2A carries no
  in-message sender/recipient (addressing is transport-level there).
* **Mapping.** `task_id` <-> A2A `taskId`; `intent` <-> `Message.parts` (a
  single structured part); `context_label` <-> loosely `contextId` (here it is
  a pilot context label, not a server-generated grouping id); `messageId` is
  not carried -- correlation is a harness-plane concern (SS F.1), never a
  SUT-supplied field.

This is a **construct-validity threat recorded in SS J** (ADR 0020): results on
the in-process adapter are not automatically results about the official SDK's
transport behaviour, and the divergence is disclosed rather than absorbed.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import rfc8785


class DelegationError(Exception):
    """Base: the delegation port failed closed."""


@dataclass(frozen=True)
class DelegationEnvelope:
    """One Supervisor->Specialist delegation message (the A2A hop).

    `credentials` is an opaque mapping each arm fills differently: empty for
    B0; capability prefix + HTC chain + AT for B3 (Part C credential-flow
    rows). The envelope never carries sealed truth, never carries `tau_gt`,
    and never carries a harness verdict -- it is SUT-visible by construction.
    """

    from_agent: str
    to_agent: str
    task_id: str
    intent: Mapping[str, Any]  # the delegated instruction: {"tool": ..., "arguments": {...}}
    context_label: str
    credentials: Mapping[str, Any]

    def canonical_bytes(self) -> bytes:
        """RFC 8785 canonical bytes of the JSON-modelled fields.

        Used by the determinism regression (same spec, same seed ->
        byte-identical envelopes) and by nothing on any decision path. Fields
        that are raw bytes (a minted capability hop, an HTC, an INV) are
        rendered as lowercase hex so the encoding is total and injective.
        """
        return rfc8785.dumps(
            {
                "from_agent": self.from_agent,
                "to_agent": self.to_agent,
                "task_id": self.task_id,
                "intent": _encodable(self.intent),
                "context_label": self.context_label,
                "credentials": _encodable(self.credentials),
            }
        )


def _encodable(value: Any) -> Any:
    """Render a credentials/intent tree JSON-encodable, bytes as lowercase hex."""
    if isinstance(value, Mapping):
        return {key: _encodable(value[key]) for key in value}
    if isinstance(value, (list, tuple)):
        return [_encodable(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


class DelegationTransport(Protocol):
    """The port: exactly one operation.

    An adapter delivers the envelope to the named recipient and returns the
    recipient's reply object (opaque to the port). Arms and agents depend on
    this protocol only; the concrete adapter is injected, never imported by
    name at a call site (asserted by regression test).
    """

    def deliver(self, envelope: DelegationEnvelope) -> Any: ...


class InProcessDelegationTransport:
    """The in-process adapter: synchronous dispatch to registered handlers.

    A handler is the receiving agent's `receive` callable, registered under
    the agent's name. Delivery to an unregistered recipient fails closed.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[DelegationEnvelope], Any]] = {}

    def register(self, agent_name: str, handler: Callable[[DelegationEnvelope], Any]) -> None:
        if agent_name in self._handlers:
            raise DelegationError(f"agent {agent_name!r} is already registered")
        self._handlers[agent_name] = handler

    def deliver(self, envelope: DelegationEnvelope) -> Any:
        handler = self._handlers.get(envelope.to_agent)
        if handler is None:
            raise DelegationError(f"no registered recipient {envelope.to_agent!r}")
        return handler(envelope)
