"""The Supervisor: a deterministic mock driving the scripted delegation.

Driven entirely by the SUT-visible scenario document's scripted
`intent -> delegation` trace: no LLM, no sampling, no wall-clock branch, no
dict-ordering dependence -- the same spec and the same injected credential
state produce byte-identical envelopes (`DelegationEnvelope.canonical_bytes`,
regression-tested). Times come from the spec's frozen logical epoch, never
from a clock.

The Supervisor holds `U_task` -- the one authorization input any runtime
principal sees (SS A.3) -- and delegates over the injected transport port.
**What the envelope carries is decided by the arm, not by this agent**
(`arm.delegate`), which is what makes the arms comparable over one substrate.
This agent never reads sealed truth and never computes `R`; it imports
nothing from `src/harness/` (red line 6).
"""

from collections.abc import Mapping
from typing import Any

from src.sut.baselines.base import Arm, HopContext
from src.sut.protocol.a2a import DelegationEnvelope, DelegationTransport


class Supervisor:
    """Holds the task grant; delegates the scripted intent to the Specialist."""

    def __init__(self, *, arm: Arm, transport: DelegationTransport) -> None:
        self._arm = arm
        self._transport = transport

    def run(self, visible: Mapping[str, Any]) -> Any:
        """One scripted delegation, from the SUT-visible scenario document."""
        hop = HopContext(
            task_id=visible["task_id"],
            audience=visible["audience"],
            from_agent=visible["supervisor"],
            to_agent=visible["specialist"],
            authority_elements=tuple(
                (action, resource) for action, resource in visible["authority_elements"]
            ),
            attenuation_elements=tuple(
                (action, resource) for action, resource in visible["attenuation_elements"]
            ),
            now_epoch=visible["now_epoch"],
            expiry_epoch=visible["expiry_epoch"],
        )
        envelope = DelegationEnvelope(
            from_agent=hop.from_agent,
            to_agent=hop.to_agent,
            task_id=hop.task_id,
            intent=dict(visible["delegation_intent"]),
            context_label=visible["context_label"],
            credentials=self._arm.delegate(hop),  # the arm decides what is carried
        )
        return self._transport.deliver(envelope)
