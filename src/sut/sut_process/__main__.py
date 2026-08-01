"""The SUT child process: agents, arms and the arm's decision, out of process.

**Spawned, never imported** — the rule ADR 0015 rule 4 set for the AS, applied
to the rest of the system under test (EXP5 STEP 3). `src/harness/sut_process.py`
starts this with `python -m src.sut.sut_process`, reads a start-up JSON line,
and holds the pipe.

**What lives here:** the arm (provision/delegate/present/decide), the Supervisor
and the Specialist, and the in-process A2A transport between them. **What does
not:** the runner, the mediation record, the ledger writer, the effector, the
oracle, and every sealed object. Those stay in the parent, which is what makes
the three STEP 3 properties true:

1. *No shared object graph* — a different address space, so the raw-reference
   and introspection paths gates G-6 and G-7 excluded are excluded by
   construction. `op: "gc_sweep"` lets the parent MEASURE that rather than
   assert it.
2. *The ledger writer stays in the parent* — no ledger path and no writer ever
   reaches this process, so ADR 0014's exclusive-share handle is untouchable
   from here.
3. *The channel carries data, not capability* — `wire.py` is JSON, not pickle.

**The tool is in the parent too.** When the Specialist invokes a tool this
process emits an `invoke` request and blocks for the parent's reply; the
parent's mediation boundary emits the `MediationEvent`, gates execution, and
the harness-held effector writes the ledger. So the DECISION is the SUT's and
the RECORD is the instrument's, which is the separation Part I rests on.

**`self_verdict` is a separate field from `decision`, and that is deliberate.**
`decision` is what the arm decided and what the boundary acts on; `self_verdict`
is what the SUT *claims*. In an honest run they agree. Gate G-12 injects a fault
that makes them disagree, and the oracle must detect it while reading neither —
it reads the trusted mediation record and the ledger.

No sealed object is ever requested or served here: `op: "sealed"` exists only so
STEP 4's channel-attack test can watch it be refused and recorded.
"""

import os
import sys
import traceback
from typing import Any

from src.sut.agents.specialist import Specialist
from src.sut.agents.supervisor import Supervisor
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm
from src.sut.baselines.base import HopContext, InvocationContext
from src.sut.protocol.a2a import InProcessDelegationTransport
from src.sut.sut_process import wire

ARM_CLASSES = {
    "B0": B0Arm,
    "B1": B1Arm,
    "B2-broad-noexchange": B2BroadNoExchangeArm,
    "B2-exchange-broad": B2ExchangeBroadArm,
    "B2-exchange-task": B2ExchangeTaskArm,
    "B2-exchange-task-DPoP": B2ExchangeTaskDPoPArm,
    "B-cap": BCapArm,
    "B3": B3Arm,
    "B3+": B3PlusArm,
}

# Faults gate G-12 may inject. Named here so the set is closed and inspectable:
# a fault the parent can request is a fault this module implements, and nothing
# else. `none` is the honest run.
FAULTS = (
    "none",
    "claim-blocked-while-executing",  # self_verdict lies "blocked"; the tool runs
    "claim-admitted-while-nothing-runs",  # self_verdict lies "admitted"; nothing runs
)


class Session:
    """One SUT process's mutable state. Nothing here outlives the process."""

    def __init__(self) -> None:
        self.arm: Any = None
        self.arm_name: str = ""
        self.fault: str = "none"
        self.credentials: Any = None
        self.presented: Any = None
        self.refused_requests: list[str] = []

    # -- the operations the parent may ask for ----------------------------- #
    def op_provision(self, message: dict) -> dict:
        self.arm_name = message["arm"]
        if self.arm_name not in ARM_CLASSES:
            raise ValueError(f"unknown arm {self.arm_name!r}")
        self.fault = message.get("fault", "none")
        if self.fault not in FAULTS:
            raise ValueError(f"unknown fault {self.fault!r}")
        self.arm = ARM_CLASSES[self.arm_name]()
        self.arm.provision(dict(message["setup"]))
        return {"arm": self.arm.name, "pid": os.getpid()}

    def op_delegate(self, message: dict) -> dict:
        hop = HopContext(
            task_id=message["task_id"],
            audience=message["audience"],
            from_agent=message["from_agent"],
            to_agent=message["to_agent"],
            authority_elements=tuple(tuple(pair) for pair in message["authority_elements"]),
            attenuation_elements=tuple(tuple(pair) for pair in message["attenuation_elements"]),
            widening_elements=tuple(tuple(pair) for pair in message.get("widening_elements", ())),
            now_epoch=message["now_epoch"],
            expiry_epoch=message["expiry_epoch"],
        )
        # The A2A hop happens HERE, between two agents that are both in this
        # process -- the delegation is the SUT's own, as SS E.2 requires.
        transport = InProcessDelegationTransport()
        self.credentials = self.arm.delegate(hop)
        del transport
        return {"credentials": self.credentials}

    def op_present(self, message: dict) -> dict:
        invocation = InvocationContext(
            tool=message["tool"],
            arguments=message["arguments"],
            method=message["method"],
            task_id=message["task_id"],
            audience=message["audience"],
            invocation_id=message["invocation_id"],
            now_epoch=message["now_epoch"],
            payload_labels=tuple(message.get("payload_labels", ())),
            declassification=message.get("declassification"),
            approval_artifact=message.get("approval_artifact"),
        )
        presentation = self.arm.present(self.credentials, invocation)
        return {"presentation": presentation}

    def op_decide(self, message: dict) -> dict:
        """The arm's decision, and the SUT's separate self-report.

        `decision` gates execution in the parent. `self_verdict` is a claim,
        and under an injected fault it disagrees. Both are returned; the oracle
        reads NEITHER (it reads the mediation record and the ledger).
        """
        tool, arguments = message["tool"], message["arguments"]
        try:
            admitted, reason = self.arm.decide(tool, arguments)
        except Exception as exc:  # noqa: BLE001 -- any arm failure is a denial
            admitted, reason = False, f"arm_error:{type(exc).__name__}"
        decision, self_verdict = admitted, admitted
        if self.fault == "claim-blocked-while-executing":
            # The tool still runs (`decision` unchanged); the SUT claims it did
            # not. This is the direction that HIDES a breach.
            self_verdict = False
        elif self.fault == "claim-admitted-while-nothing-runs":
            # Nothing runs; the SUT claims success. This direction MANUFACTURES
            # a false negative -- a gate testing only the first tests half.
            decision, self_verdict = False, True
        return {
            "decision": decision,
            "self_verdict": self_verdict,
            "reason_code": reason,
            "audit_tail": self._audit_tail(),
        }

    def _audit_tail(self) -> Any:
        log = getattr(self.arm, "audit_log", None)
        if not log:
            return None
        entry = dict(log[-1])
        return {key: entry.get(key) for key in ("layer", "arm", "reason", "detail")}

    def op_run_task(self, message: dict) -> dict:
        """The whole SUT side of one scenario: BOTH agents and the A2A hop.

        The Supervisor and the Specialist are constructed HERE and the hop
        between them happens HERE, so what crosses the process boundary is the
        tool invocation and nothing else -- STEP 3's "the agents, the arms and
        the boundary run in a child process".

        The Specialist's `tool_caller` emits an `invoke` request on stdout and
        blocks for the parent's reply on stdin. That nesting is what puts the
        MEDIATION RECORD and the LEDGER in the parent while the DECISION stays
        here: the parent's boundary emits the `MediationEvent`, gates execution
        and writes the ledger; this process never sees any of the three.
        """
        visible = message["visible"]
        now_epoch = int(message["now_epoch"])
        invocation_id = message["invocation_id"]
        self.presented = None

        def tool_caller(tool: str, arguments: dict) -> Any:
            decision = self.op_decide({"tool": tool, "arguments": arguments})
            _reply(
                {
                    "event": "invoke",
                    "tool": tool,
                    "arguments": arguments,
                    "presentation": self.presented,
                    **decision,
                }
            )
            reply = _await_parent()
            return reply.get("result")

        class _PresentCapturing:
            """Wraps the arm so the presented wire material reaches the parent
            without the agent knowing anything about the channel."""

            def __init__(self, arm, session):
                self._arm, self._session = arm, session

            def __getattr__(self, name):
                return getattr(self._arm, name)

            def delegate(self, hop):
                return self._arm.delegate(hop)

            def present(self, credentials, invocation):
                presentation = self._arm.present(credentials, invocation)
                self._session.presented = presentation
                return presentation

            def decide(self, tool, arguments):
                return self._arm.decide(tool, arguments)

        proxy = _PresentCapturing(self.arm, self)
        transport = InProcessDelegationTransport()
        specialist = Specialist(
            arm=proxy,
            tool_caller=tool_caller,
            method=visible["method"],
            audience=visible["audience"],
            clock=lambda: now_epoch,
            invocation_id_provider=lambda: invocation_id,
        )
        transport.register(visible["specialist"], specialist.receive)
        supervisor = Supervisor(arm=proxy, transport=transport, clock=lambda: now_epoch)
        result = supervisor.run(visible)
        return {"result": result, "pid": os.getpid()}

    def op_gc_sweep(self, message: dict) -> dict:
        """Measure property 1 rather than assert it.

        Sweeps this process's whole object graph for the harness types a
        co-resident SUT could otherwise reach by introspection -- the ledger
        writer, the mediation boundary, the effector, the sealed-truth
        accessor. In-process these are findable; here the count must be **0**,
        because they live in another address space.

        Also reports which `src.harness` modules are loaded, so a future edit
        that imported the harness into the SUT process would show up as a
        number rather than as a review miss.
        """
        import gc

        wanted = set(message.get("types", ()))
        found: dict[str, int] = {name: 0 for name in wanted}
        for obj in gc.get_objects():
            try:
                name = type(obj).__name__
            except Exception:  # noqa: BLE001 -- a half-built object is not a match
                continue
            if name in found:
                found[name] += 1
        return {
            "found": found,
            "harness_modules": sorted(m for m in sys.modules if m.startswith("src.harness")),
            "pid": os.getpid(),
        }

    def op_sealed(self, message: dict) -> dict:
        """Refused, always, and the request is recorded (STEP 4).

        There is no branch that could serve one: this process is never given a
        sealed object, so the refusal is not a policy that could be edited away
        -- there is nothing here to return.
        """
        field = str(message.get("field", ""))
        self.refused_requests.append(field)
        return {
            "refused": True,
            "field": field,
            "reason": (
                "no sealed object exists in the SUT process. tau_gt, IntendedInvocation and "
                "C_sets are harness-only (SS A.3, red line 5); this process is never handed one, "
                "so there is nothing to withhold"
            ),
            "refused_requests": list(self.refused_requests),
        }

    def op_ping(self, message: dict) -> dict:
        return {"pid": os.getpid(), "fault": self.fault, "arm": self.arm_name}


OPERATIONS = {
    "provision": Session.op_provision,
    "run_task": Session.op_run_task,
    "delegate": Session.op_delegate,
    "present": Session.op_present,
    "decide": Session.op_decide,
    "gc_sweep": Session.op_gc_sweep,
    "sealed": Session.op_sealed,
    "ping": Session.op_ping,
}


def main() -> int:
    session = Session()
    # The start-up line, mirroring the AS: the parent reads exactly one before
    # sending anything, so a child that failed to import is a startup error
    # rather than a hang.
    sys.stdout.write(
        wire.dumps({"ready": True, "pid": os.getpid(), "operations": sorted(OPERATIONS)}) + "\n"
    )
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        # Every failure below is answered with an `error` reply and the loop
        # continues. A malformed message must not crash this process, because a
        # crash would be indistinguishable from a denial at the parent (STEP 4).
        try:
            message = wire.loads(line)
        except Exception as exc:  # noqa: BLE001
            _reply({"error": "unparseable", "detail": str(exc)[:200]})
            continue
        if not isinstance(message, dict):
            _reply({"error": "not-an-object", "detail": type(message).__name__})
            continue
        operation = OPERATIONS.get(str(message.get("op", "")))
        if operation is None:
            _reply({"error": "unknown-op", "detail": str(message.get("op"))[:80]})
            continue
        try:
            _reply({"ok": True, **operation(session, message)})
        except Exception as exc:  # noqa: BLE001 -- report, never die
            _reply(
                {
                    "error": type(exc).__name__,
                    "detail": str(exc)[:400],
                    "trace": traceback.format_exc()[-600:],
                }
            )
    return 0


def _await_parent() -> dict:
    """Block for the parent's reply to a nested `invoke` request.

    A closed pipe or an unparseable reply is a DENIAL here, not an exception
    that would unwind into a half-finished task: the SUT cannot conclude
    anything from the harness going away.
    """
    line = sys.stdin.readline()
    if not line:
        return {"result": None, "error": "parent-closed"}
    try:
        message = wire.loads(line.strip())
    except Exception:  # noqa: BLE001
        return {"result": None, "error": "parent-reply-unparseable"}
    return message if isinstance(message, dict) else {"result": None}


def _reply(message: dict) -> None:
    sys.stdout.write(wire.dumps(message) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
