# 0020 — The A2A hop is a port with an in-process adapter; the SDK stays unpinned

## Context

The experimental body needs the Supervisor→Specialist delegation hop (the A2A leg of the
A2A→MCP boundary) before any arm can run. ADR 0004's build-vs-reuse rule says `a2a-python`
enters only as a pinned dependency **after its gate passes** — *a pin never precedes its gate* —
and ADR 0004 lists the SDK among the planned reuse targets. But **Part G defines no A2A gate**:
the DAG runs G-1…G-15 and none of them exercises the A2A SDK. That is an **enumeration gap** of
the same kind the §F.4 note records for "IA (HTC correctness)": the reuse plan names a
dependency whose admission gate does not exist. Following the G-11 discipline (*do not invent
identifiers or gates to close a gap*), this ADR records the gap and leaves defining an A2A gate
— or deciding none is needed — to the author.

Meanwhile the apparatus cannot wait: G-13, G-12, G-3, G-9, G-14, G-15 and G-10 all need real
agents delegating over a real seam.

## Decision

[DESIGN] The delegation hop is built **behind a port**, and the SDK is **not** added:

- `src/sut/protocol/a2a.py` defines `DelegationEnvelope` (fields: `from_agent`, `to_agent`,
  `task_id`, `intent`, `context_label`, and an opaque `credentials` mapping each arm fills
  differently — empty for B0; capability prefix + HTC chain + AT for B3), and
  `DelegationTransport`, a protocol with exactly **one operation**, `deliver(envelope)`.
- `InProcessDelegationTransport` is the sole adapter in this pass: synchronous, in-process
  dispatch to registered handlers, failing closed on an unregistered recipient.
- **The seam that permits the swap:** arms and agents depend on the port only. The adapter is
  **injected by the composition root** (the harness runner or a test); no arm, agent, or
  boundary module names the adapter class. A regression test asserts this by AST scan, so an
  SDK-backed adapter later replaces one constructor call site and touches no arm, no agent, and
  no boundary code.

### What the in-process adapter does and does not reproduce

Reproduced (as closely as an in-process object can): the message *shape* — a task-scoped
delegation carrying `taskId`-equivalent (`task_id`), a structured instruction
(`intent` ↔ `Message.parts`), and a context field (`context_label` ↔ loosely `contextId`).

**Not reproduced** — each a named divergence, disclosed rather than absorbed:

1. **Transport and serialization.** No HTTP/JSON-RPC wire, no serialized message bytes, no
   AgentCard discovery, no streaming, no push notifications. Delivery is a Python call.
2. **Task lifecycle and `TASK_STATE_AUTH_REQUIRED`.** A2A v1.0 defines an in-task authorization
   workflow in which a task transitions to `TASK_STATE_AUTH_REQUIRED` and secondary credentials
   are acquired out of band **[VERIFIED basis: §A.1's verified thesis paragraph]**. The adapter
   has no task states; `credentials` ride in the envelope, filled by the arm.
3. **Error semantics.** In-process exceptions, not A2A error codes.
4. **Addressing.** `from_agent`/`to_agent` are envelope fields; A2A addresses at the transport
   level and carries no in-message sender.
5. **`messageId`.** Not carried: correlation is harness-plane (§F.1's unforgeable
   `correlation_id`), never a SUT-supplied field.
6. **Evidence bytes.** With no wire form, the `ObservedRequest.raw_arguments` bytes the harness
   records are the canonical serialization of the presented arguments mapping observed at the
   boundary, not captured wire bytes. The oracle's recomputation contract (§F.1) is unchanged.

### Construct-validity threat, recorded in §J

The methodology text (ADR 0004, Part B) plans the **official SDK**; this pass measures over an
in-process adapter. Any conclusion about A2A *transport* behaviour would therefore not follow
from runs on this adapter, and the divergence **belongs in §J's threat list** — added to
`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §J.5 in the same commit as this ADR, alongside the
ADR 0014 platform-bound-ledger entry, which is the precedent for recording a validity threat
rather than absorbing it. What the benchmark measures — authorization issuance, propagation,
attenuation, and invocation binding across the boundary — is carried in the envelope contents
and the boundary checks, which the port preserves; the claim boundary is stated, not assumed.

## Rejected alternatives

- **Pin `a2a-sdk`/`a2a-python` now.** Violates ADR 0004 (no gate has run; none is defined), and
  EXP1 forbidden action 8. Rejected outright.
- **Vendor or reimplement a subset of the SDK's wire protocol.** A half-faithful wire is worse
  than a declared port: it would *look* like the SDK surface while diverging in undisclosed
  ways, exactly the silent-divergence failure mode CLAUDE.md forbids. The port makes the
  divergence explicit and total.

## Status

accepted — 2026-07-30

## Consequences

- `src/sut/protocol/a2a.py` exists; arms and agents depend on the port only; the adapter is
  injected. Regression tests cover determinism of the envelope encoding, fail-closed delivery,
  the swap seam (a test double implements the protocol without touching arm/agent code), and
  the no-adapter-import rule (AST scan).
- §J.5 gains item 20 (the in-process A2A adapter as a construct-validity threat); Part B.2
  registers this ADR. Same commit — never silently.
- **Open, author's call:** whether Part G should gain an A2A-SDK gate (the pin-after-gate rule
  has nothing to attach to today). Until then the SDK stays unpinned and the port stands.
- When an SDK gate exists and passes, the SDK-backed adapter implements `DelegationTransport`
  and replaces the in-process adapter at the composition root; divergences 1–5 close and
  divergence 6 (evidence bytes) is revisited — the wire bytes become recordable.
