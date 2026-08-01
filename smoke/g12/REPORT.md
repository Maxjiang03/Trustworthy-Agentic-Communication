# Gate G-12 — oracle independence under fault injection

**Verdict: PASS**, 2026-08-01, on Windows (the sealed measurement platform, ADR 0014).

**Part G row:** *fault-injected SUT reporting a **wrong** self-verdict while the ledger records the
true effect; plus correlation-ID swap/drop/duplicate/concurrency injection.*
**Criterion:** *the oracle's `admission_breach`/`realized_harm`/`log_integrity_failure` and the
correlation-ID checks detect every discrepancy **without** reading any SUT verdict or SUT digest.*
**Stake, in Part G's own words:** *oracle independence; every security result.*

Run: `make gate GATE=g12` · `uv run python smoke/g12/spike.py`

---

## The seven limbs

| limb | establishes | failing world |
|---|---|---|
| **L1** | The lying SUT, **both directions** | `L1.W1` — non-vacuity: the honest run admits and the direction-2 fault genuinely denies, so the faults changed what *happened*, not only what was claimed |
| **L2** | The oracle is **structurally incapable** of reading a SUT verdict or digest | `L2.W1` — a predicate reading `self_verdict`, caught by the same AST scan |
| **L3** | `log_integrity_failure` fires on a lie, silent on an honest block | both negative arms: honest block → silent; honest admission with an effect → silent |
| **L4** | Correlation faults: swap, drop, duplicate | the uncorrupted records read `CONSISTENT`, so the three detections are not a predicate that flags everything |
| **L4.C** | **Real** cross-process concurrency | four scenarios, four separate SUT child processes |
| **L5** | **DROP told apart from an unreached tool** | the honest run reads `CONSISTENT` |
| **L5.C** | The same, on records from **real runs** rather than constructed ones | — |

## L1 — the lying SUT, both directions

Run in **separated mode**, which is what makes the lie meaningful: the self-report is produced in a
process holding no reference into harness memory, so the records the oracle reads cannot have been
touched by the liar. Before EXP5 STEP 3 this test would have been a program lying to itself.

- **Direction 1 — claims BLOCKED while the tool executes.** Trusted record: `admitted=True`; ledger:
  1 effect. The lie is *invisible to the oracle because the oracle never asked*.
- **Direction 2 — claims ADMITTED while nothing runs.** Trusted record: `admitted=False`; effects: 0;
  linkage: `unreached`. Read as an unreached tool, **not** a successful call.

A gate testing only direction 1 would have tested half of it.

## L2 — the structural half of the criterion

An AST scan of `src/harness/oracle/predicates.py`, on the model of block 1's import red-line test:
the oracle imports no `src.sut` module, and **names none** of `self_verdict`, `audit_log`,
`audit_tail`, `reason_code`, `sut_verdict`, `arm_verdict`, `claimed` — a verdict field can only be
read by naming it, so the absence of the names is the absence of the reading. The scan is shown
non-vacuous two ways: it confirms the oracle *does* name `admitted`, `effect_id`, `correlation_id`
and `intended_request_digest`, and `L2.W1` confirms the same scan catches a predicate that reads
`self_verdict`.

## L5 — DROP versus an unreached tool

**The fault class that deserved the most care, and it is distinguishable.**

Part I reads zero effects as no realized harm — right for an unreached tool. A *dropped* effect
record also produces zero effects. If the two were indistinguishable, deleting evidence would look
exactly like behaving well.

They are told apart because the evidence has **three authors**, and a drop breaks the chain between
them:

```
MediationEvent   emitted in the harness process, which the SUT cannot reach
ToolIngressEvent written at tool ENTRY, by the recorder installed INSIDE the boundary (G-6)
EffectEvent      written by the harness-held effector when the effect happens

        admitted  =>  ingress present  =>  effect present
```

- `UNREACHED` — blocked, **no ingress, no effect**. Nothing ran and nothing is missing.
- `DROPPED` — any break: admitted with no ingress; ingress with no effect; an effect with no ingress.

So **"zero effects" is read as "no harm" only when the earlier records are absent too.** Zero
effects *with* an ingress row present is a missing record and is reported as one. Dropping the
ingress rows as well still reads `DROPPED`, caught against the `MediationEvent`.

**The residual, stated rather than left implicit:** an adversary who could delete the ingress row
*and* the effect row *and* rewrite the `MediationEvent` would produce a consistent-looking
`UNREACHED`. That adversary is excluded not by this predicate but by **G-7** (append-only under a
Win32 exclusive-share handle no SUT process can open — re-verified from a genuinely separate process
in EXP5 STEP 4) and by the mediation record living in a process the SUT cannot reach. This predicate
detects a dropped record; it does not claim to survive an attacker who owns the instrument.

## Why the fault injectors damage copies

The run happens honestly, the records are read back, and the corruption is applied to the read-back
copy the oracle is then asked to judge. A fault injector that could write to the live ledger would
be a hole in the property G-7 established. The oracle cannot tell the difference — it sees records,
not their provenance — which is exactly why this is a valid injection.

`log_integrity_failure`'s world is reproduced the same way, and the reason is recorded: **G-6
established complete mediation**, so there is no bypass path left to drive. The gate shows the
predicate fires on the evidence a bypass *would* leave and stays silent on an honest block; it does
not re-establish complete mediation.

## `obs.raw_arguments` — §J.5 item 20, settled

**It is still a canonical re-serialization, not the bytes as received**, and with a genuine process
boundary that is now a *choice* rather than an artefact — there really are bytes crossing.

`run_scenario` builds it as `rfc8785.dumps(observation["arguments"])` from the arguments the
mediation boundary observed. In separated mode the arguments arrive over the JSON channel, are
decoded, and are re-canonicalized — so a difference in the child's serialization would normalize
away.

**Is Part I's three-digest `realized_harm_F3` still meaningful? Yes, and the reason is precise.**
The three digests are the sealed-intended, the independently-observed and the actual-effect. The
observed one is recomputed by the oracle from `raw_arguments`; the *anchor* is the **sealed** digest,
which no runtime principal can reach. A re-serialization can only lose a difference that RFC 8785
declares non-semantic (member order, spacing) — and if the child sent semantically different
arguments, the canonical bytes differ and the sealed comparison catches it. What the current form
cannot detect is a **non-canonical encoding** of semantically identical arguments, which is a
transport-fidelity question and not an authorization one.

**What would change the answer:** an SDK adapter that made the wire bytes themselves security-
relevant. This gate settles that the present form is sound for the present transport and records the
limit; capturing raw wire bytes remains open and is **G-12's finding to hand forward**, not
something quietly assumed fine.

## Platform

The L1, L4.C, L5.C limbs need the real effect ledger. On POSIX they are reported **NOT ADJUDICATED**
— never "passed" — and the structural limbs (L2, L3, L4, L5) still run, so CI confirms them
cross-platform. The gate's PASS is recorded on Windows.

## Scope

Establishes **oracle independence**. Does **not** re-establish complete mediation (G-6) or ledger
immutability (G-7); does not establish cost (**IA-3** stays `[UNVERIFIED-IA]` for G-3),
multi-process replay (**IA-9**, G-9), or the DPoP taxonomy (G-14). No timing number was produced.
