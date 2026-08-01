# Gate G-15 — the shared F4/F5 reference monitor

**Verdict: PASS**, 2026-08-01. All five mandatory limbs hold, each with the world in which it fails,
judged by the *same* predicate that judges the real one.

**Part G row:** *F4/F5 comparisons run only among `B3` and its matched ablations, **or** with the
same reference monitor on the OAuth arms.*
**What rides on it:** that no capability-versus-OAuth claim rests on a **configuration** difference
dressed as a mechanism difference.

Run: `make gate GATE=g15` · `uv run python smoke/g15/spike.py` · wired into CI beside G-4, G-11 and
G-13, so its platform-independence is **confirmed by running it** rather than assumed.

---

## The five limbs

| limb | what it establishes | the world in which it fails |
|---|---|---|
| **L1** | The OAuth arms and `B3` run the **same monitor class object** over the **same** frozen policy `H(Λ)`, and derive an **identical** `authz_context_hash` for one request | `L1.W1` — a monitor attachable to `B3` alone. Then no configuration exists under which an OAuth arm could block, `A†` is unfalsifiable, and *"`B3` blocks and OAuth does not"* can never be told apart from *"`B3` has a monitor and OAuth cannot have one"* |
| **L2** | All **72** F4/F5 cells measured — 4 fixtures × 9 arms × **2 configurations** | a single column, which could not tell `A†` apart from *"this arm cannot express the case"* |
| **L3** | Every within-configuration cross-arm comparison is sound under `comparison_is_sound()` | `L3.W1` — `B3` (monitored, **blocked**) compared against `B2-exchange-task` (unmonitored, **admitted**): the flattering comparison. Caught, with both arms named |
| **L4** | Every check is shown able to fail | four worlds, all caught: monitor on `B3` only · mixed-configuration claim · a cell recorded with no configuration · **a forged artifact accepted** |
| **L5** | `A†` survives: no configuration cell renders as a bare letter, and the dagger sits on **exactly** the pairs that measurably flip | `L5.W1` — an `A†` cell recorded with its configuration dropped. `MatrixError`, not a convention |

**L1 is structural, not behavioural.** Object identity (`b2mod.ContextApprovalMonitor is
b3mod.ContextApprovalMonitor`), plus an AST scan proving exactly **one** `ContextApprovalMonitor`
definition exists in `src/`. Two implementations that agree today would satisfy no criterion: they
could drift, and the drift would surface as a mechanism difference in the results.

**L4's W4 is the one that keeps the family meaningful.** A *genuine* approval is accepted and a
*forged* one — real signature, key nobody trusts — is refused. Without both halves, "the monitor
blocks" and "the monitor blocks everything" are the same measurement, and the attacks and the
controls would produce the same cell.

**L5 caught a real defect in this block's own code.** The renderer daggered every
admitted-and-unmonitored cell, which after ADR 0032 is wrong twice over: `B-cap`/`B0`/`B1` cannot
reach a monitor at all, and the benign **controls** are admitted under both configurations because
their artifact is valid, not because a monitor is absent. Corrected to decide the dagger from the
measured **pair**. The gate found it; that is what the gate is for.

## What was measured

`monitor_attached` is **configuration**, never an arm property, and every number below carries it.

| fixture | B0 | B1 | the four OAuth arms | B-cap | B3 / B3⁺ |
|---|:--:|:--:|:--:|:--:|:--:|
| `gt-f4-sensitive-egress` | A / A | A / A | **A† → B** | A / A | **B / B** |
| `gt-f4-declassified` *(control)* | A / A | A / A | A / **A** | A / A | **B** / **A** |
| `gt-f5-unapproved-high-risk` | A / A | A / A | **A† → B** | A / A | **B / B** |
| `gt-f5-approved` *(control)* | A / A | A / A | A / **A** | A / A | **B** / **A** |

*(each cell reads `monitor_attached=false / monitor_attached=true`)*

The OAuth blocks name the family's own conjunct — `b2_context_policy` for F4, `b2_approval_artifact`
for F5 — and so do `B3`'s: `b3_context_policy` with the egress and the missing
`DeclassificationArtifact` named, `b3_approval_artifact` with row 10's high-risk set named.

## The residual — this is the finding, not a limitation

> **With the shared monitor, F4/F5 measure the monitor rather than the mechanism.** No
> capability-versus-OAuth advantage may be claimed from these two families in either direction.

The OAuth arms admit absent the monitor and block with it; `B3` blocks in both configurations but
for **different reasons**, and that difference is the second half of the finding. It belongs in the
**results chapter**, in those words — not in limitations.

## The second result, which belongs beside it

> **Without a monitor configured, `B3` and `B3⁺` refuse the benign controls too**, because both
> policy conjuncts fail closed. So the capability policy plane is useful **only when a monitor is
> configured**: without one, `B3` is not safer on these families — it admits nothing.

That is a **result**, not a defect. The fail-closed refusal is correct and deliberate (block 2 built
it that way after finding `context_policy_ok` reading an unverified label), and its cost is a
false-block on legitimate labelled traffic. It belongs in the **results chapter and the
false-blocking analysis**, beside the residual above, rather than in limitations.

## Two `A†` corrections this gate rests on

- **ADR 0031** — `B-cap`'s two F3 OAuth-negative-control cells: `NA` → **B**. `NA` asserts the arm
  *cannot express* the case (ADR 0028); §E.1/E6 *mandates* `oauth_authn = 1` and "MUST verify
  audience and expiry", and it measurably blocks.
- **ADR 0032** — `B-cap`'s two F4/F5 cells: `A†` → plain **A**. The dagger means *flips with
  configuration*; `B-cap`'s `context = 0, approval = 0` means the monitor's verdicts could only
  arrive through the conjuncts its bitmask gates off, so attaching one is **a change of arm, not a
  change of configuration** — `context = 1, approval = 1` *is* `B3`.

One drafting cause behind both: §E.4 filled `B-cap` in as *"a capability arm"* rather than from its
own §E.5 bits. Both corrected **predictions**; no code changed and no measured cell moved.

## Scope — what this gate does NOT establish

It establishes that the F4/F5 **comparison is sound**, not that any arm is better. It does not
establish cost (**IA-3** stays `[UNVERIFIED-IA]` for G-3), the DPoP taxonomy (**G-14**),
process-separated mediation (**G-12**), or multi-process replay (**IA-9** stays `[UNVERIFIED-IA]`
for G-9). `frozen_parameters` row 5 stays UNSET, so `F2 wrong_principal` stays unscored (ADR 0028).
**No timing number was produced by this gate or anywhere in this block.**
