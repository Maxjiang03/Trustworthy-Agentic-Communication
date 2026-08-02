# Gate G-10 — the end-to-end pilot — **PASS**. The DAG is closed.

**Part G's row, verbatim:** *End-to-end pilot: the benign running example through `B0` and `B3`,
producing `ObservedRequest`, `MediationEvent`, `ToolIngressEvent`, `EffectEvent`, and independent
`reference_allow` / `observed_forwarded` / `admission_breach` / `realized_harm` / `false_block`.
**Green; oracle uses only raw evidence + sealed `IntendedInvocation` + trusted mediation/ledger;
every prior DAG gate passed.** — readiness to author the confirmatory corpus.*

Adjudicated 2026-08-02 on the row 9 sealed platform. **Nothing here is timed** — G-3 owns cost and
its figures live in `smoke/g3/` only.

## The scope, and what was deliberately NOT done

G-10 is a **readiness** gate. Its row names the **benign** example, **two** arms, four record types
and five quantities. The apparatus can now run thirteen scenarios across nine arms under two monitor
configurations — and **none of that was run here**. Over-delivery does not strengthen an
adjudication; it makes what was certified ambiguous. Every wider result exists and passes elsewhere.

## L1 — the four record types, both arms, ledger-backed

| arm | `ObservedRequest` | `MediationEvent` | `ToolIngressEvent` | `EffectEvent` |
|---|:--:|:--:|:--:|:--:|
| `B0` | 1 | 1 | 1 | 1 |
| `B3` | 1 | 1 | 1 | 1 |

`B3` produces an effect **because `gt-benign` is the false-blocking control** and `B3` admits it —
the criterion's two arms produce the same complete chain here for different reasons, and both are
right. A missing effect on either would have been a finding, not a fixture to adjust.

## L2 — the five quantities, each produced separately, per arm

| quantity | `B0` | `B3` | expected |
|---|:--:|:--:|:--:|
| `reference_allow` | True | True | True |
| `observed_forwarded` | True | True | True |
| `admission_breach` | False | False | False |
| `realized_harm` | False | False | False |
| `false_block` | False | False | False |

Both arms match the benign shape exactly. A `false_block` on `B3` would have meant the benign
control was being refused — the G-15 result appearing in a configuration where it should not — and
it does not appear.

## L3 — the source restriction, verified **on this run**, not inherited

The criterion's second clause is the substance, and G-12's adjudication was **not** re-asserted for
it. G-12's L2 is the **structural** half: the oracle's source text names no verdict field. This gate
adds the **behavioural** half.

Every input handed to the oracle was wrapped in a recorder — the sealed intent, the observation, the
mediation events, each ledger row, the sealed document — and the scoring read **11 distinct field
names, none of them SUT-supplied**:

```
C_sets, R, action, admitted, correlation_id, credential_fault,
effect_id, intended_labels, is_benign, requires_approval, resource
```

**The `MediationEvent` carries `reason_code`, and the oracle never looked at it.** That is the
point, and it is what a source scan cannot show: a module can name no forbidden field and still be
handed one at run time. Neither half suffices alone.

Non-vacuity is asserted rather than assumed: the recorder confirms the scoring **did** read
`admitted`, `R`, `C_sets` and `effect_id`, so the empty forbidden-set is the absence of a reading,
not the absence of any reading at all.

*(`OracleConfig` — the frozen policy, the trusted key sets, the scenario's `task_id` — is sealed
**configuration**, the same category as `Ω`, `Γ` and the identity registry, and is not a fourth
evidentiary source. `credential_fault` appearing above is ADR 0036's credential gate reading the
**sealed record**, which is exactly where that ADR requires it to come from.)*

## L4 — every prior DAG gate passed. Checked, not recalled.

This is a **conjunct of the criterion**, so the spike runs all fourteen rather than trusting the
board:

`G-1` `G-2` `G-3` `G-4` `G-5` `G-6` `G-7` `G-8` `G-9` `G-11` `G-12` `G-13` `G-14` `G-15` — **all
PASS on this machine.**

Two are stated rather than folded into a count:

- **G-3** is adjudicated on the **row 9 platform only**; its Linux CI run is regression protection
  and never adjudicative. **This is that machine**, so its pass counts here.
- **G-9's `IA-9`** is verified **for the arbiter**, while the ladder's `B3⁺` carries the in-process
  cache by **ADR 0034**. That is a **decision**, not an unrun gate, and the count is not inflated by
  treating it as unfinished business.

## L5 — the failing worlds

A readiness gate that cannot fail certifies nothing, and this one gates the seal.

1. **A missing record type.** `EffectEvent` suppressed: the L1 predicate reports **failure** rather
   than completing on four-fifths of the evidence.
2. **An oracle reading a forbidden source.** `self_verdict` is caught by **this gate's own**
   forbidden-name intersection, not only by G-12's AST scan — the two halves are complementary, as
   L3 explains.

## Platform

`EffectEvent` requires the real ledger, whose enforcement is Win32 share-mode locking and which
**does not degrade** (ADR 0014). Off-platform, L1/L2/L3/L5.1 print **NOT ADJUDICATED** and the spike
records no verdict — the rule G-12 applies to its ledger limbs. A readiness gate that certified
readiness on a platform where the ledger cannot run would certify nothing.

## Adjudication and scope

**PASS.** All four record types on both arms; all five quantities produced independently with the
expected shape; the source restriction verified behaviourally on this run; all fourteen prior DAG
gates passing; both failing worlds caught.

**What this certifies, in the row's own words: readiness to author the confirmatory corpus.**

**What it does not mean, stated because a last gate invites over-reading:**

- it does **not** mean the confirmatory corpus exists, or that its content is decided —
  `fixtures/confirmatory/` is empty and carries no scenario;
- it does **not** mean the seal has happened, or that anything is sealed — `PRE_REGISTRATION.md` is
  still a stub;
- it establishes **no result about any mechanism**. G-10 certifies the **apparatus**. Every finding
  about `B0`, `B3` or any other arm comes from the gates and matrices that measured them.
