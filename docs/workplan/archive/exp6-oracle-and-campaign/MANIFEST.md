# EXP6 oracle, campaign entry point and analysis-code task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-08-02:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP6_TASK.md` | 261 | `f570bbcdc1093ec3a9fce251a1a70793cabec9a44feca15e21bd6b796c87502d` |

## What the block produced

**The study can now score itself.** Before this block, Part I specified ten predicates and five
existed — every one a by-product of gate G-12 — so the F1/F4/F5 matrix cells were
`(admitted, reason_code)` pairs compared against §E.4. That is *the arm's own verdict, read back*,
which is precisely what G-12 had proved the oracle must never do.

| Phase | Delivered |
|---|---|
| **A** | The seven missing predicates — `reference_allow`, `admission_breach`, `false_block`, `realized_harm_F1`/`_F2`/`_F4`/`_F5` — plus `src/harness/oracle/artifacts.py` (Part I's two undefined validators) and `src/harness/verifier/credential_principal.py` (what produces `cred_result`) |
| **B** | `src/harness/campaign.py`: one entry point over the existing stack, four fail-closed preconditions, a per-run record for Part H step 6, and **the pilot matrix produced from oracle verdicts for the first time** |
| **C** | `analysis/`: the pre-registered statistical procedure as code — exact counts with **no** interval on the security side, and ADR 0026's *stands*/*retracted* rule with a 95% bootstrap CI on the latency side, tested on synthetic samples on **both** sides of the 20 ms margin |

No ADR was authored: every decision this block made was a resolution of something Part I left
open, recorded in the code that makes it, and none amended a frozen row, `Ω`/`Γ`, the registry,
the policy document or any `H(·)`.

## Four decisions Part I handed over rather than defined

Recorded because each could have been let happen by default:

1. **`authority_from_effects`** is exactly `{(e.action, e.resource)}` — two ledger-side fields.
   Every other candidate is disqualified by *what it is*: the presented scope is the **claim**, and
   comparing what happened against what was asserted is the thing the predicate exists to avoid.
2. **`reference_allow`'s family gates** — sealed truth says *whether* a gate applies, raw evidence
   says whether it is *satisfied*. Applied identically across all five families and all nine arms.
3. **`cred_result`** is produced by an independent harness-side credential verifier built on the
   RFC 9068 §4 reimplementation G-13 owns (D21), never on the arm's own check.
4. **`false_block`'s `is_benign`** is read from the sealed record and raises if absent, rather than
   being accepted from a caller who could mark an attack benign.

## Findings the block reported rather than smoothed over

- **The artifact-plumbing defect.** `run_scenario` built every `ObservedRequest` with
  `payload_labels=[]`, `declassification=None`, `approval_artifact=None` — **hardcoded** — and the
  Specialist built its `InvocationContext` without them. Invisible to every unit test, because
  those drive the arm directly. Through the campaign, every F4/F5 control would have scored as a
  **false block** and every F4/F5 attack correctly **for the wrong reason** — and one of those
  directions flatters the mechanism. The eighth instance of the standing hazard, and the first a
  build step surfaced on its own.
- **A retracted claim of independence.** The first version of the campaign suite described the
  oracle/reason-code agreement as *"two independent readings coinciding"*. It is not: both trace to
  the same trusted `MediationEvent`, so the agreement is **structural**. What the oracle genuinely
  adds is `reference_allow` and `admission_breach` — `gt-benign`/`B0` and `gt-f1-root`/`B0` carry
  the same outcome and the same reason code, and exactly one is a breach.
- **Two Part I underspecifications**, reported rather than absorbed: `valid_declassification` and
  `valid_approval_binds` are named and never defined; and §F.2's `authz_context_hash` binds a
  `task_id` that Part F.1's `IntendedInvocation` does not carry.
- **G-12's L2 scan was widened** from one oracle module to the whole package — a scan that
  certifies a module which reads nothing while the module it calls reads everything is worse than
  no scan. Not asked for by the specification.

## Scope note

The block delivered STEP 3–12 in full. What it did **not** do, and did not claim to: **no timing
number was produced anywhere** — the campaign carries the measurement seams as **names**, not
durations, because forbidden action 1 forbids *producing* one; the estimator saw only **synthetic**
samples; **no gate was run, prepared or marked** and no Part G row moved; `IA-3` stays
`[UNVERIFIED-IA]`; no frozen row, `Ω`/`Γ`, registry, policy document or `H(·)` was amended; row 5
stays deferred (ADR 0028) and row 9 unset; `fixtures/confirmatory/` carries no scenario; and
`PRE_REGISTRATION.md` remains a stub, as Part H requires until every in-scope smoke gate passes.
