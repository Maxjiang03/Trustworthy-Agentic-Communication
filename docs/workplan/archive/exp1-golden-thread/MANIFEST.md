# EXP1 golden-thread task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-07-30:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP1_TASK.md` | 342 | `1dabb04387f13a475fdb185c38e8feaab0086b40c0c4ac1bda9b71235b404ea6` |

## Chronology (2026-07-30, after G-11 and the ADR 0019 freeze)

This is the **first pass of the experimental body**, and the first that **adjudicates no gate**.
Eight gates had passed and every instrument existed; what did not exist was the thing they were
built to measure. `src/sut/agents/`, `protocol/`, `capability/` and `baselines/` were empty
`__init__.py` files. This pass built the **golden thread end to end** — Supervisor → A2A
delegation hop → Specialist → MCP tool call — and **two of the nine arms**, `B0` and `B3`.

**Phase A** (STEP 3–9) built the substrate and the `B0` track: the A2A **port** with an
in-process adapter (ADR 0020 — `a2a-python` stays unpinned because ADR 0004's pin-after-gate
rule has no A2A gate to attach to, an enumeration gap recorded for the author rather than closed
by inventing one); the pilot corpus as **specs plus a generator and a seed, never minted tokens**
(ADR 0007), with `C_0`/`C_1` **computed by the frozen authorizer and asserted against the spec**;
the five sandboxed `Ω` tools with server-side `R` that provably ignores every agent-supplied
field; the deterministic agents; the arm interface with the §E.5 bitmask as data; the harness
runner with the unforgeable 128-bit `correlation_id`, the fail-closed `H(Γ)`/`H(R)` start-up
check, and the sealed-truth wall; and the **import red lines made executable** (a deliberately
introduced `src.harness` import in `b0.py` made the suite fail before being removed). Phase A
ended green at `a7eb539`, pushed, seven scoped commits.

**Phase B** (STEP 10–15) added the `B3` track: the **SUT-side capability signer**, a second
implementation written from ADR 0003/0009/0018 and §F.2 rather than from harness source, with a
harness-side agreement suite pinning byte-for-byte agreement on `commit_prefix`, `H_JCS` and
`access_token_hash` (ADR 0018's worked example reproduced by both sides) — **agreement required,
shared code not**, which is what D21/G-13 need; **Phase-1 provisioning inside the AS process**
(ADR 0021), emitted on the existing start-up line to the runner-held pipe, tokens runtime-only;
and the **B3 decision path** with each §A.5 conjunct a separately named function carrying its own
reason code, `C_n` computed SUT-side by its own authorizer code, and the two policy-dependent
conjuncts gated on `frozen_parameters` rows 4/6/10 by an injected PILOT-PROVISIONAL stand-in that
construction refuses to default and that a confirmatory run refuses outright.

## Two findings from running rather than reading

1. **The `authorizer_policy_ok` discriminator masked containment.** The naive reading — "the
   authorizer refused, so `authorizer_policy_ok` fails" — also matched the **attenuation block's
   own check**, which is the *authority* plane, so every F1 amplification was attributed to
   `authorizer_policy_ok` instead of `R ⊆ C_n`. The STEP 13 counterfactual suite caught it. The
   fix discriminates on the check's **origin** (`Check n°N in authorizer` vs `Check n°N in block
   n°M`), with both message shapes pinned by test. This is the G-11 masking lesson recurring
   exactly: a rejection for a reason other than the one targeted is an untested condition, not a
   pass. **The criterion was not weakened** — the block still happens, it is now attributable.
2. **Two clocks in one decision.** The corpus published a frozen logical `now_epoch`, but the
   OAuth access token is minted by a live AS against the real clock, so the capability plane and
   the OAuth plane were being judged against instants ~12 hours apart. The fixture now publishes
   a validity **duration** and the runner injects the instant, so one clock governs every
   credential window. Determinism is unaffected: minted capability bytes are non-reproducible by
   construction anyway (ADR 0007, a G-1 verified fact).

## What this pass deliberately did NOT do

No gate marked, started, or adjudicated; no Part G row, pass criterion, dependency edge or
evidence grade edited. No frozen artifact modified and no `frozen_parameters` row set. **No
latency, throughput or overhead number measured, benchmarked or reported** — the RQ4 seams exist
and are correlated by `correlation_id`, and `IA-3` stays `[UNVERIFIED-IA]` for G-3.
`fixtures/confirmatory/` stays empty (the corpus generator refuses to run otherwise). `B1`,
`B2×5`, `B-cap`, `B3⁺`, the jti cache, the attack suite, the oracle scoring pipeline and the
nine-arm orchestrator are **not** built — only the seams they plug into.
