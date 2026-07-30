# TASK — Experimental body, block 1: the golden-thread end-to-end skeleton (B0 and B3)

Eight gates have passed and every instrument is built: the commitment scheme, the `H_JCS` and
`access_token_hash` digesters, the frozen `Ω`/`Γ` authorizer, the mediation boundary, the effect
ledger, the OAuth 2.1 AS, the HTC/INV verifier, and the frozen identity registry. **What does not
exist is the thing they were built to measure.** `src/sut/agents/`, `src/sut/protocol/`,
`src/sut/capability/`, and `src/sut/baselines/` are empty `__init__.py` files.

This pass builds the **golden thread end to end**: a Supervisor agent, an A2A delegation hop, a
Specialist agent, an MCP tool call, the boundary wiring, and **two of the nine arms — `B0` (no
delegation protection) and `B3` (the full control layer)**. Those two exercise the whole path; the
middle arms are largely configuration over the same substrate once this works.

What rides on it: **G-13, G-12, G-3, G-9, G-14, G-15 and G-10 cannot run until this exists.** They
test timing, concurrency, matched authority, and the reference monitor, and every one of them needs
real agents and real arms. This pass therefore builds the **apparatus**, and adjudicates **no gate**.

Two phases, in order. **Phase A** (STEP 3–9) is the substrate plus `B0`, and ends at a committed,
green, runnable state. **Phase B** (STEP 10–15) adds `B3` on top. If Phase B cannot be finished,
Phase A still leaves the repository better than it found it — that is why the split exists.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the launch
prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Marking **any** gate PASS, started, or adjudicated; editing any Part G row, pass criterion, dependency edge, or evidence grade | This pass builds apparatus, not evidence. G-10 is the pilot-integration gate and sits **last** in the DAG behind G-12/G-13/G-9/G-14 |
| 2 | Modifying `src/harness/authorizer/omega_gamma_v1.json`, `identity_registry_v1.json`, `frozen_config.py`, `Γ`, `Ω`, `H(Γ)`, `H(R)`, or `frozen_parameters.md` rows 8 and 11 | ADR 0016/0019 froze them. A defect found here → **STOP** and write a corrective ADR; never silently patch frozen bytes |
| 3 | Setting `frozen_parameters.md` rows 1–7, 9, 10, or inventing a `task_authorization_policy`, label policy, sink policy, high-risk set, or freshness window `Δ` | Each is a seal-time decision needing its own ADR. Rows 4/6/10 UNSET is precisely why F4/F5 stay unscored (STEP 12) |
| 4 | **Measuring, benchmarking, or reporting any latency, throughput or overhead number** | Row 2 (the G-3 threshold) and row 1 (the equivalence margin) are UNSET and **must** be fixed from external engineering need *before any timing measurement* (Part H step 2, Part J.2). Instrumentation seams are in scope; numbers are not |
| 5 | Creating or populating `fixtures/confirmatory/`, drafting `docs/PRE_REGISTRATION.md`, sealing, or running anything called a campaign | CLAUDE.md red lines 1–2; Part H |
| 6 | Any import of `src/harness/` from `src/sut/`; any import of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/` | CLAUDE.md red line 6 and ADR 0015 rules 3–4. The instrument must never share an implementation with what it adjudicates (D13/D21) |
| 7 | Reusing `src/harness/verifier/holder_binding.py`, `oracle/jcs_digest.py`, `oracle/commitment.py`, `verifier/at_digest.py`, or `authorizer/allowed.py` **as the SUT-side implementation** — by import, copy-with-edit, or shared helper module | D21: the SUT-side signer and boundary verifier must be **independent** of the harness verifier. G-13 owns this obligation and will check it. Independent means separately written, not merely separately filed |
| 8 | Pinning `a2a-sdk`/`a2a-python`, or any new dependency, in `pyproject.toml` | ADR 0004: **a pin never precedes its gate**. The A2A SDK's gate has not run (STEP 3) |
| 9 | A tool that performs a real side effect — sending mail, writing outside a temp dir, network egress | Every effector is a sandboxed stub that records an **intent** and returns, as in `smoke/g7/spike.py` |
| 10 | Letting any SUT principal read `τ_gt`, `IntendedInvocation`, or any sealed-truth object | §A.3 and CLAUDE.md red line 5; enforced structurally in STEP 8 |
| 11 | Implementing `B1`, `B2×5`, `B-cap`, `B3⁺`, the jti cache, the attack suite, the oracle scoring pipeline, or the nine-arm orchestrator | Out of scope. Build the **seams** they plug into, not the arms |
| 12 | `git push --force`, history rewrite, credentials or minted tokens committed to the repo | CLAUDE.md red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read the specification you are implementing

Read, and confirm in the report that you read: **§A.0.1** (`SignedBlock_i`, `P_i`, `Γ`, `κ`, `Ω`,
`C_i`, the hashing rule), **§A.3** (`U_max` / `U_task` / `τ_gt`), **§A.4** (B3 layers on OAuth, it
does not replace it), **§A.5 and §A.5.1** (the enforcement conjuncts in order; the three identity
notions and the `oauth_actor → htc_holder` mapping that MUST NOT require `resource_owner = holder`),
**§A.6/§A.6.1**, **Part C** (the credential-flow row for `B0` and for `B3`), **§E.1/§E.2**
(the ladder; two-phase OAuth, and that Phase-1 setup cost is *excluded* from the delegation
estimand), **§E.3** (`F1-root` vs `F1-terminal`), **§E.5** (the `B0` and `B3` bitmasks),
**§F.1** (every schema, and the unforgeable `correlation_id` paragraph), **§F.2/§F.2.1**,
**§F.3** (INV-1..6), **Part I** in full, and the **Part G G-10 row verbatim** — so you know exactly
what this apparatus must later be able to produce and why you are not producing it yet.

Then read the code you are building on: `src/harness/mediation/boundary.py`,
`src/harness/effect_ledger.py`, `src/harness/schema.py`, `src/harness/authorizer/allowed.py`,
`src/sut/authz/boundary.py`, `src/sut/oauth_as/` (`exchange.issue_initial` in particular), and
`smoke/g7/spike.py` as the worked example of ledger + mediation wiring.

**Report which parts turn out to be underspecified for implementation, and what you did.** G-4
Phase 2 found seven such points and G-11 found three. Do not assume this specification has none, and
do not invent to cover one.

---

# PHASE A — substrate and the `B0` track

## STEP 3 — Decide the A2A transport, and build it behind a port

ADR 0004 records `a2a-python` as **not pinned, its gate not run**, and Part G defines no A2A gate.
You may therefore **not** add the SDK here. Build instead:

- `src/sut/protocol/a2a.py` — a **port**: a `DelegationEnvelope` carrying, at minimum,
  `from_agent`, `to_agent`, `task_id`, `intent`, `context_label`, and an opaque
  `credentials: Mapping[str, Any]` slot that each arm fills differently (empty for `B0`; capability
  prefix + HTC chain + AT for `B3`); plus a `DelegationTransport` protocol with one operation, and
  an in-process adapter implementing it. Field names and message shape follow A2A v1.0 message
  semantics as closely as an in-process adapter can, and every place they diverge is listed.
- The arms and the agents depend on the **port only**. Swapping in an SDK-backed adapter later must
  touch no arm, no agent, and no boundary code. Prove it: the adapter is injected, never imported by
  name at a call site.

Write **ADR 0020** recording (0019 is the current highest; if you write the STEP 11 ADR first, swap
the two numbers and say so): the deferral and why (pin-after-gate), what the in-process adapter
does and does not reproduce (transport, serialization, `TASK_STATE_AUTH_REQUIRED`, error
semantics), the seam that permits the swap, and a note that this is a **construct-validity threat
belonging in §J** — the methodology text claims the official SDK, so the divergence must be
disclosed, not absorbed. Update §J's threat list and `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`
Part B in the same commit.

## STEP 4 — The pilot scenario corpus (specs and generators, never minted tokens)

Create `fixtures/pilot/golden_thread/` holding **scenario specifications plus a generator**, per
ADR 0007 — key *seeds* and specs, never pre-minted tokens. Three scenarios over the frozen `Ω`,
and nothing outside `Ω`:

| id | Shape | `R` | Why it is here |
|---|---|---|---|
| `gt-benign` | Supervisor → Specialist → `notes.write` on `notes/project` | `R ⊆ C_1` | the false-blocking control; `reference_allow` is true |
| `gt-f1-root` | same hop, then `mail.send` on `mail/outbox` | `R ⊄ C_0 = U_task` | the golden thread's headline: scope amplification at the boundary |
| `gt-f1-terminal` | same hop, then `calendar.read` on `calendar/work` where hop 1 narrowed it away | `R ⊆ C_0 ∧ R ⊄ C_1` | the case that distinguishes real per-hop narrowing from root-only enforcement (§E.3) |

Each spec fixes `U_task = C_0`, the per-hop attenuation giving `C_1`, the tool, the arguments, the
audience, the task id, the actor and holder principals **drawn from the frozen registry**, and the
seeds. `C_0` and `C_1` are **computed** by the frozen authorizer at generation time and asserted
against the spec, never hand-written into it — G-2's discipline: compute, never assert.

Two separate documents per scenario, and the separation is the point: a **SUT-visible request**
(what the agents and arms may see) and a **harness-only sealed truth** (`IntendedInvocation`,
including `τ_gt`, `R`, `C_sets`, `P_hashes`). Nothing in the SUT-visible document reveals `τ_gt`
or `R`.

`fixtures/confirmatory/` stays empty. Say so in the report.

## STEP 5 — The MCP tool server over `Ω`

`src/sut/protocol/mcp_tools.py`: a `FastMCP` server exposing exactly the five tools named in the
frozen `Ω` — `calendar.read`, `notes.read`, `notes.write`, `notes.delete`, `mail.send` — each a
**sandboxed stub** whose effector records an `EffectEvent` intent and returns. Nothing is sent,
nothing outside a temp directory is written, no socket is opened.

Each effector receives the harness-held `LedgerWriter` by **injection**; the ledger process owns the
only write path, so a SUT that lies in its self-report still cannot amend or delete what was
recorded. The server-side `required_authority(concrete_request, server_policy)` computing `R` from
tool/resource/args is **server-side and MUST NOT read any agent-supplied field** (§A.5). Give it
its own module and its own test: an agent-declared scope in the envelope must have **no** effect on
`R`.

Wire the two interposition layers in the order `smoke/g7/spike.py` establishes: the ingress recorder
first, the mediation boundary **outermost**, so a denied call reaches neither the recorder nor the
tool. The effect ledger is Win32-only by ADR 0014 — **no silent fallback**: on a non-Windows host
the ledger-dependent path refuses to run and the corresponding tests `skip` with an explicit reason,
exactly as the existing six do.

## STEP 6 — The two deterministic agents and the delegation hop

`src/sut/agents/supervisor.py` and `src/sut/agents/specialist.py`: deterministic mocks driven by the
scenario spec's scripted `intent → delegation → tool-call` trace. No LLM, no sampling, no wall-clock
branch, no dict-ordering dependence; the same spec and seed produce byte-identical envelopes.

The Supervisor holds `U_task` and delegates over the STEP 3 port; the Specialist receives the
envelope and issues the MCP tool call. Neither agent may read sealed truth. Neither agent computes
`R`. What each is allowed to carry is decided **by the arm**, not by the agent — which is what makes
the arms comparable over one substrate.

## STEP 7 — The arm interface, and `B0`

`src/sut/baselines/base.py`: an `Arm` protocol with the operations the ladder needs and no more —
provision (Phase-1 setup), delegate (per hop), present (at the boundary), decide (at the boundary).
Give it the §E.5 bitmask as data, so an arm's configuration is inspectable rather than implied.
`B1`, `B2×5`, `B-cap` and `B3⁺` are **not** implemented here; the interface must not assume their
absence either.

`src/sut/baselines/b0.py`: `B0` — every bit zero. No delegation protection, no credential, no
boundary check. It forwards, and it must be honestly incapable of doing anything else.

## STEP 8 — The harness runner: correlation, records, and the sealed-truth wall

`src/harness/runner.py`, the instrument side:

1. Mint the **unforgeable 128-bit `correlation_id`** per invocation and bind it into the sealed
   `IntendedInvocation`, the `MediationEvent`, the `ToolIngressEvent`, and (Phase B) the INV `jti`.
   Harness-minted, never SUT-supplied.
2. Verify `H(Γ)` and `H(R)` against `frozen_parameters.md` at start-up and **fail closed** on a
   mismatch, before any scenario runs.
3. Assemble the `ObservedRequest` from **raw** evidence — raw bytes, raw arguments — so the oracle
   can recompute every digest itself. No SUT-computed verdict and no SUT-computed digest enters any
   record the oracle reads (§F.1, CLAUDE.md red line 4).
4. The mediation `decide` callable invokes the **arm's** boundary decision and records the outcome.
   State this correctly in the code comment: Part I's *"NOT the SUT"* is about the **provenance of
   the record**, which is the trusted mediation layer, not about who made the decision — the
   decision **is** the mechanism under measurement. If the arm raises, the boundary records a
   denial and the tool does not run (fail closed).
5. `τ_gt` and every sealed object live behind a harness-only accessor. Add a **test that fails** if
   a SUT module can reach one.

Add an **automated import red-line test**: an AST scan asserting no `src/sut/**` module imports
`src/harness/`, no non-AS `src/sut/**` module imports `src/sut/oauth_as/`, and no `src/harness/**`
module imports `src/sut/oauth_as/`. Until now red line 6 has been convention; from this pass onward
there is real code that could cross it.

## STEP 9 — Phase A checkpoint

Run the golden thread under `B0` on all three scenarios. Expected, and expected **because it is the
vulnerability being measured, not because the code is wrong**: `B0` admits `gt-f1-root` and
`gt-f1-terminal`, and the **effect ledger independently records** an effect whose authority lies
outside `C_1` — and for `gt-f1-root`, outside `U_task`. Read that conclusion off the ledger, never
off an agent's self-report.

Then: `pre-commit run --all-files` and `uv run pytest -q` green; report the count on your platform
and the expected split on the other. Commit in logically scoped Conventional Commits (the ADR, the
port, the fixtures, the tool server, the agents, the arm interface + `B0`, the runner, the red-line
test — **not** one giant commit). Push, and verify with `git ls-remote origin main`.

**Report the Phase A result before starting Phase B.** If anything above could not be completed as
written, stop here.

---

# PHASE B — the `B3` track

## STEP 10 — The SUT-side capability signer, written independently

`src/sut/capability/`, importing nothing from `src/harness/`:

- mint `P_0` from the frozen authority template and append the attenuation block giving `P_1`;
- compute the ADR 0003 `BlockID`/`commit_prefix` commitment;
- compute `H_JCS` over arguments (RFC 8785, `rfc8785==0.1.4`) and `access_token_hash` per ADR 0018;
- sign the HTC chain and the INV under the `"AASC-HTC-v1"` / `"AASC-INV-v1"` domain tags with the
  holder identity keys named by the registry.

This is a **second implementation on purpose** (forbidden action 7). Write it from the ADRs and
§F.2, not from the harness source. Then add a harness-side **agreement test** on known vectors: the
SUT signer's output must verify under `src/harness/verifier/holder_binding.verify`, and the two
must agree byte-for-byte on `commit_prefix`, `H_JCS` and `access_token_hash`. Agreement is required;
**shared code is not**. If they disagree, that is a finding — report it, do not reconcile by making
one call the other.

## STEP 11 — Phase-1 OAuth provisioning, over the wire

`B3` runs `oauth_authn = 1` (§E.5) and layers on OAuth rather than replacing it (§A.4), so it needs
a base `AT@aud`. `exchange.issue_initial` is the §E.2 pre-issued path and is deliberately not
reachable from the token endpoint — and no non-AS module may import it.

Resolve it **inside the AS process**: `python -m src.sut.oauth_as` mints one Phase-1 base token per
registered client at start-up and emits them on its existing start-up JSON line, alongside the port,
public JWK, and certificate. Tokens are runtime-only — never written to disk, never committed,
never echoed into `results/`. Record the decision in **ADR 0021**, including why Phase-1 setup is
identical across arms and excluded from the delegation estimand, and why the alternative (a new HTTP
provisioning endpoint) was not taken.

The MCP boundary's OAuth limb **reuses `src/sut/authz/boundary.py` unchanged** —
`verify_access_token`, `allowed_authority`, `admits`. Do not reimplement it and do not extend it.

## STEP 12 — The `B3` boundary decision path

`src/sut/authz/` gains the capability-layer decision path, with **each §A.5 conjunct a separately
named function carrying its own reason code**, evaluated in the specification's order, so a block is
attributable to one condition — the shape G-11 established harness-side:

`crypto_chain_ok` · `authorizer_policy_ok` · `htc_chain_ok` · `holder_proof_ok` ·
`invocation_binding_ok` · `R ⊆ C_n` · `context_policy_ok` · `approval_artifact_ok` ·
`oauth_resource_authorization_ok` · `identity_plane_consistency_ok`.

`C_n = Allowed(P_n; Γ, κ, Ω)` is **computed here, SUT-side, by its own authorizer code** over the
frozen `Γ` and every element of `Ω` — one authorizer run per candidate, as G-2 did, never asserted
and never imported from `src/harness/authorizer/allowed.py`. `B3`'s bitmask also carries
`audit = 1`: emit the structured JSONL decision log, and keep it **off the decision path** so that
disabling it can change latency and log completeness but never a prevention outcome (§E.5).

Two of them cannot be honestly frozen yet: `context_policy_ok` depends on rows 4 and 6, and
`approval_artifact_ok` on row 10, all UNSET. Handle it the way G-4 handled `may_act` and G-7 handled
its vocabulary — **a banner-marked pilot stand-in, never a silent default**:

- the policy object is **injected configuration**, and construction fails if none is supplied;
- the pilot stand-in lives under `fixtures/pilot/`, carries a `PILOT-PROVISIONAL — NOT frozen rows
  4/6/10` banner, and a guard **refuses** it if the run is marked confirmatory;
- the three pilot scenarios carry no `LabelAssertion` and no high-risk action, so neither conjunct
  is load-bearing here — say exactly that, and record that **F4/F5 stay unscored** until those rows
  are frozen by ADR.

The `identity_plane_consistency_ok` limb needs the frozen registry **as sealed configuration
injected by the runner**, mirroring how the AS public key already reaches the boundary. It must not
import `src/harness/verifier/registry`.

## STEP 13 — Run `B3` end to end, and check it can fail

`B3` on the same three scenarios: `gt-benign` **admitted**; `gt-f1-root` and `gt-f1-terminal`
**blocked at `R ⊆ C_n`** with that reason code and **no `EffectEvent` in the ledger** — the ledger,
not the agent, is what shows nothing executed.

Then the discipline that has caught a real error every round: **construct the wrong-outcome world
and confirm it is observable.** For each blocked scenario, show that with the containment conjunct
disabled the call *would* be admitted, so the block is attributable to that conjunct and not masked
by an earlier one — the mistake G-11 found. Do the same for `htc_chain_ok` and
`invocation_binding_ok` with a wrong-holder INV and a tool/argument substitution. Ask of every
check: *if this were broken, would this test catch it?*

## STEP 14 — Instrument the timing seams; measure nothing

Add the measurement seams RQ4 will need — `setup`, `delegation`, `boundary_verification`,
`end_to_end`, decomposed and correlated by `correlation_id`. **Emit no number, benchmark nothing,
and put no timing figure in any report, ADR, or commit message** (forbidden action 4). State in the
report that the seams exist and are unmeasured, and that IA-3 stays `[UNVERIFIED-IA]` for G-3.

## STEP 15 — Say plainly what this apparatus does not yet do

Update `README.md`'s "Current phase" and `CLAUDE.md`'s "Current phase" — both still say
implementation has not begun, which stops being true in this pass. Update `smoke/README.md` **only**
to note that the apparatus the waiting gates need now exists; do **not** touch a gate's status,
report, or ADR column. Correct any statement elsewhere that becomes untrue, and where a statement
was true when written, add a **dated update note** rather than a rewrite — the record must show the
sequence.

---

## STEP 16 — Commit, push, archive

Logically scoped Conventional Commits, ADRs referenced in bodies. Stage new files **before** running
hooks. `pre-commit run --all-files` and `uv run pytest -q` green before each commit; state the count
on your platform and the expected split on the other (the ledger-dependent tests skip off Windows,
ADR 0014 — that is correct, not a failure). Archive this spec under
`docs/tasks/archive/exp1-golden-thread/` with the standing MANIFEST note that task specs are
**retrospective records, NOT pre-registration evidence**. Push and verify with
`git ls-remote origin main`.

---

## STEP 17 — Stop and report

1. STEP 0 self-check.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did about it.
3. **Phase A:** the A2A port and ADR 0020 — what the in-process adapter does and does not reproduce,
   and where the swap seam is. The three scenarios, with `C_0` and `C_1` as **computed**. The five
   tools and the proof that `R` ignores every agent-supplied field. The agents' determinism
   evidence. The `B0` run, and the **ledger** evidence of the amplified effect.
4. The import red-line test: what it scans, and the violation you introduced to confirm it fires.
5. **Phase B:** the SUT-side signer — where it lives, how independence holds, and the agreement
   test against the harness verifier, including anything the two disagreed on.
6. ADR 0021 and the Phase-1 provisioning path; confirmation that no token was written to disk or
   committed.
7. The `B3` decision path: the named conjuncts, their reason codes, their evaluation order, and how
   the two policy-dependent conjuncts are gated on rows 4/6/10 rather than defaulted.
8. The `B3` run, and for each block: which conjunct fired, and the **would-have-failed world** that
   shows it was not masked by an earlier check.
9. The timing seams, unmeasured; IA-3 still `[UNVERIFIED-IA]`.
10. Commits, push verification, test counts on both platforms, and anything you could **not** verify
    yourself.
11. Any point where you were tempted to fill a gap by assumption, to weaken a check so it would
    pass, to reuse a harness implementation to save time, or to build past this specification — and
    what you did instead.
