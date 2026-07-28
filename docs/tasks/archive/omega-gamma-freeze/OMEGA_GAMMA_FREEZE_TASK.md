# TASK — Freeze `Ω` (action/resource ontology) and `Γ` (authorizer configuration) — ADR 0016

`docs/frozen_parameters.md` **row 8** is the single item that blocks gate G-2 outright, forces the
C1 stand-in in `smoke/g4/DESIGN.md` §9, and gates the two most expensive arms (`B-cap`, `B3`).
This pass fixes it.

**Full scope is retained — no triage.** All nine arms (`B0`, `B1`, `B2-broad-noexchange`,
`B2-exchange-broad`, `B2-exchange-task`, `B2-exchange-task-DPoP`, `B-cap`, `B3`, `B3⁺`), every
gate in the Part G DAG, and the §K demonstration all stay in scope. This is a **premise of this
task**, not an aside: `Ω` must be rich enough to support every attack family every retained arm is
scored on. An `Ω` sized for a reduced design would silently narrow the experiment.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the
launch prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Setting, drafting, or implying values for `docs/frozen_parameters.md` rows 1–7 or 9 | Each has its own fixing ADR. Row 4 (context-label policy), row 5 (`task_authorization_policy`), row 6 (allowed-sink policy) are **especially** at risk here — see STEP 4 |
| 2 | Running, adjudicating, or marking PASS on G-2 or any other gate; writing a G-2 spike | `Γ` becomes *available* here; G-2 is a separate pass |
| 3 | Writing arm implementations, agents, protocol adapters, the AS, HTC/INV, or the oracle | This pass writes configuration and one ADR |
| 4 | Reducing, deferring, or marking out-of-scope any arm, gate, attack family, or claim | Full scope is retained; this task is not a triage |
| 5 | Touching `docs/PRE_REGISTRATION.md`, Part H step order, `fixtures/confirmatory/`, or any existing gate report | Out of scope |
| 6 | Inventing an `Ω` element whose necessity you cannot state, or one with no corresponding MCP tool | See STEP 3; a phantom element propagates into the AS, the ledger, the oracle, and every result table |
| 7 | `git push --force`, history rewrite, credentials in the repo | CLAUDE.md red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read what constrains `Ω` and `Γ`

Read, and confirm each in the report:

- **§A.0.1** — the frozen symbols, `Ω` as the finite action/resource ontology, and
  `C_i = Allowed(P_i; Γ, κ, Ω) = { x ∈ Ω | authorizer(P_i, x; Γ) = permit ∧ crypto_chain_ok(P_i; κ) }`,
  with `C_0 = U_task`; block identity and prefix commitments (also **ADR 0003**).
- **§A.3** — `U_max` / `U_task` / `τ_gt`, and that `τ_gt` is oracle-only.
- **§A.6.1** — monotone attenuation; **§F.2** — `INV-2 (effective monotone)`.
- **§A.5.1 / §F.2.1** — the identity plane, so you do not conflate principals with authority.
- **The Part G G-2 row, verbatim** — criteria (a)–(d); these drive `Γ` (STEP 5).
- **The `−attenuation` control** (§ around the ablation table) — the matched unsafe control that
  authorizes against `Allowed(P_0; …)`, ignoring every attenuation block.
- **The attack families** F1 (`F1-root` / `F1-terminal` / `F1-chain-tamper`), F2 (including
  `wrong_principal`), F3, F4 — every place a family names or implies a specific action or resource.
- **`smoke/g4/DESIGN.md` §5.2** — `Ω`'s action side maps to RAR `actions`, its resource side to
  `datatypes`/`identifier`; every value must be a member of `Ω`; out-of-`Ω` strings are rejections.
- **ADR 0002** (Biscuit profile: no third-party blocks, never sealed), **ADR 0003** (commitment),
  **ADR 0009** (the tagged/versioned/length-delimited digest family).
- **Part H step 3** — `Ω` and `Γ` with `H(Γ)` are named among the sealed configuration.

**Report explicitly:** the design document specifies `Ω`'s **type, role and constraints** but
nowhere enumerates its **members**. Confirm this reading. `Ω`'s contents are therefore a decision
taken here and recorded in ADR 0016 — not a derivation — and the report must not present them as
if the document already determined them.

---

## STEP 3 — Decide `Ω`, with a stated necessity for every element

`Ω` is a finite set of `(action, resource)` string pairs (`§F.2`: `frozenset[tuple[str,str]]`).
Produce a table: **element · which requirement forces it · the document location of that
requirement**. Nothing enters `Ω` without a filled second column.

Constraints the set **MUST** satisfy — check each explicitly in the report:

1. **The golden thread is expressible.** The user's narrow grant, the Supervisor's delegation, the
   Specialist's hop, and the MCP tool surface all draw from `Ω`.
2. **Amplification is expressible.** At least one element is exposed by the MCP tool surface and
   **outside** the user's grant. Without it the central phenomenon has nothing to be measured on.
3. **Non-trivial attenuation is expressible.** A two-hop chain `C_0 ⊋ C_1 ⊋ C_2` must be
   expressible with each step dropping real authority, so monotonicity is testable rather than
   vacuous.
4. **Every retained attack family has the vocabulary it needs.** For each family, state which
   elements it exercises. `F1-chain-tamper` needs an element to widen *to*; F4 needs at least one
   element that can act as an egress sink; F2 needs elements distinguishable per principal.
5. **Every element corresponds to a real MCP tool** the harness will expose, so the effect ledger
   can record it and the oracle can score it. No element exists only on paper.
6. **The set is small enough to print in the dissertation** as a table a reader can check, and
   large enough to satisfy 1–5. State the size and defend it in one sentence.
7. **The string encoding is part of the frozen artifact.** RAR containment uses byte-exact
   RFC 8259 comparison with no normalization `[VERIFIED, RFC 9396 §12]`, so fix the exact literal
   form of every action and resource string — case, separator, and namespace — and say so.

**STOP and report as a question** if a retained attack family requires an element whose *semantics*
you cannot pin down from the design document. Naming a string is a decision; guessing what a family
needs it to *mean* is not.

---

## STEP 4 — The boundary `Ω` must not cross

`Ω` is a **vocabulary**. It is not a policy. Three separate frozen-parameter rows own the policies,
and all three **stay UNSET** in this pass:

- **row 4** — the context-label → {permit, escalate, block} policy;
- **row 5** — `task_authorization_policy` (task → authorized actor principals), F2 `wrong_principal`;
- **row 6** — the allowed-sink policy for F4.

The trap is concrete: while designating an element that can act as an egress sink (constraint 4),
it is natural to also write down which sinks are allowed. **That is row 6 and it is not yours.**
Name the vocabulary; leave the policy UNSET. State in the report that you checked this boundary.

---

## STEP 5 — Write `Γ`, driven by the G-2 criteria

`Γ` must let an independent verifier compute `Allowed(P_i; Γ, κ, Ω) ⊆ Ω` from a presented Biscuit
token, and must satisfy **by construction** the four things G-2 will test. Give one short rationale
per rule, naming the criterion it serves:

- **(a)** an appended widening fact still verifies cryptographically **and** still leaves
  `C_i ⊆ C_{i−1}` — attenuation stays monotone under default block scoping (§A.0.1: a check or
  policy trusts facts from the authority block, the authorizer, and its own block only);
- **(b)** a third-party block, or `trusting {attacker_key}`, is **rejected as out of profile**
  (ADR 0002);
- **(c)** a mutation of `Γ` that broadens trust is detectable via `H(Γ)`;
- **(d)** the **`−attenuation` control** admits what full `B3` blocks — so `Γ` must be expressible
  in a **matched ablated form** that authorizes against `Allowed(P_0; …)`, ignoring attenuation
  blocks, and is otherwise identical. Ship both forms; the ablation must differ in exactly the one
  respect it is named for, or the control is not matched.

Deliver `Γ` in a form the harness verifier can load and hash, placed per the existing layout rules
(`src/harness/` is the instrument; `src/sut/` must never import from it). State where you put it
and why.

**Scope limit:** write the configuration. Do not write the G-2 spike, do not run it, and leave the
G-2 board row marked as not run.

---

## STEP 6 — `H(Γ)`

The construction **MUST** reuse the tagged, versioned, length-delimited family of ADR 0003/0009 —
never a bare digest — with **its own domain tag**, distinct from every tag already in use
(`AASC-JCS-DIGEST` and the §A.0.1 commitment tag), so the three constructions can never be
confused. Fail closed on an unsupported version. Give the construction, a **worked example** with
the exact input and resulting digest, and the string rendering (lowercase hex, matching ADR 0011).

Note in the report which bytes `H(Γ)` covers: whether it commits to the full form, the ablated
form, or both, and why that choice makes criterion (c) meaningful.

---

## STEP 7 — Record the freeze, and set exactly one row

**ADR 0016** carries: the STEP 2 finding that the document constrained but did not enumerate `Ω`;
the `Ω` table with the necessity column; the encoding decision; the STEP 4 boundary and the three
rows left UNSET; `Γ` with its per-criterion rationale and the matched ablation; the `H(Γ)`
construction with its worked example; and the consequences — G-2 unblocked, `smoke/g4/DESIGN.md`
§9's C1 conflict closed so that G-4 limb needs no stand-in, `B-cap` and `B3` buildable.

Record that `Ω` and `Γ` remain **amendable by a subsequent ADR until Part H step 3**, after which
the seal fixes them; and that any amendment re-triggers G-2 and the G-4 effective-authority limb.

Set `docs/frozen_parameters.md` **row 8** to the frozen values with ADR 0016 named as the fixing
ADR. **Rows 1–7 and 9 stay UNSET, unmodified.** Register ADR 0016 in §B.2.

---

## STEP 8 — Propagate

- `smoke/g4/DESIGN.md` §9 — C1 marked closed, by what, and that the limb no longer needs a stand-in.
- `smoke/README.md` — the G-2 row no longer blocked on `Γ`; still not run.
- Any other place that describes `Ω` or `Γ` as unset. Report anything this spec did not anticipate.

---

## STEP 9 — Commit, push, archive

Logically scoped Conventional Commits, ADR referenced in the body, `pre-commit run --all-files` and
`uv run pytest -q` green before each (expected on Windows: **42 passed**; six ledger tests are
Windows-only per ADR 0014). Archive this spec under `docs/tasks/archive/omega-gamma-freeze/` with
the standing MANIFEST note that task specs are **retrospective records, not pre-registration
evidence**. Push and verify with `git ls-remote origin main`.

---

## STEP 10 — Stop and report

1. STEP 0 self-check.
2. The STEP 2 finding, confirmed or corrected.
3. The `Ω` table with the necessity column; the seven constraints checked one by one; the encoding.
4. The STEP 4 boundary check — and confirmation that rows 4, 5 and 6 are untouched.
5. `Γ`: the rules, the criterion each serves, the matched ablated form, and where it lives.
6. `H(Γ)`: construction, domain tag, worked example, and what it covers.
7. Row 8 set; rows 1–7 and 9 confirmed untouched.
8. Commits, push verification, and anything you could not verify yourself.
9. Any point where you were tempted to fill a gap by assumption, and what you did instead.
