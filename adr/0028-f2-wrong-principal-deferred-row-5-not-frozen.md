# 0028 — `F2 wrong_principal` is deferred and unscored; `frozen_parameters` row 5 stays unfrozen

## Context

Row 5 is the `task_authorization_policy`: a mapping from a task to the actor principals authorized
to carry it. §E.4's expected matrix has one row that depends on it —
**`F2 wrong_principal (frozen task→principal policy)`** — and gate G-4 carries a standing residual
because of it: the AS's `may_act` was populated from a **spike-local** delegation policy precisely
because row 5 is unset (ADR 0017), so that family is not scored.

Every other frozen parameter in this design anchors to something outside the author's judgement.
`Ω`/`Γ` anchor to the golden thread's expressive needs (ADR 0016); the identity registry to §F.2.1's
structure (ADR 0019); rows 4/6/10 to §A.6's label lattice (ADR 0022/0023); the delegating client's
grant to §A.3's "the AS mints `U_task` as `P_0`" (ADR 0024); the latency parameters to published
figures (ADR 0025/0026); `Δ` to clock-skew convention (ADR 0027).

**Row 5 has no such anchor.** There is no standard, no RFC and no reference deployment that fixes
which principal may carry which task. Any value would be an artifact this author invented, and the
`wrong_principal` result would then measure conformance to that artifact rather than any property
of MCP, A2A or OAuth 2.1.

**Verified before drafting** (at the Commander's instruction): `task_authorization_policy` has **no
code consumer anywhere in the repository** — it appears only in two comments recording that it is
unset. In particular, **both `B2-exchange-task` provisioning paths consume only ADR 0024's task
grant and never a row 5 policy.** Deferring the family therefore removes a scored row; it does not
disturb a single built arm.

## Decision

`[DESIGN]` **Row 5 is not frozen. The `F2 wrong_principal` subfamily is deferred and unscored.**
The other three `F2` subfamilies — **`invalid_credential`**, **`wrong_holder_proof` /
`wrong_dpop_key`**, and **`unauthenticated_caller`** — are **retained and scored in full**. `F2` as
a family is not dropped; one of its four subfamilies is.

### 1. Construct-scope argument

`wrong_principal` asks whether the *right actor* is carrying a task. That is the **subject
authentication** question. This thesis measures **authorization-scope propagation across the
A2A→MCP boundary** — whether narrow user authority survives a delegation hop. The two are
different constructs, and the retained `F2` subfamilies already cover the authentication surface
that the boundary can decide from evidence with an external anchor: a credential that does not
verify, a holder proof that does not match the registered key, a caller presenting nothing.
Scoring a fourth subfamily against a policy this author wrote would add a number without adding a
construct.

### 2. Mechanism: claim-dependent deferral, as Part G already provides

Part G: *"**Claim-dependent gates** … run **only** for claims retained in the sealed scope; a
deferred claim's gate is marked **deferred** and must not contradict that deferral."* This decision
uses that mechanism rather than inventing one. The `F2 wrong_principal` row of §E.4's expected
matrix is re-annotated **`deferred — unscored (ADR 0028)`**; its nine cells are **not** recorded as
`NA`, because `NA` means *this arm cannot express the case* and would be false — the arms could
express it, the study declines to score it. The distinction is the whole point of the annotation.

### 3. G-4's `may_act` residual is released, not left hanging

G-4's row records `may_act` as spike-local *pending row 5*. Because row 5 will now never be set,
that residual is **explicitly released** by a dated update note: the spike-local delegation policy
is the **final** configuration for this study, no longer provisional, and it is sealed with the AS
configuration at Part H step 3 like any other AS parameter (ADR 0017). A residual that is
permanently unresolvable must be closed by decision; leaving it marked *pending* would state
something untrue for the rest of the project's life.

### 4. Pre-registration and held-out obligations, before the seal

Before Part H step 3: `PRE_REGISTRATION.md` records the deferral, its reason and its scope; **and
the held-out subset is scanned to confirm it contains no `wrong_principal` variant.** The held-out
third exists to test generalization to unseen instances *within the retained threat model* — an
instance of a deferred subfamily surviving in it would be scored against a policy that does not
exist, or silently dropped at analysis time after the results are visible. It is checked before
the seal, when the check can still change something.

### 5. Validity threat, stated in §J

§J gains: *this study makes **no claim** about task-to-principal authorization enforcement. A
deployment binding tasks to authorized principals may block cases this benchmark does not score,
and the absence of a `wrong_principal` result must not be read as evidence that any arm fails to
handle it.* An unscored family is a limit on what was measured, not a finding about the mechanisms.

## Rejected alternatives

**Freeze row 5 with an invented policy.** Rejected: the resulting number would measure conformance
to an author-made artifact. Worse, it would be **indistinguishable in the results tables** from the
rows anchored to `Ω`/`Γ`, the registry and the RFCs — a reader could not tell which numbers rest on
something external. Reporting nothing is more honest than reporting something ungrounded.

**Drop `F2` entirely.** Rejected: the other three subfamilies are anchored, scored, and are where
`B2-DPoP` and `B3` are distinguished on holder binding. Dropping them would discard a real result to
tidy a table.

**Mark the row `NA`.** Rejected: `NA` asserts the arms cannot express the case, which is false. The
deferral is the study's choice and must be labelled as the study's choice.

**Leave row 5 `UNSET` without an ADR.** Rejected: that is the status quo, and it leaves G-4's
residual reading *pending* forever and the §E.4 row reading as though it will be filled. An
unresolvable pending item is a decision that has not been written down.

## Status

accepted — 2026-07-31 (row 5 of `docs/frozen_parameters.md` — **deliberately not set**; amendable by
a later ADR until Part H step 3)

## Consequences

- `docs/frozen_parameters.md` row 5 is annotated **deferred by decision (ADR 0028)** rather than
  left as an open `⟨UNSET⟩` awaiting a value.
- §E.4's `F2 wrong_principal` row is re-annotated `deferred — unscored`; §J gains the validity
  statement; G-4's `may_act` residual is released by a dated update note. `smoke/g4/REPORT.md` is
  **not** rewritten — the note is appended, and the gate's adjudication is untouched.
- No built arm changes, because none consumes row 5. Confirmed by scan before drafting.
- The confirmatory attack suite and the held-out subset carry **no** `wrong_principal` variant, and
  this is verified before the seal rather than at analysis time.
- **Re-triggered by:** a decision to restore the family, which would require freezing row 5, a new
  ADR, an update to `PRE_REGISTRATION.md` and re-opening G-4's `may_act` limb.
