# 0037 — The held-out third is cut; RQ3 is answered on seen instances only

## Context

Part H step 4 requires the confirmatory corpus to be generated **including a held-out third**, and
**RQ3** asks for the per-family attack outcome and the false-blocking outcome *"on seen and sealed
held-out instances."* Neither exists. Building them is a self-contained block of new machinery: a
split derived deterministically from the sealed seed, stratified by family, sealed before any
instance runs, unreadable by the campaign at scoring time, with disjointness asserted on
specification and seed content hashes rather than on token bytes (ADR 0007).

The remaining schedule does not have room for it and for the work that must precede the seal —
the last three credential subcases, gate G-3, gate G-10, and the pre-registration document. Of
those, none is severable: G-3 and G-10 are gates, the pre-registration seals the design, and the
three subcases carry the entire `F2` and `F3` result. The held-out third is the only remaining item
that can be removed without removing a result.

This is a scope decision taken **before the seal and before any confirmatory run**, when it is a
declaration rather than a post-hoc exclusion. Taken afterwards it would be neither.

## Decision

`[DESIGN]` **The held-out third is cut. RQ3 is answered on seen instances only.** No split is
generated, none is sealed, and the confirmatory corpus is a single set.

### 1. What this does not touch

The study's main-line results do not rest on the held-out subset, and each can be named:

- **RQ1/RQ2** — scope amplification at the A2A→MCP boundary, measured by the `F1` family and the
  independent effect ledger.
- **G-13** — matched per-hop authority across all five strong baselines; the fairness of the entire
  comparison.
- **G-15** — the shared reference monitor and its residual, that `F4`/`F5` measure the monitor
  rather than the mechanism.
- **G-14** — the DPoP/INV attribution.
- **RQ4** — the latency estimand and ADR 0026's decision rule.

None consumes a held-out instance. The cut removes an arm of RQ3; it removes no other question.

### 2. What is lost, stated precisely rather than minimised

Pre-registration and a held-out subset defend against **different** threats, and only one of them
survives this decision:

- **Pre-registration** seals the design, the predicates, the thresholds and the analysis before the
  confirmatory run, so the analysis cannot be chosen after seeing the results. This protection is
  **unaffected** and remains in force.
- **A held-out subset** would additionally have addressed **instance-selection bias**: the risk
  that an author-constructed suite contains instances the mechanisms were, consciously or not,
  built to catch. **This protection is forfeited**, and no other part of the design substitutes
  for it.

Partial mitigations exist and must be reported as partial, not as replacements: the mechanisms and
the frozen parameters were fixed before most scenarios were written; every gate criterion had to be
**shown able to fail**; and §E.4's expected matrix was written in advance, so a disagreement between
a cell and a measurement is recorded as a finding rather than reconciled.

### 3. How RQ3 must be reported

RQ3's answer is qualified **wherever it appears** — the results chapter, the abstract if RQ3
features there, and §J:

> This study reports attack and false-blocking outcomes on the **constructed** instance set only.
> It makes **no claim** about generalization to instances outside that set.

The word *"generalizes"* and its variants must not appear in any RQ3 claim.

### 4. ADR 0028's scan obligation moves rather than dissolves

ADR 0028 requires that **the held-out subset be scanned** to confirm it contains no
`wrong_principal` variant, because a deferred subfamily surviving in it would be scored against a
policy that does not exist, or silently dropped at analysis time. **That risk does not disappear
with the split; it applies to the whole corpus.** The obligation is therefore **re-pointed, not
removed**: before the seal, **the entire confirmatory corpus** is scanned for any `wrong_principal`
variant, as an executed test rather than a note. Letting an obligation lapse because the object it
named was cut is exactly how a deferred family would quietly re-enter scoring.

## Rejected alternatives

**Build a smaller held-out set — a fifth or a tenth rather than a third.** Rejected: the machinery
is the cost, not the size. A split still needs deterministic derivation, family stratification,
sealing before any run, and unreadability at scoring time. A smaller set buys a weaker version of
the same guarantee for the same effort.

**Keep the held-out arm of RQ3 and answer it after the seal.** Rejected outright: a split
constructed after the confirmatory results are visible is not a held-out set, whatever it is
called. It would be the post-hoc exclusion this project's entire pre-registration discipline exists
to prevent.

**Cut something else instead.** Rejected, and the enumeration is in Context: the three remaining
credential subcases carry the whole `F2`/`F3` result; G-3 and G-10 are gates; the pre-registration
document is what makes the confirmatory run confirmatory. The held-out third is the only remaining
item whose removal removes no result.

**Leave Part H step 4 as written and simply not do it.** Rejected: an unmet requirement left
standing in the design document is a false record. The step is amended with a dated note so the
document says what the study did.

## Status

accepted — 2026-08-02 (Commander's ruling; scope; amendable by a later ADR until Part H step 3)

## Consequences

- **Part H step 4** is amended with a dated update note recording that the confirmatory corpus is a
  single set with no held-out third, and why.
- **RQ3's wording** in the design document is amended in the same way — *"on seen and sealed
  held-out instances"* becomes *"on the constructed instance set"*, with the previous wording
  retained in the note so the record shows the sequence.
- **§J** gains the instance-selection-bias threat in the words of §2 above, stated as a limitation
  of what was measured rather than a property of the mechanisms.
- **ADR 0028's scan** is re-pointed to the whole confirmatory corpus and remains a pre-seal
  obligation.
- `PRE_REGISTRATION.md` records the cut, its reason and its date, so a reader can see the decision
  was taken before the seal rather than inferred from an absent result.
- **Re-triggered by:** any decision to restore the held-out arm, which would require a new ADR, the
  split machinery, and re-opening Part H step 4 — and which, after the confirmatory run, could not
  be done at all.
