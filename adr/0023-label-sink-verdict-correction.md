# 0023 — Rows 4 and 6 do not compose: row 6 is the permit whitelist, row 4 the severity

**Amends ADR 0022** (its composition rule only; every value ADR 0022 froze is unchanged).
Rows 4 and 6 are amendable until Part H step 3, so this is an amendment, not an unseal.

## Context

ADR 0022 froze rows 4 and 6 and, facing a genuine gap in §A.6 — the sink rule is stated as a
*necessary condition* while row 4 states an *outcome per label* — resolved it by **composing**
the two planes and taking the more restrictive on `permit < escalate < block`. That resolution
was recorded honestly as a decision rather than absorbed. It was still wrong, and the evidence
is internal: **the composition falsified two of the frozen document's own necessity statements.**

Measured on the artifact as frozen by ADR 0022:

- `(internal, internal-sink)` composed to **escalate**, although row 6 lists that pair as
  *allowed* and its necessity says exactly why: *"Internal data staying inside the boundary is
  the ordinary working case. Without this pair the policy would forbid all internal traffic and
  the benign workload could not run."* Under the composition it did forbid it.
- `(internal, external-sink)` composed to **block**, so `escalate` survived **only** in the cell
  that was supposed to permit — although row 4's necessity for `internal` says *"this is the only
  rule that produces escalate, and it is what makes the DeclassificationArtifact path observable
  rather than decorative."* Under the composition the escalate path was unreachable in the one
  cell that needed it.

A frozen document whose rules contradict its own justifications is not frozen in any useful
sense: the necessity column exists precisely so that a rule and its reason can be checked
against each other, and here they disagreed.

**The underlying error is a category error.** The two rows answer *different questions* —
row 6 answers **whether** an egress is allowed, row 4 answers **how severe** a disallowed one is
— so treating them as two verdicts over one cell and reconciling them was never the right shape.
There is nothing to reconcile.

## Decision

[DESIGN] **Row 6 is the permit whitelist; row 4 supplies the severity.** Exactly **one** verdict
per cell, never two combined:

```
label is absent                          -> block        (fail closed, unchanged)
(label, sink) in row 6 allowed_pairs     -> permit
otherwise                                -> row 4's egress outcome for that label
```

which yields, over the frozen vocabulary and sink classes:

| | `internal-sink` | `external-sink` |
|---|---|---|
| `public` | **permit** | **permit** |
| `internal` | **permit** | **escalate** |
| `sensitive` | **block** | **block** |
| *unlabelled* | **block** | **block** |

Both falsified necessity statements now hold: `(internal, internal-sink)` permits, so ordinary
internal traffic runs; and `escalate` survives at `(internal, external-sink)`, which is the cell
where a `DeclassificationArtifact` would actually be needed.

**The table is written into the artifact and checked against the rule.** It is *derived*, not
independent — every cell is what the rule yields — but a policy whose cells cannot be read at a
glance is a policy nobody checks. The loader recomputes the rule over every cell and refuses to
load if the written table and the rule disagree anywhere, so the two can never drift apart.

**What is unchanged.** Every *value* ADR 0022 froze: the vocabulary and its order, the join, the
derived egress predicate, the outcome-per-label table, the fail-closed unlabelled rule, the two
sink classes, the three allowed pairs, and all of row 10. Only the rule for turning them into a
verdict changes. The refusal/acceptance split is also unchanged: `escalate` still refuses,
because `authz_context_hash` remains ADR 0009 category (c) owned by **G-15**.

## Consequences

- `H(Λ)` is recomputed over the amended document:

  ```
  H(Λ) = ce4e1e75c782e7bf83cdb7407ace64a91f86683c23ee58c6d9846728814183a7
         (was 2affd907093721669807fd2895050b33ac6bb1046feb1dba41735b0105af1b21, ADR 0022)
  ```

  `docs/frozen_parameters.md` rows 4 and 6 carry the new value; the runner's start-up check and
  the corpus generator's pre-write check verify against it and fail closed on a mismatch.
- **No pilot outcome moves, and this was verified rather than assumed.** Every pilot scenario is
  unlabelled and `mail.send` is the only egress action over the frozen `Ω`, so the unlabelled
  fail-closed rule blocks it under *both* readings; the amendment changes only cells no pilot
  scenario reaches. The verification is recorded in the corrective-pass report and pinned by
  test.
- The three-verdict constant is no longer an *order* anywhere: with one verdict per cell there is
  nothing to rank, so the restrictiveness map is removed from both planes rather than left as
  dead scaffolding.
- ADR 0022 gains a pointer to this ADR and is **not** rewritten — the trail is the point.
- Registered in Part B.2 of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, same commit.

## Status

accepted — 2026-07-30
