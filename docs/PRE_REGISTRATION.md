# Pre-Registration — NOT YET AUTHORED

**Status:** Stub. This document does not exist yet and MUST NOT be drafted ahead of schedule.

Per `EXPERIMENT_ARCHITECTURE_FINAL.md` **Part H**, the pre-registration is authored at **step 2 of the seal loop — after every in-scope smoke gate (Part G) has passed on the pilot corpus** — and is derived from the architecture document. It will freeze: the hypotheses, the oracle predicates, the baseline configurations, the latency estimands, and the equivalence margin. It is then sealed together with the implementation commit, oracle, analysis code, configuration, pinned environment, and corpus generator, under a detached manifest with a public temporal anchor.

## Decisions taken BEFORE the seal, recorded here so the sequence is visible

This section is **not** a draft of the pre-registration. It records scope decisions taken before
Part H step 2, so a reader can see each was made **in advance** rather than inferred from an absent
result. Nothing else in this document may be written until the gates pass.

- **2026-08-02 — the held-out third is CUT [ADR 0037].** The confirmatory corpus is a **single set**
  with no held-out subset, and the split machinery was **cancelled, not deferred**. When the
  pre-registration is authored it MUST state: (a) that RQ3 is answered **on the constructed instance
  set only**, with no generalization claim; (b) that **instance-selection bias is unmitigated** and
  that pre-registration does **not** substitute for a held-out subset, since the two defend against
  different threats; and (c) that the partial mitigations — mechanisms and frozen parameters fixed
  before most scenarios were written, every gate criterion shown able to fail, §E.4's matrix written
  in advance — are **partial**, never replacements. Recorded on the date of the decision, before any
  confirmatory result existed to be influenced by it.
- **ADR 0028's deferral obligations**, unchanged in substance and re-pointed by ADR 0037: this
  document MUST state the `F2 wrong_principal` deferral, its reason and its scope; and the **whole
  confirmatory corpus** (formerly "the held-out subset") MUST be scanned before the seal to confirm
  it contains no `wrong_principal` variant.

**Any earlier draft of this document is superseded and must not be reused.**

Writing or sealing this document before the smoke gates pass would defeat the pre-registration and is prohibited.
