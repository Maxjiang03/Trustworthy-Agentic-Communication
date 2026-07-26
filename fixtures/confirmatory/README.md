# fixtures/confirmatory — EMPTY BY DESIGN

This directory stays **empty** until Part H step 4 (post-seal). No scenario
file may be added before sealing. Pilot and confirmatory corpora are disjoint
by construction.

The confirmatory corpus is produced only by the sealed corpus generator
(code + deterministic key seeds + scenario specifications,
`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part H step 4, ADR 0007), and its
disjointness from `fixtures/pilot/` is verified on scenario-specification and
seed content hashes (Part H step 5) — never on token bytes, which are not
reproducible across mints. Biscuit tokens are minted at campaign runtime from
the sealed inputs. See also CLAUDE.md red lines 1–2.

**Seed-disclosure warning (ADR 0007).** Publishing the corpus seeds publishes
every private key derived from them. This corpus is a **testbed artifact
only**; its keys MUST NOT be reused in any deployment. This warning is a
binding obligation on the corpus generator when it is written.
