# fixtures/confirmatory — EMPTY BY DESIGN

This directory stays **empty** until Part H step 4 (post-seal). No scenario
file may be added before sealing. Pilot and confirmatory corpora are disjoint
by construction.

The confirmatory corpus is produced only by the sealed corpus generator
(code + seed, `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part H step 4), and its
disjointness from `fixtures/pilot/` is verified on content hashes (Part H
step 5). See also CLAUDE.md red lines 1–2.
