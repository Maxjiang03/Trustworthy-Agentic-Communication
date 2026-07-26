# Smoke Gates — Status Board

Feasibility smoke gates per `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G. **No v0.5, no
sealing, no confirmatory corpus until every in-scope gate passes on the pilot corpus.** Each gate
is a minimal runnable spike, not an experiment. A failing gate stops its branch and applies the
gate-outcome policy (fallbacks), recorded as an ADR.

**Execution DAG (respect dependencies):**

```
G-1 / G-5 / G-8  →  G-6 / G-7  →  G-2 / G-4 / G-11  →  G-12 / G-13  →  G-9 / G-14  →  G-10
```

G-3 (latency spike) may run any time after G-1, but its threshold is fixed beforehand
(`docs/frozen_parameters.md` item 2, currently UNSET). Claim-dependent gates (G-3, G-14, G-15,
INV-only check) run only for claims retained in the sealed scope.

Run a gate: `make gate GATE=g1`

| Gate | Depends on | Status | Report | ADR |
|------|-----------|--------|--------|-----|
| G-1 | — | **PASS** — restored after the ADR 0003 corrective suite passed (10/10 regression tests): commitment is now the versioned BlockID scheme (encoding-independent, fail-closed); biscuit-python==0.4.0 pinned; G-1.G′ replaced the seal check (ADR 0002) | [g1/REPORT.md](g1/REPORT.md) | [0002](../adr/0002-python-biscuit-library.md), [0003](../adr/0003-capability-commitment-scheme.md) |
| G-2 | G-6/G-7 | blocked — requires frozen authorizer Γ and H(Γ) (`docs/frozen_parameters.md` item 8, UNSET) | — | — |
| G-3 | G-1 (threshold fixed beforehand) | not started | — | — |
| G-4 | G-6/G-7 | not started — **construction spike authorised to start early** (ADR 0008): the behaviourally faithful AS build may proceed in parallel with G-6/G-7, inheriting the `ath` and DPoP-nonce items from G-5; **adjudication stays after G-6/G-7** with unchanged pass criteria; IA-4 stays [UNVERIFIED-IA]; authlib stays unpinned (`# PENDING GATE`) | — | [0008](../adr/0008-g4-spike-parallelisation.md) |
| G-5 | — | **PASS** — `joserfc==1.7.4` pinned for the JOSE surface only (ADR 0006): cnf/jkt binding with the RFC 8037 A.3 known answer, RFC 9449 §4.3 subset verifier, wrong-holder rejected at the thumbprint comparison; AS simulated locally — the real AS stays gated on G-4 (authlib pending line unchanged) | [g5/REPORT.md](g5/REPORT.md) | [0006](../adr/0006-dpop-jose-library.md) |
| G-6 | G-1/G-5/G-8 | **PASS** — `mcp==1.28.1` pinned (ADR 0013): full dispatch-path enumeration with file:symbol citations; wrap-at-fn + wrap-on-insert interposition mediates every enumerated path (7 bypass attempts all mediated or blocked); denied calls never execute (witness-verified); exactly one event on the error path; non-vacuity confirmed with the interposition removed | [g6/REPORT.md](g6/REPORT.md) | [0013](../adr/0013-mcp-sdk-pin.md) |
| G-7 | G-1/G-5/G-8 | **PASS** — exclusive-share ledger process (Win32 `FILE_SHARE_READ`-only handle): all SUT write/amend/delete attempts fail at the OS level (chmod-proof), records survive a lying SUT self-report, correlation ids intact, zero entries for unreached tools; `ingress_request_digest` settled as `H_JCS` (ADR 0012) | [g7/REPORT.md](g7/REPORT.md) | [0012](../adr/0012-ingress-digest-construction.md), [0013](../adr/0013-mcp-sdk-pin.md) |
| G-8 | — | **PASS** — `rfc8785==0.1.4` pinned (ADR 0005): encoding-invariant, RFC-vector-conformant (Appendix B 24/24; `canonicaljson` demonstrated non-conformant and rejected), separate-process signer/verifier agreement, fail-closed; the frozen `H_JCS` construction (hash/tag/encoding) recorded as an open decision | [g8/REPORT.md](g8/REPORT.md) | [0005](../adr/0005-jcs-library.md) |
| G-9 | G-12/G-13 | not started | — | — |
| G-10 | all prior DAG gates | not started | — | — |
| G-11 | G-6/G-7 | not started | — | — |
| G-12 | G-2/G-4/G-11 | not started | — | — |
| G-13 | G-2/G-4/G-11 | not started | — | — |
| G-14 | G-12/G-13 | not started | — | — |
| G-15 | claim-dependent | not started | — | — |
