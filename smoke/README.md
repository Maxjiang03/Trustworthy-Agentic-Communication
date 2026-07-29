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
| G-2 | G-6/G-7 | **PASS** — the first authorizer-with-policies run in the project, against the `Ω`/`Γ` frozen by ADR 0016 (`H(Γ) = f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb`), with every `C_i` **computed** by 7 authorizer runs per prefix, never asserted: (a) a widening append verifies under `κ_pub` yet leaves `C_i ⊆ C_{i−1}` — extended to six broadening vectors incl. rules, `expiry` and `token_audience`, two probed under their unlocking condition — while legitimate narrowing gives `C_2 ⊊ C_1 ⊊ C_0 = U_task`; (b) a **fully constructed** attacker-signed third-party block is rejected structurally pre-evaluation (the library itself verifies it under `κ_pub`, so the project check is load-bearing) and carries no authority if evaluated anyway, and a `trusting {attacker_key}` authorizer is refused pre-evaluation though it would otherwise admit; (c) five trust-broadening/`Ω`-widening mutations each change `H(Γ)` while a re-serialization does not, artifact byte-intact; (d) `−attenuation` admits exactly `C_0 \ C_n` more, differing in exactly `evaluation.prefix`. **IA-2 verified by this gate**; residuals: exact pin, scoped to these frozen bytes, SUT-side independent implementation still owed (D13/D21, G-13) | [g2/REPORT.md](g2/REPORT.md) | [0002](../adr/0002-python-biscuit-library.md), [0003](../adr/0003-capability-commitment-scheme.md), [0016](../adr/0016-omega-gamma-freeze.md) |
| G-3 | G-1 (threshold fixed beforehand) | not started | — | — |
| G-4 | G-6/G-7 (**both PASS — the adjudication precondition is satisfied**) | **not adjudicated — Phase 1 complete, design under review.** RFCs 8693/9396/8707/9449/9068 + OAuth 2.1 read from the text ([g4/DESIGN.md](g4/DESIGN.md) §1); `authlib==1.7.2` probed ephemerally and found **UNSUPPORTED** — its `rfc8693` package is a 162-byte docstring with zero symbols and `authorization_details` appears nowhere ([g4/probe_authlib.py](g4/probe_authlib.py), exit 0), **confirming** ADR 0004's build finding; the pinned profile, rejection catalogue, identity plane, key isolation and both fair-baseline hazard directions are specified; AS placement decided (ADR 0015). **No AS code written.** Pass criteria, dependency edges and evidence grades unchanged (ADR 0008); IA-4 stays [UNVERIFIED-IA]; authlib stays unpinned (`# PENDING GATE`). Limbs L1–L3 are adjudicable at Phase 2 — **L2 now runs against the frozen `Ω`/`Γ`, not a stand-in** (ADR 0016 closed conflict C1), while L3 still uses the spike-local registry (C3, re-run at G-11); the **`INV.access_token_hash` limb is proposed for a follow-on run after G-11** and must not be reported as passed before then | [g4/DESIGN.md](g4/DESIGN.md) (design, not a gate report) · [g4/SCOPE.md](g4/SCOPE.md) | [0008](../adr/0008-g4-spike-parallelisation.md), [0015](../adr/0015-as-placement.md), [0016](../adr/0016-omega-gamma-freeze.md) |
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
