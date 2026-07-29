# Frozen (Seal-Time) Parameters — 1 of 10 set

Every parameter below **must** be frozen and hashed before sealing
(`EXPERIMENT_ARCHITECTURE_FINAL.md`, Part H step 3). **Row 8 is set (ADR 0016); the other nine
are not chosen yet.** The equivalence
margin and the G-3 latency smoke threshold **must** be fixed from external engineering need
**before any timing measurement** (Part H step 2; Part G, G-3; Part J.2 item 9) — the G-3
threshold first, the equivalence margin separately and after it, both before any confirmatory
timing result. Fixing each value is a decision: record an ADR (`adr/`) and fill in the value and
justification here.

| # | Parameter | Value | Justification |
|---|---|---|---|
| 1 | Equivalence margin for the "lightweight" claim | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line, from external engineering need — record with the fixing ADR⟩ |
| 2 | G-3 latency smoke threshold (separate from, and set before, the equivalence margin) | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line, fixed before any timing measurement — record with the fixing ADR⟩ |
| 3 | Freshness window `Δ` | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |
| 4 | Context-label → {permit, escalate, block} policy | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |
| 5 | `task_authorization_policy` (task → authorized actor principals) for F2 `wrong_principal` | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |
| 6 | Allowed-sink policy for F4 | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |
| 7 | Reference LLM-turn denominators (full-turn primary + conservative TTFT) — secondary framing only | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |
| 8 | `Ω` (action/resource ontology) and `Γ` (authorizer configuration) — frozen and hashed as `H(Γ)` | **SET (ADR 0016).** `Ω` = 7 `(action, resource)` elements over 5 tools; `Γ` = the MSc-profile authorizer plus its matched `−attenuation` ablation. Artifact: `src/harness/authorizer/omega_gamma_v1.json`. `H(Γ) = f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb` | ADR 0016: the smallest vocabulary in which the golden thread, amplification, two-hop strict attenuation and every retained attack family are expressible, with `Γ` written against the four G-2 criteria; amendable by a later ADR until Part H step 3, and any amendment re-triggers G-2 and the G-4 effective-authority limb. |
| 9 | Sealed measurement platform — OS + exact Windows version/build (decision: ADR 0014; the campaign runs on Windows, the ledger enforcement is Win32-only) | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — the exact build is read off the measurement box at seal time; record with the fixing ADR⟩ |
| 10 | Oracle classification policy — the **high-risk action set** (Part I `is_high_risk`, F5/approval) and the **sensitive-label set** (Part I `is_sensitive`, F4/egress) | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the ADR that builds the oracle⟩. Registered (not decided) by gate G-2: the `Ω`/`Γ` freeze exposed that neither set is owned by any other row — row 4 owns label→outcome, row 6 owns sinks, and `Ω` supplies a destructive action (`notes.delete`) without classifying it, correctly, since classification is policy and not vocabulary. The sensitive-label set depends on the row 4 label vocabulary (also UNSET), so row 4 is fixed first or in the same ADR. |

Related frozen artifacts sealed alongside these values (Part F.2.1, Part H step 3): the
identity-plane registry, and the hashes of all configuration in the v0.5 candidate manifest.
