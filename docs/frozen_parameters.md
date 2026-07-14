# Frozen (Seal-Time) Parameters — ALL UNSET

Every parameter below **must** be frozen and hashed before sealing
(`EXPERIMENT_ARCHITECTURE_FINAL.md`, Part H step 3). **None is chosen yet.** The equivalence
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
| 8 | `Ω` (action/resource ontology) and `Γ` (authorizer configuration) — frozen and hashed as `H(Γ)` | ⟨UNSET — fix before Part H step 3⟩ | ⟨one line — record with the fixing ADR⟩ |

Related frozen artifacts sealed alongside these values (Part F.2.1, Part H step 3): the
identity-plane registry, and the hashes of all configuration in the v0.5 candidate manifest.
