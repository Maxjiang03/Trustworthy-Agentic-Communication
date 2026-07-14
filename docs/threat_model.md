# Threat Model

**Derived from** `EXPERIMENT_ARCHITECTURE_FINAL.md` (the single source of truth); every section
below cites the part of that document it restates. If this summary and the architecture document
ever disagree, the architecture document wins. Evidence grades ([VERIFIED] / [DESIGN] /
[UNVERIFIED-IA]) are carried over from the source sections.

## 1. Setting

The study measures authorization-scope propagation and its cost at the A2A→MCP boundary on a
**frozen benchmark** of delegation scenarios (Part A.1). All quantitative results are properties
of this benchmark; the study makes no claim about the frequency of such failures in deployed
systems, nor about how widely any mechanism is adopted (Part A.1, D40).

## 2. The three scopes (Part A.3 — strict separation)

| Scope | Meaning | Visibility |
|---|---|---|
| `U_max` | Long-lived maximum authority the user permits the Supervisor to hold; bounds what the Authorization Server may issue. | AS issuance policy |
| `U_task` | Authority the trusted Authorization Server mints at task start for this task; the **only** authorization input any runtime principal sees; carried authentically in the signed capability. This is `C_0`, the root of the attenuation chain. | every runtime principal |
| `τ_gt` | Harness-only ground-truth task-required scope, used solely to score how tightly a mechanism tracked least privilege. | **offline oracle only** — no system-under-test principal may read it (enforced in code; Part H freeze checklist) |

`U_task` is minted by the AS at task start, **not** derived by the Supervisor; the Supervisor and
every downstream hop may only **narrow** it. The defended claim is therefore "B3 preserves an
authenticated upstream task grant with per-hop monotone narrowing," not "B3 autonomously derives
task least privilege" (Part A.3, D18).

## 3. Three identity notions (Part A.5.1 — MUST NOT conflate) [DESIGN]

- `resource_owner = (iss, sub)` — the end user on whose behalf authority was granted; the OAuth subject.
- `oauth_actor = (iss, act) or (iss, client_id)` — the acting agent presenting the token (RFC 8693 `act`/`client_id`).
- `htc_holder` — the terminal holder identity key named by the HTC chain, required to sign INV.

The identity-plane check maps **only** `oauth_actor → htc_holder`. It MUST NOT require
`resource_owner = holder` — delegation means the actor differs from the resource owner. INV
additionally carries `access_token_hash = H(AT@aud)`, so a capability plus holder proof cannot be
combined with a *different* access token than the one whose resource authorization was checked
(Part A.5.1).

## 4. Keys, trust root, and the identity plane (Parts F.2, F.2.1)

- **`κ`** — the Authorization Server root public key: the trust root against which the signed-block
  chain (`crypto_chain_ok(P_n; κ)`) and the first holder-transition certificate `HTC_0` verify.
- **Biscuit block keys are not delegate identities [VERIFIED].** Biscuit's per-block signatures use
  single-use keypairs that prove blocks are correctly chained; only the authority block is signed
  by a well-known multi-use key. Those block keys do **not** authenticate *which principal*
  performed each attenuation.
- **Holder binding is the project-defined HTC chain [DESIGN].** `HTC_0` is signed by `κ`; each
  `HTC_i` (i ≥ 1) is signed by the current holder identity key, binds `prefix_hash = H(P_{i−1})`
  and `child_block_hash = H(SignedBlock_i)`, and names `next_holder_pubkey`. The terminal INV must
  be signed by the key the last HTC names, chaining back to issuance. `task_id`/`audience` are
  invariant along the chain, `depth` is contiguous from 0, and `exp` is non-increasing (Part F.2).
- **Domain separation and versioning (MUST).** Every signature is over a byte string prefixed with
  a fixed domain tag and schema version (`"AASC-HTC-v1"`, `"AASC-INV-v1"`), so an HTC can never be
  reinterpreted as an INV or across versions (Part F.2).
- **Zero-hop rule (MUST).** With no delegation (`n = 0`), a valid chain is exactly `HTC_0` with
  `next_holder_pubkey = initial_holder_pubkey`; INV is signed by that key; no separate code path
  (Part F.2).
- **Identity-plane registry [DESIGN].** `actor_of(·)` maps an OAuth `act`/`client_id` claim to a
  single principal; the registry maps that principal to exactly one `htc_holder` public key. Every
  actor claim and holder key used in a scenario MUST resolve to exactly one principal; unmapped
  actors/keys are rejected. `resource_owner` subjects are recorded but are **not** part of the
  holder mapping. The registry, `Ω`, `Γ`, the frozen `task_authorization_policy`, and the
  allowed-sink policy are all frozen and hashed before sealing (Part F.2.1;
  `docs/frozen_parameters.md`).

## 5. Attacker capabilities (Part D)

### 5.1 Key possession

- **K-none** — holds only a captured credential (bearer token, capability, or a complete captured
  DPoP proof); does **not** possess the terminal holder identity key.
- **K-holder** — possesses the terminal holder identity key (compromised Specialist).

### 5.2 Tampering points (Part D.3)

- **T-reuse** — present a captured credential as a different caller.
- **T-tool** — substitute the tool, same endpoint.
- **T-args** — substitute arguments, same tool.
- **T-scope** — request authority outside `C_n`.
- **T-replay** — bit-identical in-window resubmission.

### 5.3 The two H4 hypotheses (Part D.1, D35)

- **H4a (post-signature, non-holder tampering).** An adversary who captured a valid credential but
  does **not** possess the terminal holder identity key attempts to (i) reuse it as a different
  caller, or (ii) substitute tool/arguments after signing.
- **H4b (compromised-holder misuse).** An adversary who **does** possess the terminal holder
  identity key attempts to exceed the grant. Prediction: **no** mechanism blocks a compromised
  holder acting *within* `C_n`; all `C_n`-enforcing mechanisms block it from exceeding `C_n`,
  because scope containment is independent of holder identity. B3 does not claim to stop a
  compromised holder from misusing authority it legitimately holds; that residual is out of scope
  of every mechanism and stated as such.

### 5.4 Four-way DPoP attacker taxonomy (Part D.2) [VERIFIED basis]

| Adversary | Holds / position | Outcome |
|---|---|---|
| `dpop-stolen-AT-key-substitution` | `AT@aud` but not the DPoP holder key; presents the token with its own key | **Blocked** by DPoP (proof fails against the token `cnf`/`jkt`) |
| `dpop-captured-proof-replay` | a complete valid method+URI DPoP proof and the token; resubmits bit-identically | **Not** blocked by DPoP alone (same method+URI); blocked only by an authenticated-request-ID replay cache keyed on the DPoP `jti` |
| `dpop-first-use-body-mutation` | a malicious component **between the holder's proof signing and the TLS client**; alters body/tool on the **first** use, reusing the holder's genuine, not-yet-seen proof | **Not** blocked by DPoP (body/tool outside the proof); blocked by an INV body/args binding |
| `dpop-compromised-holder` | **possesses** the DPoP holder key; signs fresh valid proofs | No holder-proof mechanism blocks a compromised holder within scope; scope containment still bounds it |

An attacker without the holder key cannot produce any valid DPoP proof, so there is no valid-DPoP
request without either the captured proof or the holder key (Part D.2). The DPoP proof covers
method+URI only [VERIFIED, RFC 9449]; since MCP tool calls are JSON-RPC to one endpoint, DPoP
stops *who* replays, not *what* is substituted at the same endpoint (Parts C, D.3).

### 5.5 Attacker × key-possession × tampering-point matrix (Part D.3)

✅ = blocked, ❌ = admitted, — = legitimate/NA. **Predictions to be tested on the sealed corpus,
not observed findings** (Part 0 item 5).

| Attacker key | Tampering point | B2-exchange-task (bearer) | B2-exchange-task-DPoP | B3 | B3 conjunct that blocks |
|--------------|-----------------|:-------------------------:|:---------------------:|:--:|-------------------------|
| K-none | T-reuse | ❌ | ✅ | ✅ | `holder_proof_ok` + `htc_chain_ok` |
| K-none | T-tool (same endpoint) | ❌ | ❌ | ✅ | `invocation_binding_ok` (tool) |
| K-none | T-args (same tool) | ❌ | ❌ | ✅ | `invocation_binding_ok` (canonical_request_digest) |
| K-none | T-scope (outside `C_n`) | ✅ | ✅ | ✅ | `R ⊆ C_n` (containment) |
| K-none | T-replay (bit-identical) | ❌ | ❌ | ❌ (B3⁺ ✅) | none in B3; B3⁺ jti cache |
| K-holder | T-scope (outside `C_n`) | ✅ | ✅ | ✅ | `R ⊆ C_n` (independent of holder) |
| K-holder | in-scope action | — | — | — | legitimate; no mechanism blocks (H4b) |

DPoP closes T-reuse but not T-tool/T-args at a shared endpoint — the gap B3's canonical body/args
binding fills; the residual difference is credited to **INV**, not the capability (Part D.3).

## Known residual: append-induced rejection (availability)

An adversary positioned between the terminal holder and the boundary verifier can append a block
to the presented capability. Because attenuation is monotone, this **cannot escalate authority**;
and because appending changes `H(P_n)`, the `INV.capability_hash` binding **rejects** the request.
The residual effect is therefore a **rejection** — an availability effect — not an authorization
breach. An adversary in that position could equally drop or corrupt the message, so sealing the
capability would not close this residual. Availability effects are not among the scored families
F1–F5; this residual is recorded for completeness. `[Gate G-1; ADR 0002]`

## Out of scope

**Out of scope.** The study concerns authorization-scope propagation. The following are out of scope, and are named so the exclusion is deliberate rather than an omission: prompt injection and goal hijack against the language model; memory or context poisoning; tool-definition poisoning and supply-chain attacks on tool registries; unexpected code execution; and attacks on the enforcement code, the trust store, or the cryptographic primitives. Generalization of the results is claimed only for the threat model and the attack instances constructed here, not for a population of all possible attacks.
