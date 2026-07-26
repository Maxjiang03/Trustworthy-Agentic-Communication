# Experiment Architecture — Final Consolidated (Implementation Candidate for Smoke Tests)

**Project:** Trustworthy Agentic Communication — measuring authorization-scope propagation and its cost at the A2A→MCP boundary
**Author:** Yixian Jiang (3154807J), MSc Cybersecurity, University of Glasgow
**Supervisor:** Professor Shahid Raza
**Consolidates:** `DESIGN_REVISION_v0.4.1.md` + all corrections in `DESIGN_REVISION_v0.4.1a_ERRATA.md`, folded into one authoritative document.
**Status:** **Implementation candidate — NOT sealable.** This is the specification Claude Code follows to run the feasibility smoke tests in Part G. **No confirmatory experiment, no sealing, and no v0.5** until every in-scope Part G gate passes. No statement here may be described as "proven by specification"; every implementation assumption is enumerated in §F.4 with the gate that must confirm it.
**Evidence grades used throughout:** **[VERIFIED]** = checked against a primary source (RFC / protocol spec / Biscuit spec or FAQ) this session; **[DESIGN]** = a project decision, internally consistent but not externally mandated; **[UNVERIFIED-IA]** = a property a library or environment must have, not yet confirmed in code (see §F.4).

---

## Part 0 — How to read this document (for Claude Code)

1. **Do not implement past a failing gate.** Part G defines a dependency DAG. If a gate fails, stop on that branch and apply the fallback in the gate-outcome policy; record it as an ADR entry.
2. **The pilot corpus is the only corpus you may run.** The confirmatory corpus does not exist yet and must not be authored or executed during smoke tests (§A.8, Part H).
3. **Two checks are blocking before any capability coding:** the Biscuit monotonicity semantics (§F.3 / G-2) and complete mediation + effect-ledger interposition (G-6 / G-7). Two more are blocking before any comparative claim: matched per-hop authority with independent `Allowed(AT_i)=C_i` verification (G-13) and the identity-plane split with the four-way DPoP taxonomy (§D / G-14).
4. **Symbols are frozen in §A.0.1.** Every formula uses `P_i` (immutable signed-block prefix) and `C_i = Allowed(P_i; Γ, κ, Ω)` (authority set). Hashes cover `P_i`, never the mutable proof tail.
5. **Nothing is a result yet.** Every expected-outcome cell in Parts D/E is a *prediction to be tested on the sealed corpus later*, not an observed finding.

---

# Part A — Scientific frame

## A.0 Status of claims

Three grades, kept distinct: **[VERIFIED]**, **[DESIGN]**, **[UNVERIFIED-IA]** (defined in the header). The single most important consequence: the confused-deputy amplification prevention is a **[DESIGN]** decision resting on **[UNVERIFIED-IA]** assumptions about the chosen capability library, **not** a proven property, until the §G gates pass.

### A.0.1 Canonical type definitions (used by every formula below)

These separate the immutable signed structure from the mutable proof tail and from the authority set, so no formula conflates them.

- **`SignedBlock_i`** — the `i`-th Biscuit block in canonical serialization (authority block for `i = 0`, attenuation block for `i ≥ 1`), including its block signature and the carried next-public-key, **excluding** the token's mutable proof tail (the trailing single-use secret or final seal signature).
- **`P_i`** — the **canonical signed-block prefix** `⟨SignedBlock_0, …, SignedBlock_i⟩`, the append-only list of signed blocks up to hop `i`, serialized canonically. Immutable once created; **does not** include the mutable proof tail.
- **`Γ`** — the frozen project **authorizer configuration** (its checks, allow/deny policies, and its fixed trusted-key set; §A.6.1).
- **`κ`** — the **Authorization Server root public key**.
- **`Ω`** — the frozen, finite **action/resource ontology**; authority is always a subset of `Ω`.
- **`C_i = Allowed(P_i; Γ, κ, Ω) = { x ∈ Ω | authorizer(P_i, x; Γ) = permit ∧ crypto_chain_ok(P_i; κ) }`** — the **effective authority set** admitted by prefix `P_i` under authorizer `Γ`, verified against `κ`, restricted to `Ω`. `C_0 = U_task`.

**Commitment rule [DESIGN, ADR 0003 — replaces the raw-byte hashing rule].** Every capability-state commitment commits to the **ordered signed-block prefix `P_i`**, never to the full token with its mutable proof tail — and never to raw container bytes: **protobuf is not a canonical encoding**, so a semantically equivalent re-encoding (field reordering, non-minimal varints) changes raw bytes, and a raw-byte hash would bind an encoding rather than the block sequence and falsely reject legitimate requests. Commitments are therefore taken over **signature-derived block identifiers**: `BlockID_i` is block `i`'s signature — the Biscuit revocation identifier **[VERIFIED: SPECIFICATIONS.md "Revocation identifiers": the revocation identifier for a block is its signature]** — extracted only from a token whose chain verified against `κ`. The symbol `H(P_i)` **denotes** `commit_prefix(BlockID_0..BlockID_i)`: SHA-256 over the domain-separated, versioned, length-delimited sequence (`"AASC-CAP-COMMIT"` ‖ version `0x01` ‖ alg `0x01` (Ed25519-only) ‖ `u32be(count)` ‖ each `u32be(len) ‖ BlockID`); unsupported version/algorithm values fail closed. Concretely: HTC `parent_prefix_hash := commit_prefix(BlockID_0..BlockID_{i−1})`, HTC `child_block_hash := BlockID_i`, INV `capability_hash := capability_commitment(P_n) = commit_prefix(BlockID_0..BlockID_n)`. The proof tail carries no block identifier and a re-encoding changes no signature, so HTC/INV bindings are stable across a legitimate append **and** across semantically equivalent re-encodings.

## A.1 Central thesis (frozen-benchmark wording; no frequency or adoption claim)

> MCP defines an **optional** HTTP authorization profile: when authorization is used, an MCP server acts as an OAuth 2.1 resource server and verifies that a presented token was issued for it. A2A v1.0 defines authentication and leaves authorization to the implementation, and it specifies an **in-task authorization workflow** in which an agent needing additional credentials transitions the task to `TASK_STATE_AUTH_REQUIRED` and the client supplies secondary credentials obtained out of band; A2A defines **no** standardized task grant and **no** normative per-hop monotone transformation that preserves an upstream task grant as a bound on downstream MCP tool effects. OAuth 2.1 is an **authorization framework**; **TLS** provides transport security. Whether the user's task grant is preserved across the A2A-to-MCP boundary is therefore not guaranteed by the protocols but determined by deployment choices. This dissertation constructs a **frozen benchmark** of delegation scenarios and measures, on that benchmark, how a ladder of deployment mechanisms behaves when authority crosses the boundary: whether the authority exercised at an MCP tool call remains within the user's task grant, and what security and runtime cost each mechanism incurs. The comparison holds task-authorization semantics, action and resource ontology, and execution substrate identical across mechanisms, so the only variables are how authorization is issued, propagated, attenuated, and bound to the individual invocation, and what online dependencies and overhead each mechanism incurs. All quantitative results are properties of this frozen benchmark; the study makes **no** claim about the frequency of such failures in deployed systems, nor about how widely any mechanism is adopted. **[VERIFIED: MCP authorization profile is optional and OAuth-2.1-based; A2A v1.0 `TASK_STATE_AUTH_REQUIRED` in-task auth with out-of-band credential acquisition; neither defines a normative task-grant transform.]**

**Framing note (prevents overreach).**

> This study does not claim a capability token is the only mechanism capable of expressing tool-level least privilege, and makes no claim about real-world prevalence. A token-exchange deployment configured with fine-grained authorization details can express comparable authority. A Datalog policy inside a capability, an OAuth scope, and a rich authorization request all depend on a shared, out-of-band vocabulary of actions and resources; none derives task requirements autonomously. What the benchmark isolates is which security properties follow from a mechanism's configuration and which require an explicit cross-hop authorization-preservation and invocation-binding mechanism, and at what cost.

## A.2 Research questions

- **RQ1.** Which authorization properties do the MCP and A2A specifications guarantee at the A2A-to-MCP boundary, and which do they defer to the implementer?
- **RQ2.** On the frozen benchmark, how often does the authority actually exercised at the boundary exceed the user's task grant, and under which configurations does the excess survive? Decomposed into the authority admitted at the boundary, the authority the request required, and the authority actually exercised (from an independent effect ledger).
- **RQ3.** For each baseline and each matched leave-one-out variant, what is the per-family attack outcome under each family's own success predicate, and the false-blocking outcome on a benign workload with near-miss cases, on seen and sealed held-out instances?
- **RQ4.** What is the absolute added latency of each mechanism, separated into setup, delegation, boundary-verification, and end-to-end components, under cold and warm conditions, and how does the security-versus-overhead trade-off compare?

## A.3 The three scopes (strict separation)

- **`U_max`** — long-lived maximum authority the user permits the Supervisor to hold; bounds what the Authorization Server may issue.
- **`U_task`** — authority the trusted Authorization Server mints at task start for this task; the **only** authorization input any runtime principal sees; carried authentically in the signed capability. This is `C_0`, the root of the attenuation chain.
- **`τ_gt`** — harness-only ground-truth task-required scope; visible to the **offline oracle only**; **no system-under-test principal may read it** (enforced in code; Part H freeze checklist). Used solely to score how tightly a mechanism tracked least privilege.

`U_task` is minted by the AS at task start, **not** derived by the Supervisor. The Supervisor and every downstream hop may only **narrow** it. The claim is therefore **"B3 preserves an authenticated upstream task grant with per-hop monotone narrowing,"** not "B3 autonomously derives task least privilege."

## A.4 B3 is an additional layer on OAuth, not a replacement [DESIGN, D28]

In the B3 arm the caller is still authenticated to the MCP boundary using OAuth 2.1 and TLS exactly as in the B2 arms; the OAuth access token still establishes MCP resource authorization and the acting identity. What B3 adds, and the OAuth token does not carry, is the root-signed monotonically-attenuating **capability** (`C_0..C_n` and labels), the **holder-transition-certificate (HTC) chain** (binding each hop to the next holder's identity key), and the **per-invocation binding assertion (INV)** (binding authority to the concrete tool call). The capability governs *what authority may be exercised*; the OAuth layer governs *authentication and MCP resource authorization*; **TLS** governs transport. B3 does not remove or bypass the OAuth resource-server check; it layers authorization-preservation and invocation-binding above it. Effective authority is the **intersection** of OAuth resource authorization and capability authority.

## A.5 Enforcement algorithm (pre-execution rule over `R`; `A` measured after execution)

`A` (exercised authority) is a post-execution observable and **cannot** be checked before allowing; the pre-execution rule is over `R` (required authority).

```
C_n = authority( verify_capability_chain(capability, κ) )     # = Allowed(P_n; Γ, κ, Ω), §A.0.1
R   = required_authority( concrete_request, server_policy )   # server computes from tool/resource/args;
                                                              # NEVER an agent-reported field

allow  ⟺  crypto_chain_ok(P_n; κ)          # signed-block chain verifies to root key
        ∧ authorizer_policy_ok(P_n; Γ)     # frozen authorizer Γ permits (block scoping, §A.6.1)
        ∧ htc_chain_ok                     # HTC chain valid to κ (§F.2)
        ∧ holder_proof_ok                  # INV signed by terminal HTC holder identity key
        ∧ invocation_binding_ok            # INV binds capability_hash/task/invocation/aud/method/tool/digest, in-window (§F.2)
        ∧ R ⊆ C_n                          # containment
        ∧ context_policy_ok                # capability label POLICY vs independently verified payload LabelAssertions (§A.6)
        ∧ approval_artifact_ok             # for high-risk actions (§F.2)
        ∧ oauth_resource_authorization_ok  # MCP resource server accepts AT@aud for this server
        ∧ identity_plane_consistency_ok    # oauth_actor(AT) maps to terminal htc_holder key (§A.5.1)

# After execution the oracle checks A ⊆ R, A ⊆ C_n, A ⊆ U_task from the effect ledger.
# Any allow with A ⊄ C_n is an enforcement/execution defect (mediation or tool-trust violated).
```

Under complete mediation, a trusted tool performing only the requested action, and no hidden side effects, `allow` with `R ⊆ C_n ⊆ … ⊆ C_0 = U_task` yields an expected `A ⊆ U_task`. This is **verified post-hoc** (§F.3 INV-5/6), not assumed.

### A.5.1 Three identity notions (MUST NOT conflate) [DESIGN, from E3/E5]

- `resource_owner = (iss, sub)` — the end user on whose behalf authority was granted; the OAuth subject.
- `oauth_actor = (iss, act) or (iss, client_id)` — the acting agent presenting the token (RFC 8693 `act`/`client_id`).
- `htc_holder` — the terminal holder identity key named by the HTC chain, required to sign INV.

The identity-plane check maps **only `oauth_actor → htc_holder`**. It **MUST NOT** require `resource_owner = holder` — delegation means the actor differs from the resource owner. INV additionally carries `access_token_hash = H(AT@aud)` so a capability + holder proof cannot be combined with a *different* access token than the one whose resource authorization was checked.

## A.6 Context labels — ingestion-vs-issuance resolution [DESIGN, D29 + E8]

Labels are asserted at ingestion by a trusted source (they exist before task-time capability issuance), so a single capability signature cannot cover both. `context_policy_ok` therefore evaluates the capability's label **policy** (Datalog over label facts) against **independently verified payload `LabelAssertion`s**, resolved **by payload digest** — not labels read from `C_n`, and not a caller-asserted label. For each value a tool touches, the boundary looks up the `LabelAssertion` whose `payload_digest` matches, verifies its signature under the trusted label issuer, and uses that verified label. Egress to a recipient is permitted only if `(verified label, sink)` is in the frozen allowed-sink policy, or a valid `DeclassificationArtifact` covers it. Derived values take the least-upper-bound (join) of input labels.

- **MSc model (what §E scores).** Trusted **pre-labelled payloads**: each fixture data item carries a label fixed at authoring time, signed by a fixture label issuer. The MSc F4 claim is explicitly **"propagation and egress-policy enforcement over trusted pre-labelled payloads,"** not runtime label origination.
- **Conference model.** Full ingestion-time signed labels with independent verification; the interface above already supports it, so no later interface change is needed.

### A.6.1 Biscuit monotonicity: three distinct checks [VERIFIED]

**Do not conflate** `crypto_chain_ok`, `authorizer_policy_ok`, and effective authorization.

- `crypto_chain_ok(P_i; κ)` — the signed-block chain verifies against `κ`. A cryptographically valid appended attenuation block satisfies this **even if it contains a widening fact**; appending is an untrusted-holder operation and is *expected* to verify.
- `authorizer_policy_ok(P_i; Γ)` — the project authorizer `Γ` permits the concrete request.
- `C_i = Allowed(P_i; Γ, κ, Ω)` under **default block scoping**: a check/policy trusts facts from the authority block, the authorizer, and its own block only.

**MSc profile restriction (MUST).** In the MSc profile, `Γ` **MUST NOT** enable any `trusting {public_key}` annotation and the token **MUST NOT** contain third-party blocks. The only trusted origins are the authority block and the authorizer. Any capability with a third-party block, or any authorizer importing external-key facts, is **out of profile** and **MUST** be rejected before evaluation.

**Monotonicity invariant, over authority sets:**
```
INV-2 (effective monotone):  ∀ i ∈ [1,n]:  C_i ⊆ C_{i−1}   where C_i = Allowed(P_i; Γ, κ, Ω)
```
This holds **by Biscuit's block-scoping semantics under the MSc profile**: later-block facts are not trusted by the authority block or the authorizer, third-party trust is disabled, so adding `SignedBlock_i` can only add checks and therefore only remove elements from the authority set. Monotonicity is **not** enforced by rejecting widening blocks at signature verification; a widening fact simply has no effect because nothing trusts it. **[VERIFIED: Biscuit Datalog reference — "adding a block can only restrict what a token can do, and never extend it"; default trust is authority block + authorizer + same block only; third-party facts require `trusting {key}`.]**

---

# Part B — Decision log (ADR)

## B.1 Repealed / superseded

| Decision | Action | Reason |
|----------|--------|--------|
| **D3 (v0.2): "B3 = B2 + six modules, strict superset / replacement"** | **REPEALED**, replaced by **D28** (B3 is an additional layer on the OAuth substrate; the cumulative intuition survives only as the §C credential-flow composition). | Superset framing wrongly conflated "adds authority-governance" with "replaces the OAuth check." |
| **D23 (v0.4): "holder binding via RFC 7800 `cnf`," as if capability-native** | **SUPERSEDED by D31**: RFC 7800 `cnf` is an OAuth/JWT construct, **not native to Biscuit**; Biscuit block signatures use single-use keypairs proving chain linkage, not delegate identity **[VERIFIED, FAQ]**. Holder binding is the project-defined **HTC** (§F.2), signed by each hop's identity key. `cnf` is used **only** in the DPoP arm (D34). | Prevents mis-describing a bolted-on mechanism as capability-native. |
| **D11/D12: "B3 derives task least privilege"** | Superseded by **D18**: "preserves an authenticated upstream task grant with per-hop monotone narrowing." | The system cannot authentically derive task-required scope at runtime. |
| **Any "not uniformly adopted" / frequency phrasing** | **REMOVED** (D40). | Benchmark cannot support a prevalence claim. |
| **"ready to seal" status** | **REVOKED.** Implementation candidate; sealing gated on Part G. | v0.5 only after smoke tests pass. |
| **Flat single `B2-task` arm** | **SUPERSEDED by D19** (three arms, §C). | A mixed arm made H-F1 unfalsifiable. |
| **"RFC 8693 inherently down-scopes"** | **REMOVED**; replaced by the pinned experiment AS profile (D27 + E2). | RFC 8693 leaves per-hop exchange and narrowing to deployment policy **[VERIFIED]**. |

## B.2 Decisions in force (consolidated)

D1, D2 (real OAuth 2.1 baseline), D4–D10, D13/D21 (independent oracle: three sources, per-family predicates, log-integrity failure), D17 (three scopes), D18 (grant-preservation claim), D19 (three OAuth arms), D20 (`R ⊆ C` pre-execution rule), D22 (Biscuit appends per hop **[VERIFIED]**; the format defines sealing as a terminal operation, but the chosen binding does not expose it and this design never seals — see the D22 note below and ADR 0002), D24 (label provenance, MSc-narrowed), D25 (approval as verifiable artifact), D26 (security = exact counts, no CI; latency = the only CIs), D27 (per-hop online exchange is a deployment property, not an RFC necessity **[VERIFIED]**), D28–D40 (§B.1 and the new-decisions set: DPoP arm D34, rewritten H4 D35, matched ablations D36, B3⁺ jti semantics D37, pilot/confirmatory separation D38, unverified-assumption enumeration D39, frozen-benchmark scoping D40). Additional consolidated decisions from the errata: three-scope separation, identity-plane split (A.5.1), HTC full spec (§F.2), composite oracle (§F.1/Part I), F1 split and matched per-hop authority (§E), four-way DPoP taxonomy (§D), two-phase OAuth cost (§E), gate DAG and seal loop (Part G/H). Plus the build-vs-reuse rule (ADR 0004; note below); the corpus-seal rule — the sealed confirmatory corpus stores scenario specifications, deterministic key seeds, and the generator, never pre-minted token bytes (ADR 0007; Part H note); the G-4 split — the AS construction spike may start ahead of G-6/G-7, while G-4 adjudication stays where the DAG puts it with unchanged criteria (ADR 0008); the frozen `H_JCS` construction with its digest-field classification (ADR 0009; §F.2); the §K LLM-demonstration scope — retained, qualitative only, outside Parts A–J and outside the seal (ADR 0010; §J.7); the commitment-family string rendering — lowercase hex, matching `H_JCS`, with `P_hashes` classified as the ADR 0003 prefix commitment (ADR 0011); and the `ingress_request_digest` settlement — `H_JCS`, recorder-side at the tool, closing the ADR 0009 G-7 deferral (ADR 0012); and the sealed measurement platform — the confirmatory campaign runs on Windows, the sealed environment includes the OS, the POSIX ledger variant is deferred post-submission, and no cross-platform claim is made until it passes the five G-7 checks (ADR 0014).

**D22 note — this design never seals.** Further delegation is governed by the HTC chain (a new hop requires an `HTC_i` signed by the current holder's identity key, §F.2); further attenuation by any party is harmless because attenuation is monotone (§A.6.1); and a block appended after the terminal hop is rejected because it changes `H(P_n)` and therefore fails the `INV.capability_hash` binding (§F.2). Sealing is consequently **not required** by this design, and the absence of a seal API in the chosen Python binding does not affect it. `[Gate G-1; ADR 0002]`

**Build-vs-reuse note [DESIGN, ADR 0004].** Zero repositories are forked. External functionality enters only as **pinned dependencies**, each pinned exactly and only after its gate passes: `biscuit-python==0.4.0` (G-1, ADR 0002/0003); a JCS library (G-8); a DPoP/JOSE library (G-5); an OAuth stack for the AS if viable (G-4); `a2a-python` and the official MCP Python SDK after their gates (G-6/G-7 exercise the MCP mediation surface). Built from scratch: the HTC/INV constructs, the nine-arm orchestration, the independent effect ledger + oracle, the attack-family fixtures, and — most likely, since per the concluded external investigation no off-the-shelf Python AS supports both RFC 8693 down-scoped exchange and RFC 9396 RAR — a behaviourally faithful OAuth 2.1 AS. **AIP is not forked**: reusing its code would violate oracle independence (the oracle must share no implementation with anything it judges, D13/D21); AIP anchors the "measurement, not novel mechanism" citation and serves as comparator (feature-matched table or P3 comparator arm; its own paper names a controlled OAuth 2.1 comparison as future work). This decision does not change the DAG order. `[ADR 0004]`

---

# Part C — Credential-flow table (per baseline)

Notation: **AT** = OAuth access token; **AT@aud** = audience-restricted AT (RFC 8707); **XCHG** = RFC 8693 token exchange under the **pinned experiment AS profile**; **CAP** = root-signed attenuating capability (`P_0..P_n`, authority `C_0..C_n`); **HTC** = holder-transition-certificate chain; **INV** = per-invocation binding assertion; **DPoP** = RFC 9449 proof (method+URI only); **cnf** = RFC 7800 confirmation claim (OAuth/DPoP arm only). **All agents obtain the same pre-provisioned resource-specific base `AT@aud` in Phase 1 (§E two-phase).**

| Baseline | Phase-2 Supervisor→Specialist (A2A) | Specialist→MCP boundary | Binds authority to the invocation | Prevents stolen-credential reuse by another holder |
|----------|--------------------------------------|--------------------------|-----------------------------------|----------------------------------------------------|
| **B0** | none | plain call | nothing | nothing |
| **B1** | static API key forwarded | API key in header | nothing | nothing (bearer) |
| **B2-broad-noexchange** | AT (broad) forwarded | AT@aud (broad), bearer | audience only | nothing (bearer, in-window) |
| **B2-exchange-broad** | XCHG → AT′ (broad, scope unchanged) | AT′@aud, bearer | audience only | nothing (bearer) |
| **B2-exchange-task** | XCHG → AT′ narrowed to `C_i` (+RAR) | AT′@aud (task scope), bearer | audience + scope | nothing (bearer, in-window) |
| **B2-exchange-task-DPoP** [D34] | XCHG → AT′ narrowed to `C_i`, **DPoP-bound (cnf=holder jkt)** | AT′@aud + **DPoP proof** over method+URI | audience + scope + **holder key** | **DPoP holder binding** — stolen token unusable without holder key; **DPoP covers method+URI only, not tool/body** [VERIFIED] |
| **B-cap** | append block → `P_i` (offline, no XCHG) | CAP `C_n`, **no HTC, no INV** (bearer capability); OAuth authn on (§E.1) | scope via `C_n` only | nothing (bearer capability) |
| **B3** [D28] | append block → `P_i` **+ HTC hop** (offline) | AT@aud (auth) **+ CAP `C_n` + HTC chain + INV** | audience + scope + **holder identity** + **method+tool+canonical body/args digest + access_token_hash** | **HTC chain + terminal holder proof** — stolen capability unusable without the holder identity key, **and** INV binds the exact call |
| **B3⁺** | as B3 | as B3 **+ jti consumed in bounded cache** | as B3 + duplicate detection | as B3, plus bit-identical replay blocked |

**Three holder-binding regimes made distinct:**
1. **Bearer holder theft** (B2-broad, B2-exchange-*, B-cap): bearer token/capability; anyone capturing it in-window can present it.
2. **DPoP holder binding** (B2-DPoP): AT bound to a holder key via `cnf`/`jkt`; the caller proves possession. Defeats bearer theft. **But** the DPoP proof covers method+URI only **[VERIFIED, RFC 9449]**; since MCP tool calls are JSON-RPC to one endpoint, it does **not** bind the specific tool or body/args — it stops *who* replays, not *what* is substituted at the same endpoint.
3. **B3 body/args binding** (B3): the INV assertion binds `capability_hash, access_token_hash, task_id, audience, method, tool, canonical_request_digest, iat, exp`, signed by the terminal holder identity key named in the HTC chain. Defeats bearer theft (holder proof) **and** same-endpoint tool/argument substitution (canonical body/args digest), which DPoP does not cover. Body/args binding is credited to **INV**, not the capability.

---

# Part D — Attacker × key-possession × tampering-point matrix; rewritten H4; DPoP taxonomy

## D.1 Rewritten H4 [D35] — two falsifiable hypotheses

> **H4a (post-signature, non-holder tampering).** An adversary who captured a valid credential but does **not** possess the terminal holder identity key attempts to (i) reuse it as a different caller, or (ii) substitute tool/arguments after signing. Prediction: `B2-exchange-task` (bearer) admits both; `B2-exchange-task-DPoP` admits (ii) at the same endpoint but blocks (i); **B3 blocks both** (HTC terminal-holder proof blocks (i); canonical body/args digest in INV blocks (ii)). Falsified if B3 admits either, or if DPoP blocks same-endpoint tool/argument substitution.
>
> **H4b (compromised-holder misuse).** An adversary who **does** possess the terminal holder identity key (compromised Specialist) attempts to exceed the grant. Prediction: **no** mechanism blocks a compromised holder acting *within* `C_n` (legitimate authority); **all** `C_n`-enforcing mechanisms block it from exceeding `C_n`, because scope containment is independent of holder identity. Falsified if B3 blocks in-scope compromised-holder actions (would be over-blocking) or any `C_n`-enforcing mechanism admits out-of-`C_n` actions.

**B3 does not claim to stop a compromised holder from misusing authority it legitimately holds.** It claims to stop scope escalation (chain) and credential misuse by non-holders (HTC + INV). The compromised-holder-within-scope residual is out of scope of every mechanism and stated as such.

## D.2 DPoP attacker taxonomy [VERIFIED basis; replaces the earlier informal model]

Four distinct adversaries, each with stated held artifacts and position:

- **`dpop-stolen-AT-key-substitution`** — has `AT@aud` but not the DPoP holder key; presents the token with its own key. **Blocked** by DPoP (proof fails against the token `cnf`/`jkt`).
- **`dpop-captured-proof-replay`** — has a complete valid method+URI DPoP proof and the token; resubmits bit-identically. **Not** blocked by DPoP alone (same method+URI); blocked only by an authenticated-request-ID replay cache keyed on the DPoP `jti`.
- **`dpop-first-use-body-mutation`** — a malicious component **between the holder's proof signing and the TLS client** alters the body/tool on the **first** use, reusing the holder's genuine, not-yet-seen proof. **Not** blocked by DPoP (body/tool outside the proof); blocked by an INV body/args binding.
- **`dpop-compromised-holder`** — **possesses** the DPoP holder key; can sign fresh valid proofs. No holder-proof mechanism blocks a compromised holder within scope; scope containment still bounds it.

The earlier "pre-emptive submission that does not reuse the victim's proof" phrasing is **removed**: an attacker without the holder key cannot produce any valid DPoP proof, so there is no valid-DPoP request without either the captured proof or the holder key.

## D.3 The matrix

Tampering points: **T-reuse** (captured credential as a different caller); **T-tool** (substitute tool, same endpoint); **T-args** (substitute arguments, same tool); **T-scope** (request authority outside `C_n`); **T-replay** (bit-identical in-window resubmission). Key possession: **K-none** (only a captured credential); **K-holder** (possesses terminal holder identity key). ✅ = blocked, ❌ = admitted, — = legitimate/NA.

| Attacker key | Tampering point | B2-exchange-task (bearer) | B2-exchange-task-DPoP | B3 | B3 conjunct that blocks |
|--------------|-----------------|:-------------------------:|:---------------------:|:--:|-------------------------|
| K-none | T-reuse | ❌ | ✅ | ✅ | `holder_proof_ok` + `htc_chain_ok` |
| K-none | T-tool (same endpoint) | ❌ | ❌ | ✅ | `invocation_binding_ok` (tool) |
| K-none | T-args (same tool) | ❌ | ❌ | ✅ | `invocation_binding_ok` (canonical_request_digest) |
| K-none | T-scope (outside `C_n`) | ✅ | ✅ | ✅ | `R ⊆ C_n` (containment) |
| K-none | T-replay (bit-identical) | ❌ | ❌ | ❌ (B3⁺ ✅) | none in B3; B3⁺ jti cache |
| K-holder | T-scope (outside `C_n`) | ✅ | ✅ | ✅ | `R ⊆ C_n` (independent of holder) |
| K-holder | in-scope action | — | — | — | legitimate; no mechanism blocks (H4b) |

DPoP closes T-reuse but not T-tool/T-args at a shared endpoint — exactly the gap B3's canonical body/args binding fills. A measured, falsifiable distinction, not an assertion of superiority; the residual difference is credited to **INV**, not the capability.

---

# Part E — Baseline ladder, two-phase OAuth, F1 split, expected matrix, bitmasks

## E.1 The ladder [DESIGN, D19] — every strong baseline receives identical `C_0..C_n`

| Baseline | Mechanism | Receives per-hop `C_i`? | Prevents F1-terminal? | Binds invocation? | Holder-bound? | Online per-hop? | Isolates |
|----------|-----------|:-----------------------:|:---------------------:|:-----------------:|:-------------:|:---------------:|----------|
| **B0** | no delegation protection | n/a | no | no | no | no | the vulnerability exists |
| **B1** (appendix) | static API key | n/a | no | no | no | no | a static secret adds nothing |
| **B2-broad-noexchange** | OAuth 2.1, broad, bearer, RFC 8707 | broad only | no | no | no | no | audience binding alone does not attenuate |
| **B2-exchange-broad** | + XCHG, scope unchanged | broad | no | no | no | **yes** | isolates the exchange round-trip cost from narrowing |
| **B2-exchange-task** | + XCHG narrowed to `C_i` (+RAR) | **yes** | **yes** | no | no | **yes** | the fair strong OAuth arm |
| **B2-exchange-task-DPoP** [D34] | + DPoP (cnf=holder jkt) | **yes** | **yes** | method+URI only | **yes** (key) | **yes** | DPoP holder binding vs B3 body/args binding |
| **B-cap** | attenuating capability, no HTC, no INV; OAuth authn **on** | **yes** | **yes** | no | no | no (offline) | offline attenuation, separated from binding |
| **B3** | full control layer | **yes** | **yes** | **yes** | **yes** | no (offline) | binding + holder + labels + offline stateless verification |
| **B3⁺** | B3 + bounded jti cache | **yes** | **yes** | yes + dup detection | **yes** | no | price of closing duplicate replay |

**B-cap fixed [E6]:** primary B-cap fixes `oauth_authn = 1` on the same OAuth substrate as B3, and **MUST** verify audience and expiry. A standalone-capability (`oauth_authn = 0`) configuration may exist **only** as a separate exploratory arm, never in the formal matrix. No undecided cell appears in the formal matrix.

**Honest headline (paste-ready):**

> On the frozen benchmark, a well-configured token-exchange deployment (`B2-exchange-task`) and the capability baselines all prevent scope amplification, because all enforce the same narrowed `C_n`. They differ in three measured respects: the token-exchange arms bind authority to an audience and a scope but not to the individual invocation, whereas B3 binds each invocation and each holder; the token-exchange arms narrow by contacting the authorization server on each delegation hop under the tested configuration, whereas the capability arms attenuate offline; and the bearer token, once issued, is replayable by any holder in its window, whereas B3's holder binding prevents reuse by a different party. The benchmark measures the security consequences on the invocation-integrity and replay families and the overhead consequences on the decomposed latency axis.

## E.2 Two-phase OAuth [DESIGN, E2] — setup cost vs delegation cost

- **Phase 1 — setup (identical across all agents; measured separately as `setup_cost`, excluded from the delegation estimand).** Every agent obtains a resource-specific base `AT@aud` through the **same** pre-provisioned path (auth-code + PKCE against the pinned AS, or a pre-issued fixture token), identical for B2 and B3. No delegation authority is expressed in the base token; it establishes only MCP resource authorization and the OAuth actor identity.
- **Phase 2 — delegation (the measured `delegation_cost`, per hop; the quantity compared).** B2 arms perform, at each hop, an online XCHG under the pinned AS profile to obtain `AT_i` with authority `C_i`; B3/B-cap perform an **offline** attenuation `P_{i−1} → P_i` (authority `C_i`) with no AS round-trip. The online-vs-offline difference is the intended measurement.

**Pinned experiment AS profile [DESIGN, replaces "RFC 8693 inherently down-scopes"].** RFC 8693 does **not** by itself guarantee a narrower exchanged token; scope/audience/`authorization_details` are AS-policy-determined **[VERIFIED]**. This experiment pins an AS exchange profile that, at hop `i`, issues `AT_i` with exactly authority `C_i` and **enforces** `C_i ⊆ C_{i−1}` by construction (rejecting any exchange that would widen beyond `C_{i−1}`). An **independent harness verifier** recomputes `Allowed(AT_i)` over `Ω` and asserts `Allowed(AT_i) = C_i` for every hop and every strong baseline (gate G-13). If the AS/library cannot realize the profile, it is disclosed and the affected baseline is marked, never silently mis-provisioned.

## E.3 F1 split [DESIGN, E2]

- **`F1-root`** — the request requires `R ⊄ U_task` (outside the root grant `C_0`). Expected **block** on every strong baseline (all enforce `C_n ⊆ C_0`).
- **`F1-terminal`** — `R ⊆ U_task ∧ R ⊄ C_n` (inside the root grant but outside the narrowed terminal authority). Expected **block** on every strong baseline **iff** it realized the full `C_0→…→C_n` narrowing; a baseline enforcing only `C_0` would admit it — hence matched provisioning and the `Allowed(AT_i)=C_i` check are mandatory.
- **`F1-chain-tamper`** — the attacker manipulates a hop to make `C_i ⊄ C_{i−1}`. Expected **block** on B-cap/B3 by Biscuit block scoping under the MSc profile (§A.6.1) and on exchange arms by the pinned AS profile refusing a widened `AT_i`. **NA** for B0, B1, `B2-broad-noexchange`, `B2-exchange-broad` (no per-hop authority chain to tamper with).

## E.4 Scenario families and the expected matrix

Families: **F1** amplification (root / terminal / chain-tamper); **F2** identity; **F3** invocation integrity {`dpop-stolen-AT-key-substitution` (=T-reuse), `dpop-first-use-body-mutation` (=T-tool/T-args), audience-mismatch (OAuth negative control), expired-token (OAuth negative control), `dpop-captured-proof-replay` (=bit-identical)}; **F4** information-flow/egress; **F5** human approval. Held-out instances sealed from F1, F3, F4.

**Expected allow/block/NA matrix** (frozen benchmark; **predictions**, exact counts to be measured on the sealed corpus, not asserted). **B** = expected block, **A** = expected allow (attack succeeds / benign proceeds), **NA** = not applicable.

| Subcase (family) | B0 | B1 | B2-broad-noexch | B2-exch-broad | B2-exch-task | B2-DPoP | B-cap | B3 | B3⁺ |
|------------------|:--:|:--:|:---------------:|:-------------:|:------------:|:-------:|:-----:|:--:|:---:|
| F1-root (R ⊄ U_task) | A | A | A | A | **B** | **B** | **B** | **B** | **B** |
| F1-terminal (R ⊆ U_task, R ⊄ C_n) | A | A | A | A | **B** | **B** | **B** | **B** | **B** |
| F1-chain-tamper | NA | NA | NA | NA | **B** | **B** | **B** | **B** | **B** |
| F2 invalid_credential | NA | **B** | **B** | **B** | **B** | **B** | **B** | **B** | **B** |
| F2 wrong_principal (frozen task→principal policy) | NA | NA | **B** | **B** | **B** | **B** | **B** | **B** | **B** |
| F2 wrong_holder_proof / wrong_dpop_key | NA | NA | NA | NA | NA | **B** | NA | **B** | **B** |
| F2 unauthenticated_caller | A | **B** | **B** | **B** | **B** | **B** | **B** | **B** | **B** |
| F3 dpop-stolen-AT-key-substitution (T-reuse) | A | A | A | A | A | **B** | A | **B** | **B** |
| F3 dpop-first-use-body-mutation (T-tool/T-args) | A | A | A | A | A | A | A | **B** | **B** |
| F3 audience mismatch (OAuth neg. control) | A | A | **B** | **B** | **B** | **B** | NA | **B** | **B** |
| F3 expired token (OAuth neg. control) | A | A | **B** | **B** | **B** | **B** | NA | **B** | **B** |
| F3 dpop-captured-proof-replay (bit-identical) | A | A | A | A | A | A | A | A | **B** |
| F4 sensitive egress, no declassification | A | A | A† | A† | A† | A† | A† | **B** | **B** |
| F5 high-risk action, no approval artifact | A | A | A† | A† | A† | A† | A† | **B** | **B** |

† F4/F5 comparisons are valid **only** among B3 and its matched ablations, **unless** the OAuth arms are given the **same** boundary-owned context/approval reference monitor (using the mechanism-neutral `authz_context_hash`, §F.2). A difference existing only because B3 has a monitor and the OAuth arm does not **MUST NOT** be reported as a capability-vs-OAuth advantage; it is a reference-monitor-configuration difference and is labelled as such (gate G-15). The A† cells therefore denote "admitted **absent** the shared monitor"; with the shared monitor the OAuth arms also block, and F4/F5 then measure the monitor, not the mechanism.

**Replay/holder detail** (four-way taxonomy, with the orthogonal control arms):

| Subcase | B2-exch-task (bearer) | B2-DPoP | B2-DPoP + replay cache | B2-DPoP + INV-only | B3 | B3⁺ |
|---------|:---------------------:|:-------:|:----------------------:|:------------------:|:--:|:---:|
| dpop-stolen-AT-key-substitution | A | **B** | **B** | **B** | **B** | **B** |
| dpop-first-use-body-mutation | A | A | A | **B** | **B** | **B** |
| dpop-captured-proof-replay (bit-identical) | A‡ | A | **B** | A | A | **B** |

‡ bare bearer has no authenticated per-request ID, so the replay cache **cannot** attach to `B2-exch-task`; its replay exposure is inherent to the bearer choice, not closed by the orthogonal layer.

## E.5 Module bitmask per baseline (and matched ablations)

```
bits = [ oauth_authn | crypto_chain | authorizer | htc/holder | invoke | contain | context | approval | jti_cache | audit ]
```

| Baseline / variant | oauth | crypto_chain | authorizer | htc/holder | invoke | contain | context | approval | jti | audit |
|--------------------|:-----:|:------------:|:----------:|:----------:|:------:|:-------:|:-------:|:--------:|:---:|:-----:|
| B0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| B1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| B2-broad-noexchange | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| B2-exchange-broad | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| B2-exchange-task | 1 | 0 | 0 | 0 | 0 | (scope in token) | 0 | 0 | 0 | 1 |
| B2-exchange-task-DPoP | 1 | 0 | 0 | dpop-cnf | 0 | (scope in token) | 0 | 0 | 0 | 1 |
| B-cap | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| **B3** | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 |
| **B3⁺** | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| B3 −attenuation (unsafe control, §E.6) | 1 | 1 | *root-only* | 1 | 1 | 1 | 1 | 1 | 0 | 1 |
| B3 −holder | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 1 |
| B3 −invoke | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 0 | 1 |
| B3 −contain | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 1 |
| B3 −context | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 1 |
| B3 −approval | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 1 |

(For `B2-exchange-task`, containment is enforced by the AS-issued token scope, not a boundary module; the parenthetical marks that. `audit` never sits on the decision path — toggling it tests log completeness and latency, **not** prevention; the pre-registration does **not** predict that removing `audit` changes any prevention outcome.)

## E.6 Matched ablation closing semantics [DESIGN, D36 + E1] — orthogonal fixtures

Each ablation is `B3` with exactly one decision-path conjunct disabled and an **orthogonal fixture** blocked only by that conjunct.

| Variant | Conjunct disabled | Closing semantics (precise) | Orthogonal fixture |
|---------|-------------------|------------------------------|--------------------|
| **−attenuation** (renamed from −chain; **non-Biscuit unsafe control**) | effective-authorization recomputation over the chain | Instead of `C_n = Allowed(P_n; Γ, κ, Ω)`, authorize against `Allowed(P_0; Γ, κ, Ω)` — **ignoring every attenuation block**. A well-formed Biscuit authorizer cannot be made to trust later-block widening without third-party keys (forbidden by the MSc profile), so this is implemented as an **unsafe reference monitor that bypasses Biscuit attenuation**, present only to show narrowing produces the F1-terminal block. | A capability where `C_n ⊊ C_0` and `R ∈ C_0 \ C_n`: full B3 (evaluates `C_n`) **blocks**; `−attenuation` (evaluates `C_0`) **admits**. |
| **−holder** | `holder_proof_ok` + `htc_chain_ok` | Skip HTC-chain and terminal-holder proof; accept as bearer capability | A capability captured from the legitimate holder, presented by a **different** key with a self-signed INV |
| **−invoke** | `invocation_binding_ok` | Skip binding of authority to method/tool/args/audience/window; accept any in-scope tool | A valid in-scope capability replayed against a **different tool or arguments**, same audience, in-window |
| **−contain** | `R ⊆ C_n` | Skip containment; allow if chain and bindings verify regardless of whether `R` exceeds `C_n` | A holder-bound, invocation-bound request requiring authority **outside** `C_n` |
| **−context** | `context_policy_ok` | Skip the label→action-type policy | An in-scope outward call carrying a **sensitive-labelled** payload with no declassification artifact |
| **−approval** | `approval_artifact_ok` | Skip approval-artifact verification | A high-risk in-scope action with **no** valid approval artifact |

Each orthogonal fixture is designed so **only** the named conjunct blocks it; every other conjunct passes. This is what makes each a matched leave-one-out rather than a component-only build.

---

# Part F — Implementation schemas and formal invariants

## F.1 EvidenceBundle, sealed intent, trusted mediation, effect ledger [DESIGN, D33 + E7]

The oracle **never** reads a SUT-computed auth verdict or a SUT-computed digest. It recomputes everything from raw evidence, sealed truth, and an immutable external ledger.

```python
# --- Per-mechanism credential evidence (raw or securely retained) ---
class ApiKeyEvidence(BaseModel):     kind: Literal["api_key"];    raw_key_ref: str
class OAuthEvidence(BaseModel):       kind: Literal["oauth"];      raw_at: bytes; dpop_proof: Optional[bytes] = None
class CapabilityEvidence(BaseModel):  kind: Literal["capability"]
                                      signed_blocks: list[bytes]           # P_0..P_n as canonical SignedBlocks
                                      htc_chain: list[bytes]; invocation_assertion: bytes; raw_at: bytes

# --- Composite bundle: OAuth+capability+HTC+INV; DPoP+INV; B0/no-credential ---
class EvidenceBundle(BaseModel):
    oauth:      Optional[OAuthEvidence]      = None
    capability: Optional[CapabilityEvidence] = None
    api_key:    Optional[ApiKeyEvidence]     = None
    inv_only:   Optional[bytes]              = None   # for the B2-DPoP + INV-only control arm
    # B0 / no-credential = all fields None

class LabelAssertion(BaseModel):    payload_digest: str; label: str; issuer_kid: str; iat: int; exp: int; signature: bytes
class DeclassificationArtifact(BaseModel):
    task_id: str; audience: str; tool: str; request_digest: str; recipient: str
    payload_digest: str; from_label: str; to_label: str; policy_version: str
    approver_kid: str; iat: int; nbf: int; exp: int; jti: str; signature: bytes

# --- What the harness OBSERVES at the boundary (no SUT verdict, no SUT digest) ---
class ObservedRequest(BaseModel):
    correlation_id: str                 # UNFORGEABLE, harness-minted (128-bit; bound into sealed intent + records + INV jti)
    evidence: EvidenceBundle            # raw; harness re-verifies every layer independently
    audience: str; method: str; tool: str
    raw_arguments: bytes                # the ORACLE recomputes the digest from these bytes itself
    payload_labels: list[LabelAssertion]
    declassification: Optional[DeclassificationArtifact]
    approval_artifact: Optional[bytes]
    iat: int

# --- Trusted mediation records, emitted by the interposition layer (gates G-6/G-7) ---
class MediationEvent(BaseModel):     correlation_id: str; admitted: bool; reason_code: str; boundary_ts_ns: int
class ToolIngressEvent(BaseModel):
    correlation_id: str; tool: str; audience: str
    ingress_request_digest: str         # digest computed at the tool ingress, independently
    payload_digest: Optional[str]; value_id: Optional[str]; ingress_ts_ns: int

# --- Sealed ground truth, harness-only (τ_gt lives here; no SUT principal may read it) ---
class IntendedInvocation(BaseModel):
    correlation_id: str
    resource_owner: tuple[str,str]      # (iss, sub)
    oauth_actor: tuple[str,str]         # (iss, act/client_id)
    htc_holder_kid: str
    audience: str; method: str; tool: str
    intended_request_digest: str        # sealed expected JCS digest
    intended_labels: list[str]; requires_approval: bool
    U_task: frozenset[tuple[str,str]]
    P_hashes: list[str]                 # H(P_0)..H(P_n)
    C_sets:   list[frozenset[tuple[str,str]]]   # C_0..C_n over Ω
    R: frozenset[tuple[str,str]]        # required authority of the concrete request
    tau_gt: frozenset[tuple[str,str]]   # ground-truth task-required scope; ORACLE-ONLY
    attack_subcase: str                 # e.g. "F3:dpop-first-use-body-mutation"

# --- Immutable external effect ledger ---
class EffectEvent(BaseModel):
    effect_id: str; correlation_id: str
    tool: str; audience: str
    action: str; resource: str; recipient: Optional[str]
    effect_request_digest: str          # digest of what the tool ACTUALLY acted on
    payload_digest: Optional[str]; value_id: Optional[str]
    data_labels_touched: list[str]; approval_ref: Optional[str]
    principal: str; timestamp_ns: int
```

**Unforgeable correlation ID [DESIGN].** `correlation_id` is a harness-minted random 128-bit value bound into the sealed `IntendedInvocation`, the `MediationEvent`, the `ToolIngressEvent`, and (for authenticated mechanisms) the INV `jti`. The SUT cannot fabricate, swap, drop, or duplicate the linkage without detection; gate G-12 injects swap/drop/duplicate/concurrency faults and the oracle flags any mismatch.

## F.2 INV assertion, holder-transition certificate, approval artifact [DESIGN, D30/D31/D25 + E4/E8]

The three objects below are the `HolderTransitionCert` (HTC), the `InvocationAssertion` (INV), and the `ApprovalArtifact`, given here as signed-payload templates rather than plain pydantic classes because each is a **signed** object with a domain tag; the field lists are the authoritative schemas.

**Domain separation and versioning (MUST).** Every signature is over a byte string prefixed with a fixed domain tag and schema version, so an HTC can never be reinterpreted as an INV or across versions. Tags: `"AASC-HTC-v1"`, `"AASC-INV-v1"`. Each object carries `schema_version` and a `kid` selecting the signer key from the identity-plane registry.

**`H_JCS` construction (frozen) [DESIGN, ADR 0009].** `H_JCS(x) = lowercase_hex( SHA-256( b"AASC-JCS-DIGEST" ‖ 0x01 ‖ u32be(len(C)) ‖ C ) )`, where `C` is the RFC 8785 canonical UTF-8 bytes of `x` (`rfc8785==0.1.4`, ADR 0005). Same family as the §A.0.1 capability commitment — versioned, domain-separated, length-delimited, fail-closed on any unsupported version — with a distinct tag and no algorithm byte (the hash is fixed by the version), so the two constructions and a bare digest can never be confused. Output is 64 lowercase hex characters; this fixes the string encoding of every `H_JCS`-governed digest field (`intended_request_digest`, `effect_request_digest` — the full field classification is in ADR 0009). Oracle-side implementation: `src/harness/oracle/jcs_digest.py`; the SUT-side computation must be independent (D21), and the oracle never consumes a SUT-computed digest (§F.1).

```
# Hop 0 (issuance), signed by the AS root key κ:
HTC_0 = Sign_κ,"AASC-HTC-v1"(
    schema_version:1; kid:kid_AS
    prefix_hash: commit_prefix(BlockID_0..BlockID_0)   # authority prefix commitment (§A.0.1, ADR 0003)
    child_block_hash: BlockID_0         # block 0's signature (revocation identifier)
    signer_pubkey: κ_pub
    next_holder_pubkey: initial_holder_pubkey     # UNIFIED field name at every hop
    task_id; audience; iat; nbf; exp; depth:0 )

# Hop i ≥ 1, signed by the CURRENT holder identity key:
HTC_i = Sign_{holder_{i-1}},"AASC-HTC-v1"(
    schema_version:1; kid:kid_{holder_{i-1}}
    prefix_hash: commit_prefix(BlockID_0..BlockID_{i-1})   # parent prefix commitment (§A.0.1, ADR 0003)
    child_block_hash: BlockID_i         # exact child block's signature (revocation identifier)
    signer_pubkey: holder_{i-1}_pubkey  # == HTC_{i-1}.next_holder_pubkey
    next_holder_pubkey: holder_i_pubkey
    task_id; audience                   # copied unchanged from HTC_{i-1}
    iat; nbf; exp                       # exp ≤ HTC_{i-1}.exp (non-increasing)
    depth: HTC_{i-1}.depth + 1 )        # contiguous

# Per-invocation assertion, signed by the TERMINAL holder identity key:
INV = Sign_{holder_n},"AASC-INV-v1"(
    schema_version:1; kid:kid_{holder_n}
    capability_hash: capability_commitment(P_n)   # = commit_prefix(BlockID_0..BlockID_n), ADR 0003
    access_token_hash: H(AT@aud)        # binds the presented OAuth token (§A.5.1)
    task_id; audience; method; tool
    canonical_request_digest: H_JCS(raw_arguments)   # RFC 8785 JCS over arguments; frozen construction ADR 0009
    label_assertions_digest
    invocation_id (jti); iat; nbf; exp )

# Approval artifact — MECHANISM-NEUTRAL binding, so an OAuth arm with the same monitor can present it:
authz_context_hash = H( task_id, audience, tool, canonical_request_digest, resource_owner, oauth_actor )
ApprovalArtifact { authz_context_hash; approver_kid (trusted); iat; nbf; exp; jti; replay_rule; signature }
```

**Zero-hop rule (MUST).** With no delegation (`n = 0`), a valid chain is exactly `HTC_0` with `next_holder_pubkey = initial_holder_pubkey`; INV is signed by that key. No separate code path — `n = 0` is the general verification with a one-element chain.

**Verification (MUST all hold):** `HTC_0` verifies under κ with the HTC tag; for every `i ≥ 1`, `HTC_i.signer_pubkey == HTC_{i-1}.next_holder_pubkey` and `HTC_i` verifies under `signer_pubkey`; `task_id`/`audience` invariant; `depth` contiguous from 0; `exp` non-increasing, every `nbf ≤ now ≤ exp`; `prefix_hash`/`child_block_hash` match the presented `P_{i-1}`/`SignedBlock_i`; `terminal HTC.next_holder_pubkey == INV.kid` key; INV verifies under the terminal holder key with the INV tag; `INV.capability_hash == capability_commitment(presented token)` (recomputed from raw bytes, §A.0.1/ADR 0003); `INV.access_token_hash == H(presented AT@aud)`; `INV.canonical_request_digest == H_JCS(raw_arguments)`; the number of HTCs **equals** the number of presented signed blocks — every presented `SignedBlock_i` is covered by a corresponding `HTC_i`, and a block with no covering HTC is **rejected** (the `INV.capability_hash` check already detects such a block; this count check fails fast and yields an unambiguous reason code; implemented oracle-side as `check_htc_coverage`, ADR 0003) `[ADR 0002/0003]`. Verification requires only κ plus the in-chain holder keys resolved via the registry.

**Why HTC is separate from Biscuit [VERIFIED].** Biscuit's per-block signatures use single-use keypairs that prove blocks are correctly chained; only the authority block is signed by a well-known multi-use key. Those block keys do **not** authenticate *which principal* performed each attenuation. Holder binding needs delegate *identity*, so the HTC chain is signed by each hop's identity key and carries `next_holder_pubkey`; the terminal INV must be signed by the key the last HTC names, chaining back to issuance. This is a project construction layered on Biscuit, and is described as such.

### F.2.1 Identity-plane registry [DESIGN]

`actor_of(·)` maps an OAuth `act`/`client_id` claim to a single principal; the registry maps that principal to exactly one `htc_holder` public key. Every actor claim and holder key used in a scenario **MUST** resolve to exactly one principal; unmapped actors/keys are rejected. `resource_owner` subjects are recorded but are **not** part of the holder mapping. The registry, `Ω`, `Γ`, the frozen `task_authorization_policy` (task → authorized actor principals, for F2 `wrong_principal`), and the allowed-sink policy are all frozen and hashed before sealing.

## F.3 Capability-chain invariants [DESIGN, D32]

With `C_i = Allowed(P_i; Γ, κ, Ω)` (§A.0.1), `R` the required authority, `A` the exercised authority (from the ledger):

```
INV-1 (root):           C_0 ⊆ U_max
INV-2 (monotone):       ∀ i ∈ [1,n]:  C_i ⊆ C_{i-1}                # by block scoping, MSc profile (§A.6.1)
INV-3 (terminal):       C_n ⊆ C_0 = U_task                        # transitively
INV-4 (request):        allow ⟹ R ⊆ C_n                          # containment, pre-execution
INV-5 (effect≤request): A ⊆ R      # under complete mediation + trusted tool
INV-6 (effect≤grant):   A ⊆ C_n ⊆ U_task                          # composition; VERIFIED POST-HOC
```

INV-1..3 rest on Biscuit block scoping under the MSc profile; **the entire F1 result depends on G-2 confirming that the frozen `Γ` yields `C_i ⊆ C_{i−1}` for every appended block — an [UNVERIFIED-IA] until G-2 passes.** INV-4 is the containment conjunct. INV-5/6 are **checked by the oracle after execution** from the ledger; a violation indicates a mediation or tool-trust failure to report.

## F.4 Unverified implementation assumptions [D39] — nothing is "proven by spec"

| # | Assumption | Status | Gate |
|---|-----------|--------|------|
| IA-1 | The chosen Python Biscuit library exists, is maintainable, and exposes append-block attenuation + root-public-key verification with a stable API | **Verified by gate G-1** for `biscuit-python==0.4.0` (PyO3 over `biscuit-rust` 6.0.0; wheels for cp39–cp313; no Rust toolchain required): offline attenuation without the root secret, verification with the root public key alone, stable prefix commitments `H(P_i)` (the §A.0.1 **BlockID commitment**, ADR 0003 — encoding-independent, not a raw-container-byte hash), and append-detection all confirmed. **Residuals:** the binding is a 0.x API (a version bump re-triggers G-1); `BlockID_i` is the spec-defined revocation identifier (the block signature), so the commitment depends on the versioned **format specification**, not the 0.x Python API; the Biscuit format is **not formally audited**. | G-1 |
| IA-2 | Under the frozen `Γ`, `C_i ⊆ C_{i−1}` holds for every appended block, and third-party/`trusting` config is rejected as out of profile | **[UNVERIFIED-IA]** | G-2 |
| IA-3 | Ed25519 signing/verifying of HTC+INV is deterministic and fast enough that boundary verification stays below the equivalence margin | **[UNVERIFIED-IA]** | G-3 |
| IA-4 | The OAuth stack (`authlib`) supports RFC 8693 exchange narrowing to `C_i` + RFC 9396 authorization_details, or a behaviourally faithful AS can be built | **[UNVERIFIED-IA]** | G-4 |
| IA-5 | A DPoP-bound (cnf/jkt) access token can be issued/verified in the local AS | **Verified by gate G-5** for `joserfc==1.7.4` (JOSE surface only, ADR 0006), with issuance **simulated locally** (frame-local mint): `jkt` per RFC 7638/RFC 8037 (A.3 known answer reproduced by the library and an independent computation), `cnf.jkt`-bound token issue/verify (issuer key ≠ holder key), proof verification per RFC 9449 §4.3 items 3–9, 11 + the §6.1 binding, wrong-holder proof rejected **at the `cnf.jkt` ↔ proof-`jwk` thumbprint comparison**, independent `htm`/`htu` rejection, negative control green. **Residuals:** the **real AS is G-4** (token endpoint, RFC 8693/9396, `ath`, nonce — all still [UNVERIFIED-IA]); the four-way DPoP taxonomy is G-14; `htu` RFC 3986 normalization is a production-verifier concern (G-11/G-14); exact 1.x pin — any bump re-triggers G-5. | G-5 |
| IA-6 | The MCP Python SDK exposes tool-call handling where the boundary can mediate **every** call (complete mediation) and emit a `MediationEvent` | **Verified by gate G-6** for `mcp==1.28.1` (ADR 0013): every enumerated SDK dispatch path (documented protocol path, server-side convenience calls, internal dispatch, post-install registration, direct registry insertion, forged-request handler invocation) converges on the registered tool-function object, which the harness installer wraps (wrap-at-fn + wrap-on-insert registry); denial blocks execution (tool-side witness), a raising tool emits exactly one event, and with the interposition removed the same calls reach the tool with zero events (non-vacuity). **Residuals:** claim scoped to FastMCP servers built by the harness installer; in-process raw-reference/introspection paths excluded by SUT process separation (stressed at G-12); interposition targets private SDK internals — exact pin, any bump re-triggers G-6; boundary **policy** correctness is not claimed (G-2/G-11/G-13). | G-6 |
| IA-7 | An immutable external effect ledger + `ToolIngressEvent` recorder can be interposed at the tool, independent of agent self-report | **Verified by gate G-7** for `mcp==1.28.1` + the exclusive-share ledger process (`src/harness/effect_ledger.py`): ingress + effect events recorded with the harness-minted `correlation_id`; every SUT-side write/append/truncate/delete attempt fails at the OS level (Win32 `FILE_SHARE_READ`-only handle; attribute/`chmod`-proof); in-place modification rejected with bytes unchanged; the ledger survives a lying SUT self-report (the lie is detected from the ledger alone); an unreached tool produces zero entries. `ingress_request_digest` = `H_JCS` recorder-side (ADR 0012). **Residuals:** Windows-only enforcement — a recorded platform decision, not a footnote (**ADR 0014**: Windows is the sealed measurement platform; the POSIX variant is deferred post-submission and no cross-platform claim is made until it passes the five G-7 checks); in-process reachability inside the harness process excluded by SUT process separation and stressed at G-12; record semantics are oracle territory (Part I). | G-7 |
| IA-8 | RFC 8785 JCS canonicalization agrees across signer and verifier | **Verified by gate G-8** for `rfc8785==0.1.4` (pure Python, Apache-2.0, typed): encoding-invariant canonicalisation (member order, insignificant whitespace, equivalent escapes), separate-process signer/verifier byte-identical agreement, RFC-vector conformance (§3.2.4 byte vector exact; §3.2.3 UTF-16 code-unit sort order; Appendix B numbers 24/24), fail-closed on out-of-model input (NaN/Infinity, lone surrogates, non-string keys, non-JSON types, ints at or beyond 2^53). **Residuals:** 0.x pin (any bump re-triggers G-8; the regression suite is the harness); the frozen `H_JCS` construction (hash function, domain tag, digest string encoding) is **underspecified here and deliberately not invented** — open decision, `smoke/g8/REPORT.md` §9; RFC 8785 is Informational, so conformance rests on the vector tests, not on a standards-track mandate. | G-8 |
| IA-9 | The jti cache (B3⁺) does atomic multi-process check-and-insert, fail-closed, under the harness concurrency | **[UNVERIFIED-IA]** | G-9 |

**[VERIFIED] facts (not assumptions):** Biscuit appends per hop; the format defines sealing as a terminal operation (not exposed by the chosen binding and not used by this design — D22 note, ADR 0002); Biscuit block keys are single-use and do not authenticate delegates; monotonicity is by Datalog block scoping, not signature rejection; DPoP proofs cover method+URI only; A2A leaves authorization to implementations and defines `TASK_STATE_AUTH_REQUIRED` in-task auth with out-of-band credential acquisition; MCP authorization is an optional OAuth-2.1 profile; RFC 8693 does not mandate per-hop exchange or down-scoping; RFC 7800 `cnf` is holder-of-key and should be paired with audience restriction.

## F.5 B3⁺ jti-cache semantics [DESIGN, D37]

```
Structure:    bounded map jti -> expiry_ns; max size; TTL eviction; key namespace = (mechanism_tag, jti).
Consumption:  at the boundary, AFTER all other conjuncts pass and BEFORE the tool executes,
              an ATOMIC check-and-insert:
                  if jti present and not expired -> REJECT as duplicate (no execution)
                  else insert(jti, now+Δ) and proceed
Atomicity:    single critical section; MULTI-PROCESS atomic (not just per-thread); no window in which
              two identical jti both pass (gate G-9).
Concurrency:  concurrent identical requests -> exactly one proceeds; the rest rejected.
Fail-closed:  on capacity or backend error, REJECT rather than admit on doubt.
Failure/retry:if the tool call fails AFTER jti consumption, the jti stays consumed for Δ; a legitimate
              retry within Δ is rejected as a duplicate. Deliberate, documented trade-off: B3⁺ trades
              retry-within-Δ for duplicate-replay prevention. Retries wait out Δ or carry a fresh jti.
Eviction:     entries older than Δ evicted lazily and/or by periodic sweep; never revives a valid jti.
Idempotency:  at-most-once ADMISSION per jti within Δ. Does NOT make the tool idempotent; prevents
              duplicate admission, not duplicate effects from a single admission.
```

The retry-vs-duplicate trade-off is why bit-identical replay is a *residual* in B3 and closed only in B3⁺ at a stated usability cost — and why the benign near-miss "legitimate retry within Δ" fixture is expected to be **blocked** under B3⁺, which the false-blocking analysis reports honestly rather than hides.


---

# Part G — Feasibility smoke-gate checklist (Claude Code runs these)

**No v0.5, no sealing, no confirmatory corpus until every in-scope gate passes on the pilot corpus.** Each gate is a minimal runnable test, not an experiment.

**Execution DAG (respect dependencies):**
```
G-1 / G-5 / G-8  →  G-6 / G-7  →  G-2 / G-4 / G-11  →  G-12 / G-13  →  G-9 / G-14  →  G-10
```
G-3 (latency spike) may run any time after G-1, but its threshold is fixed beforehand. **Claim-dependent gates** (G-3 latency, G-14 replay/DPoP, G-15 F4/F5, and the INV-only check) run **only** for claims retained in the sealed scope; a deferred claim's gate is marked deferred and must not contradict that deferral.

### G.1 Feasibility spikes (runnable immediately)

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-1** | Import the Python Biscuit library; mint `C_0` (`P_0`); append one block → `P_1`; verify against the root **public** key only; confirm **(F)** prefix commitments are **stable** under append and agree between signer and verifier, and **(G′)** the **terminal** commitment **changes** under append — commitments per the §A.0.1 **BlockID commitment scheme** (ADR 0003), not raw prefix bytes | Round-trips and verifies with `κ_pub` alone; `commit_prefix(P_0)` identical before and after append; signer-side and verifier-side commitments agree **across a separate-process verifier**; terminal commitment differs after a post-hoc append, so `INV.capability_hash` rejects it; **commitment is encoding-independent** (a semantically equivalent container re-encoding yields the same commitment); **fail-closed** on unsupported commitment version and non-Ed25519 algorithms; API stable enough to script. *(Seal terminality is not a criterion: this design never seals — ADR 0002. G-1 is CONDITIONAL PASS until the ADR 0003 corrective suite passes — status on the smoke board.)* | IA-1; whole capability track |
| **G-3** *(claim: latency)* | Sign/verify 1,000 HTC+INV pairs (Ed25519); time boundary verification | Median below the **externally fixed** G-3 smoke threshold (set before measuring) | IA-3; the "lightweight" claim |
| **G-5** | Issue/verify a DPoP-bound (cnf/jkt) token; proof over method+URI; reject a wrong-holder proof | As stated | IA-5; DPoP arm and H4a |
| **G-8** | Canonicalize identical arguments on signer and verifier via RFC 8785 JCS; compare digests | Byte-identical | IA-8; invocation binding (T-args) |

### G.2 Construct-validity gates (interposition; before the authorizer/mutation gates)

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-6** | Interpose the boundary in the MCP SDK tool-call path; attempt a bypass | No tool call executes without passing the boundary and emitting a `MediationEvent` | IA-6; construct validity of every result |
| **G-7** | Interpose the effect ledger + `ToolIngressEvent` recorder at the tool; execute one call; read both back | Both recorded independently of any SUT self-report; `correlation_id` matches the harness-minted value | IA-7; the independent oracle, all F-predicates |

### G.3 Authorizer, provisioning, HTC gates (require the Part F fixes)

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-2** | Freeze and hash `Γ` (`H(Γ)`). (a) appended widening fact — verifies cryptographically **and** leaves `C_i ⊆ C_{i−1}`; (b) third-party block / `trusting {attacker_key}` — **rejected** as out of profile; (c) `Γ` mutation broadening trust — detected via `H(Γ)`; (d) `−attenuation` control admits what full B3 blocks. Block identity and prefix commitments here are those of ADR 0003 / §A.0.1 (`BlockID_i`, `commit_prefix`), so G-2's `Allowed(P_i)` computation and G-1's commitment scheme cannot drift apart | (a)–(d) all hold; every `C_i` computed over `Ω` by the frozen `Γ`, not asserted | IA-2; the entire F1 prevention claim |
| **G-4** | RFC 8693 exchange under the pinned AS profile yielding `C_i`; verify OAuth-resource ∩ capability effective authority, `actor→holder` mapping, `INV.access_token_hash` | Task-narrowed token issues; both layers enforced; actor mapping resolves | IA-4; B2-exchange-task and the fair-baseline claim |
| **G-11** | HTC mutations: wrong-signer, parent-swap, child-swap, depth-rollback, capability-swap, terminal-key-mismatch, domain-tag confusion (HTC bytes replayed as INV), expired/`nbf`-violating cert; **plus the commitment-layer mutations: block reordering, truncation, container re-encoding, missing HTC coverage, unsupported commitment version, unsupported algorithm** | Each **rejected**; the valid chain (including the `n=0` zero-hop case) passes. Commitment-layer status: reordering, truncation, re-encoding, coverage, version, and algorithm rejection are already **[VERIFIED]** at the commitment layer by the ADR 0003 regression suite (tests 1–8); G-11 proper re-tests them through the full HTC/INV verifier once implemented | IA (HTC correctness); H4a |

### G.4 Oracle-independence and matched-authority gates

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-12** | Fault-injected SUT reporting a **wrong** self-verdict while the ledger records the true effect; plus correlation-ID swap/drop/duplicate/concurrency injection | The oracle's `admission_breach`/`realized_harm`/`log_integrity_failure` and the correlation-ID checks detect every discrepancy **without** reading any SUT verdict or SUT digest | oracle independence; every security result |
| **G-13** | Assert `Allowed(AT_i) = C_i` for every hop and every strong baseline; assert each realizes the same `C_0→…→C_n` on F1-root/terminal/chain-tamper (chain-tamper NA where no chain) | Equalities hold; no strong baseline differs in authority granularity | matched fairness; the whole comparison |

### G.5 Claim-dependent replay/DPoP and reference-monitor gates

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-9** | Fire N concurrent bit-identical requests at the replay cache **across processes**; induce a backend error | Exactly one proceeds; no double-admission; fail-closed observed; frozen `(mechanism_tag, jti)`/TTL/capacity budget | IA-9; B3⁺ and the replay layer |
| **G-14** *(claim: replay/DPoP)* | Attach the same authenticated-ID cache to B2-DPoP and B3; run the four-way DPoP taxonomy | Both block `captured-proof-replay` identically; INV-only blocks `first-use-body-mutation` while the replay cache alone does not; bare bearer cannot carry the cache | the DPoP/INV attribution |
| **G-15** *(claim: F4/F5)* | Verify F4/F5 comparisons run only among B3+ablations **or** with the same reference monitor on OAuth arms, via `authz_context_hash` | No cross-mechanism F4/F5 claim rests on a monitor-configuration difference | F4/F5 fairness |

### G.6 Final pilot integration gate

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-10** *(last)* | End-to-end pilot: the benign running example through B0 and B3, producing `ObservedRequest`, `MediationEvent`, `ToolIngressEvent`, `EffectEvent`, and independent `reference_allow`/`observed_forwarded`/`admission_breach`/`realized_harm`/`false_block` | Green; oracle uses only raw evidence + sealed `IntendedInvocation` + trusted mediation/ledger; every prior DAG gate passed | readiness to author the confirmatory corpus |

### Gate-outcome policy (fallbacks; record each as an ADR entry)

- **G-1/G-2 fail** (Python Biscuit unusable or non-monotone in practice) → fallback to a Macaroon-style caveat chain (symmetric HMAC; verifier holds the root secret — **losing** the root-public-key property, update §C) or FFI to the Rust `biscuit-auth` library.
- **G-4 fails** → build a behaviourally faithful AS enforcing the mandated checks directly; disclose it.
- **G-6 or G-7 fail** → construct validity of the whole study is at risk; **re-architect interposition before any confirmatory work.** Highest priority.
- **G-13 fails** (cannot realize per-hop `C_i` equally) → mark the affected baseline, never silently mis-provision.

---

# Part H — Freeze, seal loop, and confirmatory campaign [DESIGN, E9]

**Order (MUST).**
1. Implement, debug, and run the Part G gates on the **pilot** corpus only.
2. Freeze hypotheses, oracle predicates, baseline configurations, latency estimands, and the **equivalence margin** (separate from, and set after, the G-3 smoke threshold; both fixed before any confirmatory result).
3. Freeze and hash the **v0.5 candidate**: design document, implementation commit, oracle code, analysis code, all configuration (`Ω`, `Γ` with `H(Γ)`, identity-plane registry, `task_authorization_policy`, allowed-sink policy), the pinned dependency environment **including the operating system and its exact version/build — the sealed measurement platform (ADR 0014; `docs/frozen_parameters.md` row 9)**, and the **corpus generator** — its code, the deterministic key seeds for every principal, the seed→keypair derivation rule, and the scenario specifications, the sealed inputs from which the confirmatory corpus is deterministically produced. The seal covers **generators and seeds, never pre-minted token bytes** (ADR 0007; note below).
4. Run the corpus generator under the fixed rule to produce the confirmatory corpus (including the held-out third).
5. Verify **disjointness** of pilot and confirmatory corpora (no shared scenario file; assert on **scenario-specification and seed content hashes**, never on token bytes, which differ across mints even for the same logical scenario — ADR 0007).
6. Emit a **detached** manifest (never written into a file it hashes; add a public temporal anchor — OpenTimestamps and/or an OSF registration — plus a signed git commit to a public remote), then perform the **final seal**.
7. Execute the frozen campaign **once**.

**Token non-reproducibility note [ADR 0007].** Biscuit tokens are **not byte-reproducible across
mints**: the format uses a single-use ephemeral block key per append, so two mints of the same
logical capability differ in bytes **[VERIFIED, gate G-1 corrective pass]**. Step 3 therefore
seals scenario specifications, deterministic key seeds, and the generator — tokens are minted at
campaign runtime from those sealed inputs. Determinism is unaffected: every oracle verdict is a
function of `C_n = Allowed(P_n; Γ, κ, Ω)` and the sealed scenario, never of token bytes (§A.0.1,
§F.1, Part I), and `INV.capability_hash` is computed over the runtime-presented token's BlockID
commitment (§F.2, ADR 0003). **Seed-disclosure warning [DESIGN]:** publishing the corpus seeds
publishes every private key derived from them; the corpus is a testbed artifact only and its keys
MUST NOT be reused in any deployment — a binding obligation on the corpus generator when it is
written.

**What "once" means (MUST).** It governs the deterministic **security** verdicts: each sealed scenario is evaluated once for its verdict; no scenario is re-run to obtain a different verdict. It does **not** forbid the pre-registered **latency** repetitions (a random quantity), which are part of the single campaign.

**Abort / infrastructure / rerun / unseal rules (MUST).**
- **Abort** (crash, resource exhaustion) → discard the partial run in full; report no partial security results; re-run the **same** sealed artifacts. An abort is not a result and does not count as the "once."
- **Infrastructure failure vs finding** → a failure attributable to infrastructure (harness bug, ledger outage, environment drift) is logged in a deviations record; fixing infrastructure that does **not** touch sealed design/oracle/config/corpus does **not** require a reseal, but the fix commit and its hash are appended before re-running.
- **Any change to sealed design, oracle, config, or corpus → full unseal/reseal**: bump the candidate version, re-hash all artifacts, regenerate the manifest, record the reason; the previous seal and its results are marked superseded and are **not** cherry-picked.
- **No result-driven tuning** after the final seal; only disclosed infrastructure fixes are permitted.

**Statistical protocol [D26].**
- **Security and blocking outcomes** are reported as **exact counts and rates only** — `blocked/total`, attack-success count, false-block count, per-family exact results, at both class-macro (per family) and instance-micro (per instance) granularity, with template-derived variants clustered. **No confidence interval** is placed on any security/blocking proportion (a fixed author-constructed suite has no random-sampling population; verdicts are deterministic). Repetition of a security verdict is used **only** to detect nondeterminism.
- **Latency** is the **only** quantity with repeated sampling and confidence intervals (a genuine random quantity): micro-benchmarks ≥ ~1,000 timed iterations per configuration; end-to-end ≥ ~200 per configuration across ≥ 3 independent batches; report median, p95, IQR/bootstrap CI; **decompose** into setup / delegation / boundary-verification / end-to-end; report **cold and warm** separately; randomize/interleave or Latin-square counterbalance condition order within each batch; discard warm-up; persistent TLS and Ed25519 keep handshakes and signature randomness out of the measured path. Absolute overhead is the **primary** result; the fraction-of-one-LLM-turn (against both a full-turn and a conservative TTFT denominator) is a **secondary** interpretive aid. The "lightweight" claim is pre-registered as **retracted** if the absolute added boundary-verification latency of B3 over B0 exceeds the equivalence margin.

**Held-out and generalization.** The held-out third is author-constructed but sealed before B3 implementation; describe it as **sealed parameterized instances not used for post-result tuning**, and limit the generalization claim to unseen instances within the threat model. A supervisor- or third-party-sourced held-out set (for a stronger claim) is deferred to the conference extension.

---

# Part I — Independent oracle predicates (executable)

Each reads only raw evidence, sealed `IntendedInvocation`, and the trusted mediation/ledger records. Reported quantities are **separated**: `reference_allow`, `observed_forwarded`, `admission_breach`, `realized_harm`, `false_block`, plus `log_integrity_failure`. `H_JCS` below is the frozen construction of ADR 0009 (defined in §F.2; oracle-side implementation `src/harness/oracle/jcs_digest.py`).

```python
def effects_of(led, cid):      return [e for e in led if e.correlation_id == cid]
def mediation_of(med, cid):    return next((m for m in med if m.correlation_id == cid), None)

# (0) REFERENCE DECISION — what a correct monitor SHOULD do, from sealed truth only
def reference_allow(intent):
    return intent.R <= intent.C_sets[-1]           # R ⊆ C_n (plus family-specific gates in the fixture)

# (1) OBSERVED FORWARDING — did the boundary admit, per the trusted mediation record (NOT the SUT)
def observed_forwarded(med, cid):
    m = mediation_of(med, cid);  return bool(m and m.admitted)

# (2) ADMISSION BREACH — boundary admitted something the reference says it should not
def admission_breach(intent, med, cid):
    return observed_forwarded(med, cid) and not reference_allow(intent)

# (3) REALIZED HARM — an actual effect violated the family predicate (over the effect SET)
def realized_harm_F1(intent, led, cid):
    A = authority_from_effects(effects_of(led, cid))
    return not A <= intent.C_sets[-1]              # A ⊄ C_n

def realized_harm_F2(intent, cred_result, led, cid):
    ok = cred_result.principal_verified and cred_result.principal == intent.oauth_actor
    return (not ok) and len(effects_of(led, cid)) > 0

def realized_harm_F3(intent, obs, led, cid):
    oracle_digest = H_JCS(obs.raw_arguments)       # oracle-computed, independent (ADR 0009)
    for e in effects_of(led, cid):
        if e.effect_request_digest != intent.intended_request_digest: return True
        if e.effect_request_digest != oracle_digest:                  return True   # never compare
        if (e.tool, e.audience) != (intent.tool, intent.audience):    return True   # effect vs a
    return False                                                                    # tampered-only digest

def realized_harm_F4(intent, obs, led, cid):
    for e in effects_of(led, cid):
        if e.recipient is not None:
            for lbl in e.data_labels_touched:
                if is_sensitive(lbl) and not valid_declassification(obs, lbl, e): return True
    return False

def realized_harm_F5(led, obs, cid):
    for e in effects_of(led, cid):
        if is_high_risk(e.action) and not valid_approval_binds(obs.approval_artifact, e): return True
    return False

# (4) FALSE BLOCK — a legitimate (benign) request was not forwarded
def false_block(intent, med, cid, is_benign):
    return is_benign and reference_allow(intent) and not observed_forwarded(med, cid)

# cross-cutting: boundary reported blocked but an effect occurred
def log_integrity_failure(med, led, cid):
    m = mediation_of(med, cid)
    return bool(m and not m.admitted and len(effects_of(led, cid)) > 0)
```

**No-/partial-/multi-effect handling (MUST).** Every `realized_harm_*` is over the **set** of correlated effects: zero effects ⇒ no realized harm; a partial effect that still violates ⇒ realized harm; multiple effects ⇒ realized harm if **any** violates. `admission_breach` (a decision property) and `realized_harm` (an effect property) are reported **separately** for every family, as are `reference_allow`, `observed_forwarded`, and `false_block`. F3 always compares the sealed-intended, the independently-observed, and the actual-effect digests; it never compares an effect only against a possibly-tampered observed digest.

---

# Part J — Standard scientific workflow: what to prepare besides this document

This section is the checklist of preparation that a rigorous computer-security-systems study needs **around** the code, so that the artifact is credible, reproducible, and paper-ready. Ordered by when it is needed.

## J.1 Before writing any code (this week)

1. **Repository skeleton + hygiene.** One repo; `src/` (sut, harness), `fixtures/pilot/`, `fixtures/confirmatory/` (empty until Part H step 4), `analysis/`, `docs/` (this file), `adr/` (decision records). MIT/Apache license, `.editorconfig`, pre-commit hooks (formatter, linter). A repo that is clean from commit 1 is far cheaper than retrofitting.
2. **Pinned, reproducible environment.** `pyproject.toml` + a **locked** resolver file (`uv.lock` or `requirements.lock` with hashes); a `Dockerfile` (or devcontainer) that pins the Python version and every dependency; record OS and CPU in a `hardware_profile`. Reproducibility is graded at top venues via artifact evaluation — this is not optional for the conference path.
3. **Determinism controls.** Fix `PYTHONHASHSEED`; a single seed source threaded through the harness; Ed25519 (deterministic) for all signing; canonical JSON (RFC 8785 JCS) everywhere a digest is taken. Document them in one place.
4. **ADR log started.** One short markdown per decision (context, decision, status, consequences). Every Part G fallback and every seal-time parameter becomes an ADR. This is your audit trail against "PARKing" (deciding after seeing results).
5. **A written threat model + assumptions page** (you already have the substance in Parts A/D) as a standalone `docs/threat_model.md`, including the explicit out-of-scope list, so an examiner sees the boundary is deliberate.

## J.2 During smoke tests (Part G)

6. **A smoke-test report per gate.** For each gate: what ran, the observed result, pass/fail, and — if it changed a design choice — the ADR it produced. This becomes the "feasibility" subsection of the dissertation and pre-empts the "did you actually verify your library assumptions?" question.
7. **CI that runs the gates.** Even a minimal GitHub Actions workflow running `pytest` on every push protects against silent regressions and is itself evidence of engineering rigor for artifact evaluation.
8. **A harness-self-test suite** (tests of the *oracle*, not the SUT): hand-labelled traces where you know the right answer, plus the fault-injection tests (G-12). The oracle must be tested independently of the system it judges.
9. **Fix the seal-time parameters and record them, unset, now:** the equivalence margin (from external engineering need, before timing), the freshness window Δ, the context-label→outcome policy, the `task_authorization_policy`, the reference LLM-turn denominators. Put them in a `docs/frozen_parameters.md` with each value's justification; fill values before Part H step 3.

## J.3 Before sealing (Part H)

10. **Pre-registration document** (you already have `PRE_REGISTRATION.md`; update it to this consolidated design: the frozen-benchmark thesis, RQ1–4, H1–H9/H4a-b, the per-family predicates, the descriptive-statistics rule, the latency protocol, the sealing/temporal-anchor procedure). Seal it with the detached manifest + OpenTimestamps/OSF + signed commit.
11. **Corpus generator + disjointness check** as code, not by hand, so the confirmatory corpus is deterministically regenerable and provably disjoint from pilot.
12. **Analysis code frozen with the rest.** Every table/figure regenerated from `results/raw/` by one command (`make reproduce`); no manual spreadsheet steps. Freeze it in the seal so results cannot be massaged post hoc.

## J.4 During and after the confirmatory campaign

13. **A deviations log** (`DEVIATIONS.md`): any departure from the pre-registration, dated, with reason; abort/rerun events; infrastructure fixes and their hashes. Reviewers trust a study that reports its deviations far more than one that appears flawless.
14. **Raw traces are immutable and archived.** `results/raw/` is write-once; back it up (e.g., a release artifact or Zenodo DOI for the conference version). Tables/figures are pure functions of it.
15. **An artifact-evaluation-ready package**: README with exact reproduction steps, the container, the locked environment, `make reproduce`, and a mapping from each paper claim → the script that regenerates its number. This is the concrete deliverable USENIX/S&P/CCS/NDSS artifact evaluation asks for; preparing it incrementally is far cheaper than at the end.

## J.5 Supervision and external validity (ongoing)

16. **A supervisor-facing one-page status** kept current: which gates passed, which decisions are frozen, what is deferred to the conference version. Prof. Raza's earlier guidance (seminal sources, tight scope) applies to the write-up; keep the design/claim scope honest with him as gates resolve.
17. **A monthly literature re-check** (the 2026 preprint stream is fast): before sealing and again before submission, re-verify no published work has closed the measurement gap or invalidated a "first controlled comparison" qualifier, and update positioning. Never let "first/novel" stand unqualified.
18. **Independent held-out (conference only).** Arrange, if feasible, for the supervisor or a third party to contribute a held-out scenario set for the conference extension, so the generalization claim can be strengthened beyond author-constructed instances.
19. **Platform-bound ledger enforcement — a reproducibility/validity threat, recorded [DESIGN, ADR 0014].** The effect ledger's independence enforcement is Win32 share-mode locking, so the confirmatory campaign and its seal are bound to Windows, and third-party re-verification of gate G-7 requires a Windows machine until the deferred POSIX variant (planned after submission, before any artifact-evaluated conference version) passes the same five G-7 checks — until then **no cross-platform claim is made anywhere**. Two tamper-evidence properties with **different guarantors**, never conflated: campaign-time integrity is guaranteed by the live exclusive file handle (G-7); post-campaign integrity is guaranteed by the Part H seal (content hashes, detached manifest, public temporal anchor).

## J.6 What is explicitly NOT part of smoke tests (do not start)

Second MCP server, multiple resource domains, delegation-depth sweep, official AIP comparator run, adaptive attacks, the full ingestion-time signed-label model, and the independently sourced held-out set are **conference/journal extensions**, defined on the same interfaces so no P0/P1 work is discarded, but **not** to be built during the smoke-test phase.

## J.7 The §K LLM-in-the-loop demonstration — outside Parts A–J, outside the seal [DESIGN, ADR 0010]

The research proposal's single qualitative demonstration (a real LLM agent and a poisoned MCP tool in the golden-thread example, under B0 and B3 only) is retained but exists **outside Parts A–J and outside the seal**: it is qualitative, produces no counts, rates, or statistics, may never enter a results table, is not part of the sealed corpus or the single confirmatory campaign, and running it can never trigger an unseal. The deterministic-mock design remains the sole basis for every measured result (pre-registered reason: it removes LLM sampling as a confound). It is reported with explicit limitations under external validity; if the schedule does not permit it before the 11 September submission, it is dropped and the dissertation records the scope change and its reason — never silently omitted. `[ADR 0010]`

---

## Appendix — Honest open status (not resolved; not required for the smoke-test step)

1. **Python Biscuit maturity (IA-1/IA-2)** — format production-used but not formally audited; the specific library's fitness is unverified until G-1/G-2.
2. **Complete mediation in the MCP SDK (IA-6)** — depends on SDK internals not yet inspected.
3. **Independent effect-ledger interposition (IA-7)** — the core of construct validity; unverified until G-7.
4. **Equivalence margin value** — fixed from external engineering need before timing; not chosen here.
5. **Conference-model label provenance** — MSc narrows F4 to pre-labelled payloads; full model defined, not built.
6. **Independent held-out authorship** — author-constructed for the MSc; third-party set deferred.
7. **AIP comparator** — no official run; feature-matched table only for the MSc.

None is described as done. They are the agenda between here and a sealed v0.5, and between an MSc submission and a conference paper.

---

*End of consolidated Experiment Architecture (implementation candidate). Claude Code: run Part G along the DAG; stop and apply the fallback at any failing gate; do not author or execute the confirmatory corpus; do not generate v0.5. Nothing here is sealed, and no implementation assumption is a verified fact until its gate passes.*
