# 0019 — Freeze the identity-plane registry, hashed as `H(R)`

## Context

§F.2.1 specifies the identity-plane registry: `actor_of(·)` maps an OAuth `act`/`client_id` claim to
a **single** principal, the registry maps that principal to **exactly one** `htc_holder` public key,
every actor claim and holder key used in a scenario MUST resolve to exactly one principal, unmapped
actors **and** unmapped keys are rejected, and `resource_owner` subjects are recorded but are **not**
part of the holder mapping. It also lists the registry among the artifacts frozen and hashed before
sealing.

Until now it did not exist. `smoke/g4/DESIGN.md` §9 **C3** therefore ran G-4's `actor→holder` limb
(L3) on a spike-local stand-in whose holder keys were raw spike keys rather than the terminal keys of
a verified HTC chain, with the re-adjudication trigger recorded as **G-11**. This ADR builds and
freezes the registry, which closes C3 and re-triggers that limb.

**A tension that had to be resolved.** §F.2.1 requires the registry to be frozen and hashed *before*
sealing, yet holder keys are per-campaign material derived from sealed seeds (ADR 0007). Freezing key
bytes would either pin one campaign's keys into a pre-campaign artifact or make the artifact
unfreezable.

## Decision

### 1. The artifact freezes **structure**, not key bytes

`[DESIGN]` The frozen artifact is **`src/harness/verifier/identity_registry_v1.json`**, with
`src/harness/verifier/registry.py` as its loader, validator, binder and hasher. It fixes the
principals, their `kid`s, the actor→principal mapping, the recorded resource owners, and each
principal's **derivation label** — and contains **no key bytes**. `bind(document, resolve_key)`
resolves labels to actual public keys at campaign start, from the seeds the runner holds. `H(R)`
covers the structure and **not** the key values.

This is the line **ADR 0016 already drew** for `Γ`, which freezes "the cardinality and role of the
trusted-key set, not the key bytes", and for `H(Γ)`, which deliberately does not cover the value of
`κ`. Substituting a different key set is caught by the Part H seal over the seeds; changing *which*
principals exist, or *which* actor maps to which, is caught by `H(R)`.

A test asserts the artifact contains no key material: every principal entry has exactly the three
keys `{kid, key_reference, necessity}`.

### 2. Contents, with a necessity per entry

`[DESIGN]` Nothing entered without a stated requirement forcing it, and the loader **rejects** an
entry whose `necessity` is missing.

| Entry | `kid` | Necessity |
|---|---|---|
| **AS root** | `kid-as-root` | §F.2: `HTC_0` is signed by `κ` and carries `kid_AS`, and §F.2's verification paragraph resolves **every** `kid` through this registry. Without an entry the root signature has no named key. |
| **supervisor** | `kid-holder-supervisor` | The first delegating hop of the golden thread (ADR 0016 §1): holder of `P_0` and signer of `HTC_1`. A chain of depth ≥ 1 cannot exist without it. |
| **specialist** | `kid-holder-specialist` | The delegate of the golden thread and the terminal holder in the two-hop case, so it is the key `INV` must be signed by. Also the second principal, so F2 `wrong_principal` has one to be distinguishable from. |
| **worker** | `kid-holder-worker` | A third principal, so depth-2 chains have a genuine nested `act` history and `depth` contiguity is exercised over more than one increment (§F.2; RFC 8693 §4.1 nesting). |

Actor claims `agent-supervisor` / `agent-specialist` / `agent-worker` map to those three principals.
`user-yixian` is recorded as a **resource owner** and appears in no holder mapping.

### 3. String encoding, fixed

`[DESIGN]` Principals are US-ASCII lowercase single words; actor claims are `agent-` plus one
lowercase word; `kid`s are lowercase hyphen-separated and **unique across the whole registry**, since
`kid` is a key *selector* (§F.2) and a duplicate would make it ambiguous; public keys on the wire are
base64url unpadded raw Ed25519. Comparison is byte-exact RFC 8259 equality with no normalization —
the same rule ADR 0016 fixed for `Ω`, and for the same reason.

### 4. `H(R)`

`[DESIGN]` The same tagged, versioned, length-delimited family as ADR 0003/0009/0016/0018, with its
own domain tag:

```
TAG     = b"AASC-REGISTRY-DIGEST"   # 20 bytes; distinct from every tag in use
VERSION = 0x01                      # fail-closed on any other value
C       = RFC 8785 canonical UTF-8 bytes of the whole document

H(R)    = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
```

For the frozen artifact (`C` = 2302 canonical bytes):

```
H(R) = d1bfc5ffcb22e2ded736f5248b99b9f019ba314b93ddd808e50ea522b3fb4cbe
```

Non-vacuity, as ADR 0016 did for `H(Γ)`: `H(R)` differs from the bare SHA-256 of the same canonical
bytes **and** from `H_JCS` of the same document, so the tag is doing work. Member reordering leaves it
unchanged; adding a principal, an actor mapping, or a resource owner changes it.

### 5. The boundary this registry does **not** cross

`[DESIGN]` It is the **actor→holder mapping only**. It is **not** the
`task_authorization_policy` (task → authorized actor principals), which is
`docs/frozen_parameters.md` **row 5** and stays **UNSET** — so the F2 `wrong_principal` family stays
**unscored** and G-4's `may_act` stand-in stays a stand-in. The artifact carries the boundary in a
`scope_boundary` field, and a test asserts the document mentions no task policy and contains no
`may_act`.

### 6. Amendment

`[DESIGN]` Amendable by a **later ADR** until Part H step 3, after which it is sealed. Any amendment
**re-triggers the gates that consumed it**: **G-11** (the HTC/INV verifier resolves every `kid` and
holder key through it) and **G-4**'s `actor→holder` limb. Same rule ADR 0016 set for `Ω`/`Γ`.

## Status

accepted — 2026-07-29

## Consequences

- **`smoke/g4/DESIGN.md` §9 C3 is closed**, recorded there as a dated update note rather than a
  rewrite, and G-4's limb **L3** was re-run at G-11 against the frozen registry. The outcome is
  unchanged — the actor resolves to exactly one principal and one holder key, an unmapped actor is
  rejected, and `resource_owner = holder` is never required (§A.5.1 MUST NOT) — so the closure
  confirms the stand-in had not flattered the result.
- **A new `frozen_parameters` row is set** for the registry, and **only** that row: §F.2.1 lists the
  registry among the artifacts frozen before sealing, so unlike ADR 0009/0018 this is a genuine
  seal-time parameter. Rows 1–7, 9 and 10 are untouched and row 8 (`Ω`/`Γ`) is byte-unchanged.
- **What is still owed.** The holder keys are now *registered*, but that a resolved key is the
  terminal holder of a **verified HTC chain** is what the G-11 verifier establishes, and
  `holder_proof_ok` at the boundary belongs to the arms. The registry is data, not code: the SUT
  receives the same bytes as start-up configuration from the runner, never by importing the harness
  (red line 6).
