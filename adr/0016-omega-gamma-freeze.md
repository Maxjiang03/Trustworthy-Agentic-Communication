# 0016 — Freeze `Ω` (action/resource ontology) and `Γ` (authorizer configuration), hashed as `H(Γ)`

## Context

`docs/frozen_parameters.md` **row 8** was the single unset item that blocked gate **G-2** outright
(`Γ` and `H(Γ)` are literally what G-2 freezes and tests), forced the **C1** stand-in in
`smoke/g4/DESIGN.md` §9, and gated the two capability arms (`B-cap`, `B3`), which cannot be built
without the vocabulary their attenuation narrows over.

**What the architecture document does and does not say.** It specifies `Ω`'s **type, role and
constraints** and nowhere enumerates its **members**:

- §A.0.1 defines `Ω` as "the frozen, finite **action/resource ontology**; authority is always a
  subset of `Ω`", and `C_i = Allowed(P_i; Γ, κ, Ω) = { x ∈ Ω | authorizer(P_i, x; Γ) = permit ∧
  crypto_chain_ok(P_i; κ) }`, with `C_0 = U_task`.
- §F.1 fixes the **type** — `U_task`, `C_sets`, `R` and `tau_gt` are all
  `frozenset[tuple[str, str]]`, so an element is an `(action, resource)` **string pair**.
- §A.6.1 / §F.3 fix the **invariant** the members must support (`INV-2: C_i ⊆ C_{i−1}`), §A.3 the
  three scopes, §A.5.1 / §F.2.1 the identity plane, Part G the G-2 criteria, §E.3/§E.4/§E.6 the
  attack families and matched ablations, and Part H step 3 that `Ω` and `Γ` with `H(Γ)` are sealed
  configuration.
- No section lists a single action or resource string.

The contents of `Ω` and the text of `Γ` are therefore a **decision recorded here — not a
derivation from the document**, and this ADR must not be read as if the document already
determined them. `[DESIGN]`

**Two citation corrections, recorded rather than silently applied.** The task specification that
commissioned this freeze cited "§F.2" for `frozenset[tuple[str,str]]` and for `INV-2`. In the
published document the type block is in **§F.1** (`class IntendedInvocation`) and `INV-2` is in
**§F.3** (restated in §A.6.1); §F.2 is the HTC/INV/approval-artifact section. The substance is
unchanged; the citations above are the correct ones.

## Decision

### 1. `Ω` — seven elements, each with a stated necessity

`[DESIGN]` `Ω` is the frozen `frozenset[tuple[str, str]]` below. Nothing entered it without a
filled second column; nothing was added for symmetry.

| # | Element `(action, resource)` | Which requirement forces it | Where that requirement is stated |
|---|---|---|---|
| 1 | (`calendar.read`, `calendar/work`) | The golden thread's first read — the user's grant, the Supervisor's delegation and the Specialist's hop all draw on it. Also one of the ≥2 **distinct actions that must co-exist inside one terminal `C_n`**, so the tool-substitution fixture is blocked by `invocation_binding_ok` and not by containment | §A.3 (`U_task = C_0`), §D.3 T-tool, §E.6 −invoke row |
| 2 | (`calendar.read`, `calendar/personal`) | **Amplification.** An element the MCP tool surface exposes (same tool, different argument) lying **outside** the user's grant; without it the central phenomenon has nothing to be measured on. It is the `F1-root` target (`R ⊄ U_task`) | Part A.1, §E.3 `F1-root`, §E.4 F1-root row |
| 3 | (`notes.read`, `notes/project`) | Golden-thread read, and the **in-scope** source of the F4 sensitive-labelled payload — the F4/−context fixture must be blocked only by `context_policy_ok`, so its source cannot be out of scope | §A.6 (MSc pre-labelled model), §E.4 F4 row, §E.6 −context row |
| 4 | (`notes.read`, `notes/meeting`) | The **second resource under one action, both able to sit inside one `C_n`**, so the argument-substitution fixture is blocked only by `invocation_binding_ok` | §D.3 T-args, §E.6 −invoke row |
| 5 | (`notes.write`, `notes/project`) | A **mutating** element, so `A ⊆ R` and `A ⊆ C_n` are checked post-hoc against an effect that changes state, not only reads. Also the element dropped at hop 1 that makes `C_0 ⊋ C_1` a real narrowing | §F.3 INV-5/INV-6, §A.6.1 INV-2 |
| 6 | (`notes.delete`, `notes/project`) | The **destructive** element F5 needs: a high-risk in-scope action whose fixture is blocked only by `approval_artifact_ok`. It must **not** be the egress element, or the −context and −approval fixtures each trip the other's conjunct and stop being matched | §E.4 F5 row, §E.6 −approval row, Part I `is_high_risk` |
| 7 | (`mail.send`, `mail/outbox`) | The **egress** element F4 needs — the only element whose effect carries a `recipient`. Also the `C_0 \ C_1` element `F1-chain-tamper` widens back to, and the second principal-distinguishable element for F2 `wrong_principal` | §F.1 `EffectEvent.recipient`, §E.3 `F1-chain-tamper`, §E.4 F2/F4 rows |

Five tools (`calendar.read`, `notes.read`, `notes.write`, `notes.delete`, `mail.send`), five
resources (`calendar/work`, `calendar/personal`, `notes/project`, `notes/meeting`,
`mail/outbox`), seven elements.

**Domain.** The document names the principals (user → Supervisor → Specialist → MCP tool) but not
the scenario's subject matter. The vocabulary continues the one the pilot spikes already used —
`calendar.read` / `notes.read` / `mail.send` in `smoke/g6/spike.py` and `smoke/g7/spike.py`, and
`calendar.read` in ADR 0009's worked example — so the frozen ontology and the already-exercised
tool surface do not describe two different worlds. Those spike values carry a `(pilot)` suffix and
remain spike-local; the literals frozen here are the campaign's.

**How the seven constraints are met** (each checked, not assumed):

1. **Golden thread expressible.** "Summarise this week's project meetings into the project notes
   and email the summary to the team": `C_0 = {1, 3, 4, 5, 7}`, Supervisor→Specialist
   `C_1 = {1, 3, 4}`, Specialist's hop `C_2 = {3, 4}`. Every hop and the tool surface draw from `Ω`.
2. **Amplification expressible.** `Ω \ C_0 = {2, 6}` — both exposed by the tool surface: a
   calendar the task never granted, and deletion of the very notes the task may only read and
   append to.
3. **Non-trivial attenuation expressible.** `C_2 ⊊ C_1 ⊊ C_0` above, each step dropping real
   authority (hop 1 drops the write and the send; hop 2 drops the calendar), so `INV-2` is
   testable rather than vacuous.
4. **Every retained family has its vocabulary.** F1-root → 2 (or 6); F1-terminal → 5 and 7 (in
   `C_0`, outside `C_n`); F1-chain-tamper → widen back to 7 ∈ `C_0 \ C_1`, or to 2 ∉ `C_0`; F2
   `wrong_principal` → 1 vs 7 (a scheduling actor and a sending actor are distinguishable);
   F2 `invalid_credential`/`unauthenticated_caller`/`wrong_holder_proof` → any in-scope element;
   F3 T-tool → 1 ↔ 3, T-args → 3 ↔ 4, T-reuse/T-replay/audience/expiry → any in-scope element;
   F4 → payload read at 3, egressed at 7; F5 → 6.
5. **Every element corresponds to a real MCP tool.** The action string **is** the tool name, one
   tool per action, so `EffectEvent.tool == EffectEvent.action` by construction and
   `authority_from_effects` (Part I) is `{(e.action, e.resource)}` with no mapping table between
   ledger and ontology. The loader rejects any element whose action is not a declared tool, so a
   phantom element cannot enter.
6. **Size.** Seven elements over five tools — one printable dissertation table a reader can check
   against the fixtures, and the smallest set that satisfies 1–5 (dropping any row above removes a
   named requirement: the two-in-`C_n` pairs are what keep §E.6's −invoke fixture matched, and 6
   and 7 must be distinct for −approval and −context to stay orthogonal).
7. **String encoding is part of the frozen artifact.** RAR containment compares with byte-exact
   RFC 8259 string equality and no normalization `[VERIFIED, RFC 9396 §12 — read at G-4 Phase 1,
   `smoke/g4/DESIGN.md` §1.2]`, so the literal form is frozen: **US-ASCII only, lowercase only**,
   actions `namespace.verb` with exactly one `.`, resources `root/collection` with exactly one
   `/`, no other punctuation, no digits-only segments in use, no whitespace, **no non-ASCII
   characters at all** — which is why NFC-vs-NFD equivalence can never arise for a member of `Ω`,
   and why `Read` and `read` are simply two different strings, one of which is not in `Ω`. The
   loader enforces the grammar; `tests/test_omega_gamma_freeze.py` enforces it in both arms.

**Mapping onto RFC 9396** (consistent with `smoke/g4/DESIGN.md` §5.2, adding nothing to it): the
action side of `Ω` is carried in `actions`, the resource side in `datatypes`, and with exactly one
`locations` value — the single MCP resource server the smoke-test scope allows (§J.6 defers a
second server) — the §5.2 product rule `expand(AD) = {(l, a, d)}` is in bijection with a subset of
`Ω` under `(l, a, d) ↦ (a, d)`. Any value outside `Ω` is a rejection, never an implicit new
authority element.

### 2. The boundary `Ω` does not cross

`[DESIGN]` `Ω` is a **vocabulary, not a policy**. Three frozen-parameter rows own the policies and
**all three stay UNSET in this decision**:

- **Row 4 (context-label → {permit, escalate, block}).** `Ω` names **no label**. Labels attach to
  payloads by digest (§A.6), not to ontology elements; no element is described here as sensitive.
- **Row 5 (`task_authorization_policy`).** `Ω` names **no principal** and no task→principal
  mapping. That elements 1 and 7 are *distinguishable* per principal is a property of the
  vocabulary; **which** principal may exercise which is row 5.
- **Row 6 (allowed-sink policy for F4).** This is the concrete trap the freeze had to avoid.
  Element 7 is designated as the element whose effect carries a `recipient` — that is vocabulary.
  **Which recipients are allowed is row 6 and is not set here.** `mail/outbox` is the outbound
  channel; the recipient is a per-request argument scored against row 6's policy, which remains
  UNSET.

Two further non-encroachments, checked explicitly: **row 3 (freshness window `Δ`)** — `Γ` carries
a `time`/`expiry` check but fixes **no duration**; and **rows 1, 2, 7, 9** are untouched.

**A gap this freeze exposes but does not fill:** Part I's `is_high_risk(e.action)` (F5) and
`is_sensitive(lbl)` (F4) are policies with **no dedicated `frozen_parameters` row** — row 4 covers
the label→outcome policy and row 6 the sink policy, but nothing names the high-risk action set.
`Ω` supplies a destructive action (element 6) and **does not classify it**. Recorded for the
Commander; not decided here.

### 3. `Γ` — the frozen authorizer, written against the four G-2 criteria

`[DESIGN]` `Γ` is the authorizer configuration below: its checks and policy, its evaluation rule,
and its fixed trusted-key set (§A.0.1, §A.6.1).

**Capability shape it assumes.** The authority block (block 0, signed by `κ`) carries one
`right(action, resource)` fact per element of `C_0 = U_task`, plus `token_audience`, `token_task`
and `expiry`. Each attenuation block `i ≥ 1` carries one `scope(action, resource)` fact per
element of `C_i` **and the check that consumes them, in the same block**, so default block scoping
trusts them.

**`Γ`'s Datalog** (frozen text; comments are part of the frozen bytes):

```datalog
check if time($t), expiry($e), $t <= $e;
check if request_audience($aud), token_audience($aud);
check if request_task($task), token_task($task);
allow if operation($action, $resource), right($action, $resource);
```

**Evaluation rule.** `Allowed(P_i; Γ, κ, Ω)` is computed as **|Ω| independent authorizer runs**,
one per candidate `x ∈ Ω`, with `operation(action, resource)` injected as an **authorizer** fact
together with `time`, `request_audience` and `request_task`; `x ∈ C_i` iff that run selects the
`allow` policy. No policy matching ⇒ **deny** (fail-closed). Seven probes per prefix.

**Rule-by-rule rationale, naming the criterion each serves:**

- **(a) — an appended widening fact still verifies and still leaves `C_i ⊆ C_{i−1}`.** The positive
  grant is read **only** from the authority block: `right` appears nowhere in `Γ`'s own facts, and
  the `allow` policy trusts facts from the authority block and the authorizer alone (§A.0.1
  default block scoping). A `right(...)` appended in block `k` is a fact **nothing trusts** — the
  policy does not, and no earlier block's check does — so the block verifies cryptographically and
  changes no authority. Narrowing, by contrast, is *additive in checks*: each attenuation block
  contributes one more mandatory conjunct, so `C_i = right ∩ ⋂_{j ≤ i} scope_j`, which is
  non-increasing in `i` by construction. `[DESIGN; that the pinned library realizes these
  semantics is IA-2, **[UNVERIFIED-IA]**, and is exactly what G-2 adjudicates — nothing here may
  be read as a verified monotonicity claim.]`
- **(b) — a third-party block or `trusting {attacker_key}` is rejected as out of profile.** `Γ`
  declares `trusted_keys: ["kappa"]`, `trusted_key_count: 1`, `trusting_annotations: "forbidden"`,
  `third_party_blocks: "reject"`, `block_scoping: "default"` (ADR 0002; §A.6.1 MSc profile MUST).
  Rejection is **structural and pre-evaluation**: a token carrying an external (third-party) block
  signature is refused before any Datalog runs — already implemented and exercised in
  `src/harness/oracle/commitment.py` (`_reject_non_ed25519` raises on `externalSignature`).
- **(c) — a `Γ` mutation that broadens trust is detectable via `H(Γ)`.** See §4: `H(Γ)` covers the
  whole frozen document, so adding a trusted key, permitting `trusting` annotations, flipping
  `third_party_blocks` to accept, editing the Datalog, **or widening `Ω`** all change the digest.
- **(d) — the `−attenuation` control admits what full `B3` blocks.** Shipped as a **matched
  ablated form**. A well-formed Biscuit authorizer cannot be made to trust later-block widening
  without third-party keys, which the profile forbids (§E.6), so the ablation is **not** a
  different Datalog program: it is the *same* authorizer applied to a different prefix. The
  ablation is stored as a delta — `derived_from: "gamma"`, `differs_in_exactly:
  ["evaluation.prefix"]`, `override: {"evaluation.prefix": "P_0"}` — so it **cannot** differ in
  more than the one respect it is named for; the loader rejects a delta whose override does not
  match its declaration, and a test asserts the materialized forms differ in exactly that path and
  share byte-identical Datalog. This matches §E.5's `−attenuation` bitmask row (`authorizer:
  root-only`) and §E.6's closing semantics ("authorize against `Allowed(P_0; Γ, κ, Ω)`, ignoring
  every attenuation block"); it is an **unsafe control**, never a deployable authorizer.

### 4. Where it lives, and `H(Γ)`

`[DESIGN]` The frozen artifact is **`src/harness/authorizer/omega_gamma_v1.json`**, with
`src/harness/authorizer/frozen_config.py` as its loader, validator and hasher.

**Why there, and why data rather than code.** Two sides must evaluate the *same* frozen bytes with
*independent* implementations: the SUT boundary authorizes with `Γ`, and the harness verifier and
oracle recompute `Allowed(P_i; Γ, κ, Ω)` — D13/D21 forbid the oracle sharing implementation with
what it judges, which is the discipline ADR 0009 already applies to `H_JCS`. A shared **module**
would violate that; a shared **document** does not. The harness owns the canonical copy and the
digest because the harness is what must load and hash it (Part H step 3), and the SUT receives the
same bytes as **start-up configuration** supplied by the runner — never by import, so
`src/sut/` still imports nothing from `src/harness/` (CLAUDE.md red line 6). Placing it in
`src/sut/` would have inverted that: the instrument would then read its adjudication standard out
of the measured tree.

**`H(Γ)` construction** — the tagged, versioned, length-delimited family of ADR 0003/0009, never a
bare digest, with its **own** domain tag:

```
TAG      = b"AASC-GAMMA-DIGEST"   # 17 bytes; != b"AASC-JCS-DIGEST", != b"AASC-CAP-COMMIT"
VERSION  = 0x01                   # one byte; any other value fails closed
C        = RFC 8785 canonical UTF-8 bytes of the whole document (rfc8785==0.1.4, ADR 0005)

H(Γ)     = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
```

Conventions match `commitment.py` and `jcs_digest.py`: fixed ASCII tag, one version byte,
big-endian 4-byte length prefix, SHA-256, fail-closed on an unsupported version, **lowercase hex**
output (ADR 0011's single rendering rule). Like `H_JCS` there is **no algorithm byte** — a future
hash change is a new VERSION, not a parameter. RFC 8785 canonicalization makes the digest
invariant to JSON member order and insignificant whitespace, so reformatting the artifact cannot
change `H(Γ)` while any change of content does.

**Worked example** (reproducible by hand; the illustrative document, not the frozen one):

```
input (any member order):  {"gamma":{"profile":"msc"},"config_version":1}
C (canonical, 46 bytes):   {"config_version":1,"gamma":{"profile":"msc"}}
preimage:                  b"AASC-GAMMA-DIGEST" || 0x01 || 0x0000002E || C
H(Γ):                      80a0f13f95b7be7c16f54d051c5da0d9882e343bdecb5eea47f1aacc0b0bb7d1
bare SHA-256(C) (differs): 7a916c3077b725ab8350e21aecd7e88789fce7c0e0cab396079ef67ada6d7996
H_JCS of the same input:   6f7e1e753992ad4af0223308aefee6f5aff7c3c29a2b803813a96c98ce85c524
```

The two differing values are the non-vacuity evidence: the tag separates `H(Γ)` from a bare digest
**and** from the sibling construction over the same canonical bytes.

**The frozen artifact's digest** (`C` = 2493 canonical bytes), recorded in
`docs/frozen_parameters.md` row 8:

```
H(Γ) = f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb
```

**Which bytes `H(Γ)` covers, and why that makes criterion (c) meaningful.** It covers the **whole
document — `Ω`, the full `Γ`, and the ablation delta — as one artifact**, deliberately:

- `C_i ⊆ Ω` by definition (§A.0.1), so **adding an element to `Ω` widens every `C_i`**. A digest
  over `Γ` alone would leave the most direct authority-broadening mutation in the system
  undetected. This also matches row 8, which names one hash for both objects.
- Covering the ablation delta means the `−attenuation` control cannot **drift** into differing in
  a second respect without changing the digest — and an unnoticed drift there does not merely
  broaden trust, it invalidates the matched comparison the control exists to support.

**What it does not cover, stated plainly:** the **value** of `κ`. `κ` is a per-campaign key derived
from a sealed seed (ADR 0007) and sealed at Part H step 3; `Γ` freezes the **cardinality and role**
of the trusted-key set (exactly one key, the AS root public key, resolved from sealed
configuration), not the key bytes. Substituting a *different* `κ` is therefore caught by the Part H
seal, not by `H(Γ)`; adding a *second* trusted key is caught by `H(Γ)`.

Finally, `H(Γ)` is **never written into the document it covers** (Part H step 6's detached-manifest
rule, applied at artifact scale); it lives in row 8 and in this ADR, is recomputed by the loader,
and a test fails if row 8 and the artifact ever disagree.

### 5. Amendability

`[DESIGN]` `Ω` and `Γ` remain **amendable by a subsequent ADR until Part H step 3**, after which
the seal fixes them. Any amendment — including a comment inside the frozen Datalog, since the
digest covers the bytes — **re-triggers gate G-2** and the **G-4 effective-authority limb**
(`smoke/g4/DESIGN.md` §10 rows L2/L3), on the same principle as the standing pin rule that a
version bump re-triggers its gate. This is why the necessity table and the rationale live in this
ADR rather than inside the artifact: editing prose here does not re-trigger a gate; editing the
artifact does.

## Status

accepted — 2026-07-29

## Consequences

- **G-2 is unblocked.** Its four criteria now have a frozen `Γ` and an `H(Γ)` to test against.
  G-2 is **not run and not adjudicated** by this decision, and the smoke board still shows it as
  not run; IA-2 remains **[UNVERIFIED-IA]**. Whether the frozen `Γ` actually yields
  `C_i ⊆ C_{i−1}` under `biscuit-python==0.4.0` is precisely what G-2 decides.
  *(Update, 2026-07-29: G-2 has since run against this freeze and **PASSED** — criteria (a)–(d)
  all hold with every `C_i` computed, and **IA-2 is now verified by G-2**; `smoke/g2/REPORT.md`.
  The paragraph above stands as the state at the time of this decision. The amendability rule
  below is unchanged: any later amendment of `Ω`/`Γ` re-triggers G-2 and invalidates that result
  for the amended bytes.)*
- **`smoke/g4/DESIGN.md` §9's C1 conflict is closed.** The G-4 effective-authority limb (L2) no
  longer needs `Ω_spike`/`Γ_spike`: Phase 2 runs against the frozen values. C2 (the
  `INV.access_token_hash` limb, awaiting G-11) and C3 (the identity-plane registry) are untouched
  and still open.
- **`B-cap` and `B3` are buildable**: the vocabulary their offline attenuation narrows over exists,
  and so does the authorizer that computes `C_i` from it.
- **The `−attenuation` control is specified as a matched ablation**, structurally prevented from
  differing in a second respect — closing the §E.6 requirement that "the ablation must differ in
  exactly the one respect it is named for, or the control is not matched."
- **Nothing else moves.** `docs/frozen_parameters.md` rows 1–7 and 9 stay UNSET and unmodified;
  no arm, gate, attack family or claim is reduced, deferred or marked out of scope; no gate is run
  or adjudicated; no AS, agent, adapter, HTC/INV or oracle code is written.
- A third construction now exists in the tagged-digest family (`AASC-CAP-COMMIT`,
  `AASC-JCS-DIGEST`, `AASC-GAMMA-DIGEST`), each with a distinct tag and its own fail-closed
  version byte, so the three can never be confused with one another or with a bare digest.
- Registered in Part B.2 of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, same commit as row 8.
- Open, handed to the Commander: `is_high_risk` (F5) and `is_sensitive` (F4) are policies with no
  `frozen_parameters` row of their own — see §2 above.
