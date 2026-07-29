# Gate G-2 Report — the frozen authorizer `Γ` under the pinned Biscuit library

**Outcome: PASS** (criteria (a)–(d) all exercised and all hold).
`biscuit-python==0.4.0`, frozen `Ω`/`Γ` per ADR 0016,
`H(Γ) = f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb`.
Run 2026-07-29 on Windows; `smoke/g2/spike.py` exit 0, nine mandatory checks.

## 1. Gate

The Part G G-2 row, reproduced exactly, not paraphrased:

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-2** | Freeze and hash `Γ` (`H(Γ)`). (a) appended widening fact — verifies cryptographically **and** leaves `C_i ⊆ C_{i−1}`; (b) third-party block / `trusting {attacker_key}` — **rejected** as out of profile; (c) `Γ` mutation broadening trust — detected via `H(Γ)`; (d) `−attenuation` control admits what full B3 blocks. Block identity and prefix commitments here are those of ADR 0003 / §A.0.1 (`BlockID_i`, `commit_prefix`), so G-2's `Allowed(P_i)` computation and G-1's commitment scheme cannot drift apart | (a)–(d) all hold; every `C_i` computed over `Ω` by the frozen `Γ`, not asserted | IA-2; the entire F1 prevention claim |

The assumption under test, §F.4 row IA-2, verbatim: *"Under the frozen `Γ`, `C_i ⊆ C_{i−1}` holds
for every appended block, and third-party/`trusting` config is rejected as out of profile"* —
status before this run **[UNVERIFIED-IA]**.

The gate-outcome policy for this row, also verbatim: **"G-1/G-2 fail** (Python Biscuit unusable or
non-monotone in practice) **→ fallback to a Macaroon-style caveat chain (symmetric HMAC; verifier
holds the root secret — losing the root-public-key property, update §C) or FFI to the Rust
`biscuit-auth` library."** Not invoked.

**This is the first pass in the project that runs a Biscuit authorizer with policies.** G-1
verified mint, offline append, `κ_pub`-only verification, wire round-trip, stable prefix identity
and append-detection, and its own docstring records that it "does NOT run an authorizer with
policies (that is Gamma / gate G-2)". Before this run the only authorizer contact anywhere in the
repository was a parse check (`tests/test_omega_gamma_freeze.py:215`, `AuthorizerBuilder(...)
is not None`) that minted no token and authorized nothing. The library surface exercised here is
real: `AuthorizerBuilder`, `AuthorizerBuilder.build`, `Authorizer.authorize`, `Authorizer.query`,
`Fact`, `BlockBuilder`, `Biscuit.append`, `Biscuit.third_party_request`,
`ThirdPartyRequest.create_block`, `Biscuit.append_third_party`, `Biscuit.block_external_key`.

## 2. What computes `C_i` — `src/harness/authorizer/allowed.py`

The row requires every `C_i` to be **computed over `Ω` by the frozen `Γ`, not asserted**. The
evaluator implements exactly the evaluation ADR 0016 §3 specifies.

**Fact-injection shape.** For a prefix `P_i` and each candidate `x = (action, resource) ∈ Ω`, one
independent `AuthorizerBuilder` is constructed from `Γ`'s frozen Datalog text and four facts are
added as **authorizer** facts — never token facts, never string-interpolated:

```python
Fact("operation({action}, {resource})", {"action": action, "resource": resource})
Fact("time({t})",               {"t":    context.now})       # datetime
Fact("request_audience({aud})", {"aud":  context.audience})
Fact("request_task({task})",    {"task": context.task})
```

`x ∈ C_i` iff `Authorizer.authorize()` returns an allow-policy index. `AuthorizationError` — whether
"no matching policy was found" or "an allow policy matched … and the following checks failed" — is a
**deny**. Any other exception propagates: the evaluator never converts an error into a verdict
(STEP 1 item 4). With `|Ω| = 7` and a three-hop chain that is **21 independent authorizer runs**,
one fresh authorizer each, so no authorizer state leaks between candidates or prefixes.

**`Γ` and `Ω` come from the frozen artifact.** Both are read through
`frozen_config.load_document()`; the Datalog handed to the authorizer *is* the frozen string, and
authority/attenuation blocks are rendered from the frozen **templates** by `render_block` (one
`right/2` per element of `C_0`; one `scope/2` per element of `C_i` plus its consuming check, in the
same block, so default scoping trusts them). Nothing is restated inline. No helper had to be added
to `frozen_config.py`, and neither the artifact nor `h_gamma` was modified.

**How the evaluator obtains `P_i`, and why it is G-1's prefix.** A `Chain` holds one serialized
token per hop; `P_i` is the token at hop `i`, whose signed blocks are `⟨SignedBlock_0 … SignedBlock_i⟩`
(§A.0.1). Identifiers and commitments come from `src/harness/oracle/commitment.py` — the ADR 0003
`BlockID_i` (the Biscuit revocation identifier = the block signature) and `commit_prefix`, the same
construction G-1 used and the ADR 0003 suite pins. There is **no second notion of "the prefix"** in
this gate. `Chain.__post_init__` verifies from those identifiers that each hop really extends the
previous one (`block_ids(i)[:len(prev)] == prev`), so the prefix relation is checked against
signatures rather than assumed from call order; `test_chain_rejects_a_non_extending_hop` and
`test_prefix_commitment_is_the_adr_0003_construction` pin both properties.

`crypto_chain_ok(P_i; κ)` is enforced **first**, by `commitment.block_ids_from_raw`, which
independently verifies the chain against `κ_pub` and refuses non-Ed25519 keys and external
signatures. It fails closed by raising, so a caller can never mistake an unverifiable prefix for one
that admits nothing.

Placement is `src/harness/` (the instrument), per STEP 3; `src/sut/` imports nothing from it, and
the module implements no arm, no AS (G-4), no HTC/INV (G-11) and no oracle predicate.

## 3. Results

`uv run python smoke/g2/spike.py` — exit 0. Values below are from one run; token bytes differ
between runs because Biscuit chains blocks with single-use keypairs, so every comparison is within a
single run.

The scenario is ADR 0016's golden thread over the frozen `Ω`:
`C_0 = U_task` (5 elements) → `C_1` (3) → `C_2` (2), with `Ω \ C_0 =
{(calendar.read, calendar/personal), (notes.delete, notes/project)}` as the amplification surface.

| Check | Mandatory | Result | What it establishes |
|---|---|---|---|
| G-2.a1 | yes | PASS | appended widening fact verifies **and** `C_2 ⊆ C_1` |
| G-2.a2 | yes | PASS | legitimate narrowing is strict: `C_2 ⊊ C_1 ⊊ C_0 = U_task` |
| G-2.a3 | yes | PASS | non-vacuity: the widening fact is live; scoping is what hides it |
| G-2.a4 | yes | PASS | six broadening vectors, incl. rules and check-facts — none widens |
| G-2.b1 | yes | PASS | third-party block rejected structurally **and** denied by `Γ` |
| G-2.b2 | yes | PASS | `trusting {attacker_key}` refused pre-evaluation; it would otherwise admit |
| G-2.c | yes | PASS | five trust-broadening mutations each change `H(Γ)`; artifact intact |
| G-2.d1 | yes | PASS | `−attenuation` admits what full `Γ` refuses, same chain |
| G-2.d2 | yes | PASS | the control differs in exactly `evaluation.prefix` |
| G-2.E | info | PASS | evaluation shape and `H(P_i)` provenance, for the record |

### (a) Appended widening fact — verifies cryptographically **and** leaves `C_i ⊆ C_{i−1}`

**Constructed.** From `P_1` and `κ_pub` alone (no root secret in scope), an attacker appends a block
carrying `right("notes.delete", "notes/project")` — an element of `Ω` outside `C_1` and outside
`C_0`.

**Observed.** The token **verifies**: `Biscuit.from_bytes(widened, κ_pub)` returns a token with
`block_count() == 3`, the independent ADR 0003 extractor returns 3 `BlockID`s, and
`block_source(2)` contains the widening fact — the append is a real, cryptographically valid
Biscuit operation, exactly as §A.6.1 says it should be. And the computed authority is unchanged:
`|C_1| = 3`, `|C_2| = 3`, `C_2 ⊆ C_1`, `(notes.delete, notes/project) ∉ C_2`.

**Library call.** `Biscuit.append(BlockBuilder(...))` builds it; membership is decided by
`Authorizer.authorize()` raising `biscuit_auth.AuthorizationError: authorization failed: no
matching policy was found, and the following checks failed:` — the `allow` policy simply never
matches, because `right` is read only from the authority block.

**The failing world.** Had the appended `right/2` entered the authority set, `C_2` would contain
`(notes.delete, notes/project)` and `C_2 ⊆ C_1` would be **False** — the assertion that would have
caught it. INV-2 would be violated at the first hop and the F1 prevention claim would have no floor.

**Legitimate narrowing (a2).** On the untampered chain the computed sets are `|C_0| = 5`,
`|C_1| = 3`, `|C_2| = 2` with `C_2 ⊊ C_1 ⊊ C_0` and `C_0 = U_task` exactly. Both directions are
therefore exercised: containment holds under attack, and attenuation actually removes authority
rather than being a no-op. Would have failed if the hops dropped nothing (equal sets, containment
vacuous) or dropped everything.

**Non-vacuity (a3).** Built on `P_0` plus one widening block, with no attenuation check in play:
the *identical* check `right("notes.delete","notes/project")` **holds** when the asking block opts
into `trusting previous` and **fails** under default scoping. So the fact is genuinely present in
the token, and Biscuit block scoping — not absence — is what excludes it. No scope annotation
available to the authorizer reaches it either (`default`, `trusting authority`, `trusting previous`
all deny), while the same authorizer still admits a genuinely granted element.

**Beyond `right/2` (a4).** Widening is not only a `right/2` fact, so six appended vectors were
tried: a derivation rule `right($a,$r) <- scope($a,$r)`; an unconditional
`right("notes.delete","notes/project") <- true`; `expiry(2099-01-01T00:00:00Z)`;
`token_audience("evil-audience")`; `token_task("other-task")`; and a re-added
`scope("mail.send","mail/outbox")`. **None enlarged `C_n`.** The two that target `Γ`'s *checks*
rather than its policy were additionally probed **under the condition they were meant to unlock**:
the appended `expiry(2099)` evaluated at a time after the real expiry admits **nothing**, and the
appended `token_audience` evaluated with that audience requested admits **nothing**. The re-added
`scope` is the subtle one: it cannot restore `mail.send`, because hop 1's check reads `scope` facts
from **its own block only**.

### (b) Third-party block / `trusting {attacker_key}` — rejected as out of profile

**Construction scope: full, not partial.** The library assembled the malicious artifact end to end —
`Biscuit.third_party_request()` → `ThirdPartyRequest.create_block(attacker.private_key,
BlockBuilder('right("notes.delete","notes/project");'))` → `Biscuit.append_third_party(
attacker.public_key, block)`. No step was blocked, so nothing here is a partial construction, and
the artifact was presented to **both** the structural layer and the authorizer.

**The load-bearing finding: the library is not the rejection.** `Biscuit.from_bytes(tp_bytes,
κ_pub)` **verifies the third-party token under the root public key alone**, and
`block_external_key(1)` returns the attacker's key (`ed25519/…`). Signature verification therefore
does *not* refuse it — which is precisely why §A.6.1's "MUST be rejected before evaluation" has to
be a project-owned check rather than something inherited from the library.

**Observed rejections, at two named layers.**

1. **Structural, pre-evaluation** — `commitment.block_ids_from_raw` raises
   `TokenStructureError: external (third-party) signature present`, reading the wire
   `SignedBlock.externalSignature` field (4) before any Datalog runs; the evaluator's `Chain`
   refuses the prefix for the same reason.
2. **Semantic backstop, at the authorizer** — presented anyway, the frozen `Γ` **denies** the
   third-party element (`no matching policy was found`), while still admitting a genuinely granted
   element on the same token. The third-party fact is trusted by nothing.

**`trusting` (b2).** The frozen `Γ` Datalog contains **zero** occurrences of `trusting`. An
authorizer carrying `allow if … right($action,$resource) trusting authority, {attacker_key}` is
refused before evaluation by `check_profile` with
`AuthorizerProfileError: out of profile: 'trusting' annotations are permitted`. The syntax parses
fine under the pinned library (both the `{param}` and literal `ed25519/<hex>` forms, in authorizer
policies and in block checks), so the profile restriction — not a library limitation — is what
prevents it.

**The failing world, demonstrated rather than argued.** That same out-of-profile authorizer, if it
*had* been evaluated, **admits** `(notes.delete, notes/project)` from the attacker's third-party
block — `authorize()` returns policy index 0. So (b) is not vacuous: the escalation is expressible
and real, and the rejection is what prevents it. Had either layer accepted the artifact, or had the
`trusting` authorizer made no difference, the check would have failed.

### (c) `Γ` mutation broadening trust — detected via `H(Γ)`

**Constructed.** Five mutations, each applied to an in-memory `deepcopy`, **never to the artifact**:
add a trusted key (`["kappa","attacker"]`, count 2); flip `third_party_blocks` to `accept`; set
`trusting_annotations` to `permitted`; edit the Datalog (`allow if operation…right…` → `allow if
true`); and widen `Ω` with an eighth element.

**Observed.** All five change `H(Γ)` and all five are distinct from one another:

| Mutation | `H(Γ)` prefix |
|---|---|
| baseline (frozen artifact) | `f63320c9da37…` |
| add a trusted key | `860a32099b7b…` |
| accept third-party blocks | `e5377fb232ce…` |
| permit `trusting` annotations | `a830fcfb5828…` |
| edit the Datalog | `37451b7d44af…` |
| widen `Ω` | `eaab04a5e9f4…` |

**Negative control.** A member-reordered copy of the same document keeps the digest **unchanged**,
so `H(Γ)` is not merely always-different — it tracks content, as RFC 8785 canonicalization intends.
Without this control the check would pass for a broken hash.

**Artifact intactness.** The on-disk file is byte-identical before and after the run
(`sha256(file) = 51482eea128c208e51d88c09e95e77553238eb4cf931fdbdb8899dbc2410d4d1`), and the
reloaded document still hashes to the row-8 value
`f63320c9da3731a6ea04dc51d9f6852f3a3e130182ce3a7fe251158751333deb`. The gate left the frozen bytes
alone. The spike also aborts (exit 2) before running any check if the loaded digest does not match
row 8.

**The failing world.** Any mutation leaving `H(Γ)` unchanged would mean a trust-broadening edit
could ship undetected past the Part H seal — the exact scenario criterion (c) exists to exclude.

### (d) `−attenuation` control admits what full `B3` blocks

**Constructed.** One chain, one tamper: hop 1 narrows `(mail.send, mail/outbox)` away, and the
terminal holder appends `right("mail.send","mail/outbox")` trying to restore it (F1-chain-tamper).
Both authorizer forms are then run **on that same chain**.

**Observed.** Full `Γ` computes `|C_n| = 2` and **refuses** `(mail.send, mail/outbox)`.
`−attenuation`, evaluating against `Allowed(P_0)`, computes `|Allowed(P_0)| = 5` and **admits** it.
The ablated set equals the independently computed `C_0`, confirming the control really is
"root-only". The admitted-but-blocked gap is
`{(calendar.read, calendar/work), (mail.send, mail/outbox), (notes.write, notes/project)}` —
i.e. exactly `C_0 \ C_n`, the authority attenuation removed.

Two distinct mechanisms are visible here and should not be conflated: the appended `right` fails to
restore authority under **either** form (block scoping, criterion (a)), while the ablation's
admission comes from **ignoring the attenuation blocks**, not from the tamper.

**Matched (d2).** The materialized full and ablated forms differ in exactly `['evaluation.prefix']`,
equal to the declared `differs_in_exactly`, with **byte-identical Datalog** — so the outcome
contrast is attributable to attenuation alone and not to a second edit. A delta declaring one path
while overriding two is rejected by the loader (`DocumentStructureError`), which ADR 0016 already
pins via `tests/test_omega_gamma_freeze.py::test_ablation_declaration_must_match_override`.

**The failing world.** If the control blocked the request too there would be no contrast and §E.6's
matched comparison would carry no information; if the full form admitted it, B3's central prevention
claim would be false.

## 4. Honest-adjudicability check (STEP 5)

Each criterion was **exercised**, not assumed:

- **(a)** — real appends built by the library from the token and `κ_pub` alone; every `C_i` computed
  by 7 authorizer runs per prefix; both the "stays contained under attack" and "actually narrows
  when legitimate" directions covered; non-vacuity shown by the same check passing under
  `trusting previous` and failing by default; and the criterion generalized past `right/2` to six
  broadening vectors, two of them probed under their unlocking condition.
- **(b)** — **full construction, no partial scope to declare.** The library assembled and signed a
  genuine third-party block and it was presented to the authorizer, not merely to the structural
  layer. The rejection observed is the one the profile relies on (§A.6.1's "MUST be rejected before
  evaluation"), located precisely: `commitment.py::_reject_non_ed25519`, on the wire
  `externalSignature` field. Non-vacuity is demonstrated by an out-of-profile authorizer that
  admits the same escalation.
- **(c)** — mutations applied programmatically to copies, digests compared, plus a negative control
  and a before/after byte comparison of the artifact.
- **(d)** — both forms run on the same tampered chain with opposite outcomes, and the control
  proven matched.

Two construction defects in the spike were found and **fixed rather than accommodated**, before any
result was recorded: the first drafts of a3 and b2 built their probes on `P_1`, whose attenuation
check failed for an unrelated reason and masked the discriminator. The criteria were not weakened —
the confound was removed by rebuilding both probes on `P_0`, where the only thing that can decide
the outcome is the property under test. Two test assertions were likewise wrong and corrected
(counting `scope(` also matched the consuming check; and `trusting previous` from the authorizer
admits nothing at all — see §6).

No criterion was found un-adjudicable, so the G-4 Phase 1 precedent (report the limb, do not mark
PASS) did not need to be applied.

## 5. Outcome

**G-2 PASSES.** All four criteria hold, every `C_i` computed rather than asserted.

`[VERIFIED]` for **`biscuit-python==0.4.0` under the frozen `Ω`/`Γ` of ADR 0016
(`H(Γ) = f63320c9da37…`)**: appended blocks — facts *and* rules — cannot enlarge the authority set
under default block scoping; `C_i ⊆ C_{i−1}` holds, and holds strictly when attenuation genuinely
narrows; a third-party block verifies under the root key but is refused structurally before
evaluation and carries no authority if evaluated anyway; `trusting` annotations are refused
pre-evaluation and would otherwise escalate; every trust-broadening or `Ω`-widening mutation changes
`H(Γ)`, while a re-serialization does not; and the `−attenuation` control admits exactly `C_0 \ C_n`
more than the full form, differing from it in exactly `evaluation.prefix`.

**IA-2 moves from [UNVERIFIED-IA] to verified by gate G-2**, with the residuals in §7.

What stays `[DESIGN]`: that this authorizer configuration is the *right* one for the study (ADR
0016's decision, including the contents of `Ω`), and every element of the design this gate does not
touch (§6).

## 6. Findings worth recording

- **The library verifies third-party tokens under `κ_pub` alone.** Out-of-profile rejection is
  therefore load-bearing project code, not an inherited library guarantee. Anyone re-implementing
  the boundary must reproduce the `externalSignature` structural check (D13/D21 means the SUT side
  reimplements it independently).
- **`trusting previous` in an *authorizer* reaches no token facts at all** — not the authority
  block, not a later block. It appears to replace the default trust set and then resolve to nothing,
  so an authorizer written with it would deny everything rather than over-trust. Pinned by
  `test_trusting_previous_reaches_no_token_facts_from_the_authorizer` so a library bump surfaces any
  change. In a *block* check, `trusting previous` does see earlier blocks' facts.
- **A later block's `trusting` annotation cannot widen authority** even so, because the positive
  grant is read by the *authorizer's* `allow` policy, which no block can influence; a block-level
  annotation can only affect whether that block's own check passes, i.e. it can only narrow.
- **Re-adding a `scope` fact does not undo an earlier hop's narrowing**, because each hop's check
  reads `scope` from its own block only — the property that makes `C_i = right ∩ ⋂_{j≤i} scope_j`
  hold operationally.
- **Authorization failure text distinguishes the two deny modes** — "no matching policy was found"
  (the grant does not cover the candidate) versus "an allow policy matched … and the following
  checks failed" (audience/task/expiry/scope). Both are denies; the boundary must not treat the
  second as an error.

## 7. Residual risks

- **Exact pin.** The claim is for `biscuit-python==0.4.0`; any version bump re-triggers G-2 (as it
  re-triggers G-1, ADR 0002).
- **Scoped to the frozen `Ω`/`Γ`.** `Ω` and `Γ` stay amendable until Part H step 3 and **any
  amendment re-triggers this gate** (ADR 0016) — the result is about these frozen bytes, not about
  Biscuit in general.
- **Datalog reasoning is the library's.** This gate observed the library's behaviour on the
  constructed cases; it is not a proof of Biscuit's semantics, and the Biscuit format remains
  **not formally audited** (ADR 0002, disclosed limitation).
- **The SUT-side implementation is still owed.** D13/D21 requires the SUT and the harness to
  evaluate the same frozen bytes with independent implementations. This gate delivers the
  harness-side evaluator only; the SUT-side one is due when the arms are built, and G-13 verifies
  `Allowed(AT_i) = C_i` across both layers.
- **`κ` is a test keypair here.** Each check mints a fresh `KeyPair()`; the sealed campaign key is
  derived from a sealed seed (ADR 0007) at Part H step 3. `H(Γ)` deliberately does not cover `κ`'s
  value.
- **Time is injected, not read from a clock.** `time(...)` is an authorizer fact supplied by the
  evaluator, so the expiry check is tested against controlled instants; clock-source trust at the
  boundary is a deployment concern this gate does not address.

## 8. What this gate does NOT establish

- Nothing about **HTC or INV** — holder binding, invocation binding, `capability_hash`,
  `access_token_hash` (gate **G-11**; §F.2). The `htc_chain_ok`, `holder_proof_ok` and
  `invocation_binding_ok` conjuncts of §A.5 are untouched.
- Nothing about the **AS** — RFC 8693 exchange, RFC 9396 `authorization_details`, DPoP-bound
  issuance (gate **G-4**; IA-4 stays **[UNVERIFIED-IA]**, `authlib` stays unpinned).
- Nothing about **`Allowed(AT_i) = C_i`** across the OAuth and capability layers, or matched
  per-hop authority across baselines (gate **G-13**).
- Nothing about **mediation or the ledger** (G-6/G-7, already passed), about **runtime arms**, the
  **oracle predicates** (Part I), **latency** (G-3), or the **replay/DPoP taxonomy** (G-9/G-14).
- Nothing about **`R`** (required authority): this gate computes `C_i` only. `R ⊆ C_n` is the
  boundary's pre-execution rule (§A.5) and is not exercised here.
- No **policy** row is decided: `docs/frozen_parameters.md` rows 1–7 and 9–10 remain UNSET, and in
  particular this gate chose no context-label, task-authorization, allowed-sink, or high-risk/
  sensitive classification.

## 9. Reproduction

```
uv sync --frozen
uv run python smoke/g2/spike.py        # exit 0; nine mandatory checks
uv run pytest -q tests/test_frozen_authorizer_semantics.py
```

The regression suite (42 tests) is the durable form of this gate and is **platform-independent** —
it runs the authorizer, so unlike the Windows-only effect-ledger tests (ADR 0014) it must pass on
Linux CI too. The spike is a one-shot artifact; the suite is what a library bump will fail against.
