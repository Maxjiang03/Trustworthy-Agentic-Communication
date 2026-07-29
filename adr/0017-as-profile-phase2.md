# 0017 — The experiment AS profile as built: RAR type URI and four implementation decisions

## Context

`smoke/g4/DESIGN.md` §5.2 defers one value to this ADR by name: *"One project-namespaced RAR type
(**exact string fixed by the Phase 2 ADR**; it is part of the AS configuration the seal already
hashes, **not** a new `frozen_parameters` row unless the Commander rules otherwise)"*. Phase 2 built
the AS (`src/sut/oauth_as/`, ADR 0015) and ran gate G-4, so that string now exists and must be
recorded where a decision belongs.

Implementation also surfaced **four points the design constrains but does not determine**. Each was
resolved during the build; none was filled by silent assumption, and each is recorded here rather
than left as a fact of the code. Full evidence and the would-have-failed worlds are in
`smoke/g4/REPORT.md` §2.

Nothing here changes G-4's pass criteria, its dependency edges, or any evidence grade (ADR 0008), and
no `frozen_parameters` row is set: rows 1–7, 9 and 10 stay UNSET and row 8 (`Ω`/`Γ`, ADR 0016) is
byte-unchanged.

## Decision

### 1. The RAR type URI

`[DESIGN]` The single project RAR type is

```
https://aasc.gla.ac.uk/rar/tool-authority
```

A URI in a namespace the designer controls, as RFC 9396 §2.1 RECOMMENDS for cross-server deployment
`[VERIFIED]`. Any other `type` is refused with `invalid_authorization_details` (RFC 9396 §5 MUST).
It is **AS configuration**, hashed by the Part H seal along with the rest of that configuration, and
deliberately **not** a new `frozen_parameters` row — per §5.2, unless the Commander rules otherwise.

### 2. `requested_expires_in`, and the default-lifetime cap

`[DESIGN]` DESIGN §5.3 step 7 requires `exp_i ≤ exp_{i−1}` and §6 lists `exp_i > exp_{i−1}` as a
widening error, but §5.3's request table names **no parameter** through which a client could ask for
a lifetime — leaving that catalogue row unreachable. The profile therefore recognises one extension
parameter, `requested_expires_in`, which OAuth 2.1 §4.4 permits ("plus any additional parameters").

Two cases are kept apart, and the distinction is the whole of "error, never a silent clamp" applied
where it belongs:

- an **explicit** `requested_expires_in` beyond `exp_{i−1}` is a widening **request** and is refused
  with `invalid_authorization_details` — silently reducing it would hide an attempt to extend
  authority in time, and would make `F1-chain-tamper` indistinguishable from benign narrowing;
- with **no** lifetime requested the AS chooses `exp_i` itself and caps **its own** default at
  `exp_{i−1}`. Nothing the client asked for is quietly reduced, so this is AS policy, not a clamp.

The cap is not a convenience. Without it a fixed default equal to the root's lifetime makes **hop 2
impossible** — the parent's *remaining* lifetime is always shorter by the elapsed time — which would
break the per-hop exchange §E.2 requires. Observed before the fix: hop 2 returned
`400 invalid_authorization_details "requested lifetime extends beyond the subject token's exp"`.

### 3. `identifier` may restate or narrow, never widen

`[DESIGN]` §5.2 permits `identifier`, but RFC 9396 §2.2's product rule covers only
`locations` × `actions` × `datatypes` — `identifier` is not a product field, so a naive
implementation would either give it no meaning or turn it into a second, unexpanded authority
channel. The profile requires `identifier`, when present, to be **one of the object's own
`datatypes`**; anything else is `invalid_authorization_details`. It can therefore restate or narrow
and can never widen.

### 4. `Ω` membership is checked on the **pair**, not value by value

`[DESIGN]` §5.2 says "every value must be a member of `Ω`", which is weaker than §A.0.1's
`C_i ⊆ Ω`: that is a constraint on the `(action, resource)` **pair**. An object with
`actions: [notes.read, notes.write]` and `datatypes: [notes/project, notes/meeting]` expands to four
pairs, of which `(notes.write, notes/meeting)` is **not** an `Ω` element even though both strings
are. Membership is therefore checked pairwise over the expansion. Splitting such a request across
several same-type objects is the RFC-sanctioned way to express it (RFC 9396 §2 allows several
entries of one type), so nothing expressible is lost.

### 5. `may_act` is keyed on the current actor, as a labelled stand-in

`[DESIGN]` §7.4 says the policy answers "which principals may act for this subject **on this
task**", but §5.1's AT claim set contains **no task claim**, and inventing one would add a claim the
design does not specify. Phase 2 therefore populates `may_act` (RFC 8693 §4.4, a single JSON object)
from a **SPIKE-LOCAL** policy keyed on the current actor's principal — a delegation chain. The
frozen `task_authorization_policy` (`frozen_parameters` **row 5, UNSET**) will key on subject and
task; the F2 `wrong_principal` family is **not scored** until that row is fixed by its own ADR.

## Status

accepted — 2026-07-29

## Consequences

- **No new dependency is pinned.** The stdlib supplies HTTP and TLS, `joserfc==1.7.4` (ADR 0006)
  supplies JOSE, and `cryptography` — already a dependency — supplies HKDF derivation and the
  run-time self-signed certificate. `authlib` stays **unpinned** and the `# PENDING GATE` block is
  untouched: the Phase 1 probe found `authlib==1.7.2` UNSUPPORTED, so IA-4 is discharged by its
  **second** limb, "a behaviourally faithful AS can be built" (ADR 0004's build-vs-reuse rule).
- **The AT profile is RFC 9068-*shaped*, not RFC 9068-conformant** (DESIGN §8.3): RFC 9068 §2.1
  requires RS256 among the supported algorithms and this project signs Ed25519 with an explicit
  allowlist (ADR 0006). **No document may call it "RFC 9068-compliant."**
- **A §8.2 fair-baseline defect was found by measurement and fixed.** Dialling the AS by the name
  `localhost` resolves `::1` first on a dual-stack host and waits for that to fail, adding ~0.7 s to
  **every** exchange — exactly the "per-hop TCP+TLS setup inflates B2 (toward B3)" hazard §8.2 names.
  Fixed with a `127.0.0.1` IP SAN on the run-time certificate and dialling the literal address; the
  regression suite went from 108.5 s to 2.69 s. Recorded because it would have biased B2's reported
  overhead toward this study's own hypothesis.
- **Limb L4 stays open.** `INV.access_token_hash` is adjudicated in a follow-on G-4 run **after
  G-11** (DESIGN §9 C2); Phase 2 tested the AS-side precondition only, and the `AASC-AT-DIGEST`
  construction remains a **proposal** for G-11. The smoke board must not show G-4 as fully
  adjudicated until then.
- **The C3 registry stand-in** re-triggers the `actor→holder` limb at **G-11**; the frozen
  identity-plane registry stays a seal-time artifact (§F.2.1).
- Recorded in Part B.2 and in the §F.4 IA-4 row in the same pass; `smoke/g4/REPORT.md` is the gate
  record.
