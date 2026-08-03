# SMOKE_G1_RESOLUTION_TASK — Author decision on gate G-1

**Read this file completely, then execute it exactly.**

Gate G-1 was correctly reported **FAIL** because check **G-1.G** (seal is terminal) could not be executed: `biscuit-python==0.4.0` exposes no seal API. You did the right thing — you did not rationalise a PASS, you did not implement a fallback, and you stopped for a decision. This file carries that decision.

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`. **Working rules:** `PROJECT_RULES.md`.

---

## STEP 0 — The decision

**Accepted: neither fallback. The G-1.G criterion is replaced, not dropped.**

**Rationale (record this; it is the substance of ADR 0002).** Sealing, in Biscuit, exists to **stop further delegation**. In this design that function is already performed by two project-owned mechanisms, so seal is redundant:

1. **Further attenuation is harmless.** Attenuation is monotone (`C_i ⊆ C_{i−1}`, §A.6.1): any party appending a block can only *narrow* authority, never escalate it.
2. **Further delegation is governed by the HTC chain, not by seal.** Adding a hop requires a new `HTC_i` signed by the **current holder's identity key** (§F.2). An attacker without that key cannot produce one; a compromised holder gains nothing by narrowing authority it already holds.
3. **A block appended after the terminal hop is rejected by the INV binding.** `INV.capability_hash = H(P_n)` (§F.2). If an adversary appends a block, the verifier recomputes `H(P_{n+1}) ≠ H(P_n)` and the request is refused.

Therefore the absence of a seal API does **not** affect this design. What the design actually depends on is the *dual* of what G-1.F already proved:

- **G-1.F (proved):** the **prefix** identity is **stable** under append — `H(P_0)` is unchanged after appending — so HTC parent bindings survive a legitimate append.
- **G-1.G′ (to prove now):** the **terminal** prefix hash **changes** under append — `H(P_n) ≠ H(P_{n+1})` — so `INV.capability_hash` detects and rejects an illegitimate post-hoc append.

Together these are exactly the two properties the design needs: *prefix-stable, terminal-sensitive*. **G-1.G is replaced by G-1.G′.**

**Rejected fallbacks (record why in the ADR):**
- *Rust FFI* — disproportionate: it would put a Rust toolchain into CI and Docker to preserve a property (seal) this design does not use.
- *Macaroon-style chain* — strongly rejected: it would surrender root-**public**-key verification (a real, load-bearing property, §A.6.1/§F.2) to close a gap that is not a gap.

---

## STEP 1 — Scope guard (unchanged)

| Forbidden | Why |
|---|---|
| Do **not** run G-2, G-5, G-8, or any other gate | This session applies one decision. Other gates have their own task files. |
| Do **not** define or freeze `Ω` or `Γ` | Seal-time frozen parameters (`docs/frozen_parameters.md`). |
| Do **not** implement HTC, INV, baselines, oracle, or mediation | G-1.G′ is a hash-level assertion in the spike; it does **not** require implementing HTC/INV. |
| Do **not** touch `fixtures/confirmatory/` | Red line 1. |
| Do **not** open the upstream `seal()` PR now | Good idea, but off the critical path with the deadline where it is. Record it in the ADR as an upstream opportunity, and move on. |
| Do **not** `git push --force` | Red line 7. |

---

## STEP 2 — Add G-1.G′ to the spike and re-run

Edit `smoke/g1/spike.py`. **Remove the G-1.G seal check** (it is unexecutable and no longer a criterion) and **add G-1.G′** in its place, as a MANDATORY check:

**G-1.G′ — append-detection (terminal hash is sensitive to append).**
1. Take the token at terminal state `P_n` (use `n = 1` from the existing spike). Compute `H(P_n)` by the same prefix-identity function G-1.F established (Biscuit container fields 2 + 3, excluding the mutable proof field 4).
2. Simulate an adversarial post-hoc append: from the `P_n` token alone, append one further attenuation block → `P_{n+1}`.
3. Compute `H(P_{n+1})`.
4. **ASSERT `H(P_n) ≠ H(P_{n+1})`.** Print both values.
5. State in the output what this establishes: *an `INV` assertion binding `capability_hash = H(P_n)` will not match a capability that has been appended to, so a post-hoc append is detected and rejected without any need for seal.*

Also add a **negative control** so the assertion cannot pass vacuously: assert that `H(P_n)` recomputed from a **serialize → deserialize** round-trip of the *unmodified* token is **equal** to the signer-side `H(P_n)` (this is already G-1.F5; re-assert it adjacent to G-1.G′ so the two appear together, showing the function is neither always-equal nor always-different).

Re-run the spike:

```
uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py
```

All six mandatory checks (B, C, D, E, F, **G′**) must now pass, and the script must exit zero.

---

## STEP 3 — Update `smoke/g1/REPORT.md` and the status board

- Change the **Outcome** to **PASS**, with a short note: *G-1.G (seal terminality) was replaced by G-1.G′ (append-detection) by author decision; see ADR 0002. Seal is not used by this design.*
- Replace the G-1.G row in the results table with **G-1.G′**, carrying the actual `H(P_n)` and `H(P_{n+1})` values from the re-run.
- In **"What this gate does NOT establish,"** add explicitly: *this gate does not establish that the library can seal a token (it cannot, and the design does not require it); it does not establish monotonicity (G-2); it does not establish performance (G-3).*
- Add a **Residual risks** section recording, in plain terms:
  - `biscuit-python` is at **0.4.0** — a **0.x API**. The pin is exact; **any version bump requires re-running G-1.**
  - `H(P_i)` is computed by parsing the Biscuit **wire format** (container fields 2 + 3, excluding the proof field 4), so it depends on the **format specification** (stable, versioned) rather than on the 0.x Python API. A **format** version change would require re-verification.
  - Biscuit's format has had informal cryptographic review but is **not formally audited** (project FAQ). This is a disclosed limitation of the study, not a blocker for a measurement contribution.
  - The library exposes no seal API. Recorded as an upstream contribution opportunity, deliberately not pursued now.
- Update `smoke/README.md`: G-1 → **PASS**, link the report and ADR 0002. Leave every other gate `not started`, and keep G-2's blocking reason (`requires frozen authorizer Γ and H(Γ)`).

---

## STEP 4 — Rewrite `adr/0002-python-biscuit-library.md`

Rewrite it (status `accepted`) to record the decision as taken, not as proposed:

- **Context** — G-1 tested IA-1. Candidates on PyPI; only `biscuit-python` is viable (PyO3 bindings over `biscuit-rust` 6.0.0; Eclipse Foundation project; typed; prebuilt wheels cp39–cp313 for all platforms, so **no Rust toolchain** in local, CI, or Docker). Five of six mandatory checks passed; G-1.G (seal) was unexecutable because the binding exposes no seal API.
- **Decision** — `[DESIGN]` Adopt **`biscuit-python==0.4.0`**, pinned exactly. `[DESIGN]` **Replace criterion G-1.G with G-1.G′ (append-detection).** `[DESIGN]` **This design never seals**; further delegation is governed by the HTC chain, further attenuation is harmless because attenuation is monotone, and a post-hoc appended block is rejected by `INV.capability_hash = H(P_n)`. Both fallbacks (Rust FFI; Macaroon chain) are **rejected** — record the disproportionality argument from STEP 0.
- **Status** — `accepted — <date>`.
- **Consequences** — pin is exact and a bump re-triggers G-1; `H(P_i)` depends on the Biscuit wire format, not the 0.x API; the not-formally-audited status is a disclosed limitation; the availability residual (STEP 5, edit 5) is recorded in the threat model; an upstream `seal()` wrapper is an open, non-blocking contribution opportunity.

---

## STEP 5 — Update the architecture document (mandatory: never diverge silently)

Apply these five edits to `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`. Quote each existing passage before editing so the diff is reviewable.

**Edit 1 — D22 (Part B.2 decision register).** Append to D22's entry:

> **This design never seals.** Further delegation is governed by the HTC chain (a new hop requires an `HTC_i` signed by the current holder's identity key, §F.2); further attenuation by any party is harmless because attenuation is monotone (§A.6.1); and a block appended after the terminal hop is rejected because it changes `H(P_n)` and therefore fails the `INV.capability_hash` binding (§F.2). Sealing is consequently **not required** by this design, and the absence of a seal API in the chosen Python binding does not affect it. `[Gate G-1; ADR 0002]`

**Edit 2 — Part G, the G-1 row.** Replace the row's *Runs* and *Pass criterion* cells with:

> **Runs:** Import the Python Biscuit library; mint `C_0` (`P_0`); append one block → `P_1`; verify against the root **public** key only; confirm **(F)** the prefix identity is **stable** under append and agrees between signer and verifier, and **(G′)** the **terminal** prefix hash **changes** under append.
> **Pass criterion:** Round-trips and verifies with `κ_pub` alone; `H(P_0)` identical before and after append; signer-side and verifier-side `H(P_1)` agree; **`H(P_n) ≠ H(P_{n+1})`**, so `INV.capability_hash` rejects a post-hoc appended block; API stable enough to script. *(Seal terminality is not a criterion: this design never seals — ADR 0002.)*

**Edit 3 — §F.4, IA-1 row.** Update its status from `[UNVERIFIED-IA]` to:

> **Verified by gate G-1** for `biscuit-python==0.4.0` (PyO3 over `biscuit-rust` 6.0.0; wheels for cp39–cp313; no Rust toolchain required): offline attenuation without the root secret, verification with the root public key alone, stable prefix identity `H(P_i)`, and append-detection all confirmed. **Residuals:** the binding is a 0.x API (a version bump re-triggers G-1); `H(P_i)` parses the Biscuit **wire format** (container fields 2 + 3, excluding the proof field 4) rather than the Python API; the Biscuit format is **not formally audited**.

**Edit 4 — §F.2, HTC verification list.** Add one conjunct (fail-fast defence in depth):

> The number of HTCs **equals** the number of presented signed blocks: every presented `SignedBlock_i` is covered by a corresponding `HTC_i`. A block with no covering HTC is **rejected**. (The `INV.capability_hash = H(P_n)` check already detects such a block; this count check fails fast and yields an unambiguous reason code.)

**Edit 5 — `docs/threat_model.md`, add an availability residual.** Under a new heading *Known residual: append-induced rejection (availability)*:

> An adversary positioned between the terminal holder and the boundary verifier can append a block to the presented capability. Because attenuation is monotone, this **cannot escalate authority**; and because appending changes `H(P_n)`, the `INV.capability_hash` binding **rejects** the request. The residual effect is therefore a **rejection** — an availability effect — not an authorization breach. An adversary in that position could equally drop or corrupt the message, so sealing the capability would not close this residual. Availability effects are not among the scored families F1–F5; this residual is recorded for completeness.

---

## STEP 6 — Pin the library

- Add `biscuit-python==0.4.0` (exact pin) to `[project].dependencies` in `pyproject.toml`.
- **Remove only the Biscuit line** from the `# PENDING GATE` comment block. **Leave the `authlib` (G-4) and DPoP/JOSE (G-5) lines** — those gates have not run.
- Run `uv lock`; commit the updated `uv.lock`.
- Confirm no Rust toolchain is required (wheels), so `Dockerfile` and CI need **no** change. State this explicitly in the report; if a wheel turns out to be unavailable on the CI platform, stop and tell me rather than adding a toolchain silently.

---

## STEP 7 — Verify, commit, push

Run `make lint` and `make test`; fix anything they flag (the spike must be ruff-clean). Confirm CI would pass.

Commits, logically grouped:

1. `feat: replace G-1.G with G-1.G' append-detection check in the Biscuit spike`
2. `docs: flip G-1 to PASS; rewrite ADR 0002 with the seal decision` — report, status board, ADR
3. `build: pin biscuit-python==0.4.0 (ADR 0002, gate G-1)` — `pyproject.toml`, `uv.lock`
4. `docs: record the seal decision in the architecture document and threat model` — the five STEP 5 edits

Reference **ADR 0002** in the body of commits 2–4. Then `git push origin main`. Never force-push. If the push fails on authentication, STOP and tell me what to configure — do not enter, store, or generate any credential.

---

## STEP 8 — Report to me

- Confirm **G-1 = PASS** and paste the actual `H(P_n)` and `H(P_{n+1})` values from G-1.G′.
- Confirm the pin landed, `uv.lock` updated, and no toolchain was added.
- List the five architecture edits with the surrounding text, so I can review the diff.
- Confirm the scope guards held: no other gate run; `Ω`/`Γ` untouched; `fixtures/confirmatory/` untouched; no upstream PR opened.
- State the **next gates**: G-5 (DPoP) and G-8 (JCS canonicalisation), which are independent and in the same DAG batch. **Do not start them** — they have their own task file.
