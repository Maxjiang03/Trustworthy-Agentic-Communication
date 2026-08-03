# SMOKE_G1_TASK — Feasibility Gate G-1: Python Biscuit library

**Read this file completely, then execute it exactly.**

This session runs **one gate only: G-1**. It is the first feasibility spike in the Part G DAG (`G-1 / G-5 / G-8 → G-6 / G-7 → G-2 / G-4 / G-11 → …`). G-1 decides whether the **entire capability track** is buildable in Python, or whether a fallback changes the technology stack.

**Authoritative design:** `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`. **Working rules:** `PROJECT_RULES.md`.

---

## STEP 0 — Orient

1. Read `PROJECT_RULES.md` in full (red lines, evidence grades, commit convention).
2. Read these sections of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`:
   - **§A.0.1** — canonical types: `SignedBlock_i`, `P_i` (signed-block prefix, **excluding the mutable proof tail**), `C_i`, `Ω`, `Γ`, `κ`. **The hashing rule matters most: every capability-state hash hashes a `P_i` prefix, never the token with its mutable proof tail.**
   - **§A.6.1** — the three distinct checks: `crypto_chain_ok`, `authorizer_policy_ok`, effective authorization. **G-1 tests only `crypto_chain_ok`.**
   - **§F.2** — HTC / INV, which bind `H(P_{i−1})`, `H(SignedBlock_i)`, `H(P_n)`.
   - **§F.4** — `IA-1` (the assumption this gate tests).
   - **Part G** — the gate table, the DAG, and the **gate-outcome policy** (fallbacks).
3. Report the line counts of `PROJECT_RULES.md` and `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` so we can confirm nothing was truncated.

---

## STEP 1 — Scope guard (what this session must NOT do)

| Forbidden | Why |
|---|---|
| **Do NOT run G-2** | G-2 requires a **frozen authorizer configuration `Γ`** and its hash `H(Γ)`. `Γ` does not exist yet; it is a seal-time frozen parameter (`docs/frozen_parameters.md`, item 8, currently `⟨UNSET⟩`). Running an authorizer with policies is out of scope for G-1. |
| **Do NOT define or freeze `Ω` or `Γ`** | Both are seal-time frozen parameters fixed via ADR before Part H step 3. G-1 uses a **throwaway pilot vocabulary** only, clearly labelled as **NOT `Ω`**. |
| **Do NOT implement HTC, INV, baselines, oracle, or mediation** | Implementation begins only after the gates. G-1 produces a **spike**, not production code. |
| **Do NOT test monotonicity** (`C_i ⊆ C_{i−1}`) | That is G-2. G-1 tests the library's mechanics, not the Datalog semantics. |
| **Do NOT pin the library in `pyproject.toml` before the gate passes** | Pinning an unverified library would state an `[UNVERIFIED-IA]` as fact. Use an **ephemeral** install for the spike (STEP 3). |
| **Do NOT touch `fixtures/confirmatory/`** | Red line 1. |
| **Do NOT unilaterally change the design** | If G-1 forces a design change, record an **ADR** and **update the architecture document** in the same commit. Never diverge silently (PROJECT_RULES.md). |
| **Do NOT `git push --force`** | Red line 7. |

---

## STEP 2 — Create the smoke scaffolding

```
smoke/
├── README.md          # gate status board (see below)
├── g1/
│   ├── spike.py       # runnable spike; exits non-zero if any MANDATORY check fails
│   └── REPORT.md      # the gate report, written after running (see STEP 6)
```

`smoke/README.md` holds a **gate status board** — a table with columns `Gate | Depends on | Status | Report | ADR`, one row per gate G-1…G-15, with the Part G DAG reproduced above it. Mark G-1 `in progress`; mark every other gate `not started`, and for G-2 write the blocking reason explicitly: `blocked — requires frozen authorizer Γ and H(Γ)`.

Update `Makefile` so the `gate` target is runnable:

```make
gate:
	@test -n "$(GATE)" || (echo "usage: make gate GATE=g1"; exit 1)
	python smoke/$(GATE)/spike.py
```

The spike must be **ruff-clean** (pre-commit runs on all files) and must **not** be collected by pytest (name it `spike.py`, never `test_*.py`).

---

## STEP 3 — Library discovery (discover; do not assume)

**You do not know which Python Biscuit library exists, nor its API. Find out. Do not guess a package name, and do not invent method names.**

1. Search PyPI for Biscuit token / biscuit-auth packages. Check the `biscuit-auth` GitHub organization for official Python bindings (the reference implementation is Rust; Python support may be a binding).
2. For each candidate, record in `smoke/g1/REPORT.md`:
   - package name, latest version, release date
   - whether it wraps the Rust reference implementation or is a reimplementation
   - maintenance signals (recent releases, open issues, CI status, typed API, docs)
   - install size / build requirements (does it need a Rust toolchain?)
3. Choose the best candidate for the spike. **Justify the choice in the report.**
4. Install it **ephemerally** — do not modify `pyproject.toml` yet:
   ```
   uv run --with <package>==<version> python smoke/g1/spike.py
   ```
   If `uv run --with` is unavailable, create a scratch venv outside the repo; do **not** commit an unverified pin.

If **no usable Python binding exists at all**, stop the spike and go straight to STEP 6 (gate outcome = FAIL) with the evidence.

---

## STEP 4 — Write the spike: required capabilities

Write `smoke/g1/spike.py` against the **real API you discovered**. Document the mapping from each required capability to the actual API call in the report. Each check prints `PASS` / `FAIL` with concrete evidence (byte lengths, hashes, exception types). The script **exits non-zero if any MANDATORY check fails**.

Use a **throwaway pilot vocabulary**, clearly commented as *NOT `Ω`* — for example facts like `right("calendar", "read")` and `right("notes", "write")`. These are scaffolding, not the frozen ontology.

| ID | Check | Mandatory? | What it establishes |
|----|-------|:----------:|---------------------|
| **G-1.B** | Generate an Ed25519 root keypair `(κ_priv, κ_pub)`. Mint an authority block carrying the pilot facts. This is `P_0`, authority `C_0`. | **Yes** | The token can be minted at all. |
| **G-1.C** | **Offline attenuation.** From the token alone, append one attenuation block → `P_1`. **Structure the code so `κ_priv` is genuinely out of scope at this point** (e.g. perform the append inside a function that never receives it, or delete the variable first). Assert the append needs no root secret. | **Yes** | Offline attenuation works — the property the whole capability arm rests on. |
| **G-1.D** | **Root-public-key-only verification.** Verify the attenuated token's signature chain using **only `κ_pub`**. This is `crypto_chain_ok` (§A.6.1). **Do NOT construct an authorizer with policies** — that is `Γ` and belongs to G-2. | **Yes** | Verification needs no secret (the property a Macaroon fallback would lose). |
| **G-1.E** | **Round-trip.** Serialize → bytes → deserialize → verify again. Assert the same block count and the same verification outcome. | **Yes** | The token survives the wire. |
| **G-1.F** | **Stable prefix identity — the critical check.** See STEP 5. | **Yes** | Whether `H(P_i)`, and therefore the entire HTC/INV binding, is implementable. |
| **G-1.G** | **Seal is terminal.** Seal the token, then attempt to append another block. The append **must fail**. Record the exception type. | **Yes** | Confirms the library enforces what the spec states (D22: append per hop, seal only at the terminal hop). |
| **G-1.A** | Library discovery + maintainability (STEP 3). | Informational | Feeds the ADR; a moribund or unbuildable library is itself a fail signal. |
| **G-1.H** | API stability signals: type hints, documented API, version pinnable, no Rust toolchain needed at install time (or, if needed, wheels are published). | Informational | "API stable enough to script" (the Part G pass criterion). |

Note: Biscuit chains blocks with **single-use keypairs**, so token bytes will differ between runs. That is expected and fine — every check below compares identities **within a single run**, never bytes across runs.

---

## STEP 5 — G-1.F: stable prefix identity (this is the make-or-break check)

**Why this exists.** §A.0.1 requires `HTC.parent_prefix_hash = H(P_{i−1})`, `HTC.child_block_hash = H(SignedBlock_i)`, and `INV.capability_hash = H(P_n)`, where `P_i` is the **signed-block prefix excluding the mutable proof tail**. The proof tail (the trailing single-use secret, or the seal signature) **changes on every append and on seal**. If we can only hash the whole serialized token, then `H(P_0)` computed before appending will differ from `H(P_0)` re-derived after appending, and the HTC parent binding cannot work as specified.

**This sub-check is an expansion of G-1 beyond the row currently in the architecture document.** It is legitimate — the design depends on it — but per PROJECT_RULES.md it **must not be a silent divergence**: record it in the ADR and update the Part G G-1 row in `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` (STEP 8).

**Procedure:**

1. **F1.** With the token at state `P_0` (before any append), derive a stable identity of its signed blocks, excluding the proof tail. Call it `id(P_0)_before`.
2. **F2.** Append an attenuation block → token now at `P_1`.
3. **F3.** From the `P_1` token, re-derive the identity of its **prefix** `P_0`. Call it `id(P_0)_after`.
4. **F4. ASSERT `id(P_0)_before == id(P_0)_after`.** If they differ, hashing is unstable under append and the HTC parent binding **cannot be implemented as specified**.
5. **F5.** Serialize the `P_1` token, deserialize it in a fresh object (simulating the verifier), and re-derive `id(P_1)`. **ASSERT it equals the signer-side `id(P_1)`.** Signer and verifier must agree, or `INV.capability_hash` cannot be checked.

**Investigate and report exactly what the library exposes** — do not assume any of these exist:
- a canonical serialization of the signed blocks only (ideal — hash it directly);
- per-block raw bytes and/or per-block signatures (we can concatenate canonically ourselves);
- any stable per-block identifier the library computes (Biscuit implementations sometimes expose per-block identifiers used for revocation; **verify whether this one does, do not assume**);
- block count / block accessors.

**If a direct canonical serialization of `P_i` is NOT exposed**, but some other **stable, append-invariant, per-block quantity** is, then G-1.F is a **CONDITIONAL PASS**: report precisely what is available and **propose** in the ADR a concrete basis for defining `H(P_i)` (e.g. `H(P_i) := SHA-256(concat(stable_block_id[0..i]))`). **Do not unilaterally redefine the §A.0.1 hashing rule** — propose it and stop for the author's decision.

---

## STEP 6 — Gate outcome and the fallback ladder

Classify the outcome as exactly one of:

- **PASS** — B, C, D, E, F, G all pass, and F passes via a directly hashable canonical `P_i` serialization.
- **CONDITIONAL PASS** — B, C, D, E, G pass, and F is satisfiable only by defining `H(P_i)` on a library-specific stable per-block identifier. → The §A.0.1 hashing rule needs a **refinement** (ADR + doc update + author sign-off) before implementation proceeds. **This is not a fallback; it is a design refinement.**
- **FAIL** — any of: no usable Python binding; attenuation requires the root secret; verification requires a secret; no stable append-invariant prefix identity exists; seal does not prevent further appends.

**On FAIL, do not implement a fallback.** Each fallback changes the trust model, so it needs the author's decision. Record the evidence and the ADR, then **STOP and report**. The ladder, in order of preference (from the Part G gate-outcome policy):

1. **Rust `biscuit-auth` via FFI** (PyO3/maturin) or a subprocess bridge. Preserves the root-**public**-key verification property. Cost: build complexity, a Rust toolchain in the Docker image and CI.
2. **Macaroon-style caveat chain** (symmetric HMAC). **Consequence to state loudly:** the verifier must hold the **root secret**, so the property "verification requires only `κ`, the root public key" (§F.2, §A.6.1) is **lost**, and the credential-flow table (§C) and the trust model must be updated. This is a real weakening of the design, not a like-for-like swap.

For whichever outcome, the report must state the consequence for the design in plain terms — including, on FAIL, which architecture sections would have to change.

---

## STEP 7 — Write `smoke/g1/REPORT.md`

Structure it so it can be lifted into the dissertation's feasibility subsection:

1. **Gate** — G-1; the assumption tested (`IA-1`); the DAG position; the date.
2. **Library discovery** — candidates found, maintenance signals, the one chosen, and why (STEP 3).
3. **API mapping** — a table: required capability → the actual API call used.
4. **Results** — one row per check (G-1.A … G-1.H): PASS / FAIL / CONDITIONAL, with concrete evidence (block counts, identity hashes, exception types). Include the exact `id(P_0)_before` / `id(P_0)_after` values for G-1.F.
5. **Outcome** — PASS / CONDITIONAL PASS / FAIL, with the reasoning.
6. **Consequences for the design** — what, if anything, must change; which architecture sections; which ADR records it.
7. **Reproduction** — the exact command that reproduces the run.
8. **What this gate does NOT establish** — explicitly: it does **not** establish monotonicity (`C_i ⊆ C_{i−1}`, that is G-2), does **not** establish performance (G-3), and does **not** freeze `Ω` or `Γ`.

**Never write that an unverified assumption is now a fact.** The report converts `IA-1` from `[UNVERIFIED-IA]` to a verified-by-gate status **only** for exactly what was tested.

---

## STEP 8 — ADR, `pyproject.toml`, and the architecture-document update

**Always** write `adr/0002-python-biscuit-library.md` from `adr/template.md`, whatever the outcome. It must record: the candidates evaluated; the decision (adopt package X at version Y / trigger fallback N); the `[VERIFIED]` vs `[UNVERIFIED-IA]` status of each capability after the gate; and the consequences — especially any change to the §A.0.1 hashing rule or to the trust model.

**On PASS or CONDITIONAL PASS:**
- Add the library to `pyproject.toml` `dependencies` with an exact version.
- **Remove only the Biscuit line** from the `# PENDING GATE` block. **Leave the `authlib` (G-4) and DPoP/JOSE (G-5) lines** — those gates have not run.
- Run `uv lock` and commit the updated `uv.lock`.
- If the library needs a Rust toolchain to build (no wheels), update the `Dockerfile` and the CI workflow, and note the cost in the ADR.

**Architecture-document update (mandatory, per PROJECT_RULES.md "never diverge silently"):**
- Update the **Part G G-1 row** so its pass criterion includes the prefix-identity check (G-1.F) and the seal-terminality check (G-1.G).
- Update **§F.4 IA-1** to reflect its post-gate status.
- **On CONDITIONAL PASS**, add the proposed `H(P_i)` definition to **§A.0.1** *only after the author approves it* — if the author has not yet approved, leave the document unchanged and flag the pending decision in the report and the ADR.

**On FAIL:** update `smoke/README.md` status to `FAILED — fallback pending author decision`, write the ADR with the evidence and the ladder, change nothing else, and stop.

---

## STEP 9 — Commit and push

Run `make lint` and `make test` first; fix anything they flag (the spike must be ruff-clean).

Suggested commits, logically grouped:

1. `feat: add smoke-gate scaffolding and G-1 Biscuit spike` — `smoke/README.md`, `smoke/g1/spike.py`, `Makefile` gate target
2. `docs: record G-1 gate report and ADR 0002 (Python Biscuit library)` — `smoke/g1/REPORT.md`, `adr/0002-*.md`, updated `smoke/README.md` status board
3. `build: pin Python Biscuit library (ADR 0002, gate G-1)` — *only on PASS / CONDITIONAL PASS*: `pyproject.toml`, `uv.lock`, and `Dockerfile`/CI if a toolchain is needed
4. `docs: update Part G G-1 criterion and IA-1 status after gate G-1` — the architecture-document edits from STEP 8

Reference the ADR in the commit body where a commit encodes a decision. Then `git push origin main`. **Never force-push.** If the push fails on authentication, STOP and tell me what to configure — do not enter, store, or generate any credential.

---

## STEP 10 — Housekeeping (separate `chore:` commit, last, optional)

Two small items flagged in the skeleton review. Do them **only after** the gate work is committed, in their own commit, so they never contaminate the gate's audit trail:

1. **`pytest` is currently a runtime dependency.** Move it out of `[project].dependencies` into a dev group (`[dependency-groups] dev = ["pytest>=8.0"]` or `[project.optional-dependencies].dev`), and adjust `make test` / CI / Dockerfile as needed so it is still installed where required. Re-run `uv lock`.
2. **Verify `.gitignore`.** It contains `!results/**/.gitkeep` (a negation), but confirm there is a preceding rule that actually ignores generated results content (e.g. `results/**` with the `.gitkeep` negation after it). If the ignore rule is missing, add it — otherwise large raw traces will be committed by accident later.

Commit as: `chore: move pytest to dev dependencies; fix results/ ignore rule`

---

## STEP 11 — Report to me

Finish with:

- the **gate outcome** (PASS / CONDITIONAL PASS / FAIL) and the one-sentence reason;
- the library chosen (name + version) and its maintenance signals;
- the **G-1.F result** stated explicitly — is `H(P_i)` implementable as specified, via a refinement, or not at all;
- the commits (hash + message) and whether the push succeeded;
- **any decision you need from me** (especially a CONDITIONAL PASS `H(P_i)` proposal, or a FAIL fallback choice);
- confirmation that you did **not** run G-2, did **not** define `Ω` or `Γ`, and did **not** touch `fixtures/confirmatory/`.

**Do not proceed to any other gate.** G-5 and G-8 are separate task files.
