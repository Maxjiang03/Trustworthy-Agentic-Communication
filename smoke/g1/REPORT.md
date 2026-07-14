# Gate G-1 Report — Python Biscuit library

## 1. Gate

- **Gate:** G-1 (feasibility spike, first tier of the Part G DAG: `G-1 / G-5 / G-8 → …`)
- **Assumption tested:** IA-1 — *"The chosen Python Biscuit library exists, is maintainable, and
  exposes append-block attenuation + root-public-key verification with a stable API"*
  (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4), plus the expanded criteria G-1.F (stable prefix
  identity, §A.0.1 hashing rule) and G-1.G′ (append-detection — **replaces** G-1.G seal
  terminality by author decision, ADR 0002).
- **Dates:** 2026-07-14 (first run: FAIL on G-1.G, recorded at commit `dca755b`; resolution and
  passing re-run: same day).
- **Blocks on failure:** the whole capability track (B-cap, B3, B3⁺).

## 2. Library discovery (STEP 3)

| Candidate | Verdict |
|---|---|
| **`biscuit-python`** | **Chosen and adopted (ADR 0002).** Official Python bindings for the reference Rust implementation (PyO3/maturin wrapper of `biscuit-rust`; 0.4.0 wraps biscuit-rust 6.0.0 per its CHANGELOG). Latest 0.4.0, released 2025-09-26; 7 stable releases since 2023-06. Repo `eclipse-biscuit/biscuit-python` (project moved from the `biscuit-auth` org into the Eclipse Foundation; the old URL redirects). Repo pushed 2026-07-14 (the day of this gate); `biscuit-rust` pushed 2026-07-13 — actively maintained. Typed API (`py.typed` + `__init__.pyi`). Pre-built wheels for CPython 3.9–3.13 on manylinux/musllinux/macOS/Windows and an sdist — **no Rust toolchain needed at install time** on any platform this project targets (Windows dev box, Ubuntu CI, `python:3.11-slim` Docker). |
| `biscuit-auth` (PyPI) | Does not exist (404). |
| `pybiscuit` (PyPI) | Does not exist (404). |
| `biscuit` (PyPI) | Unrelated dead web framework (single 0.0.1 release, 2020). |

Discovery method: PyPI JSON API, GitHub org/repo API, upstream `CHANGELOG.md`, upstream
`src/lib.rs` (the complete 1,730-line PyO3 surface), and runtime introspection of the installed
wheel. No other Python Biscuit implementation was found.

## 3. API mapping (required capability → actual API)

| Required capability | Actual API (module `biscuit_auth`, verified at runtime) |
|---|---|
| Ed25519 root keypair (κ) | `KeyPair()` → `.private_key` / `.public_key` |
| Mint authority block `P_0` | `BiscuitBuilder('right("calendar", "read"); …').build(private_key)` |
| Offline append `P_{i−1} → P_i` | `token.append(BlockBuilder('check if …;'))` — takes **no key argument**; returns a new `Biscuit` |
| `crypto_chain_ok(P_n; κ)` (§A.6.1) | `Biscuit.from_bytes(data, root_public_key)` — verifies the signature chain at parse time; raises `BiscuitValidationError` on failure. **No `Authorizer` was constructed** (that is `Γ`, gate G-2). |
| Serialize / deserialize | `token.to_bytes()` / `Biscuit.from_bytes(data, root)` |
| Canonical `SignedBlock_i` bytes (§A.0.1) | Not exposed as a dedicated accessor, but **directly sliceable from `to_bytes()`**: the container is `Biscuit { rootKeyId=1; authority=2 (SignedBlock); blocks=3 (repeated SignedBlock); proof=4 }` **[VERIFIED against the format spec `schema.proto`, eclipse-biscuit/biscuit]**. Fields 2/3 are exactly the §A.0.1 `SignedBlock_i` serializations; field 4 is exactly the mutable proof tail §A.0.1 excludes (`Proof = oneof { nextSecret, finalSignature }`). |
| Stable per-block identifier (corroboration) | `token.revocation_ids` — hex per-block identifiers, prefix-stable under append |
| Block introspection | `token.block_count()`, `token.block_source(i)` |
| Seal | **Not exposed** by biscuit-python 0.4.0 (runtime surface, upstream `src/lib.rs`, `.pyi` stubs; no upstream issue requests it). **No longer a criterion:** this design never seals (ADR 0002); recorded as an upstream contribution opportunity, deliberately not pursued now. |

## 4. Results

Passing run: `uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py` → **exit code 0**.
Token bytes legitimately differ between runs (single-use block keypairs); all identities below
are within-run values from the passing run.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-1.B mint | yes | **PASS** | `P_0` minted: `block_count=1`, 194 bytes, pilot facts present in block 0 |
| G-1.C offline append | yes | **PASS** | `P_0 → P_1` inside a function that receives only token bytes + `κ_pub`; the root private key never leaves the minting function's frame (enforced structurally). `block_count 1 → 2`. |
| G-1.D κ_pub-only verification | yes | **PASS** | Chain verifies with only the root **public** key; no authorizer, no policies. Wrong root key rejected with `BiscuitValidationError`. |
| G-1.E round-trip | yes | **PASS** | serialize → deserialize → verify; block count preserved; re-serialization **byte-identical** |
| G-1.F stable prefix identity | yes | **PASS** | `id(P_0)_before = id(P_0)_after = d8d3458b1e2b435545cc8b6bc4f4322ae75663d0667d97bf7101bd3c70a90516` (re-derived from the `P_1` token); signer-side and verifier-side `id(P_1)` agree (`7b1b962d10a8333d9c7212386ec12e4f7d57190bca7d9bef16902747d6435b8d`); proof tail (container field 4) mutates under append while the signed-block prefix does not; `revocation_ids` prefix-stable (`r0=b25052ce41f133ba…`). |
| **G-1.G′ append-detection** | yes | **PASS** | `H(P_n) = 7b1b962d10a8333d9c7212386ec12e4f7d57190bca7d9bef16902747d6435b8d`; adversarial post-hoc append from the token alone → `H(P_{n+1}) = b79d58cd5dd3b3dd33913fa3c4dfee17d0d831193420483c72a0c8917df0c380`; **different = True**. Negative control: `H(P_n)` recomputed after a round-trip of the *unmodified* token equals the signer-side value (True) — the identity function is neither always-equal nor always-different. **What this establishes:** an `INV` assertion binding `capability_hash = H(P_n)` will not match a capability that has been appended to, so a post-hoc append is detected and rejected without any need for seal. |
| G-1.A discovery/maintainability | info | PASS | §2: official, active (pushed the day of this gate), Eclipse-governed |
| G-1.H API stability | info | PASS | typed (`py.typed` + stubs), pinnable, full wheel coverage, no build toolchain needed |

`id(P_i)` = SHA-256 over the length-framed canonical `SignedBlock` bytes `0..i` extracted from
the container (fields 2, 3 in order; field 4 excluded) — the §A.0.1 rule implemented verbatim:
*hash the signed-block prefix, never the mutable proof tail.*

## 5. Outcome

**PASS.** All six mandatory checks (B, C, D, E, F, G′) pass; the spike exits zero. *G-1.G (seal
terminality) was replaced by G-1.G′ (append-detection) by author decision; see ADR 0002. Seal is
not used by this design:* further delegation is governed by the HTC chain, further attenuation is
harmless (monotone), and a post-hoc appended block is rejected by the `INV.capability_hash`
binding. IA-1 is **verified by gate G-1** for exactly `biscuit-python==0.4.0` and exactly what
ran (§F.4 updated).

## 6. Consequences for the design

- `biscuit-python==0.4.0` **pinned exactly** in `pyproject.toml` (Biscuit line removed from the
  `# PENDING GATE` block; `authlib`/DPoP lines remain — gates G-4/G-5 have not run). `uv.lock`
  regenerated. **No Dockerfile or CI change**: wheels cover every target platform, so no Rust
  toolchain enters the build.
- The §A.0.1 hashing rule needed **no refinement** — `H(P_i)` is implementable verbatim.
- Architecture-document edits applied (never silent; ADR 0002): D22 note "this design never
  seals" (Part B.2); Part G G-1 row criterion now F + G′ with seal explicitly not a criterion;
  §F.4 IA-1 status → verified-by-gate with residuals; §F.2 verification list gains the fail-fast
  HTC-count conjunct. `docs/threat_model.md` gains the append-induced-rejection availability
  residual.

## 7. Reproduction

```
uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py     # pre-pin form, works always
uv run python smoke/g1/spike.py                                  # after the ADR 0002 pin
make gate GATE=g1                                                # equivalent, via the venv
```

## 8. Residual risks

- `biscuit-python` is at **0.4.0 — a 0.x API**. The pin is exact; **any version bump requires
  re-running G-1.**
- `H(P_i)` is computed by parsing the Biscuit **wire format** (container fields 2 + 3, excluding
  the proof field 4), so it depends on the **format specification** (stable, versioned) rather
  than on the 0.x Python API. A **format** version change would require re-verification.
- Biscuit's format has had informal cryptographic review but is **not formally audited** (project
  FAQ). This is a disclosed limitation of the study, not a blocker for a measurement
  contribution.
- The library exposes no seal API. Recorded as an upstream contribution opportunity, deliberately
  not pursued now (off the critical path).

## 9. What this gate does NOT establish

- **Not** that the library can seal a token — it cannot, **and the design does not require it**
  (ADR 0002; D22 note).
- **Not** monotonicity (`C_i ⊆ C_{i−1}` under a frozen `Γ`) — that is **G-2**, blocked until `Γ`
  exists and is hashed.
- **Not** performance of signing/verification — that is **G-3**, whose threshold must be fixed
  externally before any timing.
- **Not** the frozen ontology `Ω` or authorizer `Γ` — the spike used a throwaway pilot
  vocabulary (`right("calendar", "read")`, `right("notes", "write")`), clearly marked NOT `Ω`.
- **Not** HTC/INV correctness (G-11), mediation (G-6), or the effect ledger (G-7). G-1.G′ is a
  hash-level assertion; HTC/INV are not implemented.
