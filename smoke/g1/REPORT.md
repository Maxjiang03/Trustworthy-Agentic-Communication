# Gate G-1 Report — Python Biscuit library

## 1. Gate

- **Gate:** G-1 (feasibility spike, first tier of the Part G DAG: `G-1 / G-5 / G-8 → …`)
- **Assumption tested:** IA-1 — *"The chosen Python Biscuit library exists, is maintainable, and
  exposes append-block attenuation + root-public-key verification with a stable API"*
  (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4), plus the expanded criteria G-1.F (stable prefix
  identity, §A.0.1 hashing rule) and G-1.G (seal terminality, D22) required by `SMOKE_G1_TASK.md`.
- **Date:** 2026-07-14
- **Blocks on failure:** the whole capability track (B-cap, B3, B3⁺).

## 2. Library discovery (STEP 3)

| Candidate | Verdict |
|---|---|
| **`biscuit-python`** | **Chosen.** Official Python bindings for the reference Rust implementation (PyO3/maturin wrapper of `biscuit-rust`; 0.4.0 wraps biscuit-rust 6.0.0 per its CHANGELOG). Latest 0.4.0, released 2025-09-26; 7 stable releases since 2023-06. Repo `eclipse-biscuit/biscuit-python` (project moved from the `biscuit-auth` org into the Eclipse Foundation; the old URL redirects). Repo pushed 2026-07-14 (the day of this gate); `biscuit-rust` pushed 2026-07-13 — the ecosystem is actively maintained. Typed API (`py.typed` + `__init__.pyi`). Pre-built wheels for CPython 3.9–3.13 on manylinux/musllinux/macOS/Windows and an sdist — **no Rust toolchain needed at install time** on any platform this project targets (Windows dev box, Ubuntu CI, `python:3.11-slim` Docker). |
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
| **Seal (terminal)** | **NOT EXPOSED** — no `seal` on `Biscuit` or `UnverifiedBiscuit` (runtime introspection of every class); no wrapper in upstream `src/lib.rs`; absent from `biscuit_auth.pyi`; no upstream issue even requests it. The underlying `biscuit-rust` implements sealing, but it is not callable from Python. |

## 4. Results

Run: `uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py` (exit code 1).
Token bytes legitimately differ between runs (single-use block keypairs); all identities below are
within-run comparisons.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-1.B mint | yes | **PASS** | `P_0` minted: `block_count=1`, 194 bytes, pilot facts present in block 0 |
| G-1.C offline append | yes | **PASS** | `P_0 → P_1` inside a function that receives only token bytes + `κ_pub`; the root private key never leaves the minting function's frame (enforced structurally). `block_count 1 → 2`. |
| G-1.D κ_pub-only verification | yes | **PASS** | Chain verifies with only the root **public** key; no authorizer, no policies. Wrong root key rejected with `BiscuitValidationError`. |
| G-1.E round-trip | yes | **PASS** | serialize → deserialize → verify; block count preserved; re-serialization **byte-identical** |
| G-1.F stable prefix identity | yes | **PASS** | `id(P_0)_before = 32ebafa84c247c2824abda62b684e9b10ed4f831425c19e1552fe1caf385e97d`; `id(P_0)_after` (re-derived from the `P_1` token) = **same value**; signer-side and verifier-side `id(P_1)` agree (`534f2867a2887be3ef4a60b5baffdef68f59e55c399060b7f03cd3237c78f2df`); proof tail (container field 4) **mutates** under append while the signed-block prefix does not. Corroboration: `revocation_ids` are prefix-stable under append. |
| G-1.G seal terminality | yes | **FAIL — NOT EXPOSED** | No seal API exists in biscuit-python 0.4.0 (evidence in §3). "Seal, then append must fail" cannot be exercised from Python. |
| G-1.A discovery/maintainability | info | PASS | §2: official, active (pushed the day of this gate), Eclipse-governed |
| G-1.H API stability | info | PASS | typed (`py.typed` + stubs), pinnable, full wheel coverage, no build toolchain needed |

`id(P_i)` here = SHA-256 over the length-framed canonical `SignedBlock` bytes `0..i` extracted
from the container (fields 2, 3 in order; field 4 excluded) — i.e. the §A.0.1 rule implemented
verbatim: *hash the signed-block prefix, never the mutable proof tail.*

## 5. Outcome

**FAIL** — by the SMOKE_G1_TASK STEP 6 taxonomy, because mandatory check G-1.G cannot pass:
the binding does not expose seal. Five of six mandatory checks pass, including the make-or-break
G-1.F. The failure is **narrow and specific**: the only missing capability is the terminal seal
operation. No fallback is implemented; per STEP 6 the fallback choice rests with the author
(ADR 0002 records the options).

## 6. Consequences for the design

- **What is now verified-by-gate (for exactly what was tested, nothing more):** offline
  append-per-hop attenuation, root-public-key-only chain verification, wire round-trip, and a
  stable, append-invariant, signer/verifier-consistent prefix identity `H(P_i)` per §A.0.1 — the
  property the entire HTC/INV binding (`parent_prefix_hash`, `child_block_hash`,
  `capability_hash`) rests on. **IA-1 remains formally `[UNVERIFIED-IA]`** because the gate did
  not pass in full; no architecture-document edit is made on the FAIL branch.
- **What the missing seal touches in the architecture:** §A.0.1 (the proof-tail definition
  already covers the unsealed case: "the trailing single-use secret **or** final seal
  signature"), D22 ("append per hop, seal only terminally" — remains a `[VERIFIED]` fact about
  the Biscuit design; what fails is *exercising* seal from this binding), §F.4 `[VERIFIED]`
  facts list (same phrase), Part G G-1 row. **Observation (analysis, not a decision):** no
  baseline flow in Part C/E ever *executes* seal — B-cap/B3 append per hop and INV binds
  `capability_hash = H(P_n)`, so a post-INV append changes `H(P_{n+1})` and the INV binding
  itself rejects it at the boundary; seal is defence-in-depth for the capability in transit, not
  the mechanism any hypothesis depends on. Whether that residual is acceptable is the author's
  call (ADR 0002, options).
- **If the author triggers a fallback instead** (Rust FFI / Macaroons): §C credential-flow
  table, the trust model (Macaroons lose the root-public-key property), the Dockerfile/CI
  (Rust toolchain), and the G-1 row would all change — detailed in ADR 0002.

## 7. Reproduction

```
uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py
```

The library is deliberately **not** pinned in `pyproject.toml` (STEP 8 forbids pinning on FAIL);
the `# PENDING GATE` block is unchanged.

## 8. What this gate does NOT establish

- **Not** monotonicity (`C_i ⊆ C_{i−1}` under a frozen `Γ`) — that is **G-2**, blocked until `Γ`
  exists and is hashed.
- **Not** performance of signing/verification — that is **G-3**, whose threshold must be fixed
  externally before any timing.
- **Not** the frozen ontology `Ω` or authorizer `Γ` — the spike used a throwaway pilot
  vocabulary (`right("calendar", "read")`, `right("notes", "write")`), clearly marked NOT `Ω`.
- **Not** HTC/INV correctness (G-11), mediation (G-6), or the effect ledger (G-7).
- IA-1 is **not** converted to a verified fact: the gate FAILED; the per-capability statuses
  above hold only for exactly what ran.
