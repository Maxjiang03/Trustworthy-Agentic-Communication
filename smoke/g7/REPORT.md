# Gate G-7 Report — independent effect ledger and ingress recorder

## 1. Gate

- **Gate:** G-7 (construct-validity tier of the Part G DAG: `G-1 / G-5 / G-8 → G-6 / G-7 → …`)
- **Assumption tested:** IA-7 — *"An immutable external effect ledger + `ToolIngressEvent`
  recorder can be interposed at the tool, independent of agent self-report"*
  (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4). Pass criterion (Part G): both recorded
  independently of any SUT self-report; `correlation_id` matches the harness-minted value.
  The load-bearing word is **independent**.
- **Date:** 2026-07-26.
- **Blocks on failure:** IA-7; the independent oracle and every F-predicate (Part I) — the
  core of construct validity.

## 2. The architectural tension and the mechanism that resolves it

The recorder must sit **at the tool**, yet `src/sut/` may not import harness code (CLAUDE.md
red line 6). Resolution: the recorder and the effector interface are **installed by the
harness** at server-build time (the same wrap-at-fn discipline as G-6), and the ledger itself
is held by a **separate ledger process** — the SUT neither imports harness code nor can reach
the ledger by any route:

- **Exclusive-share file handle.** The ledger process opens the file via Win32 `CreateFileW`
  with `dwShareMode = FILE_SHARE_READ` (read sharing only). While that handle lives, **every**
  other open for write/append/truncate/delete fails at the OS level with a sharing violation —
  from any process, including the harness process itself, and **regardless of file
  attributes** (`chmod` does not defeat a share mode). Reads are allowed.
- **Append-only channel.** The child appends validated JSON lines received on stdin
  (`O_APPEND` CRT handle; `fsync` per record; ack per record) and can do nothing else; its
  stdin/stdout pipes are held by the harness-side `LedgerWriter` — the **only** write path.
- **Trust argument (D21, §F.1).** The SUT is handed neither the `LedgerWriter` nor the pipes;
  every filesystem route is closed by the share mode; the recorder/effector that do append are
  harness-installed closures at the tool. Remaining residual: in-process Python object
  reachability inside the harness process — excluded architecturally (the SUT never executes
  in the harness/tool-server process) and stressed adversarially at G-12. Enforcement is
  **Windows-only in this pass** (the dev/measurement box); a POSIX variant is a disclosed
  residual, not built speculatively.

The spike's closing control makes the mechanism visible: after `writer.close()` the file is an
ordinary appendable artifact — the immutability came from the **live exclusive handle**, not
from an attribute or a hidden property of the path.

## 3. Results

Passing run: `uv run python smoke/g7/spike.py` → **exit code 0** (5/5); ledger files created
only inside the repo tree (`smoke/g7/_ledger_tmp/`, removed on exit). Permanent suite
`tests/test_effect_ledger.py`: **6 tests, 6 passed**, positive and negative arms.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-7.A ingress + effect, correlation intact | yes | **PASS** | one admitted call through the G-6 boundary → exactly one `ToolIngressEvent` **and** one `EffectEvent` in the ledger, both carrying the harness-minted 128-bit `correlation_id` unchanged; `ingress_request_digest == effect_request_digest == H_JCS(arguments)` (ADR 0012, recorder-side) |
| G-7.B SUT cannot write/amend/delete | yes | **PASS** | demonstrated by attempting: `open('a')`, `open('w')`, `open('ab')`, `os.remove` → `PermissionError` (sharing violation, winerror 32 on delete); **post-`chmod 0o666` append still fails** (attribute-proof); positive arm: `writer.append` still works — the enforcement mechanism is stated (exclusive share mode), not asserted |
| G-7.C immutability in place | yes | **PASS** | `open('r+b')` → `PermissionError`; ledger bytes byte-identical before/after the attempt |
| G-7.D records survive SUT lying | yes | **PASS** | SUT self-reports `"blocked"` while the tool actually executed → the ledger still shows the `EffectEvent`; the lie is detected from the ledger **alone** (no SUT verdict read) — the property the independent-oracle design rests on (G-12 stresses it further) |
| G-7.E non-vacuity | yes | **PASS** | a denied call (G-6 boundary, outermost) produces **zero** new ledger entries — no ingress, no effect — while the boundary's `admitted=False` event shows the pipeline was live |

## 4. `ingress_request_digest` settled (ADR 0012)

ADR 0009's G-7 deferral is closed: the field adopts **`H_JCS`** (required, since it exists to
be compared against the `H_JCS`-governed `intended_request_digest`/`effect_request_digest`),
computed **recorder-side** over the arguments mapping the tool is invoked with (excluding the
SDK context parameter) — the **same object domain** as `intended_request_digest`; equality is
the benign case, divergence is the F3 signal. Full statement and the SDK-normalization caveat:
`adr/0012-ingress-digest-construction.md`.

## 5. Outcome

**PASS** — all five mandatory checks and all six regression tests green; ledger + recorder
graduated to `src/harness/effect_ledger.py`; `mcp==1.28.1` pin shared with G-6 (ADR 0013).

## 6. Consequences for the design

- §F.4 IA-7 → verified-by-gate with residuals; smoke board G-7 → PASS (same pass).
- The oracle can now read a trusted, SUT-independent record stream; G-12's fault-injection
  design builds directly on G-7.D.
- Arms must install the recorder **before** the boundary (mediation outermost) via the
  harness installers; effects are recorded by harness-constructed effectors handed to tools.

## 7. Reproduction

```
uv run python smoke/g7/spike.py                 # after the ADR 0013 pin
make gate GATE=g7                               # equivalent, via the venv
uv run pytest tests/test_effect_ledger.py -q
```

## 8. Residual risks

- **Windows-only enforcement** in this pass (Win32 share modes; `msvcrt`/`ctypes` in the
  child). The measurement box is Windows; a POSIX variant (separate process + `O_APPEND` +
  advisory locking or an append-only service) is deferred and disclosed.
- In-process Python reachability inside the harness process is excluded by architecture
  (SUT process separation), not by the OS mechanism; **G-12** injects adversarial reporting
  and correlation faults against exactly this surface.
- The ledger validates only that records are JSON objects carrying a `correlation_id`; record
  *semantics* (who may claim which principal, digest correctness) are oracle territory
  (Part I) — deliberately not enforced at the channel.
- Single-machine scope: no crash-durability claim beyond per-record `fsync`, no distributed
  ledger; adequate for the sealed single-campaign design (Part H).

## 9. What this gate does NOT establish

- **Not** oracle correctness — the Part I predicates are not implemented here; this gate only
  provides the trusted record stream they will read.
- **Not** fault detection under adversarial correlation swap/drop/duplicate/concurrency —
  that is **G-12**.
- **Not** anything about the arms: no baseline, no capability logic, no HTC/INV, no OAuth.
- **Not** the F4 label plumbing: `payload_digest`/`value_id` are carried as `None`; their
  construction stays deferred (ADR 0009 → F4 label-plumbing decision / G-15).
- **Not** POSIX enforcement, crash recovery, or any performance property (G-3).
