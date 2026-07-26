# 0014 — Windows is the sealed measurement platform; the POSIX ledger variant is deferred

## Context

Gate G-7 PASSed with an enforcement mechanism that is **platform-bound** `[VERIFIED, gate
G-7]`: the ledger file is held by a separate ledger process through a `CreateFileW` handle
opened with `dwShareMode = FILE_SHARE_READ` only, and while that handle lives every other open
for write, append, truncate, or delete fails at the OS level — from any process, immune to
attribute and `chmod` changes. That is a **Win32 sharing-semantics property with no direct
POSIX equivalent**: POSIX advisory locks bind only cooperating processes and do not stop an
uncooperative writer, so the same construction cannot be ported by translation.
`LedgerWriter.__init__` therefore raises on any non-Windows platform, which makes the six
tests in `tests/test_effect_ledger.py` fail hard on `ubuntu-latest` and `smoke/g7/spike.py`
exit 1 there — CI is red, and a third party cannot re-verify G-7 by cloning on Linux. This ADR
records the Commander's adjudication (option 丙) of that tension. Precedent for a decision
that changes scheduling/scope without changing criteria: ADR 0008.

## Decision

[DESIGN] **The confirmatory campaign runs on Windows; the sealed environment includes the
operating system.** This is a **scope statement, not a claim that the design requires
Windows**: the design requires an effect ledger whose independence is OS-enforced (§F.1, IA-7);
Windows is where that enforcement is implemented and verified today.

**Why the alternative was rejected** [DESIGN]. A POSIX fallback with weaker enforcement
(advisory locks, permissions, append-only attributes — all defeatable by or negotiable with a
same-account writer) would make the **independence property differ by platform**, so a result
measured on one OS would not be comparable to the same run on another. A **silent** fallback —
`LedgerWriter` degrading to an unenforced file on non-Windows — is prohibited outright: it
would leave every downstream conclusion resting on a file any SUT code could rewrite, the one
outcome worse than a red CI. The non-Windows path keeps **raising**.

**The three costs, accepted knowingly** (schedule: 11 September submission), not overlooked:

1. **Third parties cannot re-verify G-7 by cloning on Linux or macOS.** The five G-7 checks
   run only on Windows; on other platforms the suite skips with a reason naming this ADR, and
   the spike refuses to run rather than appearing to pass.
2. **Artifact evaluation for a future conference submission will most likely run on Linux.**
   The deferred obligation below exists precisely for this.
3. **The seal is bound to one OS.** Part H's sealed environment therefore names the operating
   system and its exact version/build alongside the pinned dependencies and lockfile
   (`docs/frozen_parameters.md` row 9, UNSET until seal time).

**The deferred obligation** [DESIGN]. A POSIX ledger variant is planned **after submission and
before any artifact-evaluated conference version**. Re-running the **five G-7 checks** under
that variant is a **precondition** for claiming cross-platform independence. Until then, **no
cross-platform claim may appear anywhere** — not in the dissertation, not in this repository,
not in a paper.

**The live-handle limitation, promoted from footnote to decision** `[VERIFIED, gate G-7
report]`. Immutability holds **only while the writer process holds the handle**; after
`writer.close()` the file is an ordinary appendable artifact (the spike's closing control
demonstrates this). Post-campaign tamper-evidence therefore rests on the **Part H seal** —
content hashes, the detached manifest, and the public temporal anchor — **not** on the ledger
mechanism. The two properties have **different guarantors**: campaign-time integrity is
guaranteed by the live exclusive handle (G-7); post-campaign integrity is guaranteed by the
seal (Part H). Neither may be cited for the other.

## Status

accepted — 2026-07-26

## Consequences

- `tests/test_effect_ledger.py` gains a module-level platform skip whose reason names this
  ADR (a reader seeing the skip sees a recorded decision, not a gap); the six tests run
  unchanged on Windows. `smoke/g7/spike.py` gains a guard that prints the platform and exits
  non-zero on non-Windows — the gate never appears to pass where its mechanism does not
  exist. CI (`ubuntu-latest`) is green again with the ledger tests **skipped, not failed**;
  the runner, steps, and Python version are unchanged.
- Part H's sealed-environment description and `docs/frozen_parameters.md` (new row, UNSET)
  carry the platform; §J records the validity-threat entry; §F.4 IA-7's residual points here.
- G-6/G-7 PASS records, reports, and criteria are unchanged; this ADR re-adjudicates nothing.
- The README states the platform scope so a green CI badge is never read as a Linux
  verification of the ledger.
