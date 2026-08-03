# The five platform-bound gates, re-measured on the row 9 machine

**Every figure below was measured at commit `7b59e19`, on 2026-08-03.**

**This is a regression confirmation, not a re-adjudication.** The verdicts already exist and were
adjudicated at earlier commits; this run establishes that they still hold after `src/harness/`
changed three times. **No `smoke/*/REPORT.md` was edited and no code, test, ADR or frozen row
changed** — `git status` over `smoke/ docs/ src/ tests/ adr/ analysis/` is empty. Deliberately not
under `smoke/`: there a `REPORT.md` is an adjudication, and this is not one.

Why these five: `src/harness/` changed, and **G-10's criterion carries the conjunct *every prior DAG
gate passed***, so that conjunct stopped being derivable from the board. Ten gates were confirmed
off-platform by the verifier at this HEAD (G-1, G-2, G-4, G-5, G-8, G-9, G-11, G-13, G-14, G-15);
these five can only be adjudicated here — G-3 because ADR 0025 binds it to row 9, G-6/G-7/G-12
because Win32 share-mode locking does not exist off Windows and ADR 0014 says the ledger does not
degrade, and G-10 because its `EffectEvent` limb needs the real ledger.

Order run: **G-3 → G-6 → G-7 → G-12 → G-10 → the suite**, with G-3 first on an idle machine, alone.
Raw logs, complete stdout and stderr, in `logs/`.

---

## 1. The machine, read before and after

| field | frozen row 9 | before | after |
|---|---|:--:|:--:|
| OS build | `26200.8875`, 25H2 | ✅ `26200.8875` / 25H2 | ✅ |
| CPU | i7-12700H | ✅ `12th Gen Intel(R) Core(TM) i7-12700H` | ✅ |
| topology | 14C/20T (12P/8E logical) | ✅ 14/20, P=`[0..11]`, E=`[12..19]` | ✅ |
| memory | 15.75 GiB DDR4 | ✅ `16911523840` B, DDR4 | ✅ |
| power scheme | `da75b896-eea0-461c-a43a-73a73caf9f43` (High performance) | ✅ same GUID | ✅ |
| on AC | yes | ✅ `true` | ✅ |

**Every row 9 fact matches.** The power-scheme *name* reads `高性能` rather than `High performance`
because the machine is localised — the same localisation already recorded when row 9 was locked. The
**GUID** is the identity and it is identical.

Hazard state, unchanged from the row 9 record: sleep on AC `600` s (not off, reported as found and
**not changed**), hibernate `0` (never), USB selective suspend `1`.

**Windows Update state**, read without triggering a scan: no reboot pending
(`WindowsUpdate\RebootRequired` and `Component Based Servicing\RebootPending` both absent); latest
hotfixes KB5101650 / KB5100998 (2026-07-23) and KB5120102 (2026-07-15), all **predating** the row 9
lock of 2026-08-02. **No update has landed since row 9 was locked.**

**After the last gate**: all 16 machine-read fields compared field by field, **zero changed**, and
the identity string is byte-identical. *The machine did not change* is measured here, not asserted.

---

## 2. G-3 — and the one difference this run found

**PASS.** But the numbers are not the recorded ones, and that is reported rather than absorbed.

| | recorded (`smoke/g3/REPORT.md`) | today | difference |
|---|:--:|:--:|:--:|
| median | **2.8264 ms** | **2.6928 ms** | **−0.1336 ms (−4.7 %)** |
| IQR | 0.2898 ms | 0.2641 ms | −0.0257 ms |
| batch 1 | 2.9190 | 2.6710 | −0.2480 |
| batch 2 | 2.8259 | **3.0324** | **+0.2065** |
| batch 3 | 2.8213 | 2.6574 | −0.1639 |
| batch 4 | 2.7511 | 2.6658 | −0.0853 |
| drift (last vs first) | −5.8 % | −0.2 % | — |
| p95 | 3.4841 ms | 3.3852 ms | — |

Both medians pass the ADR 0025 threshold of 5 ms — headroom **1.86×** today against **1.77×**
recorded. Every mandatory limb passed: `G-3.H1` (pinned to the *detected* performance cores
`[0..11]`, mask read from `GetSystemCpuSetInformation`), `G-3.H2` (on AC), `G-3.C`, `G-3.T`.

**What this is and is not.** The shift is about **half an IQR**, and today's batch 2 (3.0324) is
*higher* than every recorded batch median, so the two runs' spreads overlap substantially. Nothing
about the verdict changes. **But the dissertation cites a specific number, and which figure is the
record is the Commander's call — this run does not decide it and `smoke/g3/REPORT.md` is untouched.**

Run once. Not re-run for a better number.

---

## 3. The three ledger gates

| gate | verdict | evidence |
|---|:--:|---|
| **G-6** | **PASS — 5/5** | Every enumerated bypass path mediated or blocked: C1 `FastMCP.call_tool`, C2 `ToolManager.call_tool`, C3 `Tool.run`, C4 `tool.fn` direct, C5 post-install `add_tool`, C6 direct registry insertion, C7 `request_handlers` direct, C8 denied via `ToolManager`, C9 no `__wrapped__`/unmediated fn in registry. Non-vacuity limb `G-6.D`: interposition removed → tool reached, **zero** events |
| **G-7** | **PASS — 5/5** | SUT cannot append, truncate, binary-append, delete, or append post-`chmod`; in-place `r+b` → `PermissionError` with bytes unchanged; the ledger detects the SUT lying (`self_report=blocked`, `ledger_effects=1`); denied call → **zero** new entries. Control: the file *is* appendable after `writer.close()`, so the immutability came from the live exclusive handle and not from an attribute |
| **G-12** | **PASS — 9/9** | `L1`, `L1.W1`, `L2`, `L2.W1`, `L3`, `L4`, `L4.C`, `L5`, `L5.C` |

**G-12's ledger limbs ADJUDICATED here — they did not print NOT ADJUDICATED.** Zero occurrences of
that string in the log. This is precisely why the gate needed this machine: off-platform its
ledger-backed limbs decline rather than pass, and a Windows-only property must never be laundered
into a green Linux tick. `L4.C` drove four scenarios concurrently, **each in its own SUT child
process**, with four distinct correlation ids, every linkage `CONSISTENT`, and no invocation's ledger
holding another's effect.

---

## 4. G-10 — and the fourteen, by name

**PASS. `G-10.L1`, `L2`, `L3`, `L3.N`, `L4`, `L5.1`, `L5.2` — all mandatory, all pass.**

`G-10.L4` re-runs every prior DAG gate as a subprocess. That enumeration **is** the conjunct this
task exists to re-establish:

| | | | | | | |
|---|---|---|---|---|---|---|
| g1 **PASS** | g2 **PASS** | g3 **PASS** | g4 **PASS** | g5 **PASS** | g6 **PASS** | g7 **PASS** |
| g8 **PASS** | g9 **PASS** | g11 **PASS** | g12 **PASS** | g13 **PASS** | g14 **PASS** | g15 **PASS** |

**14 of 14. Failed: none.**

### The anticipated failure did not occur

`L4` re-runs the **G-3 spike on a machine this very run has just heated**, and G-3's real headroom is
1.77–1.86×, not the three- to tenfold its ADR's prose argued. The warm re-measurement **passed** —
i.e. it stayed under the 5 ms threshold.

**A limitation of that evidence, stated rather than glossed:** `L4` records each subprocess's
pass/fail and **not its median**, so the warm G-3 figure is not captured anywhere and cannot be
quoted. The honest claim is *the warm re-run passed*, nothing more precise. G-3 was **not** re-run to
obtain the number — that is exactly the re-running-for-a-better-figure this task forbids.

---

## 5. The suite, on this platform

**1297 passed / 0 failed / 0 skipped**, measured today at `7b59e19` on the row 9 machine.

Consistent with the verifier's Linux measurement of 1275 passed / 22 skipped: the 22 skips are the
Win32-only ledger tests, which run here.

---

## 6. Files written

`tools/gate_rerun/REPORT.md` and `tools/gate_rerun/logs/` — eight files, complete stdout and stderr,
short enough to keep in full:

```
00-platform-before.log   01-g3.log   02-g6.log   03-g7.log
04-g12.log               05-g10.log  06-suite.log  07-platform-after.log
```

**Nothing else was written or modified.** No `smoke/*/REPORT.md`, no code, no test, no ADR, no frozen
row. No verdict was moved; every verdict here confirms one that already existed.

---

## Findings for the Commander

1. **G-3's median today is 2.6928 ms against the recorded 2.8264 ms** (−4.7 %). Both pass; the
   dissertation cites one of them. Not absorbed, not adjudicated here.
2. **G-10's `L4` does not capture the warm G-3 median**, only its pass/fail — so the question the
   ordering was designed to answer ("how much does thermal state move this number?") is answered only
   as *not past the threshold*.
