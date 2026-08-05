# Gate G-4 Phase 2 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-29:

| File | SHA-256 |
|---|---|
| `G4_PHASE2_TASK.md` | `8cc768dc2f072716bfecd13ac3e0bbadfb9ef9c5f8243aabae2d57d937ac93e4` |

Chronology (2026-07-29, the same day as the ADR 0016 freeze and the G-2 run it depends on): Phase 2
implemented `smoke/g4/DESIGN.md` and ran gate **G-4**, which **PASSED over the criteria's
adjudicable limbs**. This was the project's **first real system code** — a network service with
state rather than a verification module — built at `src/sut/oauth_as/` per ADR 0015 with a
resource-server side at `src/sut/authz/boundary.py` that reimplements validation rather than sharing
it. **No new dependency was pinned**: the stdlib, `joserfc==1.7.4` and `cryptography` sufficed, and
`authlib` remains unpinned, so **IA-4 is discharged by its second limb** — "a behaviourally faithful
AS can be built" — the first limb having been refuted at Phase 1.

Limbs L1, L1′, L2, L3 and A1–A7 were exercised with the wrong outcome observable as a failure
throughout: widening refused in all four planes as an **error with no token issued** (asserted on the
*absence* of a token, since a silent clamp is the failure mode); L2 run over the **frozen `Ω`** with
no stand-in; 24 catalogue checks each asserting the exact code and status; and the **first real
exercise** of the two G-5 hand-forwards (`ath`, DPoP nonces) plus `htu` normalization. **Limb L4
(`INV.access_token_hash`) is NOT closed** — precondition only, scoped to a follow-on run after
**G-11**, so G-4 is **not** a full four-limb closure.

Three findings came from running rather than reading, and all are recorded in `smoke/g4/REPORT.md`
rather than quietly fixed: a **design gap** (no default-lifetime policy, which made hop 2 impossible
until the AS capped its *own* default at `exp_{i−1}` while keeping an *explicit* over-long request an
error); a **§8.2 fair-baseline defect** (dialling `localhost` resolved `::1` first and added ~0.7 s
to every exchange — the suite fell from 108.5 s to 2.69 s once the certificate carried a `127.0.0.1`
IP SAN), which would have inflated B2's reported overhead toward this study's own hypothesis; and a
**check the design states in prose but its numbered steps omit** — the delegating agent *is* the
client of the exchange. Five values the design left to "the Phase 2 ADR" are fixed in **ADR 0017**.
No `frozen_parameters` row was set; rows 1–7, 9 and 10 stay UNSET and row 8 with the frozen artifact
is byte-unchanged. Verified on Windows: `pre-commit` clean, spike exit 0 (twelve mandatory checks),
`183 passed` (the pre-existing 105 plus 78 new platform-independent tests).
