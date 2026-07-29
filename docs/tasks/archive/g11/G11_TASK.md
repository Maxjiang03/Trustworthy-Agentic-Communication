# TASK — Gate G-11: build the HTC/INV verifier, run the mutation suite, and close two G-4 residuals

G-11 is the gate that makes holder binding real. §F.2 already specifies both objects completely —
every field, every domain tag, the full MUST-list of verification conditions, and the zero-hop rule.
**This pass implements that specification and adjudicates the mutation suite.**

It also closes two things G-4 deliberately left open, because G-11 is where the design says they
belong:

- **C2 / limb L4** — `INV.access_token_hash` has no fixed construction. ADR 0009 puts it in
  category (c), *"fixed when INV/HTC are built and mutation-tested (G-11)"*. `smoke/g4/DESIGN.md`
  §9 C2 carries a **proposal** and forbids treating it as settled. This pass adjudicates it.
- **C3** — the identity-plane registry does not exist, so G-4's `actor→holder` limb ran on a
  spike-local stand-in. §F.2.1 specifies the registry; this pass builds and freezes it, which
  re-triggers that G-4 limb.

What rides on the gate, in the Part G row's own words: **IA (HTC correctness); H4a.** If a mutation
that should be rejected is accepted, the holder-binding claim has no floor.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the
launch prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Editing G-11's or G-4's pass criteria, dependency edges, evidence grades, or any Part G row | Gates execute frozen criteria |
| 2 | Modifying `src/harness/authorizer/omega_gamma_v1.json`, `frozen_config.py`, `Γ`, `Ω`, or `H(Γ)`; changing `frozen_parameters.md` row 8 | ADR 0016 froze it. A defect found here → STOP, corrective ADR |
| 3 | Reusing `H_JCS`, `ath`, or the §A.0.1 capability tag as the `access_token_hash` construction, or introducing a tag already in use | §F.2's domain-separation MUST, and DESIGN §9 C2's confirmed trap: `ath` is base64url over an ASCII **string**, `H_JCS` is lowercase hex over canonical **JSON** bytes. Three digests over the same token must never be confusable |
| 4 | Weakening any §F.2 verification condition, or adding a code path for the `n = 0` case | §F.2: the zero-hop rule is the general verification with a one-element chain — **no separate code path** |
| 5 | Letting the harness/oracle consume a SUT-computed digest, or sharing a digest implementation across the boundary | D13/D21, §F.1; the discipline ADR 0009 already applies to `H_JCS` |
| 6 | Implementing G-3's timing/equivalence-margin work (IA-3), G-13's `Allowed(AT_i) = C_i`, the F4/F5 reference monitor (G-15), the DPoP taxonomy (G-14), the approval-artifact **arm**, or any arm/agent/adapter | Non-goals; each is owned elsewhere. IA-3 explicitly stays `[UNVERIFIED-IA]` for G-3 |
| 7 | Setting `frozen_parameters.md` rows 1–7, 9, 10, or the `task_authorization_policy` | Only the registry is frozen here (STEP 6); the `may_act`/F2 policy stays UNSET and F2 `wrong_principal` stays unscored |
| 8 | Marking G-11 or the G-4 follow-on PASS if any mutation was not genuinely exercised | STEP 8 |
| 9 | `git push --force`, history rewrite, credentials in the repo | CLAUDE.md red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read the specification you are implementing

Read and confirm: **§F.2 in full** — the HTC₀ / HTCᵢ / INV templates field by field, the domain
tags `"AASC-HTC-v1"` / `"AASC-INV-v1"`, the `H_JCS` paragraph, the **zero-hop rule**, the complete
**Verification (MUST all hold)** list including `check_htc_coverage` and the HTC-count-equals-block-count
rule, and *"Why HTC is separate from Biscuit"* `[VERIFIED]`. Then **§F.2.1** (the registry:
`actor_of(·)` → exactly one principal → exactly one `htc_holder` key; unmapped rejected;
`resource_owner` recorded but **not** part of the holder mapping). Then **§F.3** (INV-1..3),
**§A.0.1 / ADR 0003** (`BlockID_i`, `commit_prefix`, `capability_commitment`), **ADR 0009**
(the digest family, the tag rules, and the category-(c) classification of `access_token_hash`),
**ADR 0002** (the Biscuit profile), the **Part G G-11 row verbatim**, and `smoke/g4/DESIGN.md` §9
**C2 and C3** plus §10 rows **L3** and **L4**.

Report which parts turn out to be **underspecified for implementation**, if any, and what you did —
STEP 9 item 2. G-4 Phase 2 found seven such points; do not assume this specification has none, and
do not invent to cover one.

---

## STEP 3 — Adjudicate the `access_token_hash` construction

This is a **decision**, recorded in an ADR — the pattern ADR 0016 used for `Ω`. The DESIGN §9 C2
proposal is `lowercase_hex( SHA-256( b"AASC-AT-DIGEST" ‖ 0x01 ‖ u32be(len(t)) ‖ t ) )` over the
ASCII token bytes. Adjudicate it: adopt, or reject with a reason and a replacement in the same
family.

Requirements either way:

- Same tagged, versioned, length-delimited family as ADR 0003/0009; **its own domain tag**,
  distinct from every tag in use; **fail closed** on an unsupported version; no algorithm byte.
- State the input precisely: which bytes are hashed (the compact serialization as presented,
  ASCII), and what happens to a non-ASCII byte.
- Give a **worked example** — input token string, the digest, plus `ath` and `H_JCS` over the *same*
  token as **non-vacuity evidence** that the three are mutually distinct, exactly as ADR 0016 did
  for `H(Γ)`.
- A test asserting all three differ, and that the construction rejects an unsupported version.

Record in the ADR that this closes ADR 0009's category (c) for this field and that it closes
`smoke/g4/DESIGN.md` §9 C2 — with a dated update note there, not a rewrite (the treatment used at
G-2 and G-4).

---

## STEP 4 — Build the HTC/INV verifier

Implement §F.2 exactly. Where it lives matters: the **verifier is the instrument** (`src/harness/`),
and any SUT-side production of these objects must compute its digests **independently** (D21). State
your placement and how the independence holds.

- **Signing and domain separation.** Every signature over `tag ‖ version ‖ …` per §F.2; Ed25519;
  `kid` selecting the signer from the registry. An HTC byte string presented as an INV **MUST** fail
  — that is a named mutation (domain-tag confusion), so the tags must be load-bearing, not cosmetic.
- **The full MUST-list.** Every condition in §F.2's verification paragraph, each as a separate
  named check with its own reason code, so a rejection says *which* condition failed. Include the
  HTC-count-equals-presented-signed-blocks rule and `check_htc_coverage`.
- **Chain linkage.** `HTC_i.signer_pubkey == HTC_{i−1}.next_holder_pubkey`; `task_id`/`audience`
  invariant; `depth` contiguous from 0; `exp` non-increasing; `nbf ≤ now ≤ exp` at every hop;
  `prefix_hash`/`child_block_hash` matching the presented `P_{i−1}`/`SignedBlock_i`.
- **Commitment reuse, not reinvention.** `prefix_hash`, `child_block_hash` and
  `INV.capability_hash` **MUST** come from the existing ADR 0003 `commitment.py` — the construction
  G-1 verified and G-2 used. Do not introduce a second notion of the prefix.
- **Zero-hop.** `n = 0` must flow through the same code as `n = 2`; assert in a test that no
  branch keys on `n == 0`.

---

## STEP 5 — Run the mutation suite

Write `smoke/g11/spike.py` in the established shape (`RESULTS` table of
`(check, mandatory, passed, evidence)`, explicit exit code, no state leaking). Each mutation must be
constructed so the **wrong** outcome is observable as a failure — the discipline G-2 and G-4 applied.

**The eight HTC mutations, each rejected, each with the failing world stated:** wrong-signer;
parent-swap; child-swap; depth-rollback; capability-swap; terminal-key-mismatch; **domain-tag
confusion (HTC bytes replayed as INV)**; expired / `nbf`-violating cert.

**The six commitment-layer mutations, re-tested through the full verifier:** block reordering;
truncation; container re-encoding; missing HTC coverage; unsupported commitment version;
unsupported algorithm. The row is explicit that these are already `[VERIFIED]` at the commitment
layer by the ADR 0003 regression suite (tests 1–8), and that **G-11 proper re-tests them through
the HTC/INV verifier**. Report both facts: what the commitment layer already established, and that
the verifier path rejects each too. Do not present a re-test as a first verification.

**And the positive arms, without which the suite proves nothing:** the valid chain passes,
**including the `n = 0` zero-hop case** — the row names it explicitly.

For each mutation the report gives: what was mutated, the rejection and its **reason code**, and
what the failing world would have been. A rejection for an unrelated reason is a masked check, not
a pass — G-4 Phase 2 hit exactly this and rebuilt the probes; do the same.

---

## STEP 6 — Build and freeze the identity-plane registry (closes C3)

Implement §F.2.1: `actor_of(·)` → exactly one principal; principal → exactly one `htc_holder`
public key; unmapped actors **and** unmapped keys rejected; `resource_owner` subjects recorded but
**not** part of the holder mapping.

Freeze it as an artifact and hash it, in the same family and with its **own** domain tag, following
what ADR 0016 did for `Ω`/`Γ`: a derivation table with a **necessity column** per entry citing the
requirement that forces it, the string encoding fixed, and the amendment rule (amendable by a later
ADR until Part H step 3; any amendment re-triggers the gates that consumed it).

Boundary, stated and checked: the registry is the **actor→holder mapping**. It is **not** the
`task_authorization_policy` (task → authorized actor principals), which stays UNSET, so F2
`wrong_principal` stays unscored and the `may_act` stand-in stays a stand-in. Confirm in the report
that you did not cross this line. §F.2.1 lists the registry among the artifacts frozen before
sealing — add or set only its own row in `frozen_parameters.md`; every other row is untouched.

---

## STEP 7 — Close G-4's residuals

With STEP 3 and STEP 6 done, both G-4 residuals become adjudicable:

- **L4** — run `smoke/g4/DESIGN.md` §10's L4 properly: `INV.access_token_hash == H(presented AT@aud)`
  verified through the real verifier, with a swapped token rejected. G-4's PASS was explicitly
  *"not a full four-limb closure"*; this is what closes it.
- **L3** — re-run the `actor→holder` limb against the **frozen** registry instead of the C3
  stand-in, and confirm the negative test still holds: the profile never requires
  `resource_owner = holder` (§A.5.1 MUST NOT).

Update G-4's board row, §F.4 IA-4, and `smoke/g4/REPORT.md` to reflect the closure — **stating what
changed and by which gate**, and keeping the original text with a dated note where it was true when
written. Do not restate G-4's PASS as if it had always been complete; the record must show the
sequence.

---

## STEP 8 — Adjudicate honestly

Mark G-11 **PASS** only if all fourteen mutations are rejected for the **right** reason and both
positive arms (valid chain, `n = 0`) pass. If any cannot be honestly adjudicated — or if
implementing §F.2 exposes a genuine specification defect — **do not mark PASS**: report which, why,
and the smallest correction. That is the precedent G-4 Phase 1 set and G-2 and G-4 Phase 2 honoured.

On PASS: update `smoke/README.md`'s G-11 row and the IA cell for HTC correctness with their scope
and residuals; note that **IA-3 stays `[UNVERIFIED-IA]` for G-3** — this gate establishes
correctness, not that verification fits under the equivalence margin. Write `smoke/g11/REPORT.md` in
the established shape, and state plainly what G-11 does **not** reach: G-3's timing, G-13's
`Allowed(AT_i) = C_i`, G-14, G-15, and the unscored F2 family.

Correct any statement elsewhere that becomes untrue; where a statement was true when written, add a
dated update note rather than a rewrite.

---

## STEP 9 — Commit, push, archive

Logically scoped Conventional Commits — the digest ADR, the verifier, the gate run, the registry
freeze, and the G-4 closure in **separate** commits; ADRs referenced in bodies. Stage new files
**before** running hooks. `pre-commit run --all-files` and `uv run pytest -q` green before each;
state the Windows count and the expected Linux split. The G-11 spike is platform-independent, so add
it to CI the way G-4's spike was added — **confirmed, not assumed**. Archive this spec under
`docs/tasks/archive/g11/` with the standing MANIFEST note that task specs are **retrospective
records, not pre-registration evidence**. Push and verify with `git ls-remote origin main`.

---

## STEP 10 — Stop and report

1. STEP 0 self-check.
2. The §F.2/§F.2.1 read, and anything **underspecified for implementation** with what you did.
3. The `access_token_hash` adjudication: construction, tag, worked example, and the three-way
   non-vacuity against `ath` and `H_JCS`.
4. The verifier: placement, how independence (D21) holds, the named checks and reason codes, and the
   test asserting no `n == 0` branch.
5. The fourteen mutations: per mutation, what was changed, the rejection and its reason code, and the
   would-have-failed world. Plus both positive arms.
6. The registry: derivation table with necessity, encoding, its hash and tag, its own frozen row set,
   and confirmation that the `task_authorization_policy` line was not crossed.
7. G-4's closure: L4 and L3 outcomes, and how the record shows the sequence.
8. The adjudication, IA cells and board rows updated to the true outcome; IA-3 still `[UNVERIFIED-IA]`.
9. Commits, push verification, counts on both platforms, and anything you could not verify yourself.
10. Any point where you were tempted to fill a gap by assumption, to weaken a check so it would pass,
    or to build past the specification — and what you did instead.
