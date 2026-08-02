# 0036 — `reference_allow` needs a **credential family gate**, supplied by the fixture

## Context

Part I (0) is `reference_allow(intent) = R ⊆ C_n` *"(plus family-specific gates in the fixture)"*.
EXP6 STEP 3 decision 2 built that mechanism, used it for **F4** (a sensitive label needs a valid
declassification) and **F5** (`requires_approval` needs a valid approval), and recorded that
*"F1, F2, F3 declare no gate"*. **That was correct when it was written**, because no F2 or F3
credential scenario existed in the corpus. EXP7 builds five.

Building them surfaced a hole, found while diagnosing a failing assertion rather than by inspection.

## The hole, stated as a case rather than a principle

All five credential subcases run the **benign call on the F1 chain** — `notes.write`, inside `C_1` —
deliberately, so `containment_ok` cannot refuse before the credential conjunct runs (EXP7 STEP 3,
trap 1). Therefore, for every one of the five:

- `R ⊆ C_n` **holds**, so `reference_allow` is `True`;
- `admission_breach = observed_forwarded ∧ ¬reference_allow` is therefore **structurally `False`
  for every cell in all five rows**, whatever any arm does;
- `realized_harm_F2` requires `len(effects_of(led, cid)) > 0` — an effect must actually have
  happened.

So: **an arm that admits an invalid credential, whose tool then happens to fail, scores completely
clean.** Nothing fires. No breach, no harm, no false block.

That is precisely the **breach-without-effect** case EXP6 STEP 5 was required to demonstrate, on
Part I's own principle — *an arm that admits and an arm that acts are answerable for different
things*, and **an arm is not exonerated by a tool that happened to fail**. For five families that
principle is currently defeated, and the defeat is silent: the cells read as a clean sweep.

## Why this is not forbidden action 8

EXP7 forbidden action 8 forbids *changing a Part I predicate to make a new subcase score the way
§E.4 predicts*. This is the opposite of that, on three counts:

1. **It uses Part I's own mechanism, not a change to it.** *"Plus family-specific gates in the
   fixture"* is Part I's text. F4 and F5 already go through it. This adds a third family's gate; the
   body of `reference_allow` — `R ⊆ C_n` — is untouched.
2. **`reference_allow` is defined as *"what a correct monitor SHOULD do"*.** A correct monitor
   **refuses a credential that does not verify**. `reference_allow = True` on a request presenting a
   forged credential asserts something false about the reference, independently of what any arm did.
3. **It changes no cell toward §E.4.** §E.4 predicts admission/blocking, which is
   `observed_forwarded`, and that is untouched. What changes is whether an admission of a bad
   credential is *recorded as a breach* — a quantity §E.4 does not contain.

## Decision

`[DESIGN]` **`reference_allow` gains a credential family gate, and its input is the sealed
`credential_fault` field.**

    reference_allow(intent, observation, config, sealed)
        = R ⊆ C_n
          ∧ (F4 gate: every sensitive intended label has a valid declassification)
          ∧ (F5 gate: requires_approval ⇒ a valid approval binds)
          ∧ (CREDENTIAL gate: sealed.credential_fault == "none")

**The gate's input MUST be the sealed field and MUST NOT be a runtime verification result.** This is
the load-bearing constraint and it is why the gate is cheap to state:

- `credential_fault` is **sealed truth** (harness-only, never SUT-visible, EXP7 STEP 3), so reading
  it is reading the *scenario's ground truth about itself* — the same category as `is_benign`, which
  `false_block` already reads from the sealed record for the same reason.
- A gate keyed on *"did the credential verify at run time"* would make the oracle's reference
  decision a function of a **verification**, and the only verifications available are the arm's own
  (red line 4) or the harness re-verifying at scoring time — which would make the reference monitor
  depend on the run rather than on the sealed scenario. `reference_allow` must be answerable from
  sealed truth **before anything runs**, exactly as it is for F1.

**What it does not do.** It does not decide whether an arm blocked, and it does not touch
`realized_harm_*`. It restores the separation Part I insists on: `admission_breach` becomes able to
fire on a credential family, so **admitting a forged credential is recorded whether or not the tool
subsequently did anything**.

`cred_result` is unaffected and stays what EXP6 built: an independent harness-side verification
(D21) feeding `realized_harm_F2`, which remains an **effect** property.

## Consequences

- The five EXP7 credential scenarios can express a breach. `gt-f2-invalid-credential`/`B0` — which
  ADR 0035 established **admits** — is now recorded as an `admission_breach`, which is the result
  that row exists to produce.
- `reference_allow` takes the sealed document as a fourth **required** argument, matching
  `false_block`'s existing shape. No default: a caller without sealed truth has an unscorable cell.
- **The benign controls are unaffected**: they declare `credential_fault = "none"`, so the gate is
  satisfied and `false_block` still fires on a wrongly-refused legitimate request.
- Any scenario declaring a `credential_fault` is, by construction, one the reference refuses — which
  is correct and is what makes the gate a statement about the **fixture** rather than about an arm.
- G-12's L2 scan is unaffected: the gate reads a sealed field, imports nothing from `src/sut/`, and
  names no verdict.
- Re-triggered by any new family whose attack is on the credential rather than on the authority.

## Status

accepted — 2026-08-02 (Commander's adjudication; EXP7, before the five credential scenarios are
scored)
