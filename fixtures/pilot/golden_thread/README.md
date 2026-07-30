# Pilot corpus — the golden thread (EXP1)

Three scenario specifications plus their generator, per **ADR 0007**: key *seeds* and specs,
never pre-minted tokens. Tokens and keys are minted at run time from `corpus.json`'s seed under
the derivation rule in `src/harness/key_material.py`. **Pilot corpus only** — this directory has
nothing to do with the confirmatory corpus, which does not exist and must not exist until
Part H step 4 (`fixtures/confirmatory/` stays empty; the generator refuses to run otherwise).

| id | Shape | `R` |
|---|---|---|
| `gt-benign` | Supervisor → Specialist → `notes.write` on `notes/project` | `R ⊆ C_1` (false-blocking control) |
| `gt-f1-root` | same hop, then `mail.send` on `mail/outbox` | `R ⊄ C_0 = U_task` (scope amplification) |
| `gt-f1-terminal` | same hop, then `calendar.read` on `calendar/work`, narrowed away at hop 1 | `R ⊆ C_0 ∧ R ⊄ C_1` (§E.3) |

**`C_0` and `C_1` are computed, never asserted.** The generator mints a throwaway chain from the
frozen `Ω`/`Γ` templates (hash-verified against `docs/frozen_parameters.md` rows 8 and 11 first)
and computes `Allowed(P_i; Γ, κ, Ω)` per prefix; it refuses to write documents if a computed set
differs from the spec or any scenario's stated set relation fails. Authority sets are functions
of the frozen Datalog, not of token bytes (ADR 0007), so they are stable across mints.

**Two documents per scenario — the separation is the point (§A.3):**

- `sut_visible/<id>.json` — what agents and arms may see: the task grant the Supervisor
  legitimately holds (`U_task` is the *one* authorization input any runtime principal sees), the
  scripted delegation, the arguments, the frozen logical epoch. **No `τ_gt`, no `R`, no sealed
  field.**
- `sealed/<id>.json` — harness-only sealed truth (`τ_gt`, `R`, `C_sets`, the intended digest).
  `correlation_id` and `P_hashes` are completed by the runner at mint time (tokens are minted at
  run time, ADR 0007; the correlation id is minted per invocation, §F.1). No SUT principal may
  read these files (CLAUDE.md red line 5); the wall is enforced by the harness sealed-truth
  accessor and the import red-line suite.

`τ_gt` is the ground-truth **task**-required scope. The task is the same benign golden-thread
task in all three scenarios — the two F1 scenarios are the Specialist exceeding it — so `τ_gt`
is the benign requirement everywhere and `R` differs from it exactly on the attack calls.

`context_label` is a pilot value consumed by **no** conjunct: the label→outcome policy and the
allowed-sink policy (`docs/frozen_parameters.md` rows 4 and 6) are UNSET, so F4/F5 stay
unscored and these scenarios carry no `LabelAssertion` and no high-risk action.

**Seed-disclosure warning (ADR 0007, binding).** `corpus.json` publishes the pilot seed, which
publishes every key derived from it. These keys are testbed artifacts only and MUST NOT be
reused in any deployment.

Regenerate / re-verify: `uv run python fixtures/pilot/golden_thread/generator.py`
(deterministic; `tests/test_pilot_fixtures.py` asserts the committed documents match).
