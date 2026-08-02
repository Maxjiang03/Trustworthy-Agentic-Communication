# Gate G-9 — the multi-process replay cache

**Verdict: PASS**, 2026-08-01. Cross-platform (loopback sockets, no effect ledger).

**Part G row:** *fire N concurrent bit-identical requests at the replay cache **across processes**;
induce a backend error.*
**Criterion:** *exactly one proceeds; no double-admission; fail-closed observed; frozen
`(mechanism_tag, jti)`/TTL/capacity budget.*
**What rides on it:** *IA-9; B3⁺ and the replay layer.*

Run: `make gate GATE=g9` · `uv run python smoke/g9/spike.py`

---

## Mechanism — ADR 0033

A **single-writer arbiter process**, on the spawn-and-hold-the-pipe pattern proven twice already
(the AS at G-4, the SUT at G-12). One process, one thread, one request in flight:
`accept → read one line → consume → reply → close`.

**Atomicity is structural, not locked.** There is no window between the check and the insert because
there is never a second check-and-insert to interleave with. A lock can be mis-scoped, taken on the
wrong object or released early; a server that serves one request at a time cannot be.

The arbiter constructs the **same `JtiCache` class** the in-process path uses, so this decides *where*
the check-and-insert runs, not *what* it does. Alternatives rejected in ADR 0033: an OS-level
primitive (would make the cache Windows-only for no reason, and separates the lock from the state,
which is the very window §F.5 forbids); an arbiter thread inside the harness (would undo EXP5
STEP 3 for this component); leaving it in-process (what §F.5 rules out).

## The seven limbs

| limb | result |
|---|---|
| **L1** exactly one of N=8 concurrent | ADMITTED = **1**, DUPLICATE = 7 |
| **L1.R** 20 trials × 8 | admitted counts = **{1}** — every trial |
| **L2** the lock-removed world | per-caller caches admit **8 of 8** |
| **L3** induced backend error | answered `error` → denial; killed/unreachable → denial; healthy → admitted |
| **L4** overflow reached | filled to **65536**, next distinct id → fail-closed, earlier entry survives |
| **L5** frozen budget | capacity 2^16, TTL 60 s, **no flag exists** to change either |
| **L5.C** injected clock | window crossed by advancing the instant; nothing sleeps |

**Exactly one is asserted as a count.** A cache admitting two of eight has failed even though six
were blocked; *"at least one blocked"* would not have caught it. Twenty repeated trials confirm it
is not a single lucky interleaving.

**L2 is what makes L1 a measurement.** The lock is not removed from the arbiter — that would test a
mutilated arbiter. It is removed by putting the cache back where it was: one `JtiCache` **per
caller**, which is exactly what N separate SUT processes each holding their own in-process cache
amounts to. That configuration admits **8 of 8**. So the arbiter's *exactly one* is a measurement,
not a race that happened not to occur.

**L3 has both shapes of backend failure and a positive control.** An arbiter answering `error` and
an arbiter killed mid-flight both produce a **denial**; the same client against a healthy arbiter
**admits**, so the denials are the failure and not a client that always denies. ADR 0027: reject
rather than admit on doubt. Never an admission, never a silent eviction.

**L4 reaches the real frozen capacity.** 65536 entries, inserted through the **same `consume` path**
— the bulk op loops over the real check-and-insert rather than writing entries behind it, so the
real critical section is what filled. The next distinct id is refused (fail closed), and an entry
inserted *before* the cache filled is still present: **no unexpired entry was evicted to make room**,
which is the flooding bypass ADR 0027 rejects. The budget exists so this path can be exercised, not
so the campaign stays below it.

*Update, 2026-08-02 — EXP5 STEP 13's standing check, recorded rather than quietly patched. This
limb was FLAKY and passed only because the machines it had run on were fast enough.* Reaching the
frozen `2^16` through the real `consume` path is **quadratic in the capacity**, because
`JtiCache._evict_expired` scans every entry on every call: **2,147,450,880 scan steps**, counted
exactly with an instrumented subclass rather than estimated. The spike's socket read had a **120 s**
budget, so on a slower machine the fill did not finish and the gate **errored with every other limb
green** — a flaky gate, which is worse than a failing one, and it would have surfaced first during a
confirmatory run. The tempting fix was to fill to a smaller capacity; that is **forbidden action 6**
(moving a frozen parameter to suit a test) and would mean overflow was never *reached*, which is the
entire point of the limb. **`2^16` is unchanged and the limb was given the time that budget costs**
(`FILL_TIMEOUT = 900 s`), after which it passes with the same four assertions and the same values.
**The `O(n)`-per-`consume` eviction was NOT optimised**, deliberately: the replay cache's cost is
part of what **G-3** exists to measure, and improving it before the cost gate runs would silently
change the thing being measured. It is recorded here as a known cost property, not fixed.

**L5 enforces the freeze by absence.** The arbiter accepts **no** `--capacity` or `--ttl` flag, so a
frozen parameter cannot be moved to suit a test — EXP5 forbidden action 6 held structurally rather
than by discipline.

## IA-9

**Moves to verified.** The check-and-insert is atomic across processes, the frozen budget is
unchanged, fail-closed is observed in both failure shapes, and the failing world genuinely
double-admits.

## Scope

Establishes **multi-process replay detection**. Does not establish cost (**IA-3** stays
`[UNVERIFIED-IA]` for G-3) or the DPoP taxonomy (**G-14**). `B3⁺`'s §E.5 bitmask is unchanged —
where the cache runs is not a ladder property. No timing number was produced and no test sleeps.
