# 0033 — The multi-process replay cache is a **single-writer arbiter process**

## Context

§F.5 requires the `jti` check-and-insert to be *"**MULTI-PROCESS atomic (not just per-thread)**; no
window in which two identical jti both pass (gate G-9)"*. What exists is `src/sut/authz/jti_cache.py`
— a `threading.Lock` over a dict — whose own docstring is explicit that it is atomic *within one
process* and that G-9 will have to make it multi-process. Gate **G-9** cannot be adjudicated until
that changes, and `IA-9` stays `[UNVERIFIED-IA]` until it does.

EXP5 STEP 9 fixes what must **not** move while it changes: TTL exactly `Δ = 60 s`, capacity exactly
`2^16`, key `(mechanism_tag, jti)`, fail-closed on overflow (ADR 0027). *"Whatever you choose, the
frozen parameters do not move to suit it."*

## Decision

`[DESIGN]` **A single-writer arbiter process, built on the spawn-and-hold-the-pipe pattern this
project has already proven twice** — `src/harness/as_process.py` (ADR 0015, gate G-4) and
`src/harness/sut_process.py` (EXP5 STEP 3, gate G-12).

`src/sut/replay_arbiter/` owns the cache and serves check-and-insert on a loopback TCP socket, one
request per connection, single-threaded:

    accept  ->  read one line  ->  consume  ->  reply  ->  close

`src/sut/authz/replay_client.py` is the drop-in client: same signature as `JtiCache.consume`, same
three outcomes, same key, same injected `now`.

### Why this one

**Atomicity is structural rather than locked.** One process, one thread, one request in flight —
there is no window between the check and the insert because there is never a second check-and-insert
to interleave with. A lock can be mis-scoped, taken on the wrong object, or released early; a server
that serves one request at a time cannot be. The property G-9 adjudicates is then a property of the
*shape* of the thing, which is the kind of property that survives a refactor.

**One implementation of the semantics.** The arbiter constructs the **same `JtiCache` class** the
in-process path uses, with its frozen defaults. This ADR decides *where* the check-and-insert runs,
not *what* it does — so TTL eviction by age, the fail-closed overflow, the `(mechanism_tag, jti)`
namespace and the §F.5 ordering are unchanged and untouchable from here. The arbiter takes **no
capacity or TTL flag**: there is no way to move a frozen parameter to suit a test, which is EXP5
forbidden action 6 enforced by absence rather than by discipline.

**The clock stays injected.** `now` is a request parameter and the arbiter reads no wall clock, so
an over-window fixture advances a logical instant instead of waiting `Δ`. At ≥ 200 repetitions per
configuration, real waiting would cost hours of measuring nothing and make the suite's runtime a
function of `Δ`.

**The backend error becomes real.** `--fail-mode` makes the arbiter answer `error`; killing it makes
it unreachable. Both are genuine failures of a genuine backend, and the client turns each into a
denial. Before this ADR there was no backend, so there was no induced-backend-error path to test —
G-9's criterion names one, and a cache with no backend cannot satisfy it however well it behaves.

**It runs everywhere.** Pipes and loopback sockets are cross-platform, unlike the effect ledger's
Win32 exclusive-share handle (ADR 0014). So G-9 can be adjudicated in CI on Linux rather than
inheriting a second platform-gated component.

### Alternatives rejected

**An OS-level primitive — a named mutex (`CreateMutexW`) or a file lock (`msvcrt.locking`) guarding
a shared file or mmap.** Rejected for two reasons. It would make the replay cache **Windows-only**,
adding a second platform-gated component to a project that already carries one as a recorded
limitation (ADR 0014) — and unlike the ledger, nothing about replay detection *needs* Win32
semantics, so the limitation would be self-inflicted. And it **separates the lock from the state**:
two artefacts must both be correct, and the failure mode where the lock is held but the state is
stale is exactly the window §F.5 forbids. The arbiter has one artefact.

**A single-writer arbiter as a thread inside the harness process.** Rejected because it would put
the SUT's replay cache inside the harness address space — undoing EXP5 STEP 3 for this component and
reopening the reachability residual G-6 and G-7 deferred and G-12 has just closed. The cache is the
*arm's* mechanism and belongs on the SUT side of the boundary.

**Leaving `JtiCache` in-process and declaring per-process atomicity sufficient.** Rejected: it is
what §F.5 explicitly rules out, and the honest single-process note already in `jti_cache.py` says so.

## Consequences

- Gate **G-9** becomes adjudicable: exactly-one under real concurrency, an induced backend error,
  reachable overflow, and a lock-removed world that genuinely double-admits.
- `IA-9` can move to verified **only** if all of that holds; building the mechanism is not running
  the gate, and this ADR does not claim the gate.
- A third spawned process joins the apparatus. The pattern is the one already reviewed twice, and
  the arbiter is spawned per campaign rather than per invocation.
- `src/sut/authz/jti_cache.py` keeps its in-process form and its honest note: it remains correct for
  a single-process arm and is the implementation the arbiter runs. Nothing about `B3⁺`'s §E.5
  bitmask changes — where the cache runs is not a ladder property.
- **No frozen parameter moves.** TTL `Δ = 60 s`, capacity `2^16`, key `(mechanism_tag, jti)`,
  fail-closed overflow — all unchanged, and the arbiter exposes no flag that could change them.
- A `jti` crosses a loopback socket. It is an authenticated request **identifier**, not a
  credential: the arbiter grants no authority and answers only *first use* / *duplicate* / *full*.
  Bound to `127.0.0.1`, so nothing leaves the host.

`[DESIGN]`. §F.5 requires multi-process atomicity and ADR 0027 fixes the numbers; the choice of
mechanism is this project's, consistent with ADR 0015's spawn-never-import rule.
