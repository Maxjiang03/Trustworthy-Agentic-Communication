"""The bounded `jti` replay cache (SS F.5, D37), to ADR 0027's parameters.

`B3` does not close bit-identical replay; `B3+` does, and this is the
mechanism. SS F.5 fixes its semantics and ADR 0027 fixes its numbers -- **TTL
exactly `Delta = 60 s`, capacity exactly `2^16`, fail-closed on overflow** --
and this module implements those and no others.

**Consumption, exactly as SS F.5 words it.** At the boundary, **after all other
conjuncts pass** and **before the tool executes**, a check-and-insert:

    if jti present and not expired -> REJECT as duplicate (no execution)
    else insert(jti, now + Delta) and proceed

so admission is **at most once per `jti` within `Delta`**. That is not tool
idempotency: it prevents duplicate ADMISSION, not duplicate effects from a
single admission.

**Fail-closed on overflow, and it is the opposite of the audit buffer.** When
the cache is full of *unexpired* entries an insertion is a **denial**. It never
admits on doubt, and it never evicts an unexpired entry to make room --
evicting one would let an attacker replay a previously-seen `jti` by first
flooding the cache, so the cache would appear to work while guaranteeing
nothing. **Availability is deliberately sacrificed to integrity** (ADR 0027),
which is a property of this experimental apparatus and not advice for a
deployment. Contrast `BoundedAuditBuffer`, which drops on overflow *because*
SS E.5 forbids logging from ever becoming a prevention outcome; here the
opposite choice is correct for the opposite reason.

**The key is `(mechanism_tag, jti)`**, which is what G-9's pass criterion
names. The tag exists because G-14 attaches *the same* authenticated-request-ID
cache to `B2-DPoP` and to `B3`, whose ids come from different mechanisms (a
DPoP proof `jti` and an INV `invocation_id`); without the namespace the two
could collide and one arm could deny the other's request.

**`now` is injected. Nothing here reads a wall clock** (ADR 0027), which is
what lets an over-window fixture advance a logical instant instead of waiting
`Delta` per repetition -- hours of measuring nothing, and a suite whose runtime
would depend on `Delta`.

*(Update, 2026-08-01: **gate G-9 now PASSES**, and this paragraph's honest
statement of what was missing is what it was missing. ADR 0033 puts this same
class inside a **single-writer arbiter process** (`src/sut/replay_arbiter/`),
reached through `src/sut/authz/replay_client.py`, so the check-and-insert is
atomic ACROSS processes and the induced-backend-error path exists. Nothing
below changed: the arbiter runs THIS implementation with THESE frozen
defaults, and the paragraph is kept because it remains true of this class used
directly, in one process. `IA-9` has moved to verified.)*

**This is NOT gate G-9, and must not be described as if it were.** G-9
adjudicates atomic multi-process check-and-insert under concurrency and induced
backend error. What this construction has: the SS F.5 check-and-insert order,
TTL eviction by age, the frozen capacity, fail-closed overflow, the
`(mechanism_tag, jti)` namespace, and a single critical section that is atomic
**within one process**. What it does **not** yet have: **multi-process**
atomicity, any backend, and therefore any induced-backend-error path. A
single-process cache that G-9 will later have to make multi-process is an
honest state to be in. `IA-9` stays `[UNVERIFIED-IA]`.
"""

import threading
from dataclasses import dataclass, field
from enum import Enum

from src.sut import freshness


class Consumption(Enum):
    """The three outcomes of a check-and-insert. Two of them are denials."""

    ADMITTED = "admitted"  # first use of this id in the window
    DUPLICATE = "duplicate"  # seen, unexpired -> replay
    CAPACITY = "capacity"  # full of unexpired entries -> fail closed


@dataclass
class JtiCache:
    """A bounded `(mechanism_tag, jti) -> expiry` map with TTL eviction."""

    capacity: int = freshness.REPLAY_CACHE_CAPACITY
    ttl_seconds: int = freshness.DELTA_SECONDS
    _entries: dict[tuple[str, str], int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.capacity < 1 or self.ttl_seconds < 1:
            raise ValueError("the replay cache needs a positive capacity and TTL")

    def consume(self, mechanism_tag: str, jti: str, *, now: int) -> Consumption:
        """One check-and-insert. `now` is injected; no wall clock is read.

        A single critical section, so within this process there is no window in
        which two identical ids both pass. **Across processes there is** --
        that is what gate G-9 adjudicates and this construction does not yet
        provide.
        """
        key = (mechanism_tag, jti)
        with self._lock:
            self._evict_expired(now)
            if key in self._entries:
                return Consumption.DUPLICATE
            if len(self._entries) >= self.capacity:
                # Fail closed. Deliberately NOT an eviction: removing an
                # unexpired entry here is the flooding bypass ADR 0027 rejects.
                return Consumption.CAPACITY
            self._entries[key] = now + self.ttl_seconds
            return Consumption.ADMITTED

    def _evict_expired(self, now: int) -> None:
        """Lazy eviction by AGE, never by an independent timer (ADR 0027).

        Never revives a valid `jti`: only entries whose expiry has passed are
        removed, so a replay inside the window can never find the cache empty.
        """
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            del self._entries[key]

    def __len__(self) -> int:
        return len(self._entries)
