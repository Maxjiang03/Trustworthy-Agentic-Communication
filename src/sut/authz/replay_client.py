"""The SUT-side client for the replay arbiter (ADR 0033, gate G-9).

Drop-in for `JtiCache.consume` in the arm's decision path: same signature, same
three outcomes, same `(mechanism_tag, jti)` key, same injected `now`. What
changes is only WHERE the check-and-insert happens -- in an arbiter process that
serves one request at a time, so the atomicity §F.5 requires holds ACROSS
processes and not merely within one.

**Fail-closed is this client's job, and it is not optional.** ADR 0027: *on
capacity or backend error, REJECT rather than admit on doubt.* An unreachable
arbiter, a refused connection, a truncated reply, an unparseable reply or an
explicit `error` all return `CAPACITY` -- a denial. There is no path here that
returns `ADMITTED` without the arbiter having said so.
"""

import json
import socket
from typing import Any

from src.sut.authz.jti_cache import Consumption

CONNECT_TIMEOUT_SECONDS = 10


class RemoteJtiCache:
    """`consume` against the arbiter. One connection per request, by design:
    the arbiter serves one request per connection, which is where concurrent
    clients serialize."""

    def __init__(self, port: int, *, host: str = "127.0.0.1") -> None:
        self.port = int(port)
        self.host = host

    def consume(self, mechanism_tag: str, jti: str, *, now: int) -> Consumption:
        message = json.dumps({"mechanism_tag": mechanism_tag, "jti": jti, "now": int(now)})
        reply = self._round_trip(message)
        if reply is None or "outcome" not in reply:
            # Backend error, in every shape it can take. A denial (ADR 0027).
            return Consumption.CAPACITY
        try:
            return Consumption(reply["outcome"])
        except ValueError:
            return Consumption.CAPACITY

    def _round_trip(self, message: str) -> "dict[str, Any] | None":
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS
            ) as conn:
                conn.sendall((message + "\n").encode("utf-8"))
                line = conn.makefile("r", encoding="utf-8").readline()
        except OSError:
            return None
        if not line:
            return None
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
