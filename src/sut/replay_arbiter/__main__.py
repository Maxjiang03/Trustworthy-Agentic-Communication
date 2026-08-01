"""The replay cache as a SINGLE-WRITER ARBITER process (ADR 0033, gate G-9).

§F.5 requires the `jti` check-and-insert to be **MULTI-PROCESS atomic (not just
per-thread); no window in which two identical jti both pass**. `JtiCache`'s
`threading.Lock` is atomic within one process and its own docstring says so.
This is the mechanism that makes it atomic across processes.

**Atomicity is STRUCTURAL, not locked.** One process, one thread, one request
served at a time: `accept -> read one line -> consume -> reply -> close`. There
is no critical section to forget and no window between the check and the insert,
because there is only ever one check-and-insert in flight. A lock can be
mis-scoped; a single server cannot be.

**The frozen parameters do not move** (ADR 0027, EXP5 forbidden action 6): TTL
exactly `Δ = 60 s`, capacity exactly `2^16`, key `(mechanism_tag, jti)`,
**fail-closed** on overflow. This process constructs the SAME `JtiCache` class
the in-process path uses, with its defaults, so there is one implementation of
the semantics and this module only decides *where* it runs.

**`now` is a REQUEST PARAMETER and no wall clock is read here** (ADR 0027).
That is what lets an over-window fixture advance a logical instant instead of
waiting `Δ` per repetition -- sixty seconds of measuring nothing, and a suite
whose runtime would be a function of `Δ`.

**Loopback TCP, and what that does and does not carry.** The channel carries
`(mechanism_tag, jti, now)` and returns one of three outcomes. A `jti` is an
authenticated request identifier, not a credential: possessing one lets nobody
authenticate anything, and the arbiter grants no authority -- it only ever says
*first use*, *duplicate* or *full*. Bound to `127.0.0.1` so nothing leaves the
host.

**The induced backend error is real, not simulated.** `--fail-mode` makes the
arbiter answer `error` to every request; a client that cannot reach it, or is
answered `error`, must DENY. Fail-closed on doubt is ADR 0027's rule and the
client enforces it, so the failure mode is exercised end to end rather than
mocked at the boundary of the thing under test.
"""

import argparse
import json
import os
import socket
import sys

from src.sut.authz.jti_cache import Consumption, JtiCache


def main() -> int:
    parser = argparse.ArgumentParser()
    # NO capacity or TTL flag: the frozen parameters are not configurable, so
    # they cannot be moved to suit a test (EXP5 forbidden action 6).
    parser.add_argument("--fail-mode", action="store_true", help="answer every request with error")
    args = parser.parse_args()

    cache = JtiCache()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    sys.stdout.write(
        json.dumps(
            {
                "ready": True,
                "port": port,
                "pid": os.getpid(),
                "capacity": cache.capacity,
                "ttl_seconds": cache.ttl_seconds,
                "fail_mode": bool(args.fail_mode),
            }
        )
        + "\n"
    )
    sys.stdout.flush()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            break
        # One request per connection, served to completion before the next is
        # accepted. THIS is the atomicity: concurrent clients serialize here.
        with conn:
            try:
                data = conn.makefile("r", encoding="utf-8").readline()
                if not data:
                    continue
                message = json.loads(data)
                if args.fail_mode:
                    reply = {"error": "induced-backend-error"}
                elif message.get("op") == "fill":
                    # Bulk insertion THROUGH THE SAME `consume` path -- not a
                    # shortcut around the logic. It exists so the frozen 2^16
                    # capacity can be REACHED without 65536 network round
                    # trips; every entry still goes through the real
                    # check-and-insert, and the outcome of each is counted.
                    admitted = duplicate = full = 0
                    now = int(message["now"])
                    for index in range(int(message["count"])):
                        outcome = cache.consume(
                            str(message.get("mechanism_tag", "fill")), f"fill-{index}", now=now
                        )
                        admitted += outcome is Consumption.ADMITTED
                        duplicate += outcome is Consumption.DUPLICATE
                        full += outcome is Consumption.CAPACITY
                    reply = {"admitted": admitted, "duplicate": duplicate, "capacity": full}
                elif message.get("op") == "size":
                    reply = {"size": len(cache._entries), "capacity": cache.capacity}
                else:
                    outcome = cache.consume(
                        str(message["mechanism_tag"]), str(message["jti"]), now=int(message["now"])
                    )
                    reply = {"outcome": outcome.value}
                conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))
            except Exception as exc:  # noqa: BLE001 -- report, never die
                try:
                    conn.sendall(
                        (
                            json.dumps({"error": type(exc).__name__, "detail": str(exc)[:200]})
                            + "\n"
                        ).encode("utf-8")
                    )
                except OSError:
                    pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
