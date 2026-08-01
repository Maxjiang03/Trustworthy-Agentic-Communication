"""The SUT/harness wire codec: **JSON only, and deliberately not pickle**.

This module is the whole vocabulary of the process boundary EXP5 STEP 3
introduces, and its restrictions are the point rather than an implementation
detail.

**Why not pickle.** `pickle` would make the channel a *capability* channel: it
reconstructs arbitrary objects and can execute arbitrary code on load, so a
harness that unpickled a child's message would be handing the SUT a way into
its own address space — exactly the raw-reference path gates G-6 and G-7
excluded and deferred here. JSON carries **data**: strings, numbers, booleans,
`null`, arrays and objects. There is no representation for a callable, a file
handle, or a live object graph, so property 3 of STEP 3 ("the channel carries
data, not capability") holds **by construction of the codec** rather than by
review of every message.

**Bytes need a representation, and it is explicit.** Provisioning material is
binary — a `kappa` private key, holder keys, a DPoP JWK. JSON has no byte type,
so this fixes one tagged form:

    b"\\x01\\x02"  <->  {"__bytes__": "0102"}

Explicit and auditable, and decoding is total: an object carrying `__bytes__`
becomes bytes, anything else stays what JSON made it. No type is inferred from
a string's shape, so no ordinary string can be coerced into bytes by accident.

**Key material crosses the pipe and never a file.** The AS process takes its
seed from the environment for the same reason (ADR 0015/0021, red line 8); this
channel takes provisioning material on **stdin**. Nothing here writes anything
anywhere.

This module is SUT-side and imports nothing from `src/harness/` (red line 6).
The harness has its own copy of the same two functions -- the codec is a
**wire-level fact** duplicated on both sides, exactly as `as_process.py`
duplicates the AS module path rather than importing the AS.
"""

import json
from typing import Any

BYTES_TAG = "__bytes__"


def encode(value: Any) -> Any:
    """Python -> JSON-representable, with bytes in the one tagged form."""
    if isinstance(value, (bytes, bytearray)):
        return {BYTES_TAG: bytes(value).hex()}
    if isinstance(value, dict):
        return {str(key): encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value


def decode(value: Any) -> Any:
    """JSON -> Python. Total: an untagged value is returned unchanged."""
    if isinstance(value, dict):
        if set(value) == {BYTES_TAG} and isinstance(value[BYTES_TAG], str):
            return bytes.fromhex(value[BYTES_TAG])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value


def dumps(message: Any) -> str:
    """One message, one line. Newline-delimited framing, so a partial write is
    a parse failure rather than a silently truncated message."""
    return json.dumps(encode(message), ensure_ascii=True, separators=(",", ":"))


def loads(line: str) -> Any:
    return decode(json.loads(line))
