"""Protobuf container re-encoders for the G-11 commitment-layer mutations.

Deliberately test-local and independent of `src/harness/oracle/commitment.py`:
they simulate a component elsewhere in the path that re-emits the Biscuit
container. The same technique the ADR 0003 regression suite uses.

The distinction that matters, and the reason `reorder_top_level` sits beside
`flip_byte_in_authority`:

* **`reorder_top_level`** produces a **semantically equivalent** container. It
  MUST verify, with the commitment **unchanged** -- that is ADR 0003's central
  property, and rejecting it would reintroduce the false-rejection bug ADR 0003
  was written to fix.
* **`flip_byte_in_authority`**, **`swap_appended_blocks`** and
  **`truncate_terminal`** change the block sequence or its content, so signature
  chain verification MUST refuse them.
"""


def _varint(buf: bytes, index: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, index


def _emit_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def fields(buf: bytes) -> list[tuple[int, int, object]]:
    """Split one protobuf message into (field_no, wire_type, payload) triples."""
    out: list[tuple[int, int, object]] = []
    index = 0
    while index < len(buf):
        tag, index = _varint(buf, index)
        field_no, wire = tag >> 3, tag & 7
        if wire == 2:
            length, index = _varint(buf, index)
            out.append((field_no, wire, buf[index : index + length]))
            index += length
        elif wire == 0:
            value, index = _varint(buf, index)
            out.append((field_no, wire, value))
        else:
            raise ValueError(f"unexpected wire type {wire} for field {field_no}")
    return out


def emit(field_list: list[tuple[int, int, object]]) -> bytes:
    out = bytearray()
    for field_no, wire, payload in field_list:
        out += _emit_varint((field_no << 3) | wire)
        if wire == 2:
            out += _emit_varint(len(payload)) + payload  # type: ignore[arg-type]
        else:
            out += _emit_varint(payload)  # type: ignore[arg-type]
    return bytes(out)


_AUTHORITY, _BLOCKS = 2, 3  # Biscuit container: authority=2, blocks=3 (schema.proto)


def reorder_top_level(raw: bytes) -> bytes:
    """A semantically equivalent re-encoding: top-level fields in another order."""
    return emit(sorted(fields(raw), key=lambda field: -field[0]))


def flip_byte_in_authority(raw: bytes) -> bytes:
    """Change one byte inside the committed authority block: content, not encoding."""
    parsed = fields(raw)
    position = next(index for index, (no, _, _) in enumerate(parsed) if no == _AUTHORITY)
    body = bytearray(parsed[position][2])  # type: ignore[arg-type]
    body[-1] ^= 0x01
    parsed[position] = (_AUTHORITY, 2, bytes(body))
    return emit(parsed)


def swap_appended_blocks(raw: bytes) -> bytes:
    """Swap the first two appended blocks, changing block order."""
    parsed = fields(raw)
    appended = [index for index, (no, _, _) in enumerate(parsed) if no == _BLOCKS]
    if len(appended) < 2:
        raise ValueError("need at least two appended blocks to swap")
    first, second = appended[0], appended[1]
    parsed[first], parsed[second] = parsed[second], parsed[first]
    return emit(parsed)


def truncate_terminal(raw: bytes) -> bytes:
    """Drop the terminal appended block."""
    parsed = fields(raw)
    appended = [index for index, (no, _, _) in enumerate(parsed) if no == _BLOCKS]
    if not appended:
        raise ValueError("no appended block to truncate")
    return emit([field for index, field in enumerate(parsed) if index != appended[-1]])
