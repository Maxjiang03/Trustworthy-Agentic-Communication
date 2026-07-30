"""SUT-side effective authority: `C_n = Allowed(P_n; Gamma, kappa, Omega)` (SS A.0.1).

The B3 boundary's own authorizer code (EXP1 STEP 12): one real authorizer run
per candidate element of the frozen `Omega`, with `operation`, `time`,
`request_audience` and `request_task` injected as authorizer facts -- exactly
the evaluation ADR 0016 fixes -- and membership iff the run selects an allow
policy. **Computed here, SUT-side, never asserted and never imported from
`src/harness/authorizer/allowed.py`** (red line 6; D21). The frozen document
arrives as injected data; G-2's discipline (compute, never claim) applies
unchanged.

The MSc-profile structural rejection is SUT-side project code too, because
the pinned library alone accepts third-party blocks under `kappa_pub` -- a
G-2 finding that makes this rejection load-bearing wherever tokens are
evaluated (SS A.6.1 MUST: reject before evaluation). The scanner below reads
the container's protobuf wire directly: a `SignedBlock.externalSignature`
field (4) or a non-Ed25519 `PublicKey.algorithm` (field 1 != 0) fails closed
before any Datalog runs.
"""

from datetime import datetime, timezone
from typing import Any

from biscuit_auth import (
    Algorithm,
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    Fact,
    PublicKey,
)

# Biscuit container wire facts (schema.proto): Biscuit{authority=2, blocks=3};
# SignedBlock{nextKey=2, externalSignature=4}; PublicKey{algorithm=1};
# Ed25519 = enum 0.
_FIELD_SIGNED_BLOCKS = (2, 3)
_SB_NEXT_KEY = 2
_SB_EXTERNAL_SIGNATURE = 4
_PK_ALGORITHM = 1
_ALG_ED25519_WIRE = 0


class SutAuthorityError(Exception):
    """Base: the SUT-side authority layer failed closed."""


class OutOfProfileError(SutAuthorityError):
    """The token is outside the MSc profile (SS A.6.1 MUST reject pre-evaluation)."""


def _fields(buffer: bytes):
    """Iterate (field_number, payload) over one protobuf message, fail closed."""
    index = 0
    while index < len(buffer):
        tag, index = _varint(buffer, index)
        field_number, wire_type = tag >> 3, tag & 0x07
        if wire_type == 2:
            length, index = _varint(buffer, index)
            if index + length > len(buffer):
                raise OutOfProfileError("length-delimited field overruns the container")
            yield field_number, buffer[index : index + length]
            index += length
        elif wire_type == 0:
            value, index = _varint(buffer, index)
            yield field_number, value
        else:
            raise OutOfProfileError(f"unexpected wire type {wire_type} in the container")


def _varint(buffer: bytes, index: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if index >= len(buffer):
            raise OutOfProfileError("truncated varint in the container")
        byte = buffer[index]
        index += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, index


def reject_out_of_profile(token_bytes: bytes) -> None:
    """SS A.6.1: third-party blocks and non-Ed25519 keys refuse pre-evaluation."""
    for field_number, payload in _fields(bytes(token_bytes)):
        if field_number in _FIELD_SIGNED_BLOCKS and isinstance(payload, bytes):
            for sub_number, sub_payload in _fields(payload):
                if sub_number == _SB_EXTERNAL_SIGNATURE:
                    raise OutOfProfileError("third-party (external-signature) block present")
                if sub_number == _SB_NEXT_KEY and isinstance(sub_payload, bytes):
                    for key_field, key_value in _fields(sub_payload):
                        if key_field == _PK_ALGORITHM and key_value != _ALG_ED25519_WIRE:
                            raise OutOfProfileError("non-Ed25519 key carried in the chain")


def root_public_from_wire(raw32: bytes) -> PublicKey:
    if len(raw32) != 32:
        raise SutAuthorityError("kappa public key must be 32 raw Ed25519 bytes")
    return PublicKey.from_bytes(bytes(raw32), Algorithm.Ed25519)


def _authorizer_facts(gamma: dict[str, Any], *, now_epoch: int, audience: str, task_id: str):
    now = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
    return [
        Fact("time({t})", {"t": now}),
        Fact("request_audience({aud})", {"aud": audience}),
        Fact("request_task({task})", {"task": task_id}),
    ]


def permits(
    token_bytes: bytes,
    root_public: PublicKey,
    gamma_document: dict[str, Any],
    element: tuple[str, str],
    *,
    now_epoch: int,
    audience: str,
    task_id: str,
) -> bool:
    """One authorizer run for one candidate element; deny on no policy match."""
    reject_out_of_profile(token_bytes)
    token = Biscuit.from_bytes(bytes(token_bytes), root_public)
    builder = AuthorizerBuilder(gamma_document["gamma"]["datalog"]["authorizer"])
    action, resource = element
    builder.add_fact(
        Fact("operation({action}, {resource})", {"action": action, "resource": resource})
    )
    facts = _authorizer_facts(
        gamma_document, now_epoch=now_epoch, audience=audience, task_id=task_id
    )
    for fact in facts:
        builder.add_fact(fact)
    try:
        builder.build(token).authorize()
    except AuthorizationError:
        return False
    return True


def allowed_set(
    token_bytes: bytes,
    root_public: PublicKey,
    gamma_document: dict[str, Any],
    *,
    now_epoch: int,
    audience: str,
    task_id: str,
) -> frozenset[tuple[str, str]]:
    """`Allowed(P_n; Gamma, kappa, Omega)`: one run per element of Omega."""
    omega = [(action, resource) for action, resource in gamma_document["omega"]["elements"]]
    return frozenset(
        element
        for element in sorted(omega)
        if permits(
            token_bytes,
            root_public,
            gamma_document,
            element,
            now_epoch=now_epoch,
            audience=audience,
            task_id=task_id,
        )
    )
