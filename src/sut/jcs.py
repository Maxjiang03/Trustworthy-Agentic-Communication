"""SUT-side `H_JCS` (ADR 0009), in a module that belongs to NEITHER plane.

Moved out of `src/sut/capability/digests.py` when ADR 0030's shared reference
monitor needed it. The monitor serves an OAuth arm and a capability arm alike,
so it cannot reach into the capability package for a digest that has nothing to
do with capabilities -- and `tests/test_b2_exchange_task.py` rightly fails any
B2 arm that imports `src.sut.capability`. `digests.py` re-exports it, so the
capability plane is unchanged; the canonical home is here.

Still the SUT's OWN implementation, written from ADR 0009 and never importing
`src/harness/` (red line 6). D21 is untouched: the harness computes the same
value with a separate implementation, and agreement is a verified property
rather than a shared code path.

    H_JCS = lowercase_hex( SHA-256( "AASC-JCS-DIGEST" || 0x01
                                    || u32be(len(C)) || C ) )

with `C` the RFC 8785 canonical UTF-8 bytes. No algorithm byte: a hash change
is a new VERSION, not a parameter. Canonicalization errors propagate.
"""

import hashlib

import rfc8785

VERSION = 0x01
JCS_TAG = b"AASC-JCS-DIGEST"


class SutDigestError(Exception):
    """A SUT-side digest construction failed closed."""


def h_jcs(obj: object, *, version: int = VERSION) -> str:
    """ADR 0009 `H_JCS`: canonicalization errors propagate (fail closed)."""
    if version != VERSION:
        raise SutDigestError(f"unsupported H_JCS version {version}")
    canonical = rfc8785.dumps(obj)
    material = JCS_TAG + bytes([version]) + len(canonical).to_bytes(4, "big") + canonical
    return hashlib.sha256(material).hexdigest()
