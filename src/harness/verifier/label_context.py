"""The label-plumbing constructions (ADR 0030) -- ADR 0009's last category (c).

`authz_context_hash`, `payload_digest`, `label_assertions_digest`, and the three
artifact signing domains. Every one has been ADR 0009 **category (c)** since the
beginning, deferred to *"the F4 label decision and G-15"*; this is that decision.

Same tagged, versioned, length-delimited family as ADR 0003, ADR 0009,
ADR 0016 and ADR 0018:

    digest = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
    signing input = TAG || VERSION || u32be(len(C)) || C

with `C` the canonical bytes of whatever the tag's domain is, **its own** domain
tag per construction, no algorithm byte (a hash change is a new VERSION, not a
parameter), and fail-closed on an unsupported version.

**Why six new tags rather than reuse.** G-11 tested domain-tag confusion in
*both* directions and found it real; ADR 0018 records that `ath` and
`access_token_hash` take the **same input bytes** and are kept apart by the tag
alone. Each construction below is a distinct domain -- a value, an authorization
context, a list of labels, and three signed artifact types -- and merging any two
would let one be reinterpreted as another. `_TAGS_IN_USE` is extended in the same
commit, and the pairwise-distinctness assertion covers the whole family.

**`payload_digest` is over a VALUE, not a JSON object.** ADR 0009 says so
explicitly: *"the payload domain is a data value (not necessarily a JSON object),
so `H_JCS` MUST NOT be assumed"*. SS A.6 resolves label assertions **by payload
digest**, and the same value must yield the same digest whether it arrives as a
JSON string field in a tool argument, as a `payload_digest` on an `EffectEvent`,
or on a `ToolIngressEvent`. Under `H_JCS` it would depend on the surrounding
object, and the join key ADR 0009 requires all four sites to share would not
exist. A non-`str`/`bytes` value **fails closed** rather than being serialized by
a rule this ADR did not fix.

**`authz_context_hash` is mechanism-neutral by construction.** SS F.2 defines it
over `task_id`, `audience`, `tool`, `canonical_request_digest`, `resource_owner`
and `oauth_actor` -- and **not one of those names a capability, an HTC, an INV or
a DPoP key**. That is the entire reason SS F.2 defines it this way, and the only
thing that makes one shared reference monitor possible: an OAuth arm holding no
capability token computes exactly the same value. A test asserts a capability arm
and an OAuth arm agree on it for the same request.

Trust rule (D21): this module is **instrument-side**. The SUT computes the same
values with its own implementation (`src/sut/authz/label_context.py`), and the
oracle never consumes a SUT-computed digest -- it recomputes from raw evidence.
"""

import hashlib
from typing import Any

import rfc8785

VERSION = 0x01  # any other value fails closed

# `payload_digest` -- SS A.6's join key, over a data VALUE.
PAYLOAD_TAG = b"AASC-PAYLOAD-DIGEST"
# `authz_context_hash` -- SS F.2's mechanism-neutral request binding.
AUTHZ_CONTEXT_TAG = b"AASC-AUTHZ-CTX"
# `label_assertions_digest` -- the INV's binding of the presented label set.
LABEL_SET_TAG = b"AASC-LABELSET-DIGEST"
# The three artifact signing domains (SS F.1), one per type so that a signature
# over one can never be replayed as a signature over another.
LABEL_ASSERTION_TAG = b"AASC-LABEL-v1"
DECLASSIFICATION_TAG = b"AASC-DECLASS-v1"
APPROVAL_TAG = b"AASC-APPROVAL-v1"

NEW_TAGS = (
    PAYLOAD_TAG,
    AUTHZ_CONTEXT_TAG,
    LABEL_SET_TAG,
    LABEL_ASSERTION_TAG,
    DECLASSIFICATION_TAG,
    APPROVAL_TAG,
)


class LabelContextError(Exception):
    """Base: a label-plumbing construction failed closed."""


class UnsupportedVersionError(LabelContextError):
    """A version other than VERSION was requested."""


class UnhashablePayloadError(LabelContextError):
    """The payload is not a value this construction is defined over."""


def _digest(tag: bytes, canonical: bytes, version: int) -> str:
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported {tag.decode()} version {version}")
    running = hashlib.sha256()
    running.update(tag)
    running.update(bytes([version]))
    running.update(len(canonical).to_bytes(4, "big"))
    running.update(canonical)
    return running.hexdigest()


def signing_input(tag: bytes, payload: dict[str, Any], *, version: int = VERSION) -> bytes:
    """`TAG || VERSION || u32be(len(C)) || C` over RFC 8785 canonical payload bytes.

    ADR 0018's layout, shared by the three artifact types below exactly as
    SS F.2's HTC and INV share it. Member order is not content, so a
    re-serialization of the same payload signs identically.
    """
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported signing version {version}")
    canonical = rfc8785.dumps(payload)
    return tag + bytes([version]) + len(canonical).to_bytes(4, "big") + canonical


# ---------------------------------------------------------------------------
# payload_digest -- the SS A.6 join key
# ---------------------------------------------------------------------------
def payload_digest(value: "str | bytes", *, version: int = VERSION) -> str:
    """`payload_digest` over a data VALUE (ADR 0030, closing ADR 0009 category (c)).

    `str` is encoded UTF-8; `bytes` is taken as-is. Anything else raises:
    a number, a mapping or a list has no canonical byte form this ADR fixed,
    and guessing one would silently give two different values the same digest
    -- or the same value two digests, which is worse, because SS A.6's
    resolution is a **join** and a join key that is not stable is not a key.
    """
    if isinstance(value, str):
        canonical = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        canonical = bytes(value)
    else:
        raise UnhashablePayloadError(
            f"payload_digest is defined over a str or bytes value; got {type(value).__name__}. "
            "ADR 0030 fixes no serialization for other types and refuses rather than inventing "
            "one, because SS A.6 resolves labels BY payload digest and an unstable join key is "
            "not a key"
        )
    return _digest(PAYLOAD_TAG, canonical, version)


# ---------------------------------------------------------------------------
# authz_context_hash -- SS F.2's mechanism-neutral request binding
# ---------------------------------------------------------------------------
AUTHZ_CONTEXT_FIELDS = (
    "task_id",
    "audience",
    "tool",
    "canonical_request_digest",
    "resource_owner",
    "oauth_actor",
)


def authz_context_hash(
    *,
    task_id: str,
    audience: str,
    tool: str,
    canonical_request_digest: str,
    resource_owner: "tuple[str, str] | list[str]",
    oauth_actor: "tuple[str, str] | list[str]",
    version: int = VERSION,
) -> str:
    """SS F.2's `H( task_id, audience, tool, canonical_request_digest,
    resource_owner, oauth_actor )`.

    Keyword-only and exhaustive on purpose: every one of SS F.2's six named
    inputs must be supplied, so a caller cannot quietly bind fewer of them and
    produce a value that looks like this one. The canonical bytes are the
    RFC 8785 encoding of the six-member object, so member order is not content
    and two independent implementations agree without agreeing on field order.

    **Mechanism-neutral**: not one field names a capability, an HTC, an INV or
    a DPoP key, so an OAuth arm holding no capability token computes the same
    value as `B3`. That is what makes ONE shared reference monitor possible,
    and it is why SS F.2 defines the field this way rather than over the INV.
    """
    canonical = rfc8785.dumps(
        {
            "audience": audience,
            "canonical_request_digest": canonical_request_digest,
            "oauth_actor": list(oauth_actor),
            "resource_owner": list(resource_owner),
            "task_id": task_id,
            "tool": tool,
        }
    )
    return _digest(AUTHZ_CONTEXT_TAG, canonical, version)


# ---------------------------------------------------------------------------
# label_assertions_digest -- the INV's binding of the presented label set
# ---------------------------------------------------------------------------
def label_assertions_digest(payload_digests, *, version: int = VERSION) -> str:
    """`INV.label_assertions_digest` over the presented labels' join keys.

    Over the **sorted** list of `payload_digest` values, so the binding does
    not depend on presentation order -- two presentations of the same label set
    must bind identically or the INV would reject a reordering that changed
    nothing. The empty set has a well-defined digest rather than a sentinel,
    which is what lets an unlabelled invocation be bound as *"no labels"*
    rather than as *"this field was not filled in"*.
    """
    canonical = rfc8785.dumps(sorted(payload_digests))
    return _digest(LABEL_SET_TAG, canonical, version)
