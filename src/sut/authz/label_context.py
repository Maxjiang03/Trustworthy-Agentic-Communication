"""The label-plumbing constructions, SUT-side (ADR 0030) -- the D21 counterpart.

`src/harness/verifier/label_context.py` is the instrument's implementation. This
is the measured system's, written **independently** from ADR 0030's stated byte
layout rather than by importing the harness (CLAUDE.md red line 6, D13/D21), and
`tests/test_label_context_agreement.py` pins that the two agree byte for byte on
every construction. Agreement is required; shared code is not.

The layout ADR 0030 fixes, for every construction here:

    digest        = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
    signing input =                         TAG || VERSION || u32be(len(C)) || C

`C` is the canonical bytes of the tag's own domain: UTF-8 for a payload **value**,
RFC 8785 for a structured object. Each construction carries **its own** domain
tag, because G-11 found domain-tag confusion real in both directions and
ADR 0018 records two digests over identical input bytes kept apart by the tag
alone.

**Mechanism-neutrality is the point of `authz_context_hash`.** None of SS F.2's
six named inputs mentions a capability, an HTC, an INV or a DPoP key, so an
OAuth arm holding no capability token computes the same value as `B3` -- which is
what lets ONE boundary-owned reference monitor serve every arm (gate G-15).
"""

import hashlib
from typing import Any

import rfc8785

VERSION = 0x01

PAYLOAD_TAG = b"AASC-PAYLOAD-DIGEST"
AUTHZ_CONTEXT_TAG = b"AASC-AUTHZ-CTX"
LABEL_SET_TAG = b"AASC-LABELSET-DIGEST"
LABEL_ASSERTION_TAG = b"AASC-LABEL-v1"
DECLASSIFICATION_TAG = b"AASC-DECLASS-v1"
APPROVAL_TAG = b"AASC-APPROVAL-v1"

# Named here so the agreement suite can assert both sides carry the SAME six
# domains -- a tag one side registered and the other did not would let a
# construction exist on one side of the boundary only.
NEW_TAGS = (
    PAYLOAD_TAG,
    AUTHZ_CONTEXT_TAG,
    LABEL_SET_TAG,
    LABEL_ASSERTION_TAG,
    DECLASSIFICATION_TAG,
    APPROVAL_TAG,
)


class LabelContextError(Exception):
    """Base: a SUT-side label-plumbing construction failed closed."""


def _framed(tag: bytes, canonical: bytes, version: int) -> bytes:
    """`TAG || VERSION || u32be(len(C)) || C`, assembled in one buffer.

    Deliberately built as a single concatenation rather than by incremental
    hash updates: the harness implementation streams it, this one materializes
    it, and the agreement suite compares the results. Two constructions, one
    specification.
    """
    if version != VERSION:
        raise LabelContextError(f"unsupported {tag.decode()} version {version}")
    return b"".join((tag, bytes([version]), len(canonical).to_bytes(4, "big"), canonical))


def signing_input(tag: bytes, payload: dict[str, Any], *, version: int = VERSION) -> bytes:
    """The bytes a `LabelAssertion` / `DeclassificationArtifact` /
    `ApprovalArtifact` signature is taken over."""
    return _framed(tag, rfc8785.dumps(payload), version)


def payload_digest(value: "str | bytes", *, version: int = VERSION) -> str:
    """SS A.6's join key, over a data VALUE and never over a JSON object.

    ADR 0009 forbids assuming `H_JCS` here: the same value must digest
    identically as a tool argument, as an `EffectEvent.payload_digest` and as a
    `ToolIngressEvent.payload_digest`, and under `H_JCS` it would depend on the
    object surrounding it. Anything that is neither `str` nor `bytes` is
    refused rather than serialized by a rule ADR 0030 did not fix.
    """
    if isinstance(value, str):
        canonical = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        canonical = bytes(value)
    else:
        raise LabelContextError(
            f"payload_digest is defined over str or bytes; got {type(value).__name__}"
        )
    return hashlib.sha256(_framed(PAYLOAD_TAG, canonical, version)).hexdigest()


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
    """SS F.2's mechanism-neutral request binding, over all six named inputs."""
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
    return hashlib.sha256(_framed(AUTHZ_CONTEXT_TAG, canonical, version)).hexdigest()


def label_assertions_digest(payload_digests, *, version: int = VERSION) -> str:
    """`INV.label_assertions_digest` over the SORTED presented join keys.

    Order-independent, so a reordered presentation of the same label set binds
    identically; and the empty set has a real digest rather than a sentinel, so
    an unlabelled invocation is bound as *no labels* rather than as *unfilled*.
    """
    canonical = rfc8785.dumps(sorted(payload_digests))
    return hashlib.sha256(_framed(LABEL_SET_TAG, canonical, version)).hexdigest()
