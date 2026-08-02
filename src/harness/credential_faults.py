"""The attacker between the arm and the resource server (EXP7 STEP 3).

Five §E.4 subcases are **credential attacks, not authority-scope attacks**. Every
scenario the corpus carried before them was expressible as **data** — tool,
arguments, `R`, chain — and none of these five is: each needs a specific
**corruption of the runtime credential**, which the generator has no vocabulary
for. The fault is declared in the **sealed** document and realized here, per
mechanism — the *intent realized per mechanism* pattern `widening_elements`
already uses for chain-tamper. Sealed, **never SUT-visible**: a visible fault
would let an arm branch on *"I am under attack."*

**Every fault is presentation-level. There is no provisioning level.** The first
design proposed one and building it disproved it: `B2ExchangeTaskArm.provision`
calls `verify_access_token` on the injected subject token and raises
`B2ConfigurationError` — a check that exists on purpose, so `B2` cannot be
misprovisioned — so a provisioning-level corruption tests the arm's
**configuration** and raises **before the boundary is reached**. No
`MediationEvent`, nothing for the oracle, while §E.4's rows are about what the
**boundary** does. §D.2 said so all along: every one of its four adversaries
**holds a captured credential and presents it**, or sits between proof signing
and the TLS client. None tampers with what the arm was legitimately provisioned
with.

**It re-signs and re-stages; it never weakens.** No arm is modified, no conjunct
disabled, nothing made easier to pass. What the boundary receives is a
well-formed artifact presented by the wrong party or bound to the wrong token —
which is the attack.

**`B1` has its own limb, and its absence was a real defect.** `B1`'s credential
is a **static API key** (`api_key_secret`); it carries no `access_token` at all.
A token fault therefore left it untouched and it **admitted**, while §E.4
predicts **B**. That is the **second** place `B1`'s secret plane went missing
from an abstraction — the first is §E.5's bitmask, which has no column for it
(ADR 0035). Any future mechanism enumerating credentials must ask what `B1`
carries rather than enumerating the two mechanisms that happen to be interesting.
"""

import dataclasses
import json
from typing import Any

from joserfc.jwk import OKPKey

from src.harness import key_material
from src.harness.verifier.at_digest import access_token_hash
from src.harness.verifier.holder_binding import INV_TAG, seal

FAULTS = (
    "none",
    "invalid_credential",
    "unauthenticated_caller",
    "audience_mismatch",
    "wrong_registered_holder",
    "stolen_AT_key_substitution",
)
TOKEN_FAULTS = ("invalid_credential", "unauthenticated_caller", "audience_mismatch")
HOLDER_FAULTS = ("wrong_registered_holder", "stolen_AT_key_substitution")
PRESENTATION_FAULTS = TOKEN_FAULTS + HOLDER_FAULTS

# A REGISTERED but wrong holder, so `actor_of(...)` still resolves and the
# registry lookup SUCCEEDS -- which leaves `holder_proof_ok` as the only
# conjunct that can catch the substitution. An unregistered key here would be
# caught by the identity plane instead, measuring the wrong thing.
WRONG_REGISTERED_HOLDER_LABEL = "holder-worker"
# The attacker's own key, under a label in NO registry entry -- unregistered by
# construction rather than by hoping.
ATTACKER_HOLDER_LABEL = "attacker-not-in-the-registry"


class CredentialFaultError(Exception):
    """The fault could not be realized. Never silently a no-op: a fault that did
    not apply would score as the arm behaving well."""


def validate(fault: str) -> str:
    if fault not in FAULTS:
        raise CredentialFaultError(f"unknown credential_fault {fault!r}; expected one of {FAULTS}")
    return fault


def apply_to_setup(fault: str, setup: "dict[str, Any]", **_: Any) -> "dict[str, Any]":
    """**The arm is provisioned legitimately. Nothing is corrupted here.**

    Kept as an explicit no-op so the absence of a provisioning level is
    something a reader can point at; see the module docstring for why it went.
    """
    validate(fault)
    return dict(setup)


# ---------------------------------------------------------------------------
# the attacker, between `present` and `decide`
# ---------------------------------------------------------------------------
def apply_to_presentation(
    fault: str,
    arm: Any,
    *,
    seed: bytes,
    now: int,
    wrong_audience_token: "str | None" = None,
) -> bool:
    """Corrupt what the arm STAGED. Returns whether anything was corrupted.

    `False` is a real answer, not a failure: `B0` stages no credential at all,
    and §E.4 predicts it **admits** — a measurable vulnerability (ADR 0035).
    For the holder faults `False` is the reason six cells are `NA`.
    """
    validate(fault)
    if fault == "none":
        return False
    if fault in TOKEN_FAULTS:
        # `B1` first: its credential is neither an OAuth token nor a capability,
        # and every abstraction built around those two has dropped it twice.
        return _restage_api_key(arm, fault) or _restage_token(
            arm, fault, now=now, other=wrong_audience_token
        )
    private = _substitute_key(fault, seed)
    return _restage_inv(arm, private) or _restage_dpop_proof(arm, fault, seed, now)


def _restage_api_key(arm: Any, fault: str) -> bool:
    """`B1`'s static shared secret. `present` stages `(key_id, secret)`.

    `audience_mismatch` deliberately does **not** apply: an API key names no
    resource server, so there is no audience to mismatch. That returns `False`
    and the arm admits — which is §E.4's `A` for `B1` on that row, and is an
    inability of the *mechanism* rather than a gap in this injector.
    """
    presented = getattr(arm, "_presented", None)
    if presented is None or not isinstance(presented, tuple) or len(presented) != 2:
        return False
    key_id, secret = presented
    if fault == "unauthenticated_caller":
        arm._presented = None  # a caller presenting nothing
        return True
    if fault == "invalid_credential":
        arm._presented = (key_id, str(secret) + "-forged")
        return True
    return False


def _restage_token(arm: Any, fault: str, *, now: int, other: "str | None") -> bool:
    """Swap the access token the arm staged for the boundary.

    The arm was provisioned legitimately and its own checks passed; what reaches
    the resource server is the attacker's substitute.
    """
    staged = getattr(arm, "_staged", None)
    if staged is None or not hasattr(staged, "access_token"):
        return False
    current = str(getattr(staged, "access_token") or "")
    if fault == "unauthenticated_caller":
        replacement = ""
    elif fault == "invalid_credential":
        if not current:
            return False
        replacement = _corrupt_signature(current)
    else:  # audience_mismatch
        if not other:
            raise CredentialFaultError(
                "audience_mismatch needs a token minted for another resource server; none was "
                "supplied. Refusing rather than presenting the correct token, which would score "
                "as the arm admitting an attack that was never staged"
            )
        replacement = other
    arm._staged = dataclasses.replace(staged, access_token=replacement)
    # THE GENERAL RULE (EXP7): **any presented artifact that binds the credential
    # being substituted must be re-minted under the ARM'S OWN key after fault
    # injection.** There are two today -- DPoP's `ath` (RFC 9449 SS 4.3) and the
    # INV's `access_token_hash` (ADR 0018) -- and any binding added later
    # inherits it. Otherwise the binding fails FIRST and the cell reads B while
    # measuring the binding instead of the credential: trap 1, which this corpus
    # has now sprung five times.
    _rebind_ath(arm, replacement, now)
    _rebind_inv(arm, replacement)
    return True


def _rebind_inv(arm: Any, token: str) -> None:
    """Re-mint the staged INV under the arm's OWN holder key (ADR 0018).

    Structurally identical to `_rebind_ath`: the INV binds `access_token_hash`,
    so a swapped token breaks `invocation_binding_ok` before the OAuth limb is
    reached. Re-signed with the arm's own key and its own payload, changing
    exactly one field -- so the TOKEN stays the only attack surface, which is
    what SS E.4's credential rows are about.

    Reading this instead as *"B3's INV catches token substitution a conjunct
    earlier"* would double-count: that property is already measured by
    `F3 dpop-first-use-body-mutation` and reported as G-14's C2 attribution, and
    scoring it again here is the duplication ADR 0035's NA test forbids.
    """
    staged = getattr(arm, "_staged", None)
    wire = getattr(staged, "invocation_assertion", None) if staged is not None else None
    setup = getattr(arm, "_setup", None)
    if not wire or not setup:
        return
    holders = setup.get("holder_privates") or {}
    raw = holders.get("holder-specialist")
    if raw is None:
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    envelope = json.loads(bytes(wire))
    payload = dict(envelope["payload"])
    if "access_token_hash" not in payload:
        return
    # Computed for the EMPTY token too, not skipped: the boundary recomputes
    # `H(presented token)` whatever was presented, so a skipped re-mint would
    # leave `unauthenticated_caller` failing the binding first -- the same trap
    # one fault along.
    try:
        payload["access_token_hash"] = access_token_hash(token)
    except Exception:  # noqa: BLE001 -- a token that cannot be hashed binds to nothing
        payload["access_token_hash"] = ""
    arm._staged = dataclasses.replace(
        staged,
        invocation_assertion=seal(INV_TAG, payload, Ed25519PrivateKey.from_private_bytes(raw)),
    )


def _rebind_ath(arm: Any, token: str, now: int) -> None:
    """Re-mint the DPoP proof under the arm's OWN key after a token swap.

    RFC 9449 §4.3 binds `ath` to the presented token. Swapping the token without
    re-minting would make the **proof** fail first, so the cell would read `B`
    while measuring `holder_proof_ok` instead of the token check — trap 1 in a
    new place. The arm's own key is used deliberately: only the *token* is the
    attack here.
    """
    if not hasattr(arm, "restage_proof") or getattr(arm, "staged_proof", None) is None:
        return
    from src.sut import dpop

    key = getattr(arm, "_proof_key", None)
    if key is None:
        return
    arm.restage_proof(
        dpop.create_proof(
            key,
            method=getattr(arm, "RESOURCE_METHOD", "POST"),
            url=arm._resource_url,
            ath=dpop.access_token_hash(token) if token else None,
            iat=now,
        )
    )


def _corrupt_signature(token: str) -> str:
    """Flip the last base64url character of the JWS signature.

    Header and claims stay **byte-identical**, so what fails is the signature
    check and nothing earlier: an arm that refuses this refuses because the
    credential does not verify, not because it could not be parsed.
    """
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise CredentialFaultError("the access token is not a three-part JWS; nothing to corrupt")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = parts[2][-1]
    return ".".join(
        parts[:2] + [parts[2][:-1] + (alphabet[0] if last != alphabet[0] else alphabet[1])]
    )


def _substitute_key(fault: str, seed: bytes):
    label = (
        WRONG_REGISTERED_HOLDER_LABEL
        if fault == "wrong_registered_holder"
        else ATTACKER_HOLDER_LABEL
    )
    return key_material.holder_private(seed, label)


def _restage_inv(arm: Any, private) -> bool:
    """Re-sign the staged INV under a different key. `B3`, `B3⁺`.

    The payload crosses **unchanged** — same tool, same arguments, same digests,
    same window — so the only thing that differs is who signed it. That is what
    makes a refusal attributable to `holder_proof_ok` rather than to any binding
    the payload carries.
    """
    staged = getattr(arm, "_staged", None)
    wire = getattr(staged, "invocation_assertion", None) if staged is not None else None
    if not wire:
        return False
    envelope = json.loads(bytes(wire))
    arm._staged = dataclasses.replace(
        staged, invocation_assertion=seal(INV_TAG, envelope["payload"], private)
    )
    return True


def _restage_dpop_proof(arm: Any, fault: str, seed: bytes, now: int) -> bool:
    """Re-sign the staged DPoP proof under a different key. `B2-DPoP`.

    Uses the arm's own `restage_proof` seam and the same wire builder a client
    uses: an attacker with its own key produces a well-formed proof, and the
    boundary's `cnf`/`jkt` comparison is what refuses it.
    """
    if not hasattr(arm, "restage_proof") or getattr(arm, "staged_proof", None) is None:
        return False
    from src.sut import dpop

    label = (
        WRONG_REGISTERED_HOLDER_LABEL
        if fault == "wrong_registered_holder"
        else ATTACKER_HOLDER_LABEL
    )
    substitute = OKPKey.import_key(key_material.dpop_private_jwk(seed, label))
    token = getattr(getattr(arm, "_staged", None), "access_token", None)
    arm.restage_proof(
        dpop.create_proof(
            substitute,
            method=getattr(arm, "RESOURCE_METHOD", "POST"),
            url=arm._resource_url,
            ath=dpop.access_token_hash(token) if token else None,
            iat=now,
        )
    )
    return True


__all__ = [
    "ATTACKER_HOLDER_LABEL",
    "FAULTS",
    "HOLDER_FAULTS",
    "PRESENTATION_FAULTS",
    "TOKEN_FAULTS",
    "WRONG_REGISTERED_HOLDER_LABEL",
    "CredentialFaultError",
    "apply_to_presentation",
    "apply_to_setup",
    "validate",
]
