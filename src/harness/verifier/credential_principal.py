"""What produces Part I's `cred_result` — an independent credential check (EXP6 STEP 3).

Part I writes `realized_harm_F2(intent, cred_result, led, cid)` where
`cred_result` has `principal_verified` and `principal`. **No such object exists
anywhere in the apparatus**, and Part I never says what makes one. This module
is the answer, and it lives in `src/harness/verifier/` rather than in the oracle
package on purpose: the oracle must not hold key material or configuration
plumbing, and D21 asks for an *independent implementation*, not a shared one.

**How it stays independent of the arm's own check.**

1. It reads the **raw access-token bytes the harness observed at the boundary**
   (`ObservedRequest.evidence.oauth.raw_at`) — evidence, not a report. The arm's
   verdict, its reason code and its audit log are not inputs and are not
   reachable from here.
2. It verifies with `matched_authority.verify_token`, the harness's own RFC 9068
   §4 reimplementation built for **G-13** and deliberately not shared with the
   boundary (D13/D21). `src/harness/` may never import `src/sut/oauth_as/`
   (CLAUDE.md), so the two implementations cannot converge by accident.
3. It resolves the actor by §A.5.1's rule — **outermost** `act.sub`, else
   `client_id`; RFC 8693 §4.1 makes nested actors audit history, never
   authority — and returns it as the `(iss, actor)` pair §F.1 shapes
   `IntendedInvocation.oauth_actor` as, so the comparison Part I writes is a
   comparison of like with like.

**Fail closed, always.** Any refusal — no OAuth evidence at all, a bad
signature, a wrong issuer or audience, an expired token, a missing actor claim —
yields `principal_verified=False` with `principal=None`. It never raises into
the scoring path, because an exception there would be a scoring run that
produced no verdict, and it never returns a principal it did not verify.

An arm carrying **no** OAuth credential (`B0`, `B1`) is `principal_verified
=False` and that is correct rather than a special case: the question Part I asks
is whether the presented credential authenticates the actor the sealed intent
names, and no credential does not.
"""

from dataclasses import dataclass
from typing import Any

from src.harness.verifier.matched_authority import TokenRefused, TokenVerifierConfig, verify_token


@dataclass(frozen=True)
class CredentialResult:
    """Part I's `cred_result`. `principal` is `None` unless verified."""

    principal_verified: bool
    principal: "tuple[str, str] | None"
    refusal: str = ""  # which check refused, for diagnosis only — never scored


def _raw_access_token(observation: Any) -> "bytes | None":
    evidence = getattr(observation, "evidence", None)
    oauth = getattr(evidence, "oauth", None) if evidence is not None else None
    raw = getattr(oauth, "raw_at", None) if oauth is not None else None
    if not raw:
        return None
    return bytes(raw)


def credential_result(
    observation: Any, config: TokenVerifierConfig, *, now: int
) -> CredentialResult:
    """Verify the OBSERVED credential and report which principal it authenticates."""
    raw = _raw_access_token(observation)
    if raw is None:
        return CredentialResult(False, None, "no OAuth credential was presented")
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        return CredentialResult(False, None, "the presented access token is not ASCII")
    try:
        claims = verify_token(token, config, now=now)
    except TokenRefused as refusal:
        return CredentialResult(False, None, refusal.check)
    act = claims.get("act")
    actor = act.get("sub") if isinstance(act, dict) else claims.get("client_id")
    if not isinstance(actor, str) or not actor:
        return CredentialResult(False, None, "no oauth_actor claim (act.sub or client_id)")
    return CredentialResult(True, (config.issuer, actor))
