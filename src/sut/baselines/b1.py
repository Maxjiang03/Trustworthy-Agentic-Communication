"""`B1`: a static API key (SS E.5 bits `0 0 0 0 0 0 0 0 0 1`).

SS E.1's appendix arm, and its `Isolates` column is the whole point: **a static
secret adds nothing**. `B1` sits between `B0` (no delegation protection at all)
and the OAuth arms, and exists to show that adding *authentication* without
adding *authorization* moves no F1 outcome.

A shared secret is presented at the boundary and checked for equality. It
expresses **no authority**, **no audience binding** and **no scope**, and this
module is written so that is honestly true rather than merely intended: `decide`
takes `tool` and `arguments` and **reads neither** -- there is no code path by
which the invocation could influence the verdict, exactly as `B0`'s constant
return makes `B0` incapable of deciding anything. An arm that quietly consulted
the request would stop being the control the ladder needs.

**Expected, per SS E.4, and the admissions are the measurement.** `B1` **admits**
`F1-root` and `F1-terminal` -- a valid key authenticates a caller who is then
free to exceed the task grant -- and **blocks** `F2 invalid_credential` and
`F2 unauthenticated_caller`. `F1-chain-tamper` is **NA**: `B1` has no per-hop
authority chain to tamper with (SS E.3), and that NA is recorded as **data the
matrix fixture reads** from the sealed record, exactly as `B0`'s is, never as a
skipped cell.

**The key is `(key_id, secret)`, and only the id reaches any record.** SS F.1's
`ApiKeyEvidence` carries `raw_key_ref`, a *reference* -- so the id travels into
the observed evidence and the secret never does. The secret itself is injected
as start-up configuration, derived harness-side from the sealed seed, and
touches no disk (CLAUDE.md red line 8). A wrong secret under a valid id is
still distinguishable in the record, which a bare "which key was used" label
would not be.

`audit = 1`, like every arm above `B0`: the structured decision log is emitted
OFF the decision path, into the same bounded in-memory buffer ADR 0026
requires, so a sink failure costs log completeness and never a prevention
outcome (SS E.5).
"""

import hmac
from collections.abc import Mapping
from typing import Any

from src.sut.authz.capability_path import BoundedAuditBuffer
from src.sut.baselines.base import ArmBitmask, HopContext, InvocationContext

REASON_ADMITTED = "b1_admitted"
REASON_INVALID_CREDENTIAL = "b1_invalid_credential"
REASON_NO_CREDENTIAL = "b1_no_credential"
REASON_NOT_PROVISIONED = "b1_not_provisioned"


class B1ConfigurationError(Exception):
    """Provisioning was incomplete. Construction-time, fail closed."""


class B1Arm:
    """A static shared secret, checked for equality, and nothing else."""

    name = "B1"
    bitmask = ArmBitmask(
        oauth_authn=0,  # not OAuth: no issuer, no audience, no scope, no expiry
        crypto_chain=0,
        authorizer=0,
        htc_holder=0,
        invoke=0,
        contain=0,  # THE point: it authenticates, it does not authorize
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )

    def __init__(self) -> None:
        self._key_id: str | None = None
        self._secret: str | None = None
        self._presented: tuple[str, str] | None = None
        self.audit_log = BoundedAuditBuffer()

    # -- provision: the shared secret, injected, never read from disk -------- #
    def provision(self, setup: Mapping[str, Any]) -> None:
        missing = {"api_key_id", "api_key_secret"} - set(setup)
        if missing:
            raise B1ConfigurationError(f"{self.name} provisioning is missing {sorted(missing)}")
        if not setup["api_key_secret"]:
            raise B1ConfigurationError(f"{self.name} refuses an empty shared secret")
        self._key_id = setup["api_key_id"]
        self._secret = setup["api_key_secret"]
        self._presented = None

    # -- delegate: the envelope carries the key, and carries nothing else ---- #
    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        """A static secret is not attenuated, so the hop produces nothing new.

        `hop` names the authority the Supervisor holds and the narrowing it
        intends; **neither is read**. That is the arm: there is no per-hop
        object, so there is nothing for `F1-chain-tamper` to tamper with.
        """
        if self._secret is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        return {"api_key_id": self._key_id, "api_key_secret": self._secret}

    # -- present: stage what the boundary will compare ----------------------- #
    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        """Stage the key. `invocation` is not read: nothing binds to the call.

        The returned wire carries the **id only**. The secret is compared
        in-process and never enters the SS F.1 record (red line 8).
        """
        key_id = credentials.get("api_key_id")
        secret = credentials.get("api_key_secret")
        self._presented = (key_id, secret) if secret is not None else None
        return {"api_key_id": key_id} if key_id is not None else {}

    # -- decide: equality, and nothing that could depend on the request ------ #
    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        admitted, reason = self._decide()
        # audit=1, OFF the decision path: computed from the verdict, never
        # feeding it. `tool` is recorded because the log should say what was
        # asked; it took no part in the answer.
        try:
            self.audit_log.append(
                {
                    "layer": "api-key-boundary",
                    "arm": self.name,
                    "tool": tool,
                    "admitted": admitted,
                    "reason_code": reason,
                    "authority_consulted": False,
                }
            )
        except Exception:  # noqa: BLE001 -- log loss is never a prevention outcome
            pass
        return admitted, reason

    def _decide(self) -> tuple[bool, str]:
        """Takes NO arguments, so the request cannot reach the verdict.

        Structural, not a promise: the decision function has no parameter
        through which `tool` or `arguments` could arrive. `SS E.1`'s claim
        that a static secret adds nothing is only measurable if the arm is
        incapable of adding anything.
        """
        if self._secret is None:
            return False, REASON_NOT_PROVISIONED  # fail closed
        if self._presented is None:
            return False, REASON_NO_CREDENTIAL  # F2 unauthenticated_caller
        key_id, secret = self._presented
        if key_id != self._key_id or not hmac.compare_digest(secret, self._secret):
            return False, REASON_INVALID_CREDENTIAL  # F2 invalid_credential
        return True, REASON_ADMITTED
