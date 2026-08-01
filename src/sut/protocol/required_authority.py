"""Server-side required authority: `R = required_authority(concrete_request, server_policy)`.

SS A.5 fixes the two properties this module exists for, and both are tested:

* `R` is computed **server-side from the concrete request** -- the tool being
  invoked and the resource its arguments concretely name -- under a server
  policy that is data, not agent input.
* `R` **MUST NOT read any agent-supplied authority declaration.** An agent
  cannot lower (or raise) what a request requires by *saying* something about
  scope: only the designated resource argument of the concrete call enters
  the computation, and a `scope`/`declared_scope`/`authority` field in the
  arguments has no effect (regression-tested).

The action vocabulary is the tool name itself -- the frozen `Omega` declares
every action to be a tool (`omega.tools`, ADR 0016) -- and the resource is
either read from the one designated argument (`calendar.read`, `notes.*`) or
fixed by the server for tools whose resource is not caller-addressable
(`mail.send` always acts on `mail/outbox`). Everything else fails closed:
unknown tool, missing or non-string resource argument, or a resource outside
the frozen `root '/' collection` grammar.

This module deliberately does NOT check `R` against `Omega` or any authority
set: membership and containment are the authorizer's and the boundary's
business (`R subset-of C_n` is a SS A.5 conjunct), and conflating "what does
this request require" with "is it allowed" would blur the two quantities the
oracle scores separately.
"""

import re
from collections.abc import Mapping
from typing import Any

# The frozen Omega resource grammar (ADR 0016): root '/' collection, exactly
# one '/', lowercase us-ascii. Enforced here so a malformed resource fails
# closed at R-computation rather than surfacing as a spurious containment
# verdict downstream.
_RESOURCE_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+$")

# The server policy: data, keyed by tool. `resource_argument` names the ONE
# argument the resource is read from, with the root it must live under;
# `fixed_resource` pins the resource regardless of arguments;
# `recipient_argument` names the argument carrying the effect's recipient, and
# its PRESENCE is what makes an action egress (ADR 0022 row 4's rule, applied
# to this plane's view). It is declared per tool here rather than as a list of
# egress actions anywhere, so the egress set is derived from the tool surface
# over `Omega` and an ontology amendment cannot desynchronise the two.
SERVER_POLICY: dict[str, dict[str, str]] = {
    "calendar.read": {"resource_argument": "resource", "root": "calendar"},
    "notes.read": {"resource_argument": "resource", "root": "notes"},
    "notes.write": {
        "resource_argument": "resource",
        "root": "notes",
        "payload_argument": "content",
    },
    "notes.delete": {"resource_argument": "resource", "root": "notes"},
    "mail.send": {
        "fixed_resource": "mail/outbox",
        "recipient_argument": "to",
        # ADR 0030: which argument carries the DATA VALUE a label attaches
        # to. Server-side, like every other field here -- an agent-supplied
        # hint about which of its own arguments is "the payload" would let
        # it point the label plane at a value it did not send.
        "payload_argument": "body",
    },
}


def recipient_carrying_actions(
    policy: Mapping[str, Mapping[str, str]] = SERVER_POLICY,
) -> frozenset[str]:
    """The actions whose effect carries a recipient -- ADR 0022's egress set.

    Derived from the server policy, never enumerated: over the frozen `Omega`
    this is exactly `{mail.send}`, and a test asserts that rather than the
    document declaring it.
    """
    return frozenset(tool for tool, rule in policy.items() if "recipient_argument" in rule)


def egress_recipient(
    tool: str,
    arguments: Mapping[str, Any],
    policy: Mapping[str, Mapping[str, str]] = SERVER_POLICY,
) -> str | None:
    """The recipient this concrete request would send to, or None if non-egress.

    Server-side like `required_authority`: the recipient is read from the ONE
    argument the policy designates, never from an agent-supplied claim about
    where the data is going.
    """
    rule = policy.get(tool)
    if rule is None:
        raise RequiredAuthorityError(f"no server policy for tool {tool!r}")
    name = rule.get("recipient_argument")
    if name is None:
        return None
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise RequiredAuthorityError(
            f"{tool!r} is an egress action but its {name!r} argument names no recipient"
        )
    return value


class RequiredAuthorityError(Exception):
    """The concrete request does not determine a well-formed R. Fail closed."""


def required_authority(
    tool: str,
    arguments: Mapping[str, Any],
    policy: Mapping[str, Mapping[str, str]] = SERVER_POLICY,
) -> frozenset[tuple[str, str]]:
    """The authority this concrete request requires, as SS F.1 pairs."""
    rule = policy.get(tool)
    if rule is None:
        raise RequiredAuthorityError(f"no server policy for tool {tool!r}")
    if "fixed_resource" in rule:
        resource = rule["fixed_resource"]
    else:
        name = rule["resource_argument"]
        value = arguments.get(name)
        if not isinstance(value, str):
            raise RequiredAuthorityError(
                f"{tool!r} requires a string {name!r} argument to name its resource"
            )
        if not _RESOURCE_RE.match(value) or not value.startswith(rule["root"] + "/"):
            raise RequiredAuthorityError(
                f"{tool!r} resource {value!r} violates the frozen grammar or names a foreign root"
            )
        resource = value
    return frozenset({(tool, resource)})


def payload_argument(tool: str, policy: "Mapping[str, Any] | None" = None) -> str | None:
    """Which argument of `tool` carries the data VALUE, per the SERVER policy."""
    entry = (policy or SERVER_POLICY).get(tool)
    return None if entry is None else entry.get("payload_argument")


def carried_payloads(
    tool: str, arguments: "Mapping[str, Any]", policy: "Mapping[str, Any] | None" = None
) -> "dict[str, Any]":
    """`payload_digest -> value` for the values this call actually carries.

    SS A.6 resolves label assertions **by payload digest**, so the boundary must
    know which digests the request really carries before it can decide that a
    presented assertion describes one of them. Computed here from the concrete
    arguments and the SERVER's own policy -- never from anything the agent
    asserts about its own request.
    """
    from src.sut.authz import label_context as lc

    name = payload_argument(tool, policy)
    if name is None:
        return {}
    value = (arguments or {}).get(name)
    if not isinstance(value, (str, bytes, bytearray)):
        # No value, or one ADR 0030 fixes no digest for. Fail closed by
        # carrying nothing: an unresolvable payload must never be treated as
        # one that happens to be unlabelled.
        return {}
    return {lc.payload_digest(value): value}
