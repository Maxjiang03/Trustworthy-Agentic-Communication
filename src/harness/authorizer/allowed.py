"""`Allowed(P_i; Gamma, kappa, Omega)` over the frozen configuration (gate G-2).

This module computes the effective authority set of SS A.0.1

    C_i = Allowed(P_i; Gamma, kappa, Omega)
        = { x in Omega | authorizer(P_i, x; Gamma) = permit
                         and crypto_chain_ok(P_i; kappa) }

by **running the pinned Biscuit authorizer**, exactly as ADR 0016 specifies the
evaluation: one independent authorizer run per candidate `x` in `Omega`, with
`operation(<action>, <resource>)`, `time`, `request_audience` and
`request_task` injected as **authorizer** facts (never token facts), and
membership iff that run selects an `allow` policy. No policy match, or any
failed check, is a **deny** (fail closed).

`Gamma` and `Omega` are read from the frozen artifact through
`frozen_config.load_document()`. Nothing here restates them: the Datalog text
handed to the authorizer is the frozen bytes, and the blocks are rendered from
the frozen templates (`render_block`), so what gate G-2 adjudicates is the
sealed configuration rather than a paraphrase of it.

**Prefix identity is ADR 0003's, not a second notion.** A `Chain` holds one
serialized token per hop; `P_i` is the token at hop `i`, whose blocks are
`<SignedBlock_0, ..., SignedBlock_i>` (SS A.0.1). Block identifiers and prefix
commitments come from `src/harness/oracle/commitment.py` — the same
`BlockID_i` / `commit_prefix` construction G-1 verified — and `Chain` checks
that each hop's identifier list really is a prefix of the next, so the prefix
relation is *verified from signatures*, never assumed from call order.

**Profile enforcement is pre-evaluation** (SS A.6.1 MSc profile MUST): a token
carrying a third-party (external-signature) block, or a non-Ed25519 key, is
refused before any Datalog runs — by `commitment.block_ids_from_raw`, which
this module calls first; and a configuration that permits `trusting`
annotations, trusts more than `kappa`, accepts third-party blocks, or asks for
non-default block scoping is refused before any token is touched.

Scope. This module evaluates authorizer semantics. It is **not** the AS
(gate G-4), implements no arm, no HTC/INV (gate G-11), and no oracle
predicate; the chain builders here mint capability fixtures for gate and
regression use only.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from biscuit_auth import (
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Fact,
    PrivateKey,
    PublicKey,
)

from src.harness.authorizer import frozen_config
from src.harness.oracle import commitment

# Placeholders of the frozen templates (ADR 0016 SS 3). A template line
# carrying an element placeholder is instantiated once per element of the
# authority set; every other placeholder is substituted once.
_ELEMENT_PLACEHOLDERS = ("<action>", "<resource>")


class AuthorizerProfileError(frozen_config.FrozenConfigError):
    """The configuration or the token is outside the MSc profile (SS A.6.1)."""


class ChainStructureError(frozen_config.FrozenConfigError):
    """The presented hops are not a signed-block prefix chain."""


@dataclass(frozen=True)
class RequestContext:
    """The facts injected per authorizer run, besides the candidate operation."""

    now: datetime
    audience: str
    task: str

    def facts(self) -> list[Fact]:
        return [
            Fact("time({t})", {"t": self.now}),
            Fact("request_audience({aud})", {"aud": self.audience}),
            Fact("request_task({task})", {"task": self.task}),
        ]


def render_block(template: str, elements: list[tuple[str, str]], **values: str) -> str:
    """Instantiate a frozen block template.

    A line containing `<action>`/`<resource>` is emitted once per element; any
    other placeholder is substituted from `values`; comment lines pass through.
    The template text is the frozen artifact's, so the emitted Datalog is a
    rendering of the sealed template rather than a restatement of it.
    """
    out: list[str] = []
    for line in template.splitlines():
        if any(placeholder in line for placeholder in _ELEMENT_PLACEHOLDERS):
            for action, resource in elements:
                out.append(line.replace("<action>", action).replace("<resource>", resource))
            continue
        for key, value in values.items():
            line = line.replace(f"<{key}>", value)
        out.append(line)
    rendered = "\n".join(out) + "\n"
    if "<" in rendered and ">" in rendered:
        leftover = [ln for ln in out if "<" in ln and ">" in ln and not ln.strip().startswith("//")]
        if leftover:
            raise ChainStructureError(f"unsubstituted placeholder in rendered block: {leftover!r}")
    return rendered


def datalog_instant(moment: datetime) -> str:
    """Biscuit date literal for a template `<instant>` substitution."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Chain:
    """A capability chain as the ordered serialized prefixes `P_0 .. P_n`.

    `hops[i]` is the token whose signed blocks are `SignedBlock_0..SignedBlock_i`.
    Construction verifies, from ADR 0003 block identifiers, that each hop really
    extends the previous one.
    """

    hops: tuple[bytes, ...]
    root_pub: PublicKey

    def __post_init__(self) -> None:
        if not self.hops:
            raise ChainStructureError("a chain needs at least the authority block")
        previous: list[bytes] = []
        for index, token_bytes in enumerate(self.hops):
            block_ids = commitment.block_ids_from_raw(token_bytes, self.root_pub)
            if len(block_ids) != index + 1:
                raise ChainStructureError(
                    f"hop {index} presents {len(block_ids)} signed blocks, expected {index + 1}"
                )
            if block_ids[: len(previous)] != previous:
                raise ChainStructureError(f"hop {index} is not an extension of hop {index - 1}")
            previous = block_ids

    @property
    def length(self) -> int:
        return len(self.hops)

    def prefix(self, index: int) -> bytes:
        """Serialized `P_index`."""
        return self.hops[index]

    def block_ids(self, index: int) -> list[bytes]:
        return commitment.block_ids_from_raw(self.hops[index], self.root_pub)

    def commitment(self, index: int) -> bytes:
        """`H(P_index)` — the ADR 0003 / SS A.0.1 `commit_prefix`, as used by G-1."""
        block_ids = self.block_ids(index)
        return commitment.commit_prefix(block_ids, len(block_ids) - 1)


def build_chain(
    doc: dict[str, Any],
    root_key: PrivateKey,
    root_pub: PublicKey,
    authority: list[tuple[str, str]],
    attenuations: list[list[tuple[str, str]]],
    *,
    audience: str,
    task: str,
    expiry: datetime,
) -> Chain:
    """Mint `P_0` from the frozen authority template, then append one attenuation
    block per hop from the frozen attenuation template.

    Fixture minting for gates and regression tests only — this is not the
    experiment AS (ADR 0015, gate G-4) and issues no OAuth artifact.
    """
    templates = doc["gamma"]["datalog"]
    builder = BiscuitBuilder()
    builder.add_code(
        render_block(
            templates["authority_block_template"],
            authority,
            audience=audience,
            task_id=task,
            instant=datalog_instant(expiry),
        )
    )
    token = builder.build(root_key)
    hops = [bytes(token.to_bytes())]
    for elements in attenuations:
        token = token.append(
            BlockBuilder(render_block(templates["attenuation_block_template"], elements))
        )
        hops.append(bytes(token.to_bytes()))
    return Chain(tuple(hops), root_pub)


def check_profile(doc: dict[str, Any], gamma: dict[str, Any] | None = None) -> None:
    """Fail closed unless the configuration is inside the MSc profile (SS A.6.1).

    Refuses before any token is evaluated: more than one trusted key, third-party
    blocks accepted, `trusting` annotations permitted or present anywhere in the
    frozen Datalog, or non-default block scoping.
    """
    gamma = gamma if gamma is not None else doc["gamma"]
    trust = gamma["trust"]
    if trust["trusted_keys"] != ["kappa"] or trust["trusted_key_count"] != 1:
        raise AuthorizerProfileError(f"out of profile: trusted key set {trust['trusted_keys']!r}")
    if trust["third_party_blocks"] != "reject":
        raise AuthorizerProfileError("out of profile: third-party blocks are not rejected")
    if trust["trusting_annotations"] != "forbidden":
        raise AuthorizerProfileError("out of profile: `trusting` annotations are permitted")
    if trust["block_scoping"] != "default":
        raise AuthorizerProfileError(f"out of profile: block scoping {trust['block_scoping']!r}")
    for name, source in gamma["datalog"].items():
        if isinstance(source, str) and "trusting" in source:
            # An authorizer importing external-key facts is out of profile and
            # MUST be rejected before evaluation (SS A.6.1).
            raise AuthorizerProfileError(f"out of profile: `trusting` annotation in {name!r}")


def authorize_candidate(
    token_bytes: bytes,
    root_pub: PublicKey,
    gamma: dict[str, Any],
    candidate: tuple[str, str],
    context: RequestContext,
) -> tuple[bool, str]:
    """One authorizer run for one candidate. Returns (permitted, evidence).

    `permitted` is true iff the run selects an `allow` policy with every check
    satisfied; `AuthorizationError` (no matching policy, or a failed check) is a
    deny. Any other exception propagates — this never converts an error into a
    verdict.
    """
    token = Biscuit.from_bytes(token_bytes, root_pub)
    builder = AuthorizerBuilder(gamma["datalog"]["authorizer"])
    action, resource = candidate
    builder.add_fact(
        Fact("operation({action}, {resource})", {"action": action, "resource": resource})
    )
    for fact in context.facts():
        builder.add_fact(fact)
    authorizer = builder.build(token)
    try:
        index = authorizer.authorize()
    except AuthorizationError as exc:
        return False, _ascii(str(exc))
    return True, f"allow policy index {index}"


def allowed(
    chain: Chain,
    doc: dict[str, Any],
    context: RequestContext,
    *,
    gamma: dict[str, Any] | None = None,
) -> frozenset[tuple[str, str]]:
    """`Allowed(P_i; Gamma, kappa, Omega)` for the prefix `Gamma` names.

    `evaluation.prefix` selects which prefix is authorized: `P_n` (the operative
    configuration) authorizes the presented terminal prefix; `P_0` (the
    `-attenuation` control, SS E.6) authorizes the authority block alone,
    ignoring every attenuation block. `crypto_chain_ok(P_i; kappa)` is enforced
    first and fails closed by raising, so a caller can never mistake an
    unverifiable prefix for one that admits nothing.
    """
    gamma = gamma if gamma is not None else frozen_config.gamma(doc)
    check_profile(doc, gamma)
    prefix_name = gamma["evaluation"]["prefix"]
    if prefix_name == "P_n":
        index = chain.length - 1
    elif prefix_name == "P_0":
        index = 0
    else:
        raise AuthorizerProfileError(f"unsupported evaluation prefix {prefix_name!r}")
    token_bytes = chain.prefix(index)
    commitment.block_ids_from_raw(token_bytes, chain.root_pub)  # crypto_chain_ok + profile
    return frozenset(
        candidate
        for candidate in sorted(frozen_config.omega(doc))
        if authorize_candidate(token_bytes, chain.root_pub, gamma, candidate, context)[0]
    )


def _ascii(text: str) -> str:
    """Library messages carry a `n°` sign; keep evidence strings ASCII-safe."""
    return text.encode("ascii", "replace").decode("ascii")
