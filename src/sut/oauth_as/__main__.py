"""Process entry point: `python -m src.sut.oauth_as <config.json>`.

The runner starts the AS this way before a campaign (ADR 0015 rule 1). The
sealed seed arrives in the environment variable named below and **never** on the
command line, where it would be visible in a process listing; the configuration
file carries no secret at all -- client secrets are derived here, inside this
process, from the same seed (DESIGN SS 5.1).

On start-up one JSON line is written to stdout so the parent can reach the
server: the bound port, the AS **public** JWK, the TLS certificate, and --
when the document carries a `phase1` section -- the **Phase-1 base tokens**,
one per registered client (ADR 0021; SS E.2 Phase 1). Port, JWK and
certificate are public by construction; the signing key and the seed never
appear. The Phase-1 tokens are NOT public: the stdout pipe is held by the
spawning runner alone, and the tokens are runtime-only -- never written to
disk, never committed, never echoed into `results/` (ADR 0021). Minting
happens here, inside the AS process, because `exchange.issue_initial` is the
SS E.2 pre-issued path: deliberately unreachable from the token endpoint, and
importable by no non-AS module (ADR 0015 rule 3), so the only lawful call
site is this process.
"""

import json
import os
import sys
from pathlib import Path

from src.sut.oauth_as.config import ASConfig, RegistryEntry
from src.sut.oauth_as.exchange import issue_initial
from src.sut.oauth_as.keys import derive_client_secret, derive_signing_key, derive_tls_key
from src.sut.oauth_as.server import build_tls_context, serve_in_thread

SEED_ENV = "AASC_G4_AS_SEED"  # hex-encoded sealed seed, runner-supplied


def config_from_document(document: dict, seed: bytes) -> ASConfig:
    """Build the run-time configuration, deriving every client secret in-process."""
    return ASConfig(
        issuer=document["issuer"],
        token_endpoint=document["token_endpoint"],
        rar_type=document["rar_type"],
        omega=frozenset((action, resource) for action, resource in document["omega"]),
        resource_servers=frozenset(document["resource_servers"]),
        clients={
            client_id: derive_client_secret(seed, client_id) for client_id in document["clients"]
        },
        registry={
            actor: RegistryEntry(
                principal=entry["principal"],
                identity_jwk=entry["identity_jwk"],
                holder_jwk=entry["holder_jwk"],
            )
            for actor, entry in document["registry"].items()
        },
        delegation_policy=dict(document["delegation_policy"]),
        default_lifetime_seconds=int(document.get("default_lifetime_seconds", 300)),
        require_dpop=bool(document.get("require_dpop", False)),
        require_dpop_nonce=bool(document.get("require_dpop_nonce", False)),
    )


def mint_phase1_tokens(document: dict, config: ASConfig, signing_key) -> dict[str, str]:
    """One Phase-1 base `AT@aud` per registered client (ADR 0021; SS E.2).

    The `phase1` section, when present, MUST cover exactly the registered
    client set -- a client with no provisioning spec, or a spec for an
    unregistered client, fails closed rather than silently skipping. When the
    section is absent (pre-EXP1 documents, e.g. gate G-4's), nothing is
    minted and the start-up line carries an empty mapping.
    """
    phase1 = document.get("phase1")
    if phase1 is None:
        return {}
    if set(phase1) != set(document["clients"]):
        raise SystemExit(
            "phase1 provisioning must cover exactly the registered clients: "
            f"phase1={sorted(phase1)} clients={sorted(document['clients'])}"
        )
    tokens: dict[str, str] = {}
    for client_id, spec in phase1.items():
        token = issue_initial(
            config=config,
            signing_key=signing_key,
            subject=spec["subject"],
            client_id=client_id,
            audience=spec["audience"],
            scope=spec["scope"],
            authorization_details=spec["authorization_details"],
            lifetime_seconds=spec.get("lifetime_seconds"),
        )
        tokens[client_id] = token.value
    return tokens


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m src.sut.oauth_as <config.json>", file=sys.stderr)
        return 2
    seed_hex = os.environ.get(SEED_ENV)
    if not seed_hex:
        print(
            f"{SEED_ENV} is not set; the AS cannot start without its sealed seed", file=sys.stderr
        )
        return 2

    seed = bytes.fromhex(seed_hex)
    document = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    signing_key = derive_signing_key(seed)  # parsed once, reused (SS 8.2)
    tls_context, cert_pem = build_tls_context(derive_tls_key(seed))

    config = config_from_document(document, seed)
    server, _ = serve_in_thread(config, signing_key, tls_context)
    print(
        json.dumps(
            {
                "port": server.port,
                "public_jwk": signing_key.public_jwk,
                "tls_cert_pem": cert_pem.decode("ascii"),
                # Runtime-only bearer material for the runner's pipe alone:
                # never disk, never the repo, never results/ (ADR 0021).
                "phase1_tokens": mint_phase1_tokens(document, config, signing_key),
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
