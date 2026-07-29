"""Process entry point: `python -m src.sut.oauth_as <config.json>`.

The runner starts the AS this way before a campaign (ADR 0015 rule 1). The
sealed seed arrives in the environment variable named below and **never** on the
command line, where it would be visible in a process listing; the configuration
file carries no secret at all -- client secrets are derived here, inside this
process, from the same seed (DESIGN SS 5.1).

On start-up one JSON line is written to stdout so the parent can reach the
server: the bound port, the AS **public** JWK, and the TLS certificate. All three
are public by construction; the signing key and the seed never appear.
"""

import json
import os
import sys
from pathlib import Path

from src.sut.oauth_as.config import ASConfig, RegistryEntry
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

    server, _ = serve_in_thread(config_from_document(document, seed), signing_key, tls_context)
    print(
        json.dumps(
            {
                "port": server.port,
                "public_jwk": signing_key.public_jwk,
                "tls_cert_pem": cert_pem.decode("ascii"),
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
