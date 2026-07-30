"""Spawn the experiment AS out-of-process and hold its start-up line (ADR 0015/0021).

ADR 0015 rule 1: the AS runs as its own OS process on loopback, started by
the runner via `python -m src.sut.oauth_as <config.json>`, with the sealed
seed in the environment and never on the command line. Rule 4 forbids this
module from IMPORTING the AS package -- spawning a subprocess is not an
import, and the two protocol constants this needs (the module path and the
seed environment variable name) are duplicated here as wire-level facts, the
same way the boundary duplicates token validation rather than importing it.

The start-up JSON line carries the port, the AS public JWK, the TLS
certificate, and (ADR 0021) the Phase-1 base tokens. The pipe is held HERE,
by the runner; the tokens are runtime-only and MUST never be written to
disk, committed, or echoed into `results/` (ADR 0021 rule 2) -- this class
keeps them in memory and exposes them to the composition root only.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

AS_MODULE = "src.sut.oauth_as"  # spawned, never imported (ADR 0015 rule 4)
SEED_ENV = "AASC_G4_AS_SEED"  # the AS process's documented seed variable
RAR_TYPE = "https://aasc.gla.ac.uk/rar/tool-authority"  # ADR 0017, the project RAR type URI

REPO_ROOT = Path(__file__).resolve().parents[2]


class ASProcessError(Exception):
    """The AS process failed to start or to report its start-up line."""


class ASProcess:
    """One out-of-process AS instance and its start-up material."""

    def __init__(self, document: dict[str, Any], seed: bytes) -> None:
        # The config document carries no secret (DESIGN SS 5.1); it may touch
        # disk. The seed and the minted tokens never do.
        self._config_file = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(document, self._config_file)
        self._config_file.close()
        env = dict(os.environ)
        env[SEED_ENV] = seed.hex()
        env["PYTHONPATH"] = str(REPO_ROOT)
        self._proc = subprocess.Popen(
            [sys.executable, "-m", AS_MODULE, self._config_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
        )
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            raise ASProcessError(f"AS process emitted no start-up line: {stderr.strip()}")
        startup = json.loads(line)
        self.port: int = startup["port"]
        self.public_jwk: dict[str, str] = startup["public_jwk"]
        self.tls_cert_pem: str = startup["tls_cert_pem"]
        self.phase1_tokens: dict[str, str] = startup.get("phase1_tokens", {})

    def stop(self) -> None:
        self._proc.terminate()
        try:
            self._proc.wait(timeout=10)
        finally:
            Path(self._config_file.name).unlink(missing_ok=True)

    def __enter__(self) -> "ASProcess":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def golden_thread_as_document(
    *,
    corpus: dict[str, Any],
    registry_document: dict[str, Any],
    resolved_keys: dict[str, str],
    identity_jwks: dict[str, dict[str, str]],
    omega_elements: list[list[str]],
) -> dict[str, Any]:
    """The AS config document for the golden-thread pilot (runner-assembled).

    Phase-1 provisioning note (ADR 0021 / SS E.2): the base token expresses NO
    delegation authority -- it establishes MCP resource authorization and the
    OAuth actor identity only. The pilot therefore provisions the COARSE
    RS-level grant (the whole frozen Omega at this one resource server, scope
    `mcp.invoke`); in B3 the capability is the narrowing plane and effective
    authority is the SS A.4 intersection, which the coarse base grant leaves
    to the capability.
    """
    issuer = corpus["issuer"]
    audience = corpus["audience"]
    actors = registry_document["actors"]
    resource_owner = registry_document["resource_owners"][0]
    # One RAR object per Omega element: a single object's RFC 9396 SS 2.2
    # product over all actions x all datatypes would manufacture pairs outside
    # Omega, which the AS validator rightly refuses (rar-outside-omega).
    rar = [
        {
            "type": RAR_TYPE,
            "locations": [audience],
            "actions": [action],
            "datatypes": [resource],
        }
        for action, resource in omega_elements
    ]
    registry = {}
    for actor, principal in actors.items():
        label = registry_document["principals"][principal]["key_reference"]
        registry[actor] = {
            "principal": principal,
            "identity_jwk": identity_jwks[principal],
            "holder_jwk": {"kty": "OKP", "crv": "Ed25519", "x": resolved_keys[label]},
        }
    return {
        "issuer": issuer,
        "token_endpoint": f"{issuer}/token",
        "rar_type": RAR_TYPE,
        "omega": omega_elements,
        "resource_servers": [audience],
        "clients": sorted(actors),
        "registry": registry,
        "delegation_policy": {"supervisor": "specialist", "specialist": "worker"},
        "phase1": {
            actor: {
                "subject": resource_owner,
                "audience": audience,
                "scope": "mcp.invoke",
                "authorization_details": rar,
            }
            for actor in actors
        },
    }
