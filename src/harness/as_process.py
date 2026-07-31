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


def rar_objects(elements: "list[list[str]] | list[tuple[str, str]]", audience: str) -> list[dict]:
    """One RAR object per element.

    Never one object listing every action and every datatype: a single object's
    RFC 9396 SS 2.2 product over all actions x all datatypes would manufacture
    pairs outside `Omega`, which the AS validator rightly refuses
    (`rar-outside-omega`). RFC 9396 SS 2 explicitly allows several entries of
    one type, which is the sanctioned way to express a non-rectangular set.
    """
    return [
        {"type": RAR_TYPE, "locations": [audience], "actions": [action], "datatypes": [resource]}
        for action, resource in elements
    ]


def golden_thread_as_document(
    *,
    corpus: dict[str, Any],
    registry_document: dict[str, Any],
    resolved_keys: dict[str, str],
    identity_jwks: dict[str, dict[str, str]],
    omega_elements: list[list[str]],
    task_grant: "list[list[str]] | None" = None,
    task_grant_client: str = "agent-supervisor",
) -> dict[str, Any]:
    """The AS config document for the golden-thread pilot (runner-assembled).

    Phase-1 provisioning note (ADR 0021 / SS E.2): the base token expresses NO
    delegation authority -- it establishes MCP resource authorization and the
    OAuth actor identity only. The pilot therefore provisions the COARSE
    RS-level grant (the whole frozen Omega at this one resource server, scope
    `mcp.invoke`); in B3 the capability is the narrowing plane and effective
    authority is the SS A.4 intersection, which the coarse base grant leaves
    to the capability.

    **`task_grant`, and why the coarse default cannot serve every arm.** In
    `B2-exchange-task` there is no capability plane: the TOKEN is the authority
    plane, and the AS enforces `C_i subset-of C_{i-1}` against the subject
    token's own `authorization_details`. Left coarse, the delegating party's
    base token would carry the whole of `Omega`, so the AS would enforce only
    `C_1 subset-of Omega` -- and an `F1-chain-tamper` hop widening to
    `(mail.send, mail/outbox)`, an element that IS in `Omega`, would be
    **issued** rather than refused (SS E.3 expects a block, and forbidden
    action 3 forbids weakening `B2`). `task_grant` therefore provisions the
    delegating client's base `AT@aud` with authority exactly `C_0 = U_task`,
    which is the OAuth analogue of SS A.3's "the AS mints `U_task` as `P_0`;
    the Supervisor only narrows". The path, the shape and the minting call are
    ADR 0021's, unchanged and identical to `B3`'s; only this one client's
    granted set differs, and every other client -- including the specialist,
    whose base token is the one `B3` presents -- keeps the coarse grant.
    """
    issuer = corpus["issuer"]
    audience = corpus["audience"]
    actors = registry_document["actors"]
    resource_owner = registry_document["resource_owners"][0]
    rar = rar_objects(omega_elements, audience)
    grants = {actor: rar for actor in actors}
    if task_grant is not None:
        if task_grant_client not in grants:
            raise ASProcessError(f"task_grant names unregistered client {task_grant_client!r}")
        grants[task_grant_client] = rar_objects(task_grant, audience)
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
                "authorization_details": grants[actor],
            }
            for actor in actors
        },
    }
