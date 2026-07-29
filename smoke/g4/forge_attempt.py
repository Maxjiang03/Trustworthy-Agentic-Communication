"""An agent-side attempt to mint its own access token. Run as a SEPARATE process.

`smoke/g4/DESIGN.md` SS 5.4 and ADR 0015 rule 2: the AS signing key is derived
inside the AS process from the sealed seed and never leaves it, and the runner
gives that seed to no agent process. This script plays the agent: it starts
**without** the seed, mints the best access token it can with a key of its own,
and presents it to the boundary verifier.

The expected outcome is rejection at the signature check. It reports its findings
as one JSON line on stdout so the spike can assert on them rather than on an exit
code alone.

It deliberately imports **only** the boundary (`src/sut/authz/`) and never
`src/sut/oauth_as/` -- an agent may not import the AS (ADR 0015 rule 3), which is
the very rule the spike also checks statically.
"""

import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from joserfc import jwt  # noqa: E402
from joserfc.jwk import OKPKey  # noqa: E402

from src.sut.authz import boundary  # noqa: E402

SEED_ENV = "AASC_G4_AS_SEED"
ISSUER = "https://as.aasc.local"
RESOURCE_SERVER = "https://mcp.aasc.local/tools"
RAR_TYPE = "https://aasc.gla.ac.uk/rar/tool-authority"


def main() -> int:
    if len(sys.argv) != 2:
        # The real AS public key is required. Falling back to a key of our own
        # would verify the forgery against itself and prove nothing.
        print("usage: forge_attempt.py '<as-public-jwk-json>'", file=sys.stderr)
        return 2
    as_public_jwk = json.loads(sys.argv[1])
    seed_present = bool(os.environ.get(SEED_ENV))

    # The agent has no sealed seed, so it can only invent a key of its own.
    attacker = OKPKey.generate_key("Ed25519")
    now = int(time.time())
    forged = jwt.encode(
        {"alg": "Ed25519", "typ": "at+jwt"},
        {
            "iss": ISSUER,
            "sub": "user-yixian",
            "aud": RESOURCE_SERVER,
            "client_id": "agent-supervisor",
            "iat": now,
            "exp": now + 600,
            "jti": "forged",
            "scope": "mcp.invoke mcp.read",
            # Maximal authority: everything the agent would like to hold.
            "authorization_details": [
                {
                    "type": RAR_TYPE,
                    "locations": [RESOURCE_SERVER],
                    "actions": ["notes.delete"],
                    "datatypes": ["notes/project"],
                }
            ],
        },
        attacker,
        algorithms=["Ed25519"],
    )

    config = boundary.BoundaryConfig(
        issuer=ISSUER,
        resource_server=RESOURCE_SERVER,
        as_public_jwk=as_public_jwk,
        rar_type=RAR_TYPE,
    )
    accepted, rejection = True, None
    try:
        boundary.verify_access_token(forged, config, now=now)
    except boundary.TokenRejected as exc:
        accepted, rejection = False, f"{exc.error} ({exc.reason})"

    print(
        json.dumps(
            {
                "seed_in_env": seed_present,
                "forged_token_accepted": accepted,
                "rejection": rejection,
                "attacker_key_differs_from_as": attacker.as_dict(private=False).get("x")
                != as_public_jwk.get("x"),
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
