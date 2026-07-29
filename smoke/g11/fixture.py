"""Gate G-11 fixture: valid HTC/INV chains over the **frozen** identity registry.

Shared by `smoke/g11/spike.py` and `tests/test_holder_binding.py`. Unlike G-4's
`campaign.py`, nothing here is a stand-in: the registry is the **frozen artifact**
`src/harness/verifier/identity_registry_v1.json` (ADR 0019), which is what closes
`smoke/g4/DESIGN.md` SS 9 **C3**. Only the *key values* are fixture material, and
they enter exactly where the design says per-campaign material enters -- through
`bind()`, from a seed the runner holds (ADR 0007).

The chain builders are **fixture** constructors. D21's obligation stands: the B3
arm's SUT-side INV signer must be an independent implementation, and the verifier
never consumes a SUT-computed digest.
"""

import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from biscuit_auth import BiscuitBuilder, BlockBuilder, KeyPair  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from src.harness.verifier import holder_binding as hb  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402

SEED = bytes.fromhex("5a" * 32)  # fixture seed; the runner holds the sealed one
TASK_ID = "task-g11-pilot"
AUDIENCE = "https://mcp.aasc.local/tools"
METHOD = "tools/call"
TOOL = "notes.read"
RAW_ARGUMENTS = {"collection": "notes/project", "limit": 5}
# A presented AT@aud: base64url characters and dots, as a compact serialization is.
RAW_AT = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ1c2VyLXlpeGlhbiJ9.c2lnbmF0dXJl"
# `label_assertions_digest` is bound by the INV signature but NOT recomputed here:
# its construction is ADR 0009 category (c), depends on frozen rows 4/6 (UNSET),
# and is verified at G-15. The value is opaque to this gate, by design.
LABEL_ASSERTIONS_DIGEST = "00" * 32

# The frozen registry's derivation labels, in delegation order.
HOLDER_LABELS = ("holder-supervisor", "holder-specialist", "holder-worker")


class Campaign:
    """One root keypair, one bound registry, and the chains built under them."""

    def __init__(self, seed: bytes = SEED) -> None:
        self.seed = seed
        self.root = KeyPair()  # kappa
        self.root_private = Ed25519PrivateKey.from_private_bytes(
            bytes(self.root.private_key.to_bytes())
        )
        self._privates: dict[str, Ed25519PrivateKey] = {}
        self.document = reg.load_document()  # the FROZEN registry
        self.registry = reg.bind(self.document, self.resolve)
        self.now = int(time.time())

    # -- key material -----------------------------------------------------
    def private_for(self, label: str) -> Ed25519PrivateKey:
        if label not in self._privates:
            material = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"AASC-G11-HOLDER:" + label.encode("ascii"),
            ).derive(self.seed)
            self._privates[label] = Ed25519PrivateKey.from_private_bytes(material)
        return self._privates[label]

    def resolve(self, label: str) -> str:
        """The runner's label -> public key resolution (ADR 0007 seed material)."""
        if label == "kappa":
            return hb.b64u(bytes(self.root.public_key.to_bytes()))
        return hb.public_key_wire(self.private_for(label).public_key())

    def kid_for(self, label: str) -> str:
        for entry in self.document["principals"].values():
            if entry["key_reference"] == label:
                return entry["kid"]
        raise KeyError(label)

    # -- capability -------------------------------------------------------
    def mint(self, depth: int) -> tuple[bytes, list[bytes]]:
        """A Biscuit token with `depth` appended blocks; returns (P_depth, snapshots)."""
        token = BiscuitBuilder('right("notes.read", "notes/project");').build(self.root.private_key)
        snapshots = [bytes(token.to_bytes())]
        for _ in range(depth):
            token = token.append(BlockBuilder('check if right("notes.read", "notes/project");'))
            snapshots.append(bytes(token.to_bytes()))
        return snapshots[-1], snapshots

    # -- valid evidence ---------------------------------------------------
    def evidence(self, depth: int = 2, *, token_bytes: bytes | None = None) -> hb.PresentedEvidence:
        """A fully valid presentation at `depth` hops (`n = depth`)."""
        if token_bytes is None:
            token_bytes, _ = self.mint(depth)
        labels = list(HOLDER_LABELS[: depth + 1])
        privates = [self.private_for(label) for label in labels]
        kids = [self.kid_for(label) for label in labels]
        chain = hb.build_htc_chain(
            token_bytes,
            self.root.public_key,
            self.root_private,
            privates,
            kids,
            root_kid=self.registry.as_root_kid,
            task_id=TASK_ID,
            audience=AUDIENCE,
            iat=self.now - 10,
            nbf=self.now - 10,
            # exp non-increasing along the chain, as SS F.2 requires.
            exps=[self.now + 600 - 60 * index for index in range(depth + 1)],
        )
        inv = hb.build_inv(
            token_bytes,
            self.root.public_key,
            privates[-1],
            kid=kids[-1],
            raw_at=RAW_AT,
            raw_arguments=RAW_ARGUMENTS,
            task_id=TASK_ID,
            audience=AUDIENCE,
            method=METHOD,
            tool=TOOL,
            label_assertions_digest=LABEL_ASSERTIONS_DIGEST,
            invocation_id="inv-g11-1",
            iat=self.now - 5,
            nbf=self.now - 5,
            exp=self.now + 300,
        )
        return hb.PresentedEvidence(
            token_bytes=token_bytes,
            htc_chain=chain,
            invocation_assertion=inv,
            raw_at=RAW_AT,
            raw_arguments=RAW_ARGUMENTS,
            task_id=TASK_ID,
            audience=AUDIENCE,
            method=METHOD,
            tool=TOOL,
        )

    # -- verification -----------------------------------------------------
    def verify(self, evidence: hb.PresentedEvidence, *, now: int | None = None):
        return hb.verify(
            evidence, self.registry, self.root.public_key, now=self.now if now is None else now
        )

    def reject_reason(self, evidence: hb.PresentedEvidence, *, now: int | None = None) -> str:
        """The reason code, or `"ACCEPTED"` if the mutation was not caught."""
        try:
            self.verify(evidence, now=now)
        except hb.HolderBindingRejected as exc:
            return exc.reason_code
        return "ACCEPTED"

    # -- mutation helpers -------------------------------------------------
    def with_chain(self, evidence: hb.PresentedEvidence, chain: Any) -> hb.PresentedEvidence:
        return replace(evidence, htc_chain=tuple(chain))

    def with_inv(self, evidence: hb.PresentedEvidence, inv: bytes) -> hb.PresentedEvidence:
        return replace(evidence, invocation_assertion=inv)

    def with_token(
        self, evidence: hb.PresentedEvidence, token_bytes: bytes
    ) -> hb.PresentedEvidence:
        return replace(evidence, token_bytes=token_bytes)

    def holder_private(self, index: int) -> Ed25519PrivateKey:
        """The key that signs `HTC_{index+1}` -- i.e. holder `index`."""
        return self.private_for(HOLDER_LABELS[index])
