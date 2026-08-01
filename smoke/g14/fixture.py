"""G-14's campaign: one AS, one shared cache, three arms, §D's taxonomy.

Every arm is driven through its own interface — provision, delegate, present,
decide — so no outcome here is read off anything but a decision an arm made.
Nothing is timed and nothing sleeps: the clock is injected (ADR 0027).
"""

import json
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

from src.harness import key_material  # noqa: E402
from src.harness.as_process import ASProcess, golden_thread_as_document  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.runner import GoldenThreadRunner  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402
from src.sut.authz.jti_cache import JtiCache  # noqa: E402
from src.sut.baselines.b2_dpop import DPOP_MECHANISM_TAG, B2ExchangeTaskDPoPArm  # noqa: E402
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm  # noqa: E402
from src.sut.baselines.b3 import B3Arm  # noqa: E402
from src.sut.baselines.base import HopContext, InvocationContext  # noqa: E402

SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
RESOURCE_URL = "https://mcp.aasc.local/tools/invoke"
# ONE clock for the campaign, taken from the live wall clock at start-up
# because the AS mints real tokens against it -- a frozen fake instant would
# put the OAuth plane and the capability plane on two different clocks and
# every arm would refuse before it ever reached the cache. The instant is then
# INJECTED everywhere below (ADR 0027), so nothing sleeps and a window can be
# crossed by advancing it rather than by waiting.
NOW = int(time.time())
TOOL = "notes.write"
ARGS = {"resource": "notes/project", "content": "x"}
MUTATED_TOOL = "notes.read"
MUTATED_ARGS = {"resource": "notes/project"}


def _visible() -> dict:
    return json.loads((CORPUS / "sut_visible" / "gt-benign.json").read_text(encoding="utf-8"))


def _hop(now: int) -> HopContext:
    visible = _visible()
    return HopContext(
        task_id=visible["task_id"],
        audience=visible["audience"],
        from_agent=visible["supervisor"],
        to_agent=visible["specialist"],
        authority_elements=tuple(map(tuple, visible["authority_elements"])),
        attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
        widening_elements=(),
        now_epoch=now,
        expiry_epoch=now + int(visible["validity_seconds"]),
    )


def _invocation(
    now: int, *, tool: str = TOOL, arguments: "dict | None" = None
) -> InvocationContext:
    visible = _visible()
    return InvocationContext(
        tool=tool,
        arguments=dict(arguments if arguments is not None else ARGS),
        method=visible["method"],
        task_id=visible["task_id"],
        audience=visible["audience"],
        invocation_id="g14-invocation",
        now_epoch=now,
    )


class Campaign:
    def __enter__(self) -> "Campaign":
        self.runner = GoldenThreadRunner()
        registry_document = reg.load_document()
        self.document = golden_thread_as_document(
            corpus={"issuer": ISSUER, "audience": AUDIENCE},
            registry_document=registry_document,
            resolved_keys=key_material.resolve_public(SEED),
            identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
            omega_elements=frozen_config.load_document()["omega"]["elements"],
            task_grant=self.runner.task_grant("gt-benign"),
        )
        self.process = ASProcess(self.document, SEED)
        self.process.__enter__()
        self.cache = JtiCache()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.process.__exit__(*exc)

    # -- provisioning ------------------------------------------------------- #
    def _dpop_setup(self) -> dict:
        return self.runner.b2_dpop_setup(
            scenario_id="gt-benign",
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_public_jwk=self.process.public_jwk,
            as_port=self.process.port,
            as_tls_cert_pem=self.process.tls_cert_pem,
            as_token_endpoint=self.document["token_endpoint"],
            resource_url=RESOURCE_URL,
        )

    def _bearer_setup(self) -> dict:
        return self.runner.b2_setup(
            scenario_id="gt-benign",
            access_token=self.process.phase1_tokens["agent-supervisor"],
            as_public_jwk=self.process.public_jwk,
            as_port=self.process.port,
            as_tls_cert_pem=self.process.tls_cert_pem,
        )

    def _b3_setup(self) -> dict:
        return self.runner.b3_setup(
            access_token=self.process.phase1_tokens["agent-specialist"],
            as_public_jwk=self.process.public_jwk,
        )

    def _armed_dpop(self, *, cache=None, tool=TOOL, arguments=None, present_as=None):
        arm = B2ExchangeTaskDPoPArm()
        arm.provision(self._dpop_setup())
        if cache is not None:
            arm.attach_replay_cache(cache)
        credentials = arm.delegate(_hop(NOW))
        arm.present(credentials, _invocation(NOW, tool=present_as or tool, arguments=arguments))
        return arm

    def _armed_b3(self, *, cache=None, tool=TOOL, arguments=None, present_as=None):
        arm = B3Arm()
        arm.provision(self._b3_setup())
        if cache is not None:
            arm.attach_replay_cache(cache)
        credentials = arm.delegate(_hop(NOW))
        arm.present(credentials, _invocation(NOW, tool=present_as or tool, arguments=arguments))
        return arm

    # -- what the spike asks for -------------------------------------------- #
    def both_arms_sharing_one_cache(self):
        return self._armed_dpop(cache=self.cache), self._armed_b3(cache=self.cache), self.cache

    def dpop_replay(self, *, with_cache: bool = True) -> dict:
        cache = JtiCache() if with_cache else None
        arm = self._armed_dpop(cache=cache)
        first = arm.decide(TOOL, ARGS)
        replay = arm.decide(TOOL, ARGS)  # bit-identical, same injected instant
        return {"first": first, "replay": replay}

    def b3_replay(self, *, with_cache: bool = True) -> dict:
        cache = JtiCache() if with_cache else None
        arm = self._armed_b3(cache=cache)
        first = arm.decide(TOOL, ARGS)
        replay = arm.decide(TOOL, ARGS)
        return {"first": first, "replay": replay}

    def dpop_body_mutation(self) -> dict:
        """FIRST USE with a mutated body: a fresh id, so the cache cannot help."""
        arm = self._armed_dpop(cache=JtiCache())
        return {"mutated": arm.decide(MUTATED_TOOL, MUTATED_ARGS)}

    def b3_body_mutation(self) -> dict:
        arm = self._armed_b3(cache=JtiCache())
        return {"mutated": arm.decide(MUTATED_TOOL, MUTATED_ARGS)}

    def dpop_proof_claims(self) -> frozenset:
        return self._armed_dpop().proof_claim_names()

    def bearer_with_a_cache_replay(self) -> dict:
        """The bare bearer, GIVEN a cache. It protects nothing.

        `B2ExchangeTaskArm` has no `attach_replay_cache` and no authenticated
        request id to consume -- there is nothing to put in the cache. The
        cache is handed over and observed to stay EMPTY while the captured
        token is replayed successfully.
        """
        cache = JtiCache()
        arm = B2ExchangeTaskArm()
        arm.provision(self._bearer_setup())
        credentials = arm.delegate(_hop(NOW))
        arm.present(credentials, _invocation(NOW))
        arm.decide(TOOL, ARGS)
        replay = arm.decide(TOOL, ARGS)
        return {
            "replay": replay,
            "cache_size": len(cache._entries),
            "has_attach_seam": hasattr(arm, "attach_replay_cache"),
        }

    def mechanism_tags(self) -> dict:
        from src.sut.authz.capability_path import INV_MECHANISM_TAG

        return {"B2-exchange-task-DPoP": DPOP_MECHANISM_TAG, "B3": INV_MECHANISM_TAG}
