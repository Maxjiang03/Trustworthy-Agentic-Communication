"""§E.4's two buildable F3 rows, over all nine arms (EXP4 STEP 6–7).

    F3 expired token (OAuth neg. control)   A A B B B B B B B
    F3 dpop-captured-proof-replay           A A A A A A A A B

Every cell is compared to §E.4 cell by cell. **A cell that disagrees with §E.4
is a finding to report, not a number to adjust — and neither is the prediction
to be edited to match the cell.** The one exception in this file's history is
recorded rather than hidden: `B-cap`'s two OAuth-negative-control cells read
`NA` until 2026-08-01 and were corrected to **B** by **ADR 0031**, adjudicated
by the author on the evidence that §E.1's `B-cap fixed [E6]` paragraph
*mandates* `oauth_authn = 1` and "MUST verify audience and expiry", so `NA`
(which asserts the arm **cannot express** the case, ADR 0028) was never
available for them. That correction changed a prediction; no arm changed.

**Why these two rows and not the other three F3 rows.** The three `dpop-*`
tampering rows need a captured-credential attacker model over the four-way §D.2
taxonomy; the two here need only a clock and a duplicate. Nothing below assumes
the others are unbuildable.

**The masking trap, and the pattern that avoids it** (STEP 6). A far-future
`now` fails `Γ`'s own expiry check first and hides the OAuth limb, so the block
would be attributable to the capability plane rather than to the token. Instead:
a **short-lived base token** (`TOKEN_LIFETIME`, 30 s) with the capability's own
window left at its corpus value of 3600 s, judged `JUDGED_AFTER` (45 s) later.
At that instant the token is expired and the capability, the HTC hops and the
INV are all still valid — so the only thing that can refuse is the OAuth limb,
and the audit detail is asserted to name `exp`. The three inequalities the
argument rests on (`45 > 30`, `45 < Δ = 60`, `45 < 3600`) are **asserted** in
`test_the_construction_cannot_be_masked_by_delta_or_by_gamma`, so this prose
cannot drift from the constants without a test failing.

*Update, 2026-08-01: these read 5 s and 10 s when first written, which is what
the first green run used. Widened to 30 s and 45 s for the direction that could
actually flake — not the expired one, which is safe at any AS uptime because
Phase-1 tokens expire at `as_start + TOKEN_LIFETIME` while judging happens at
`delegate_time + JUDGED_AFTER ≥ as_start + JUDGED_AFTER`, but the opposite one:
every exchange arm's AS round trip must COMPLETE inside `TOKEN_LIFETIME`, and 5 s
is a thin budget on a slow CI runner. A breach would fail loudly rather than pass
quietly — a refused exchange reads `b2_exchange_refused`, which is not the
`b2_oauth_token_rejected` the row expects — but a loud flake is still a flake,
and 30 s removes the question. Only the margin changed; the argument did not.*

**The Δ constraint on the replay row** (ADR 0027, forbidden action 7). The
replay MUST be built **within Δ**: outside it, `B3` blocks on INV freshness
rather than admitting, and the `B3` = A / `B3⁺` = B distinction — which is
`B3⁺`'s entire reason to exist — collapses in the direction that flatters this
work's hypothesis. Both decisions here run at one injected instant, and the
construction is **asserted** rather than assumed. `tests/test_b3_plus.py`
already demonstrates both halves in depth (the in-Δ replay caught by
duplication, the `now + 61` replay masked by freshness); this file reuses that
demonstration and does not rebuild it, extending it instead to the other eight
arms, which it did not cover.

Nothing here is timed (forbidden action 1). No `sleep`: the clock is injected
by re-staging, never waited out. Platform-independent — no effect ledger.
"""

import copy
import dataclasses
import json
import time
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut import freshness
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm
from src.sut.baselines.base import HopContext, InvocationContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

TOOL = "notes.write"
ARGS = {"resource": "notes/project", "content": "x"}

# The two constants the masking argument rests on.
#
# `JUDGED_AFTER > TOKEN_LIFETIME` makes the token expired at the judging
# instant **regardless of how long the AS has been up**: Phase-1 tokens expire
# at `as_start + TOKEN_LIFETIME`, an arm delegates at some `t >= as_start`, and
# judging at `t + JUDGED_AFTER` is therefore always past expiry.
#
# `TOKEN_LIFETIME` is the budget for the OTHER direction, which is the one that
# could flake: every arm's exchange round trip must COMPLETE inside it, or the
# exchange arms would be refused a token and the row would measure a refused
# exchange rather than a refused presentation. Thirty seconds against a
# loopback AS is a very large margin, and a breach fails loudly on the reason
# code rather than passing quietly -- `b2_exchange_refused` is not
# `b2_oauth_token_rejected`.
#
# `JUDGED_AFTER` must stay inside Δ (or INV freshness fires first) and far
# inside the capability's 3600 s corpus window (or `Γ`'s own expiry check fires
# first). Both are asserted below rather than left as arithmetic in a comment.
TOKEN_LIFETIME = 30
JUDGED_AFTER = 45

ARMS = (
    "B0",
    "B1",
    "B2-broad-noexchange",
    "B2-exchange-broad",
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
    "B-cap",
    "B3",
    "B3+",
)

# §E.4 `F3 expired token`, as (admitted, reason_code). `B-cap` is B per ADR 0031.
EXPECTED_EXPIRED: dict[str, tuple[bool, str]] = {
    "B0": (True, "b0_no_boundary_check"),
    "B1": (True, "b1_admitted"),
    "B2-broad-noexchange": (False, "b2_oauth_token_rejected"),
    "B2-exchange-broad": (False, "b2_oauth_token_rejected"),
    "B2-exchange-task": (False, "b2_oauth_token_rejected"),
    "B2-exchange-task-DPoP": (False, "b2_oauth_token_rejected"),
    "B-cap": (False, "b3_oauth_resource_authorization"),
    "B3": (False, "b3_oauth_resource_authorization"),
    "B3+": (False, "b3_oauth_resource_authorization"),
}
# §E.4 `F3 dpop-captured-proof-replay`: A everywhere, B for `B3⁺` alone.
EXPECTED_REPLAY: dict[str, tuple[bool, str]] = {
    arm: EXPECTED_EXPIRED[arm] if arm in ("B0", "B1") else (True, "b2_admitted") for arm in ARMS
}
for _arm in ("B-cap", "B3"):
    EXPECTED_REPLAY[_arm] = (True, "b3_admitted")
EXPECTED_REPLAY["B3+"] = (False, "b3_replay_duplicate")

# The arms with no clock to move: they read no token, so "expired" is not a
# condition they can perceive. That is the vulnerability §E.4 predicts as A,
# not an inability to express the case (which would be NA).
CLOCKLESS = ("B0", "B1")


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def as_document(runner):
    """One AS, every Phase-1 token short-lived.

    The lifetime is shortened for **all** clients rather than one, because the
    nine arms draw their base tokens from three different ones and the row must
    put every arm in the same condition.
    """
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant(),
    )
    document = copy.deepcopy(document)
    for spec in document["phase1"].values():
        spec["lifetime_seconds"] = TOKEN_LIFETIME
        for extra in spec.get("additional_grants", {}).values():
            extra["lifetime_seconds"] = TOKEN_LIFETIME
    # Exchanged tokens too: ADR 0017 caps `AT_i` at `exp_{i-1}`, but the default
    # would otherwise outlive the subject on the first hop.
    document["default_lifetime_seconds"] = TOKEN_LIFETIME
    return document


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def factories(runner, running_as, as_document):
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
    }
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )
    broad = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor:broad"],
        ladder_grant="broad",
        **common,
    )
    task = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        ladder_grant="task",
        **common,
    )
    dpop = runner.b2_dpop_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_token_endpoint=as_document["token_endpoint"],
        **common,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B2-broad-noexchange": (B2BroadNoExchangeArm, broad),
        "B2-exchange-broad": (B2ExchangeBroadArm, broad),
        "B2-exchange-task": (B2ExchangeTaskArm, task),
        "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, dpop),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
        "B3+": (B3PlusArm, b3_setup),
    }


def _armed(factories, arm_name, *, now, invocation_id="cid-f3"):
    """Provision, delegate and present on ONE injected instant.

    Delegation happens while the token is valid — an exchange arm must be able
    to complete its round trip, or the row would measure a refused exchange
    instead of a refused presentation.
    """
    factory, setup = factories[arm_name]
    visible = _visible("gt-benign")
    arm = factory()
    arm.provision(dict(setup))
    hop = HopContext(
        task_id=visible["task_id"],
        audience=visible["audience"],
        from_agent=visible["supervisor"],
        to_agent=visible["specialist"],
        authority_elements=tuple(map(tuple, visible["authority_elements"])),
        attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
        widening_elements=tuple(map(tuple, visible["widening_elements"])),
        now_epoch=now,
        expiry_epoch=now + int(visible["validity_seconds"]),
    )
    credentials = arm.delegate(hop)
    arm.present(
        credentials,
        InvocationContext(
            tool=TOOL,
            arguments=ARGS,
            method=visible["method"],
            task_id=visible["task_id"],
            audience=visible["audience"],
            invocation_id=invocation_id,
            now_epoch=now,
        ),
    )
    return arm


def _restage(arm, *, at):
    """Move the judging instant without moving anything else, or report that
    the arm has no clock at all."""
    staged = getattr(arm, "_staged", None)
    if staged is None or not hasattr(staged, "now_epoch"):
        return False
    arm._staged = dataclasses.replace(staged, now_epoch=at)
    return True


def _detail(arm):
    log = getattr(arm, "audit_log", None)
    return str(log[-1].get("detail", "")) if log else ""


# --------------------------------------------------------------------------
# Row 1 — F3 expired token
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def expired_row(factories):
    """Every arm handed an expired base token. Run once."""
    cells = {}
    opened = []
    try:
        for arm_name in ARMS:
            now = int(time.time())
            arm = _armed(factories, arm_name, now=now)
            opened.append(arm)
            moved = _restage(arm, at=now + JUDGED_AFTER)
            cells[arm_name] = {
                "verdict": arm.decide(TOOL, ARGS),
                "detail": _detail(arm),
                "clock_moved": moved,
            }
        yield cells
    finally:
        for arm in opened:
            if hasattr(arm, "close"):
                arm.close()


@pytest.fixture(scope="module")
def replay_row(factories):
    """Every arm sent one bit-identical resubmission, inside Delta. Run once."""
    cells = {}
    opened = []
    try:
        for arm_name in ARMS:
            now = int(time.time())
            arm = _armed(factories, arm_name, now=now, invocation_id="cid-f3-replay")
            opened.append(arm)
            first = arm.decide(TOOL, ARGS)
            # BIT-IDENTICAL resubmission: same tool, same arguments, same
            # staged credentials, same instant. Nothing is re-signed.
            second = arm.decide(TOOL, ARGS)
            cells[arm_name] = {
                "first": first,
                "second": second,
                "detail": _detail(arm),
                "now": now,
            }
        yield cells
    finally:
        for arm in opened:
            if hasattr(arm, "close"):
                arm.close()


class TestF3ExpiredToken:
    @pytest.mark.parametrize("arm_name", ARMS)
    def test_cell(self, expired_row, arm_name):
        produced = expired_row[arm_name]["verdict"]
        expected = EXPECTED_EXPIRED[arm_name]
        assert produced == expected, (
            f"F3 expired token / {arm_name} produced {produced}, §E.4 predicts {expected} "
            f"-- a disagreement is a FINDING, and neither the cell nor the prediction may "
            f"be adjusted toward the other"
        )

    @pytest.mark.parametrize("arm_name", [a for a in ARMS if a not in CLOCKLESS])
    def test_the_block_is_attributable_to_the_TOKEN_not_to_a_masking_limb(
        self, expired_row, arm_name
    ):
        """Block 2's trap, checked rather than avoided by hope.

        Every blocking arm must name `exp`. An arm that blocked on `Γ`'s own
        expiry, on INV freshness, or on containment would also read as **B**
        in the cell above while measuring something else entirely.
        """
        assert expired_row[arm_name]["clock_moved"] is True
        assert expired_row[arm_name]["verdict"][0] is False
        assert "exp" in expired_row[arm_name]["detail"], expired_row[arm_name]["detail"]
        assert "expired" in expired_row[arm_name]["detail"]

    @pytest.mark.parametrize("arm_name", CLOCKLESS)
    def test_the_weak_arms_have_no_clock_to_move(self, expired_row, arm_name):
        """`A` here is the VULNERABILITY, not an inability to express the case.

        `B0` and `B1` stage nothing with a `now_epoch` because they read no
        token: there is no instant at which they could notice. That is why the
        cell is `A` and emphatically not `NA` — ADR 0028's distinction, which
        ADR 0031 then applied to `B-cap`'s two cells in this same row.
        """
        assert expired_row[arm_name]["clock_moved"] is False
        assert expired_row[arm_name]["verdict"][0] is True

    def test_the_capability_plane_is_still_valid_at_the_judging_instant(self, factories):
        """The negative arm for the whole row: the SAME construction judged
        inside the token's window is ADMITTED, so the refusals above are the
        expiry and not the construction."""
        opened = []
        try:
            for arm_name in ("B-cap", "B3", "B3+", "B2-exchange-task"):
                arm = _armed(factories, arm_name, now=int(time.time()))
                opened.append(arm)
                admitted, reason = arm.decide(TOOL, ARGS)
                assert admitted is True, f"{arm_name}: {reason}"
        finally:
            for arm in opened:
                if hasattr(arm, "close"):
                    arm.close()

    def test_the_construction_cannot_be_masked_by_delta_or_by_gamma(self):
        """The two windows the judging instant must stay inside, as arithmetic.

        `JUDGED_AFTER` must exceed the token's lifetime (or nothing expires)
        while staying inside Δ (or INV freshness fires first) and far inside the
        capability's corpus window (or `Γ`'s own expiry check fires first).
        """
        assert JUDGED_AFTER > TOKEN_LIFETIME
        assert JUDGED_AFTER < freshness.DELTA_SECONDS
        assert JUDGED_AFTER < int(_visible("gt-benign")["validity_seconds"])


# --------------------------------------------------------------------------
# Row 2 — F3 dpop-captured-proof-replay
# --------------------------------------------------------------------------
class TestF3CapturedProofReplay:
    @pytest.mark.parametrize("arm_name", ARMS)
    def test_cell(self, replay_row, arm_name):
        produced = replay_row[arm_name]["second"]
        expected = EXPECTED_REPLAY[arm_name]
        assert produced == expected, (
            f"F3 replay / {arm_name} produced {produced}, §E.4 predicts {expected} "
            f"-- a disagreement is a FINDING, and neither the cell nor the prediction may "
            f"be adjusted toward the other"
        )

    @pytest.mark.parametrize("arm_name", ARMS)
    def test_the_first_submission_is_always_admitted(self, replay_row, arm_name):
        """Without this the row would be uninformative: an arm that blocked the
        FIRST request would produce `B3⁺`'s cell for the wrong reason."""
        assert replay_row[arm_name]["first"][0] is True

    def test_the_replay_is_constructed_WITHIN_delta(self, replay_row):
        """ADR 0027's fixture constraint (forbidden action 7), asserted.

        Both decisions run at one injected instant, so the INV is fresh at both
        and only duplicate detection can catch the second. Built outside Δ,
        `B3` would block on freshness — see
        `tests/test_b3_plus.py::TestTheCellB3PlusExistsFor` for that collapse
        demonstrated directly; this asserts the fixture here is not it.
        """
        for arm_name in ARMS:
            now = replay_row[arm_name]["now"]
            assert freshness.is_fresh(now, now)
        assert replay_row["B3"]["second"] == (True, "b3_admitted")
        assert replay_row["B3+"]["second"][1] == "b3_replay_duplicate"

    def test_only_b3_plus_carries_the_jti_cache(self):
        """The cell is a **ladder property**: the `jti_cache` bit is what
        separates the one B from the eight As, and it is set on exactly one
        arm."""
        from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm as _dpop

        assert B3PlusArm.bitmask.jti_cache == 1
        for other in (
            B0Arm,
            B1Arm,
            B2BroadNoExchangeArm,
            B2ExchangeBroadArm,
            B2ExchangeTaskArm,
            _dpop,
            BCapArm,
            B3Arm,
        ):
            assert other.bitmask.jti_cache == 0

    def test_the_duplicate_reason_names_the_window(self, replay_row):
        assert "already admitted" in replay_row["B3+"]["detail"]
        assert f"Delta={freshness.DELTA_SECONDS}" in replay_row["B3+"]["detail"]


class TestBothRowsCoverEveryArm:
    def test_no_cell_is_silently_absent(self):
        assert set(EXPECTED_EXPIRED) == set(ARMS)
        assert set(EXPECTED_REPLAY) == set(ARMS)
        assert len(ARMS) == 9

    def test_neither_row_carries_an_NA(self):
        """Both rows are scored for every arm. `NA` asserts an arm cannot
        express the case (ADR 0028); every arm can be handed an expired token
        and can be sent the same request twice, including the two that cannot
        perceive either."""
        assert all(isinstance(v, tuple) for v in EXPECTED_EXPIRED.values())
        assert all(isinstance(v, tuple) for v in EXPECTED_REPLAY.values())

    def test_bcap_is_B_on_the_expired_token_row_per_adr_0031(self):
        """The corrected cell, pinned so it cannot silently revert.

        §E.1's `B-cap fixed [E6]`: `oauth_authn = 1` and it **MUST** verify
        audience and expiry. `NA` would assert it cannot express the case.
        """
        assert EXPECTED_EXPIRED["B-cap"] == (False, "b3_oauth_resource_authorization")
        assert BCapArm.bitmask.oauth_authn == 1
