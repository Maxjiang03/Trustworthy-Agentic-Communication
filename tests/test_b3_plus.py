"""`B3+` and the bounded `jti` replay cache (EXP3 STEP 11).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: ADR 0027's frozen parameters **and no others**, SS F.5's
consumption semantics, and the one cell `B3+` exists for -- `B3` admits a
bit-identical replay and `B3+` blocks it.

**No test here sleeps.** ADR 0027 makes every consumer of `Delta` take `now`
as an injected parameter precisely so an over-window fixture can advance a
logical instant; sixty seconds of real waiting per repetition, at >= 200
repetitions per configuration, would cost hours and would make the suite's
runtime a function of `Delta`. A test below asserts that no replay path
sleeps.

**This is NOT gate G-9** and nothing here claims it. G-9 adjudicates atomic
**multi-process** check-and-insert under concurrency and induced backend
error; this cache is atomic within one process and has no backend. `IA-9`
stays `[UNVERIFIED-IA]`.

Platform-independent.
"""

import ast
import dataclasses
import json
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut import freshness
from src.sut.authz.capability_path import (
    INV_MECHANISM_TAG,
    REASON_REPLAY_CAPACITY,
    REASON_REPLAY_DUPLICATE,
)
from src.sut.authz.jti_cache import Consumption, JtiCache
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.base import HopContext, InvocationContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The cache itself: ADR 0027's parameters and SS F.5's semantics
# ---------------------------------------------------------------------------
class TestTheCacheIsAdr0027s:
    def test_the_defaults_are_the_frozen_parameters_and_no_others(self):
        cache = JtiCache()
        assert cache.ttl_seconds == freshness.DELTA_SECONDS == 60
        assert cache.capacity == freshness.REPLAY_CACHE_CAPACITY == 65536

    def test_the_arm_constructs_it_with_no_arguments(self):
        """So the arm cannot quietly choose its own numbers."""
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b3_plus.py").read_text(
            encoding="utf-8"
        )
        assert "JtiCache()" in source
        assert "capacity=" not in source and "ttl_seconds=" not in source

    def test_first_use_is_admitted_and_the_second_is_a_duplicate(self):
        cache = JtiCache()
        assert cache.consume("inv", "cid-1", now=1_000) is Consumption.ADMITTED
        assert cache.consume("inv", "cid-1", now=1_000) is Consumption.DUPLICATE
        # Negative arm: a DIFFERENT id is still admitted, so the cache is not
        # simply refusing everything after the first call.
        assert cache.consume("inv", "cid-2", now=1_000) is Consumption.ADMITTED

    def test_the_namespace_keeps_two_mechanisms_apart(self):
        """SS F.5's `(mechanism_tag, jti)`; G-14 attaches one cache to both arms."""
        cache = JtiCache()
        assert cache.consume("inv", "same-id", now=0) is Consumption.ADMITTED
        assert cache.consume("dpop", "same-id", now=0) is Consumption.ADMITTED
        # Negative arm: within one namespace it IS a duplicate.
        assert cache.consume("inv", "same-id", now=0) is Consumption.DUPLICATE

    def test_an_entry_expires_after_delta_by_advancing_the_instant(self):
        """No sleep: the injected instant moves instead (ADR 0027)."""
        cache = JtiCache()
        assert cache.consume("inv", "cid", now=1_000) is Consumption.ADMITTED
        assert cache.consume("inv", "cid", now=1_000 + 60) is Consumption.ADMITTED
        # Negative arm: one second earlier it is still unexpired.
        fresh = JtiCache()
        assert fresh.consume("inv", "cid", now=1_000) is Consumption.ADMITTED
        assert fresh.consume("inv", "cid", now=1_000 + 59) is Consumption.DUPLICATE

    def test_overflow_fails_closed_and_evicts_no_unexpired_entry(self):
        """ADR 0027: availability is deliberately sacrificed to integrity.

        Evicting an unexpired entry to make room would let an attacker replay
        a previously-seen id by first flooding the cache.
        """
        cache = JtiCache(capacity=2)
        assert cache.consume("inv", "a", now=0) is Consumption.ADMITTED
        assert cache.consume("inv", "b", now=0) is Consumption.ADMITTED
        assert cache.consume("inv", "c", now=0) is Consumption.CAPACITY
        # The earlier entries survived: `a` is still a duplicate, so nothing
        # was evicted to make room for `c`.
        assert cache.consume("inv", "a", now=0) is Consumption.DUPLICATE
        assert len(cache) == 2
        # And once they expire, the cache accepts again -- so CAPACITY is a
        # denial about the window, not a permanent failure.
        assert cache.consume("inv", "c", now=61) is Consumption.ADMITTED

    def test_expired_entries_are_swept_before_the_capacity_check(self):
        cache = JtiCache(capacity=1)
        assert cache.consume("inv", "a", now=0) is Consumption.ADMITTED
        assert cache.consume("inv", "b", now=0) is Consumption.CAPACITY
        assert cache.consume("inv", "b", now=61) is Consumption.ADMITTED

    def test_it_refuses_a_nonsense_configuration(self):
        with pytest.raises(ValueError):
            JtiCache(capacity=0)
        with pytest.raises(ValueError):
            JtiCache(ttl_seconds=0)

    def test_no_wall_clock_and_no_sleep_on_the_replay_path(self):
        """ADR 0027's two conditions, asserted on the source.

        `now` is a parameter everywhere; nothing waits. A fixture that
        established over-window behaviour by sleeping would add `Delta` per
        repetition and make the suite's runtime depend on `Delta`.
        """
        source = (REPO_ROOT / "src" / "sut" / "authz" / "jti_cache.py").read_text(encoding="utf-8")
        assert "time.time" not in source and "sleep" not in source
        # And no test in this file sleeps either.
        mine = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(mine)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "sleep"
        ]
        assert calls == []
        # Negative arm: the same walk, for a call this file certainly makes, so
        # the empty result above is a FINDING and not a scan that matches
        # nothing. It used to be `assert "time.time" in mine` -- which stopped
        # being a negative arm the moment this module took its instant from the
        # token's own window instead of a wall clock, and would have failed
        # loudly rather than quietly weakening. Matched on the walk rather than
        # on the text so it cannot see its own comment.
        consumed = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "consume"
        ]
        assert consumed, "the scan finds no attribute call at all, so it proves nothing"


# ---------------------------------------------------------------------------
# The arm: the one cell `B3+` exists for
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def running_as():
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": "https://as.aasc.local", "audience": "https://mcp.aasc.local/tools"},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def setup(runner, running_as):
    return runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )


def _token_window(token: str) -> tuple[int, int]:
    """`(iat, exp)` read from the access token's own claims, **unverified**.

    Unverified on purpose: this is a test reading the artifact under test to
    find an instant inside its window, never a verification path. The same
    helper `tests/test_b_cap.py` uses, for the same reason.
    """
    import base64

    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return int(claims["iat"]), int(claims["exp"])


def _instant(setup) -> int:
    """ONE instant for a construction, taken from the token's own window.

    **The straddle this removes, located rather than guessed.** `running_as` is
    a MODULE-scoped fixture, so the AS mints `phase1_tokens` once, when the
    module starts, with a 300 s lifetime (`default_lifetime_seconds`). Reading
    `int(time.time())` inside a test is then a SECOND clock, separated from the
    mint by however long the module has been running -- and
    `oauth_resource_authorization_ok` verifies that token at the instant the
    test injects. Under the full suite pinned to one CPU with three busy loops
    the separation crossed 300 s and the FIRST submission was refused with
    `b3_oauth_resource_authorization` / `exp: token has expired`, which is
    exactly what the pre-seal flake hunt observed and attributed to Delta.

    Measured directly: at this instant the arm admits; at `iat + 301` it returns
    `(False, 'b3_oauth_resource_authorization')`.

    Taken from `iat` rather than from a clock, so the window cannot drift out
    from under the test however long the AS has been up. **No window is
    widened**: the token's lifetime is left exactly where it was, which is the
    point -- widening it would hide the defect rather than remove it.
    """
    issued_at, expires_at = _token_window(setup["access_token"])
    assert issued_at < expires_at, "the token has no window to be inside"
    return issued_at


def _armed(arm, setup, now=None, invocation_id="cid-replay-probe"):
    visible = _visible("gt-benign")
    now = _instant(setup) if now is None else now
    arm.provision(setup)
    credentials = arm.delegate(
        HopContext(
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
    )
    arm.present(
        credentials,
        InvocationContext(
            tool="notes.write",
            arguments={"resource": "notes/project", "content": "x"},
            method=visible["method"],
            task_id=visible["task_id"],
            audience=visible["audience"],
            invocation_id=invocation_id,
            now_epoch=now,
        ),
    )
    return arm, now


ARGS = {"resource": "notes/project", "content": "x"}


class TestTheInstantComesFromTheTokenNotFromAClock:
    """**The straddle this module used to carry, and the world it fails in.**

    A fix nobody has watched fail is a fix nobody has tested (§6.2). These
    construct the failing world explicitly: the same arm, the same setup, judged
    at an instant OUTSIDE the module-scoped token's window — which is what a
    wall-clock read becomes once the module has been running long enough.
    """

    def test_the_instant_is_inside_the_tokens_own_window(self, setup):
        issued_at, expires_at = _token_window(setup["access_token"])
        assert issued_at <= _instant(setup) <= expires_at

    def test_the_token_lifetime_is_UNCHANGED(self, setup):
        """No window was widened to make this work. 300 s is what the AS's
        `default_lifetime_seconds` gives, and it stays there — widening it
        would have hidden the straddle rather than removed it."""
        issued_at, expires_at = _token_window(setup["access_token"])
        assert expires_at - issued_at == 300

    def test_OUTSIDE_the_window_the_first_submission_is_REFUSED(self, setup):
        """The failing world, and it names the observed failure exactly.

        The pre-seal flake hunt recorded run 000 as
        `test_the_replay_is_constructed_WITHIN_delta` failing on
        `assert arm.decide(...)[0] is True`, and attributed it to Delta. It was
        not Delta: past the token's `exp` the refusal is
        `b3_oauth_resource_authorization`, and the FIRST submission — the one
        that must be admitted before a replay can be tested — never lands.
        """
        _issued_at, expires_at = _token_window(setup["access_token"])
        arm, _ = _armed(B3PlusArm(), setup, now=expires_at + 1)
        admitted, reason = arm.decide("notes.write", ARGS)
        assert (admitted, reason) == (False, "b3_oauth_resource_authorization")
        assert "expired" in arm.audit_log[-1]["detail"]

    def test_INSIDE_the_window_it_is_admitted(self, setup):
        """Negative arm: the refusal above is about the window, not about the
        arm refusing everything."""
        arm, _ = _armed(B3PlusArm(), setup)
        assert arm.decide("notes.write", ARGS) == (True, "b3_admitted")

    def test_no_test_in_this_module_reads_the_wall_clock(self):
        """Structural, and parsed rather than grepped so it cannot match its
        own prose. One instant per construction, taken from the window."""
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        clock_reads = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "time"
        ]
        assert clock_reads == [], (
            f"a wall-clock read at line(s) {clock_reads}: this module's tokens are minted by a "
            "MODULE-scoped AS fixture, so a second clock here is separated from the mint by "
            "however long the module has been running"
        )


class TestTheCellB3PlusExistsFor:
    def test_b3_admits_a_bit_identical_replay(self, setup):
        """SS E.4: `F3 dpop-captured-proof-replay` is `B3` = **A**.

        Every conjunct is a function of the request, and the request is
        identical, so every conjunct accepts it. That is the residual SS E.1
        says `B3+` closes -- not a defect in `B3`.
        """
        arm, _ = _armed(B3Arm(), setup)
        assert arm.decide("notes.write", ARGS) == (True, "b3_admitted")
        assert arm.decide("notes.write", ARGS) == (True, "b3_admitted")

    def test_b3_plus_blocks_it(self, setup):
        """SS E.4: `B3+` = **B**, and the reason names the duplicate."""
        arm, _ = _armed(B3PlusArm(), setup)
        assert arm.decide("notes.write", ARGS) == (True, "b3_admitted")
        admitted, reason = arm.decide("notes.write", ARGS)
        assert (admitted, reason) == (False, REASON_REPLAY_DUPLICATE)
        assert "at-most-once" in arm.audit_log[-1]["detail"]

    def test_the_replay_is_constructed_WITHIN_delta(self, setup):
        """ADR 0027's fixture constraint, checked rather than assumed.

        Both decisions use the same injected instant, so the INV is fresh at
        both and only duplicate detection can catch the second. A replay built
        OUTSIDE `Delta` would be blocked by `B3` too -- on freshness, not on
        duplication -- collapsing the distinction this cell measures.
        """
        now = _instant(setup)
        arm, _ = _armed(B3PlusArm(), setup, now=now)
        assert freshness.is_fresh(now, now)
        assert arm.decide("notes.write", ARGS)[0] is True
        assert arm.decide("notes.write", ARGS)[1] == REASON_REPLAY_DUPLICATE

    def test_and_a_replay_outside_delta_is_masked_by_freshness(self, setup):
        """The very collapse ADR 0027's addition warns about, demonstrated.

        Re-staged at `now + 61`, **`B3` itself blocks** -- at
        `invocation_binding_ok`, not at the replay layer -- so a fixture built
        this way would measure INV freshness and report it as duplicate
        detection.
        """
        now = _instant(setup)
        arm, _ = _armed(B3Arm(), setup, now=now)
        assert arm.decide("notes.write", ARGS)[0] is True
        arm._staged = dataclasses.replace(arm._staged, now_epoch=now + 61)
        admitted, reason = arm.decide("notes.write", ARGS)
        assert (admitted, reason) == (False, "b3_invocation_binding")
        assert "freshness window" in arm.audit_log[-1]["detail"]

    def test_a_fresh_invocation_id_is_admitted_again(self, setup):
        """Negative arm: `B3+` blocks DUPLICATES, not second requests.

        The same cache, the same instant, the same call -- and a different
        harness-minted invocation id, which is what a genuinely new invocation
        carries (SS F.1: the INV `jti` IS the correlation id).
        """
        arm, now = _armed(B3PlusArm(), setup, invocation_id="cid-first")
        assert arm.decide("notes.write", ARGS)[0] is True
        assert arm.decide("notes.write", ARGS)[1] == REASON_REPLAY_DUPLICATE

        second = B3PlusArm()
        second.jti_cache = arm.jti_cache  # the SAME cache
        _armed(second, setup, now=now, invocation_id="cid-second")
        assert second.decide("notes.write", ARGS)[0] is True
        assert len(arm.jti_cache) == 2

    def test_the_id_consumed_is_the_invocation_id_under_the_inv_tag(self, setup):
        arm, now = _armed(B3PlusArm(), setup)
        assert arm.decide("notes.write", ARGS)[0] is True
        assert ("inv", "cid-replay-probe") in arm.jti_cache._entries
        assert INV_MECHANISM_TAG == "inv"


class TestConsumptionOrderAndCost:
    def test_the_id_is_consumed_only_after_every_conjunct_passes(self, setup):
        """SS F.5, and it matters: consuming an id for a request that was
        going to be refused anyway would burn it for a legitimate retry."""
        arm, _ = _armed(B3PlusArm(), setup)
        blocked = arm.decide("mail.send", {"to": "p@example.test", "subject": "s", "body": "b"})
        assert blocked[0] is False
        assert len(arm.jti_cache) == 0, "a refused request must not consume its id"
        # Positive arm: an admitted one does consume.
        assert arm.decide("notes.write", ARGS)[0] is True
        assert len(arm.jti_cache) == 1

    def test_the_trace_records_the_consumption(self, setup):
        arm, _ = _armed(B3PlusArm(), setup)
        arm.decide("notes.write", ARGS)
        assert "jti_consumed" in arm.audit_log[-1]["evaluated"]
        # Negative arm: B3 proper has no such step.
        plain, _ = _armed(B3Arm(), setup)
        plain.decide("notes.write", ARGS)
        assert "jti_consumed" not in plain.audit_log[-1]["evaluated"]

    def test_capacity_exhaustion_is_a_denial_with_its_own_reason(self, setup):
        """Fail closed, and attributable -- not folded into `duplicate`."""
        arm, now = _armed(B3PlusArm(), setup)
        arm.jti_cache = JtiCache(capacity=1)
        arm._decision_path._jti_cache = arm.jti_cache
        arm.jti_cache.consume("inv", "someone-else", now=now)
        admitted, reason = arm.decide("notes.write", ARGS)
        assert (admitted, reason) == (False, REASON_REPLAY_CAPACITY)
        assert "fails CLOSED" in arm.audit_log[-1]["detail"]

    def test_the_retry_cost_is_real_and_stated(self, setup):
        """SS F.5's trade-off: a legitimate retry within `Delta` is refused.

        `B3+` trades retry-within-`Delta` for duplicate-replay prevention, and
        the false-blocking analysis reports it rather than hiding it.
        """
        arm, now = _armed(B3PlusArm(), setup)
        assert arm.decide("notes.write", ARGS)[0] is True
        assert arm.decide("notes.write", ARGS)[1] == REASON_REPLAY_DUPLICATE
        # ... and it is released once the window passes.
        assert arm.jti_cache.consume("inv", "cid-replay-probe", now=now + 61) is (
            Consumption.ADMITTED
        )


class TestItIsAConfigurationNotACopy:
    def test_only_the_jti_bit_differs_from_b3(self):
        b3, plus = B3Arm().bitmask.as_bits(), B3PlusArm().bitmask.as_bits()
        assert plus == (1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        differing = [i for i, (a, b) in enumerate(zip(b3, plus)) if a != b]
        assert differing == [8]  # jti_cache

    def test_it_shares_b3s_decision_path_and_operations(self):
        assert B3PlusArm.delegate is B3Arm.delegate
        assert B3PlusArm.present is B3Arm.present
        assert B3PlusArm.decide is B3Arm.decide
        # Negative arm: provisioning is extended, to hand over the cache.
        assert B3PlusArm.provision is not B3Arm.provision

    def test_it_declares_itself_b3_plus_in_every_audit_record(self, setup):
        arm, _ = _armed(B3PlusArm(), setup)
        arm.decide("notes.write", ARGS)
        assert arm.audit_log[-1]["arm"] == "B3+"
        assert arm.audit_log[-1]["is_ablation"] is False


class TestNotGateG9:
    """Stated explicitly, because describing this as G-9-ready would be false."""

    def test_the_module_says_which_g9_properties_it_lacks(self):
        source = (REPO_ROOT / "src" / "sut" / "authz" / "jti_cache.py").read_text(encoding="utf-8")
        assert "NOT gate G-9" in source
        assert "multi-process" in source
        assert "IA-9" in source

    def test_the_cache_is_per_arm_and_therefore_per_process(self, setup):
        """Two arms hold two caches: no shared backend exists yet.

        G-9's criterion is atomic check-and-insert **across processes**, which
        this construction does not provide and does not claim to.
        """
        first, _ = _armed(B3PlusArm(), setup)
        second, _ = _armed(B3PlusArm(), setup)
        assert first.jti_cache is not second.jti_cache
        assert first.decide("notes.write", ARGS)[0] is True
        assert second.decide("notes.write", ARGS)[0] is True, (
            "a second arm admits the same id, which is exactly the multi-process "
            "gap G-9 adjudicates and this construction does not close"
        )
