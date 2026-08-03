"""Time-bound credentials handed to a cell, and the guard that bounds them.

**The defect.** Phase-1 access tokens are minted **once, at AS process
start-up** (`default_lifetime_seconds = 300`) and reused by every cell of a
pass, so the exposure clock starts *earlier than the campaign's own start* and
no frozen row bounds it. Measured on `gt-benign` — the benign control — with the
lifetime pinned short:

| arm | reason_code | false_block | unscorable |
|---|---|---|---|
| `B0` / `B1` | admitted | False | — |
| `B-cap` / `B3` / `B3+` | `b3_oauth_resource_authorization` | **True** | **0** |

The campaign **completed and scored** the three capability arms as false-blocking
the benign control, with `reference_allow` still `True`. Nothing was refused and
nothing contradicted anything.

**The asymmetry is why it survived.** The same expiry makes the `B2` arms raise
`B2ConfigurationError` out of `provision` and abort the pass — loud — while the
capability arms deny through `ConjunctFailed` and get scored — silent. One
defect, two behaviours, only one of them visible. And a strong arm that blocks
`gt-benign` leaves the F1 headline with no contrast at all: that result rests on
the strong arms blocking `F1-root`/`F1-terminal` **and admitting the control**.

**Why the Δ guard missed it.** `clock_refusal`'s first check inspects the `iat`
of the ADR 0030 declassification and approval against Δ. The access token is not
an ADR 0030 artifact, is not Δ-bound, and carries its own `exp`. It was simply
not in the set the guard looked at.

Nothing here is timed (no latency figure). Platform-independent:
`ledger_backed=False`, no Win32 handle.
"""

import ast
import base64
import inspect
import json
import time

import pytest

from src.harness import campaign as C
from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm

SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# Short enough that the window closes before the cells run. The sleep that
# follows is the ONLY one in this repository and it is permitted for exactly
# this: constructing the failing world. Nothing else here waits.
SHORT_LIFETIME_SECONDS = 1
WAIT_SECONDS = 2.5


def _as_document(runner, *, lifetime=None):
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )
    if lifetime is not None:
        document["default_lifetime_seconds"] = lifetime
    return document


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def live_as(runner):
    """A normally-provisioned AS, for the enumeration and the inert case."""
    with ASProcess(_as_document(runner), SEED) as process:
        yield process


@pytest.fixture(scope="module")
def setups(runner, live_as):
    """Every setup dict the harness hands an arm, one per §E.1 shape."""
    common = {
        "as_public_jwk": live_as.public_jwk,
        "as_port": live_as.port,
        "as_tls_cert_pem": live_as.tls_cert_pem,
        "scenario_id": "gt-benign",
    }
    document = _as_document(runner)
    return {
        "B0": {},
        "B1": runner.b1_setup(),
        "B2": runner.b2_setup(
            access_token=live_as.phase1_tokens["agent-supervisor"],
            ladder_grant="task",
            **common,
        ),
        "B2-DPoP": runner.b2_dpop_setup(
            access_token=live_as.phase1_tokens["agent-supervisor"],
            as_token_endpoint=document["token_endpoint"],
            **common,
        ),
        "B3": runner.b3_setup(
            access_token=live_as.phase1_tokens["agent-specialist"],
            as_public_jwk=live_as.public_jwk,
        ),
    }


# ---------------------------------------------------------------------------
# STEP 1 — the enumeration, committed as a test rather than claimed in prose
# ---------------------------------------------------------------------------
class TestWhichCredentialsCarryAValidityWindow:
    """**A guard covering a set nobody enumerated is a guard assumed complete.**

    This pins the set. A time-bound credential added to any setup makes it fail,
    which is the point: the whole defect was a credential nobody had listed.
    """

    EXPECTED = {
        "B0": (),
        "B1": (),
        "B2": ("access_token", "as_tls_cert_pem"),
        "B2-DPoP": ("access_token", "as_tls_cert_pem"),
        "B3": ("access_token",),
    }

    @pytest.mark.parametrize("arm_shape", sorted(EXPECTED))
    def test_the_time_bound_set_is_exactly_this(self, setups, arm_shape):
        found = tuple(name for name, _nbf, _exp in C.credential_windows(setups[arm_shape]))
        assert found == self.EXPECTED[arm_shape], (
            f"{arm_shape}: the time-bound credentials handed to a cell are {found}, not "
            f"{self.EXPECTED[arm_shape]}. A new one is IN SCOPE -- it is the same defect"
        )

    def test_the_untimed_majority_is_genuinely_untimed(self, setups):
        """Non-vacuity: most fields carry no window, so the two above are a
        finding rather than a scan that matches everything."""
        for arm_shape, setup in setups.items():
            timed = len(C.credential_windows(setup))
            assert timed <= 2, arm_shape
            if setup:
                assert timed < len(setup), arm_shape

    def test_the_capability_arms_carry_ONE_and_the_oauth_arms_TWO(self, setups):
        """The AS's self-signed TLS certificate is the SECOND one, found by
        this enumeration rather than anticipated. It reaches only the arms that
        dial the AS, and its window is a day rather than five minutes -- but it
        is time-bound, so it is covered rather than assumed harmless."""
        assert dict(
            (name, (nbf, exp)) for name, nbf, exp in C.credential_windows(setups["B2"])
        ).keys() == {"access_token", "as_tls_cert_pem"}
        assert "as_tls_cert_pem" not in setups["B3"]

    def test_detection_is_by_SHAPE_so_a_third_credential_is_FOUND(self, setups):
        """A hardcoded field name would cover today and miss tomorrow."""
        token = setups["B3"]["access_token"]
        grown = dict(setups["B3"], some_future_credential=token)
        assert "some_future_credential" in {n for n, _, _ in C.credential_windows(grown)}

    def test_a_URL_is_not_mistaken_for_a_credential(self, setups):
        """`https://as.aasc.local` has exactly two dots. Counting them was the
        first implementation, and it made every issuer and endpoint in the setup
        an unreadable credential -- which would have refused every cell in the
        healthy case. A guard that refuses everything measures nothing."""
        for field in ("issuer", "resource_server"):
            assert C.credential_windows({field: setups["B2"][field]}) == ()
        assert C.credential_windows({"u": "https://mcp.aasc.local/tools/invoke"}) == ()


# ---------------------------------------------------------------------------
# STEP 2 — how the guard reads, and what it must never do
# ---------------------------------------------------------------------------
class TestTheGuardReadsButNeverVerifies:
    def test_a_token_with_a_BROKEN_signature_still_yields_its_window(self, setups):
        """**Unverified, demonstrated rather than asserted.** The guard decides
        SCORABILITY, never ADMISSION: verifying here would gate the measurement
        on the very verifier under measurement. A corrupted signature must
        change nothing about what the guard reads."""
        token = setups["B3"]["access_token"]
        header, payload, _signature = token.split(".")
        corrupted = f"{header}.{payload}.AAAA{'B' * 40}"
        assert C.credential_windows({"access_token": corrupted}) == C.credential_windows(
            {"access_token": token}
        )

    def test_no_verification_call_appears_in_the_guard(self):
        """Structural, parsed rather than grepped so it cannot match prose."""
        for function in (C._jwt_window, C._x509_window, C.credential_windows, C.clock_refusal):
            import textwrap

            tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
            names = [
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", "")
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
            ]
            assert not [n for n in names if "verify" in n.lower()], (
                f"{function.__name__} calls a verifier; the harness must not run the SUT's "
                "verification to decide whether a cell is scorable"
            )

    def test_nbf_is_optional_and_exp_is_not(self, setups):
        """Mirrors the SUT's own reading (`claims.get("nbf")`). Phase-1 tokens
        carry no `nbf`, so requiring one would refuse every cell."""
        windows = C.credential_windows(setups["B3"])
        assert windows[0][1] is None  # nbf absent
        assert isinstance(windows[0][2], int)  # exp present

    def test_an_unreadable_credential_FAILS_CLOSED(self):
        """Absence of a readable window is not evidence of a valid one."""
        header = base64.urlsafe_b64encode(b'{"alg":"Ed25519","typ":"at+jwt"}').decode().rstrip("=")
        broken = f"{header}.bm90LWpzb24.AAAA"
        assert C.credential_windows({"access_token": broken}) == (
            ("access_token", C.UNREADABLE[0], C.UNREADABLE[1]),
        )
        refusal = C.clock_refusal(
            artifacts={}, credentials={"access_token": broken}, judged_at=1_000_000, delta=60
        )
        assert "UNSCORABLE" in refusal

    def test_the_guard_runs_BEFORE_the_run_and_on_the_cells_own_instant(self):
        """Both constraints, structurally.

        It must be before the run, or the `B2` half -- which raises inside
        `provision` -- is never seen. And it must compare against the value
        handed to `run_scenario` as `now`, or it would be a second clock.
        """
        source = inspect.getsource(C.run_campaign)
        guard = source.index("clock_refusal(")
        run = source.index("runner.run_scenario(")
        assert guard < run, "the guard must run before the cell, or the B2 half escapes it"
        assert "judged_at=cell_instant" in source
        assert "now=cell_instant," in source


# ---------------------------------------------------------------------------
# STEP 3 — the failing world, BOTH halves
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def expired_as(runner):
    """An AS whose phase-1 tokens expire before any cell runs."""
    with ASProcess(_as_document(runner, lifetime=SHORT_LIFETIME_SECONDS), SEED) as process:
        # Permitted here and nowhere else: this IS the failing world.
        time.sleep(WAIT_SECONDS)
        yield process


def _campaign(runner, factories):
    return C.run_campaign(
        runner=runner,
        factories=factories,
        scenarios=("gt-benign",),
        seed=SEED,
        as_issuer=ISSUER,
        as_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "A" * 43},
        resource_server=AUDIENCE,
        rar_type="urn:aasc:mcp-invoke",
        sut_mode="in-process",
        run_mode="pilot",
        ledger_backed=False,
    )


@pytest.fixture(scope="module")
def capability_factories(runner, expired_as):
    setup = runner.b3_setup(
        access_token=expired_as.phase1_tokens["agent-specialist"],
        as_public_jwk=expired_as.public_jwk,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B-cap": (BCapArm, setup),
        "B3": (B3Arm, setup),
        "B3+": (B3PlusArm, setup),
    }


@pytest.fixture(scope="module")
def b2_factories(runner, expired_as):
    return {
        "B2-exchange-task": (
            B2ExchangeTaskArm,
            runner.b2_setup(
                access_token=expired_as.phase1_tokens["agent-supervisor"],
                as_public_jwk=expired_as.public_jwk,
                as_port=expired_as.port,
                as_tls_cert_pem=expired_as.tls_cert_pem,
                scenario_id="gt-benign",
                ladder_grant="task",
            ),
        )
    }


class TestHalfOneTheCapabilityArmsAreRefusedNotScored:
    """Silent half: these were scored `false_block = True` on the control."""

    def test_they_are_unscorable(self, runner, capability_factories):
        result = _campaign(runner, capability_factories)
        refused = {arm for _s, arm, _r in result.unscorable}
        assert refused == {"B-cap", "B3", "B3+"}
        assert not any(cell.arm in refused for cell in result.cells)

    def test_no_cell_is_scored_false_block_on_the_benign_CONTROL(
        self, runner, capability_factories
    ):
        result = _campaign(runner, capability_factories)
        assert [c.arm for c in result.cells if c.false_block] == []

    def test_the_arms_holding_no_token_are_UNAFFECTED(self, runner, capability_factories):
        """Non-vacuity: the guard refuses the cells whose credential expired,
        not every cell. `B0` carries no setup and `B1` a static secret."""
        result = _campaign(runner, capability_factories)
        assert {cell.arm for cell in result.cells} == {"B0", "B1"}
        assert all(cell.observed_forwarded for cell in result.cells)

    def test_the_refusal_names_the_credential_the_window_and_the_instant(
        self, runner, capability_factories
    ):
        result = _campaign(runner, capability_factories)
        for _scenario, _arm, reason in result.unscorable:
            assert "access_token" in reason
            assert "is valid over" in reason
            assert "the cell is judged at" in reason
            assert "UNSCORABLE" in reason
            reason.encode("ascii")  # read off non-UTF-8 consoles


class TestHalfTwoTheB2ArmIsRefusedNotRaised:
    """Loud half: this aborted the whole pass with `B2ConfigurationError`."""

    def test_the_campaign_COMPLETES_instead_of_aborting(self, runner, b2_factories):
        result = _campaign(runner, b2_factories)
        assert [arm for _s, arm, _r in result.unscorable] == ["B2-exchange-task"]
        assert result.cells == []

    def test_one_expired_token_now_produces_ONE_outcome_for_EVERY_arm(
        self, runner, capability_factories, b2_factories
    ):
        """The acceptance standard, in one assertion. Before this guard the
        same expiry gave a scored `false_block` for a capability arm and a
        raised `B2ConfigurationError` for an OAuth one."""
        capability = _campaign(runner, capability_factories)
        oauth = _campaign(runner, b2_factories)
        outcomes = {arm for _s, arm, _r in capability.unscorable} | {
            arm for _s, arm, _r in oauth.unscorable
        }
        assert outcomes == {"B-cap", "B3", "B3+", "B2-exchange-task"}


class TestTheGuardRemovedTheDefectReturns:
    """A guard nobody has watched refuse anything is untested code."""

    def test_without_it_the_capability_arms_are_scored_false_block(
        self, runner, capability_factories, monkeypatch
    ):
        monkeypatch.setattr(C, "clock_refusal", lambda **_kwargs: "")
        result = _campaign(runner, capability_factories)
        scored = {cell.arm for cell in result.cells if cell.false_block}
        assert scored == {"B-cap", "B3", "B3+"}
        assert result.unscorable == []
        assert all(
            cell.reason_code == "b3_oauth_resource_authorization"
            for cell in result.cells
            if cell.false_block
        )
        # ...and the oracle does not contradict it: the reference still allows.
        assert all(cell.reference_allow for cell in result.cells)

    def test_without_it_the_b2_arm_RAISES_and_aborts_the_pass(
        self, runner, b2_factories, monkeypatch
    ):
        monkeypatch.setattr(C, "clock_refusal", lambda **_kwargs: "")
        with pytest.raises(Exception, match="does not verify at this boundary"):
            _campaign(runner, b2_factories)


# ---------------------------------------------------------------------------
# STEP 4 — inert in the fast case
# ---------------------------------------------------------------------------
class TestTheGuardIsInertWhenTheCredentialIsValid:
    def test_a_live_token_covers_the_instant_and_refuses_nothing(self, setups):
        now = int(time.time())
        for arm_shape, setup in setups.items():
            assert (
                C.clock_refusal(artifacts={}, credentials=setup, judged_at=now, delta=60) == ""
            ), arm_shape

    def test_the_boundary_is_exp_EXCLUSIVE_and_nbf_INCLUSIVE(self, setups):
        """Stated rather than left to a reader. `exp` is an expiry: the token is
        invalid *at* it, as RFC 7519 §4.1.4 has it."""
        _name, _nbf, expires_at = C.credential_windows(setups["B3"])[0]
        setup = setups["B3"]
        assert (
            C.clock_refusal(artifacts={}, credentials=setup, judged_at=expires_at - 1, delta=60)
            == ""
        )
        assert (
            C.clock_refusal(artifacts={}, credentials=setup, judged_at=expires_at, delta=60) != ""
        )

    def test_a_certificate_window_is_read_too(self, setups):
        """The second credential, checked and not merely enumerated."""
        windows = dict((n, (nbf, exp)) for n, nbf, exp in C.credential_windows(setups["B2"]))
        not_before, not_after = windows["as_tls_cert_pem"]
        assert (
            C.clock_refusal(
                artifacts={},
                credentials={"as_tls_cert_pem": setups["B2"]["as_tls_cert_pem"]},
                judged_at=not_after + 1,
                delta=60,
            )
            != ""
        )
        assert (
            C.clock_refusal(
                artifacts={},
                credentials={"as_tls_cert_pem": setups["B2"]["as_tls_cert_pem"]},
                judged_at=not_before + 1,
                delta=60,
            )
            == ""
        )

    def test_the_delta_artifact_check_is_UNCHANGED(self):
        """The first check still works and still reads the frozen row."""
        artifacts = {"declassification": {"iat": 1_000_000}}
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_030, delta=20) != ""
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_030, delta=40) == ""
        assert json.dumps(C.artifact_instants({"payload_labels": ({"iat": 1},)})) == "[]"
