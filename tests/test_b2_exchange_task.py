"""`B2-exchange-task` -- the fair strong OAuth arm (EXP2 STEP 9).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Three things are under test:

1. **The exchange is real and it narrows.** A live RFC 8693 round trip against
   the running AS yields `AT_1` whose effective authority at the boundary is
   exactly `C_1` -- computed from the token's own claims, never asserted.
2. **The mirrored derivation and the AS accept each other.** The harness
   reimplements the AS's documented client-secret HKDF rather than importing
   it (ADR 0015 rule 4); agreement is required, shared code is not, and a
   wrong secret is refused so the agreement is not vacuous.
3. **The four anti-bias requirements, asserted STRUCTURALLY.** Forbidden
   action 4 rules out gratuitous per-hop cost because it inflates `B2` toward
   `B3` -- toward this project's own hypothesis. Forbidden action 5 rules out
   measuring anything. **Nothing in this file times anything**: every
   requirement is checked by construction, identity, or call count.

Platform-independent: the AS and the exchange touch no effect ledger.
"""

import ast
import base64
import builtins
import http.client
import json
import os
import ssl
import time
from pathlib import Path

import pytest
from joserfc.jwk import OKPKey

from src.harness import key_material
from src.harness.as_process import RAR_TYPE, ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner, RunnerError
from src.harness.verifier import registry as reg
from src.sut.authz import boundary
from src.sut.baselines import b2_exchange_task as b2mod
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.base import HopContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def _sealed(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


def _as_document(task_grant) -> dict:
    registry_document = reg.load_document()
    return golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=task_grant,
    )


@pytest.fixture(scope="module")
def as_document(runner):
    # The delegating client's base AT@aud carries authority exactly
    # `C_0 = U_task`, so the AS enforces `C_1 subset-of C_0` rather than
    # `C_1 subset-of Omega`. `U_task` comes from the corpus itself, which is
    # the same source the arm's own ADR 0024 check reads.
    return _as_document(runner.task_grant("gt-benign"))


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def coarse_as():
    """The MISPROVISIONED world ADR 0024 describes: no `task_grant` at all.

    Every client's base `AT@aud` then carries the whole frozen `Omega`, which
    is the parameter's own default. Used only by the counterfactual below.
    """
    document = _as_document(None)
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture
def setup(runner, running_as):
    return runner.b2_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_public_jwk=running_as.public_jwk,
        as_port=running_as.port,
        as_tls_cert_pem=running_as.tls_cert_pem,
    )


def _hop(visible: dict, *, now_epoch: int = 0, widening=()) -> HopContext:
    now = int(time.time()) if now_epoch == 0 else now_epoch
    return HopContext(
        task_id=visible["task_id"],
        audience=visible["audience"],
        from_agent=visible["supervisor"],
        to_agent=visible["specialist"],
        authority_elements=tuple(map(tuple, visible["authority_elements"])),
        attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
        widening_elements=tuple(map(tuple, widening)),
        now_epoch=now,
        expiry_epoch=now + int(visible["validity_seconds"]),
    )


@pytest.fixture
def provisioned(setup):
    arm = B2ExchangeTaskArm()
    arm.provision(setup)
    try:
        yield arm
    finally:
        arm.close()


# --------------------------------------------------------------------------
# 1. The exchange is real, and it narrows to exactly C_1
# --------------------------------------------------------------------------
class TestTheExchangeNarrows:
    def test_the_hop_yields_a_token_whose_authority_is_exactly_c1(self, provisioned, setup):
        visible, sealed = _visible("gt-benign"), _sealed("gt-benign")
        credentials = provisioned.delegate(_hop(visible))
        assert "access_token" in credentials, "the AS issued no token for a benign hop"

        config = boundary.BoundaryConfig(
            issuer=setup["issuer"],
            resource_server=setup["resource_server"],
            as_public_jwk=setup["as_public_jwk"],
            rar_type=setup["rar_type"],
        )
        claims = boundary.verify_access_token(
            credentials["access_token"], config, now=int(time.time())
        )
        allowed = boundary.allowed_authority(claims, config)
        expected_c1 = frozenset(map(tuple, sealed["C_sets"][1]))
        assert allowed == expected_c1
        # Negative arm: C_1 is a PROPER subset of C_0, so the equality above is
        # not merely restating the base token's grant.
        expected_c0 = frozenset(map(tuple, sealed["C_sets"][0]))
        assert allowed < expected_c0

    def test_the_base_token_carries_exactly_c0(self, setup, running_as):
        """The premise the AS's containment check rests on."""
        config = boundary.BoundaryConfig(
            issuer=setup["issuer"],
            resource_server=setup["resource_server"],
            as_public_jwk=setup["as_public_jwk"],
            rar_type=setup["rar_type"],
        )
        claims = boundary.verify_access_token(setup["access_token"], config, now=int(time.time()))
        assert boundary.allowed_authority(claims, config) == frozenset(
            map(tuple, _sealed("gt-benign")["C_sets"][0])
        )
        # Negative arm: the SPECIALIST's base token is the coarse one B3 uses,
        # so this narrowing is the delegating client's alone and B3's Phase 1
        # is untouched.
        coarse = boundary.verify_access_token(
            running_as.phase1_tokens["agent-specialist"], config, now=int(time.time())
        )
        assert boundary.allowed_authority(coarse, config) == frozenset(
            (a, r) for a, r in frozen_config.load_document()["omega"]["elements"]
        )

    def test_the_delegation_is_not_impersonation(self, provisioned):
        """RFC 8693 SS 1.1: `sub` stays the resource owner; the actor is in `act`."""
        credentials = provisioned.delegate(_hop(_visible("gt-benign")))
        payload = credentials["access_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        assert claims["sub"] == "user-yixian"
        assert claims["act"] == {"sub": "agent-specialist"}
        assert claims["client_id"] == "agent-supervisor"

    def test_a_widening_hop_is_refused_with_no_token_issued(self, provisioned):
        """SS E.3 chain-tamper, as the exchange arm realizes it."""
        visible = _visible("gt-benign")
        credentials = provisioned.delegate(_hop(visible, widening=[["mail.send", "mail/outbox"]]))
        assert "access_token" not in credentials, "a widening exchange must issue NO token"
        refusal = credentials["exchange_refusal"]
        assert refusal.status == 400
        assert refusal.error == "invalid_authorization_details"
        assert provisioned.exchanges[-1]["issued"] is False
        # Negative arm: the same hop without the widening element is issued, so
        # the refusal is attributable to the widening and not to the request.
        assert "access_token" in provisioned.delegate(_hop(visible))

    def test_an_exchange_that_narrows_further_is_issued(self, provisioned, setup):
        """The AS refuses widening, never narrowing -- so the refusal above is
        about direction, not about the AS refusing anything unfamiliar."""
        visible = dict(_visible("gt-benign"))
        visible["attenuation_elements"] = [["notes.read", "notes/project"]]
        credentials = provisioned.delegate(_hop(visible))
        config = boundary.BoundaryConfig(
            issuer=setup["issuer"],
            resource_server=setup["resource_server"],
            as_public_jwk=setup["as_public_jwk"],
            rar_type=setup["rar_type"],
        )
        claims = boundary.verify_access_token(
            credentials["access_token"], config, now=int(time.time())
        )
        assert boundary.allowed_authority(claims, config) == {("notes.read", "notes/project")}


# --------------------------------------------------------------------------
# The ADR 0024 guarantee, held by the ARM
# --------------------------------------------------------------------------
class TestTheArmCannotBeMisprovisioned:
    """`task_grant` is opt-in on the AS document and its default is the
    dangerous value, so the guarantee cannot live with the caller.

    The arm reads the authority of the token it actually holds and refuses
    unless it equals the run's `U_task`. Being correctly provisioned today is
    not the same property as being impossible to misprovision.
    """

    def test_a_coarse_base_token_is_refused(self, setup, running_as):
        """The exact mistake: hand the arm a base token that was not narrowed.

        The specialist's token from this very AS is coarse -- `task_grant`
        narrows the delegating client's alone -- so this is the misprovisioning
        a caller reaches by passing the wrong client's token or by forgetting
        `task_grant` entirely.
        """
        with pytest.raises(b2mod.B2ConfigurationError) as raised:
            B2ExchangeTaskArm().provision(
                dict(setup, access_token=running_as.phase1_tokens["agent-specialist"])
            )
        message = str(raised.value)
        assert "ADR 0024" in message
        assert "mail.send" in message  # it names what the token wrongly grants

    def test_a_narrower_than_u_task_base_token_is_also_refused(self, setup):
        """The equality is `==`, not `subset-of`.

        A token carrying LESS than `U_task` would make the arm unable to pass
        on `C_1` and would show up as a spurious block -- the opposite bias,
        and equally unacceptable.
        """
        narrower = [["notes.read", "notes/project"]]
        with pytest.raises(b2mod.B2ConfigurationError):
            B2ExchangeTaskArm().provision(dict(setup, grant_elements=narrower))

    def test_the_correctly_provisioned_arm_provisions(self, setup):
        """Positive arm: the refusals above are not refusing everything."""
        arm = B2ExchangeTaskArm()
        arm.provision(setup)
        arm.close()

    def test_the_runner_reads_u_task_from_the_corpus(self, runner):
        """One source for the AS's provisioning and the arm's self-check.

        Passed as an argument on both sides, one caller mistake could give
        them two different answers and the check would agree with itself while
        being wrong.
        """
        assert runner.task_grant("gt-benign") == sorted(_visible("gt-benign")["authority_elements"])
        # Every scenario of ONE FAMILY declares the same task grant -- they are
        # one task with different invocations. The corpus carries two families
        # since F4/F5 joined it, on deliberately different chains, so the
        # invariant is per-family and an UNNAMED request must fail closed
        # rather than pick one.
        grants = {
            path.stem: sorted(json.loads(path.read_text(encoding="utf-8"))["authority_elements"])
            for path in sorted((CORPUS / "sut_visible").glob("*.json"))
        }
        f1 = {name: g for name, g in grants.items() if not name.startswith(("gt-f4", "gt-f5"))}
        f45 = {name: g for name, g in grants.items() if name.startswith(("gt-f4", "gt-f5"))}
        assert len(set(map(str, f1.values()))) == 1, f1
        assert len(set(map(str, f45.values()))) == 1, f45
        assert len(f1) == 4 and len(f45) == 4
        # The load-bearing half: asked without a family, the runner REFUSES.
        # Silently returning one family's grant would provision an AS for the
        # wrong chain and every F4/F5 cell would be masked by containment.
        with pytest.raises(RunnerError, match="distinct task grants"):
            runner.task_grant()

    def test_a_token_that_does_not_verify_is_refused_before_the_comparison(self, setup):
        """Fail closed: an unverifiable token has no authority to compare."""
        with pytest.raises(b2mod.B2ConfigurationError) as raised:
            B2ExchangeTaskArm().provision(dict(setup, access_token="not.a.jwt"))
        assert "does not verify" in str(raised.value)


class TestAdr0024Counterfactual:
    """What token exchange actually does under agent delegation.

    This is a **result**, not only a regression guard. RFC 8693 does not by
    itself guarantee a narrower exchanged token -- scope, audience and
    `authorization_details` are AS-policy-determined **[VERIFIED]** -- and the
    pinned profile enforces `C_i subset-of C_{i-1}` against the **subject
    token's own** grant. So how much authority a delegating agent can pass on
    is decided by how its base token was provisioned, not by the exchange
    grant type. Two deployments differing in nothing but that provisioning
    give opposite answers to the same chain-tamper hop.

    Recorded permanently because it is the mechanism behind ADR 0024: an
    OAuth deployment that provisions agents with a coarse resource-level grant
    -- the natural thing to do, and what this pilot did by default -- gets no
    protection from token exchange against a hop that widens within that
    grant.
    """

    WIDENING = [["mail.send", "mail/outbox"]]

    @staticmethod
    def _arm_against(process, runner, task_grant):
        arm = B2ExchangeTaskArm()
        arm.provision(
            runner.b2_setup(
                scenario_id="gt-benign",
                access_token=process.phase1_tokens["agent-supervisor"],
                as_public_jwk=process.public_jwk,
                as_port=process.port,
                as_tls_cert_pem=process.tls_cert_pem,
                grant_elements=task_grant,
            )
        )
        return arm

    def test_with_a_coarse_base_grant_the_as_issues_the_widened_token(self, coarse_as, runner):
        """The deployment believes `U_task` is the whole ontology, so it is
        honestly provisioned for that -- and the AS then has nothing to refuse.
        """
        omega = [list(pair) for pair in frozen_config.load_document()["omega"]["elements"]]
        arm = self._arm_against(coarse_as, runner, omega)
        try:
            credentials = arm.delegate(_hop(_visible("gt-benign"), widening=self.WIDENING))
            assert "access_token" in credentials, "expected the AS to ISSUE the widened token"
            config = boundary.BoundaryConfig(
                issuer=ISSUER,
                resource_server=AUDIENCE,
                as_public_jwk=coarse_as.public_jwk,
                rar_type=RAR_TYPE,
            )
            claims = boundary.verify_access_token(
                credentials["access_token"], config, now=int(time.time())
            )
            granted = boundary.allowed_authority(claims, config)
            assert ("mail.send", "mail/outbox") in granted, (
                "the widened element was issued to the delegate"
            )
            # And the consequence, made concrete: the boundary then ADMITS the
            # very call SS E.3 predicts a block for.
            from src.sut.baselines.base import InvocationContext

            visible = _visible("gt-f1-chain-tamper")
            arm.present(
                credentials,
                InvocationContext(
                    tool="mail.send",
                    arguments=visible["delegation_intent"]["arguments"],
                    method=visible["method"],
                    task_id=visible["task_id"],
                    audience=visible["audience"],
                    invocation_id="cid-counterfactual",
                    now_epoch=int(time.time()),
                ),
            )
            assert arm.decide("mail.send", visible["delegation_intent"]["arguments"]) == (
                True,
                b2mod.REASON_ADMITTED,
            ), "B2 loses SS E.3's predicted block for a PROVISIONING reason"
        finally:
            arm.close()

    def test_with_the_task_scoped_grant_the_as_refuses(self, running_as, runner):
        """The same hop, the same code, the same AS profile -- one difference."""
        arm = self._arm_against(running_as, runner, runner.task_grant("gt-benign"))
        try:
            credentials = arm.delegate(_hop(_visible("gt-benign"), widening=self.WIDENING))
            assert "access_token" not in credentials
            refusal = credentials["exchange_refusal"]
            assert refusal.error == "invalid_authorization_details"
            assert refusal.status == 400
        finally:
            arm.close()

    def test_the_two_deployments_differ_in_nothing_else(self, as_document, runner):
        """The contrast is the provisioned grant and nothing besides.

        Otherwise the counterfactual would be about two different AS profiles
        rather than about one profile under two provisionings.
        """
        coarse = _as_document(None)
        scoped = as_document
        assert coarse["phase1"]["agent-supervisor"] != scoped["phase1"]["agent-supervisor"]
        for key in ("issuer", "token_endpoint", "rar_type", "omega", "clients", "registry"):
            assert coarse[key] == scoped[key]
        assert coarse["delegation_policy"] == scoped["delegation_policy"]
        # And only the DELEGATING client's grant moved.
        for actor in ("agent-specialist", "agent-worker"):
            assert coarse["phase1"][actor] == scoped["phase1"][actor]


# --------------------------------------------------------------------------
# 2. The mirrored derivation agrees with the AS
# --------------------------------------------------------------------------
class TestMirroredDerivationAgreement:
    def test_the_mirrored_secret_authenticates_a_real_exchange(self, provisioned):
        """Agreement is proven by the AS ACCEPTING it, not by comparing bytes."""
        credentials = provisioned.delegate(_hop(_visible("gt-benign")))
        assert "access_token" in credentials

    def test_a_wrong_secret_is_refused(self, setup):
        """Negative arm: the AS really is checking, so the acceptance means something."""
        arm = B2ExchangeTaskArm()
        arm.provision(dict(setup, client_secret="not-the-derived-secret"))
        try:
            credentials = arm.delegate(_hop(_visible("gt-benign")))
        finally:
            arm.close()
        assert "access_token" not in credentials
        assert credentials["exchange_refusal"].error == "invalid_client"

    def test_the_mirrored_actor_key_is_the_one_the_as_registered(self, setup, as_document):
        """The other half of the agreement: the assertion verifies AS-side."""
        registered = as_document["registry"]["agent-specialist"]["identity_jwk"]
        mirrored = dict(setup["actor_identity_private_jwk"])
        assert mirrored["x"] == registered["x"]
        # Negative arm: the private half is present here and absent there, so
        # the AS holds only the public key (`smoke/g4/DESIGN.md` SS 5.4).
        assert "d" in mirrored and "d" not in registered

    def test_no_secret_reaches_the_configuration_file_the_as_process_reads(
        self, as_document, setup, running_as
    ):
        """`ASProcess` writes the config document to a temp file; secrets must
        not be in it (CLAUDE.md red line 8, `smoke/g4/DESIGN.md` SS 5.1)."""
        serialized = json.dumps(as_document)
        assert setup["client_secret"] not in serialized
        assert setup["actor_identity_private_jwk"]["d"] not in serialized
        assert SEED.hex() not in serialized
        for token in running_as.phase1_tokens.values():
            assert token not in serialized
        # Negative arm: the document is not empty of everything -- the PUBLIC
        # identity key is there, which is what the AS legitimately needs.
        assert setup["actor_identity_private_jwk"]["x"] in serialized


# --------------------------------------------------------------------------
# 3. The four anti-bias requirements -- structural, never timed
# --------------------------------------------------------------------------
class TestAntiBiasStructural:
    """Forbidden actions 4 and 5. Nothing here measures a duration."""

    # -- requirement 1: the literal 127.0.0.1, never the name `localhost` ----
    def test_the_client_dials_the_literal_loopback_address(self, provisioned):
        assert b2mod.LOOPBACK == "127.0.0.1"
        assert provisioned._connection.host == "127.0.0.1"

    def test_the_module_contains_no_localhost_literal_at_all(self):
        """Structural, not behavioural: the name cannot be dialled from here.

        Resolving `localhost` tries `::1` first on a dual-stack host and waits
        for that to fail -- the 0.7 s-per-hop cost G-4 found by measurement
        (`smoke/g4/DESIGN.md` SS 8.2), and an inflation of B2 toward B3.
        """
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b2_exchange_task.py").read_text(
            encoding="utf-8"
        )
        literals = [
            node.value
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        # Docstrings are Constant nodes too, so exclude the module/class/function
        # docstrings before asserting -- the check is about CODE literals.
        docstrings = {
            ast.get_docstring(node, clean=False)
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        }
        code_literals = [text for text in literals if text not in docstrings]
        assert not any("localhost" in text for text in code_literals), (
            "a `localhost` literal appears in the B2 request path"
        )
        # Negative arm: the loopback literal IS there, so the scan can see
        # host strings at all.
        assert any(text == "127.0.0.1" for text in code_literals)

    # -- requirement 2: one TLS context, one keep-alive connection ------------
    def test_one_context_and_one_connection_are_reused_across_hops(self, provisioned, monkeypatch):
        visible = _visible("gt-benign")
        context, connection = provisioned._tls_context, provisioned._connection

        built = {"connections": 0, "contexts": 0}
        original_init = http.client.HTTPSConnection.__init__
        original_load = ssl.SSLContext.load_verify_locations

        def counting_init(self, *args, **kwargs):
            built["connections"] += 1
            return original_init(self, *args, **kwargs)

        def counting_load(self, *args, **kwargs):
            built["contexts"] += 1
            return original_load(self, *args, **kwargs)

        monkeypatch.setattr(http.client.HTTPSConnection, "__init__", counting_init)
        monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", counting_load)

        provisioned.delegate(_hop(visible))
        socket_after_first = provisioned._connection.sock
        provisioned.delegate(_hop(visible))

        assert built == {"connections": 0, "contexts": 0}, (
            "a hop built a new connection or a new TLS context"
        )
        assert provisioned._tls_context is context
        assert provisioned._connection is connection
        # Keep-alive: the SAME socket carried both round trips. Without
        # HTTP/1.1 keep-alive the second hop would have paid a fresh TCP
        # handshake and a fresh TLS handshake.
        assert socket_after_first is not None
        assert provisioned._connection.sock is socket_after_first

    def test_a_second_arm_would_have_built_its_own(self, setup):
        """Negative arm: the counters above can move, so zero means something."""
        built = {"connections": 0}
        original_init = http.client.HTTPSConnection.__init__

        def counting_init(self, *args, **kwargs):
            built["connections"] += 1
            return original_init(self, *args, **kwargs)

        http.client.HTTPSConnection.__init__ = counting_init
        try:
            arm = B2ExchangeTaskArm()
            arm.provision(setup)
            arm.close()
        finally:
            http.client.HTTPSConnection.__init__ = original_init
        assert built["connections"] == 1  # exactly one, at PROVISIONING time

    # -- requirement 3: no key parsed on the request path ---------------------
    def test_no_key_is_parsed_on_the_request_path(self, provisioned, monkeypatch):
        """Parsed once at provisioning, reused per hop (`smoke/g4/DESIGN.md` SS 8.2).

        Scoped to the DELEGATION path, which is what SS E.2 Phase 2 compares.
        The boundary's `BoundaryConfig.public_key()` does re-import per call,
        but that is `src/sut/authz/boundary.py` -- used UNCHANGED and
        identically by `B2`, `B-cap` and `B3` -- so it cannot bias one arm
        toward another.
        """
        parses = {"count": 0}
        original = OKPKey.import_key

        def counting(*args, **kwargs):
            parses["count"] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(OKPKey, "import_key", staticmethod(counting))
        provisioned.delegate(_hop(_visible("gt-benign")))
        provisioned.delegate(_hop(_visible("gt-benign")))
        assert parses["count"] == 0, "a key was parsed during a delegation hop"
        # Negative arm: provisioning DOES parse, so the counter is live.
        assert provisioned._actor_key is not None
        parses["count"] = 0
        fresh = B2ExchangeTaskArm()
        fresh.provision(dict(provisioned._setup))
        fresh.close()
        assert parses["count"] >= 1

    # -- requirement 4: no disk I/O on the request path -----------------------
    def test_no_disk_io_on_the_request_path(self, provisioned, monkeypatch):
        """The trust anchor is PEM TEXT from injected configuration (`cadata=`),
        never a certificate file opened per request."""
        opened: list[object] = []

        def refuse_open(*args, **kwargs):
            opened.append(args[0] if args else kwargs)
            raise AssertionError(f"disk I/O on the request path: open({args!r})")

        monkeypatch.setattr(builtins, "open", refuse_open)
        monkeypatch.setattr(os, "open", refuse_open)
        credentials = provisioned.delegate(_hop(_visible("gt-benign")))
        assert "access_token" in credentials
        assert opened == []

    def test_that_trap_really_fires(self, monkeypatch, tmp_path):
        """Negative arm: the trap above is armed, so passing through it means
        no file was opened rather than that the patch missed."""
        target = tmp_path / "probe.txt"
        target.write_text("x", encoding="utf-8")

        def refuse_open(*args, **kwargs):
            raise AssertionError("disk I/O")

        monkeypatch.setattr(builtins, "open", refuse_open)
        with pytest.raises(AssertionError):
            open(target, encoding="utf-8")


# --------------------------------------------------------------------------
# The golden thread under B2, end to end through the runner
# --------------------------------------------------------------------------
class TestTheGoldenThreadUnderB2:
    """SS E.4's prediction for this arm, and it is the honest outcome.

    A well-configured token-exchange deployment prevents scope amplification
    because it enforces the same narrowed `C_n`. `B3` blocking where this arm
    also blocks is NOT evidence of an advantage for `B3`.
    """

    @staticmethod
    def _run(runner, setup, scenario_id):
        arm = B2ExchangeTaskArm()
        try:
            return arm, runner.run_scenario(scenario_id, arm, setup=setup, ledger_backed=False)
        finally:
            arm.close()

    @pytest.mark.parametrize(
        "scenario_id,admitted,reason",
        [
            ("gt-benign", True, b2mod.REASON_ADMITTED),
            ("gt-f1-root", False, b2mod.REASON_TOKEN_SCOPE),
            ("gt-f1-terminal", False, b2mod.REASON_TOKEN_SCOPE),
        ],
    )
    def test_pilot_outcome(self, runner, setup, scenario_id, admitted, reason):
        _, run = self._run(runner, setup, scenario_id)
        event = run.mediation_events[-1]
        assert (event.admitted, event.reason_code) == (admitted, reason)

    def test_f1_terminal_needs_the_full_narrowing_to_block(self, runner, setup, provisioned):
        """SS E.3: `F1-terminal` is inside `C_0` and outside `C_1`.

        So an arm enforcing only `C_0` would ADMIT it -- which is why matched
        provisioning is mandatory, and why the block above means the exchange
        really realized `C_1`.
        """
        sealed = _sealed("gt-f1-terminal")
        required = frozenset(map(tuple, sealed["R"]))
        assert required <= frozenset(map(tuple, sealed["C_sets"][0]))
        assert not required <= frozenset(map(tuple, sealed["C_sets"][1]))

    def test_the_presented_evidence_is_a_bare_bearer_token(self, runner, setup):
        """No capability, no HTC, no INV -- SS E.1's `B2-exchange-task` row."""
        _, run = self._run(runner, setup, "gt-benign")
        assert run.observed.evidence.oauth is not None
        assert run.observed.evidence.capability is None
        assert run.observed.evidence.inv_only is None
        assert run.observed.evidence.api_key is None
        # And the sealed record has no capability commitments, because the arm
        # presented no chain to commit to.
        assert run.intent.P_hashes == []

    def test_exactly_one_online_exchange_per_delegation_hop(self, runner, setup):
        """SS E.2: the round trip IS the measured difference and is not shortcut.

        Counted, never timed (forbidden action 5).
        """
        arm, _ = self._run(runner, setup, "gt-benign")
        assert len(arm.exchanges) == 1
        assert arm.exchanges[0]["issued"] is True


# --------------------------------------------------------------------------
# The arm's shape: no capability-layer conjunct, and none may be added
# --------------------------------------------------------------------------
class TestTheArmGetsNoCapabilityConjunct:
    def test_the_bitmask_is_the_ss_e5_row(self):
        arm = B2ExchangeTaskArm()
        # oauth | crypto_chain | authorizer | htc/holder | invoke | contain |
        # context | approval | jti | audit
        assert arm.bitmask.as_bits() == (1, 0, 0, 0, 0, 1, 0, 0, 0, 1)

    def test_it_imports_no_capability_layer(self):
        """Structural: the module cannot run a capability conjunct it never imports."""
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b2_exchange_task.py").read_text(
            encoding="utf-8"
        )
        imported: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any(name.startswith("src.sut.capability") for name in imported)
        assert "src.sut.authz.capability_path" not in imported
        assert not any(name.startswith("src.sut.oauth_as") for name in imported)  # ADR 0015 rule 3
        assert not any(name.startswith("src.harness") for name in imported)  # red line 6
        # Negative arm: it DOES reuse the shared boundary, unchanged.
        assert "src.sut.authz.boundary" in imported

    def test_provisioning_fails_closed_on_missing_material(self, setup):
        for field in (
            "client_secret",
            "actor_identity_private_jwk",
            "as_tls_cert_pem",
            "grant_elements",
        ):
            incomplete = {k: v for k, v in setup.items() if k != field}
            with pytest.raises(b2mod.B2ConfigurationError):
                B2ExchangeTaskArm().provision(incomplete)
        arm = B2ExchangeTaskArm()
        arm.provision(setup)  # positive arm: the complete set provisions
        arm.close()

    def test_an_unprovisioned_arm_refuses(self):
        assert B2ExchangeTaskArm().decide("notes.write", {}) == (
            False,
            b2mod.REASON_NOT_PROVISIONED,
        )

    def test_a_refused_exchange_leaves_nothing_to_present(self, provisioned):
        from src.sut.baselines.base import InvocationContext

        visible = _visible("gt-benign")
        credentials = provisioned.delegate(_hop(visible, widening=[["mail.send", "mail/outbox"]]))
        wire = provisioned.present(
            credentials,
            InvocationContext(
                tool="notes.write",
                arguments={"resource": "notes/project", "content": "x"},
                method=visible["method"],
                task_id=visible["task_id"],
                audience=visible["audience"],
                invocation_id="cid-b2",
                now_epoch=int(time.time()),
            ),
        )
        assert wire == {}, "a refused hop must present an EMPTY wire"
        admitted, reason = provisioned.decide(
            "notes.write", {"resource": "notes/project", "content": "x"}
        )
        assert admitted is False
        assert reason == b2mod.REASON_EXCHANGE_REFUSED
        assert "invalid_authorization_details" in provisioned.audit_log[-1]["detail"]
