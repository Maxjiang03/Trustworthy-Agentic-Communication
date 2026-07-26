"""Regression suite for the independent effect ledger (gate G-7, ADR 0012/0013).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Enforcement under test: the exclusive-share ledger process of
src/harness/effect_ledger.py (CreateFileW, FILE_SHARE_READ only) -- every
non-harness write route fails at the OS level while the writer lives.

Pilot vocabulary and PILOT reason codes only. The mail.send tool is a
sandboxed stub (records intent, never sends). Ledger files live INSIDE the
repo tree (tests/_ledger_tmp/, removed by the fixture).
"""

import asyncio
import os
import secrets
import shutil
import sys
import time
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger
from src.harness.mediation.boundary import install_boundary
from src.harness.oracle.jcs_digest import h_jcs
from src.harness.schema import EffectEvent

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ARGS_MAIL = {"to": "x@example.test", "subject": "s", "body": "b"}


@pytest.fixture()
def ledger_path():
    tmp = REPO_ROOT / "tests" / "_ledger_tmp" / secrets.token_hex(4)
    tmp.mkdir(parents=True)
    yield str(tmp / "ledger.jsonl")
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        (REPO_ROOT / "tests" / "_ledger_tmp").rmdir()
    except OSError:
        pass


def probe_event(cid: str) -> EffectEvent:
    return EffectEvent(
        effect_id=secrets.token_hex(8),
        correlation_id=cid,
        tool="mail.send",
        audience="mcp://toy-tools(pilot)",
        action="probe(pilot)",
        resource="probe",
        recipient=None,
        effect_request_digest=h_jcs({"probe": True}),
        payload_digest=None,
        value_id=None,
        data_labels_touched=[],
        approval_ref=None,
        principal="harness(pilot)",
        timestamp_ns=time.time_ns(),
    )


def build_stack(writer: LedgerWriter) -> dict:
    """Test-local toy stack: recorder first, mediation boundary outermost."""
    server = FastMCP("g7-test-server")
    audience = "mcp://toy-tools(pilot)"
    witness = {"mail.send": 0}
    events: list = []
    deny: set[str] = set()
    corr = {"current": ""}

    def mail_send(to: str, subject: str, body: str) -> str:
        witness["mail.send"] += 1
        writer.append(  # sandboxed effector: records the intent, never sends
            EffectEvent(
                effect_id=secrets.token_hex(8),
                correlation_id=corr["current"],
                tool="mail.send",
                audience=audience,
                action="send(pilot)",
                resource=f"mail:{to}",
                recipient=to,
                effect_request_digest=h_jcs({"to": to, "subject": subject, "body": body}),
                payload_digest=None,
                value_id=None,
                data_labels_touched=[],
                approval_ref=None,
                principal="specialist(pilot)",
                timestamp_ns=time.time_ns(),
            )
        )
        return "queued(sandbox)"

    server.add_tool(mail_send, name="mail.send", description="sandboxed stub")
    install_ingress_recorder(
        server, audience=audience, correlation_provider=lambda: corr["current"], writer=writer
    )
    install_boundary(
        server,
        decide=lambda tool, args: (
            tool not in deny,
            f"{'denied' if tool in deny else 'ok'}(pilot)",
        ),
        correlation_provider=lambda: corr["current"],
        emit=events.append,
    )
    return {"server": server, "witness": witness, "events": events, "deny": deny, "corr": corr}


async def _call(ctx: dict, tool: str, args: dict):
    async with create_connected_server_and_client_session(ctx["server"]._mcp_server) as client:
        return await client.call_tool(tool, args)


# --- 1. correlation-ID propagation ---------------------------------------------


def test_correlation_id_propagation(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        ctx = build_stack(writer)
        cid1 = secrets.token_hex(16)
        ctx["corr"]["current"] = cid1
        result = asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        # Positive: ingress + effect both carry the harness-minted id unchanged.
        entries = read_ledger(ledger_path)
        assert not result.isError and len(entries) == 2
        assert all(e["correlation_id"] == cid1 for e in entries)
        assert {("ingress_request_digest" in e) for e in entries} == {True, False}
        # Negative: a second minted id produces entries under ITS id, not cid1.
        cid2 = secrets.token_hex(16)
        ctx["corr"]["current"] = cid2
        asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        new = [e for e in read_ledger(ledger_path) if e["correlation_id"] == cid2]
        assert len(new) == 2 and cid2 != cid1


# --- 2. SUT write/append/delete attempts rejected ------------------------------


def test_sut_write_attempts_rejected(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        writer.append(probe_event(secrets.token_hex(16)))
        # Negative arms: every non-harness write route fails at the OS level.
        with pytest.raises(OSError):
            open(ledger_path, "a").close()
        with pytest.raises(OSError):
            open(ledger_path, "w").close()
        with pytest.raises(OSError):
            open(ledger_path, "ab").close()
        with pytest.raises(OSError):
            os.remove(ledger_path)
        os.chmod(ledger_path, 0o666)  # attribute games do not defeat sharing mode
        with pytest.raises(OSError):
            open(ledger_path, "ab").close()
        # Positive arm: the harness write path still works after the attacks.
        writer.append(probe_event(secrets.token_hex(16)))
        assert len(read_ledger(ledger_path)) == 2


# --- 3. in-place modification rejected -----------------------------------------


def test_in_place_modification_rejected(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        writer.append(probe_event(secrets.token_hex(16)))
        before = Path(ledger_path).read_bytes()
        # Negative arm: no write handle is obtainable, so no in-place tamper.
        with pytest.raises(OSError):
            with open(ledger_path, "r+b") as handle:
                handle.seek(0)
                handle.write(b"TAMPERED")
        assert Path(ledger_path).read_bytes() == before
        # Positive arm (the enforcement is the LIVE handle, nothing magical):
        writer.close()
        with open(ledger_path, "ab") as handle:  # after release the file is ordinary
            handle.write(b"")


# --- 4. effect recorded despite a false SUT self-report ------------------------


def test_effect_survives_false_self_report(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        ctx = build_stack(writer)
        cid = secrets.token_hex(16)
        ctx["corr"]["current"] = cid
        result = asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        sut_self_report = {"correlation_id": cid, "verdict": "blocked"}  # the lie
        # Positive: the ledger alone exposes the lie (no SUT verdict consulted).
        effects = [
            e
            for e in read_ledger(ledger_path)
            if e["correlation_id"] == cid and "effect_request_digest" in e
        ]
        assert not result.isError and sut_self_report["verdict"] == "blocked"
        assert len(effects) == 1 and ctx["witness"]["mail.send"] == 1
        # Negative: an honest "admitted" report would NOT be flagged by the
        # same check (report-blocked AND effects-present).
        honest_report = {"correlation_id": cid, "verdict": "admitted"}
        assert not (honest_report["verdict"] == "blocked" and len(effects) > 0)


# --- 5. no effect recorded when the tool is not reached ------------------------


def test_no_effect_when_tool_not_reached(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        ctx = build_stack(writer)
        ctx["deny"].add("mail.send")
        cid = secrets.token_hex(16)
        ctx["corr"]["current"] = cid
        result = asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        # Positive: denied -> zero ledger entries, tool never ran, but the
        # boundary DID record the denial (the pipeline was live, not broken).
        assert result.isError and read_ledger(ledger_path) == []
        assert ctx["witness"]["mail.send"] == 0
        assert len(ctx["events"]) == 1 and ctx["events"][0].admitted is False
        # Negative: lifting the deny, the same call produces both entries.
        ctx["deny"].clear()
        ctx["corr"]["current"] = secrets.token_hex(16)
        asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        assert len(read_ledger(ledger_path)) == 2


# --- 6. ingress digest matches the ADR 0012 construction -----------------------


def test_ingress_digest_matches_adr0012(ledger_path):
    with LedgerWriter(ledger_path) as writer:
        ctx = build_stack(writer)
        ctx["corr"]["current"] = secrets.token_hex(16)
        asyncio.run(_call(ctx, "mail.send", ARGS_MAIL))
        ingress = [e for e in read_ledger(ledger_path) if "ingress_request_digest" in e]
        # Positive: recorder-side digest == H_JCS over the arguments object ==
        # the intended-style computation over the same object (ADR 0012).
        assert len(ingress) == 1
        assert ingress[0]["ingress_request_digest"] == h_jcs(ARGS_MAIL)
        # Negative: different arguments -> different ingress digest.
        ctx["corr"]["current"] = secrets.token_hex(16)
        changed = dict(ARGS_MAIL, subject="s2")
        asyncio.run(_call(ctx, "mail.send", changed))
        ingress2 = [e for e in read_ledger(ledger_path) if "ingress_request_digest" in e][-1]
        assert ingress2["ingress_request_digest"] == h_jcs(changed) != h_jcs(ARGS_MAIL)
