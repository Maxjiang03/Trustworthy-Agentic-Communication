"""Gate G-7 spike: independent effect ledger + ToolIngressEvent recorder.

Tests IA-7 (docs/EXPERIMENT_ARCHITECTURE_FINAL.md SS F.4): an immutable
external effect ledger plus a ToolIngressEvent recorder can be interposed at
the tool, INDEPENDENT of agent self-report. Pass criterion (Part G): both
recorded independently of any SUT self-report; correlation_id matches the
harness-minted value.

Mechanism (src/harness/effect_ledger.py): a separate ledger process holds
the file via CreateFileW with FILE_SHARE_READ only -- every other
open-for-write/truncate/delete fails at the OS level; the harness holds the
child's pipes (the only write path). The mail.send tool is a SANDBOXED STUB
whose effector RECORDS an intent to act and returns; nothing is ever sent.
Pilot vocabulary and PILOT reason codes only -- NOT the frozen ontology
Omega. In-memory transport; the ledger file lives INSIDE the repo tree
(smoke/g7/_ledger_tmp/, removed on exit).
"""

import asyncio
import json
import os
import secrets
import shutil
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))  # repo root, for src.*

from src.harness.effect_ledger import LedgerWriter, install_ingress_recorder, read_ledger  # noqa: E402
from src.harness.mediation.boundary import install_boundary  # noqa: E402
from src.harness.oracle.jcs_digest import h_jcs  # noqa: E402
from src.harness.schema import EffectEvent  # noqa: E402

RESULTS = []


def record(check: str, ok: bool, evidence: str) -> None:
    RESULTS.append((check, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {check}: {evidence}")


class SandboxedMailEffector:
    """Records an EffectEvent for each send INTENT; never sends anything."""

    def __init__(self, writer: LedgerWriter, corr: dict, audience: str):
        self._writer, self._corr, self._audience = writer, corr, audience

    def record_send(self, to: str, subject: str, body: str) -> None:
        self._writer.append(
            EffectEvent(
                effect_id=secrets.token_hex(8),
                correlation_id=self._corr["current"],
                tool="mail.send",
                audience=self._audience,
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


def build_stack(ledger_path: str) -> dict:
    writer = LedgerWriter(ledger_path)
    server = FastMCP("g7-toy-server")
    audience = "mcp://toy-tools(pilot)"
    witness = {"mail.send": 0}
    events: list = []
    deny: set[str] = set()
    corr = {"current": ""}
    effector = SandboxedMailEffector(writer, corr, audience)

    def mail_send(to: str, subject: str, body: str) -> str:
        witness["mail.send"] += 1
        effector.record_send(to, subject, body)
        return "queued(sandbox; nothing sent)"

    server.add_tool(mail_send, name="mail.send", description="sandboxed stub")
    # Recorder first, boundary second: the mediation wrapper stays OUTERMOST,
    # so a denied call never reaches the recorder.
    install_ingress_recorder(
        server, audience=audience, correlation_provider=lambda: corr["current"], writer=writer
    )
    install_boundary(
        server,
        decide=lambda tool, args: (tool not in deny, f"{'denied' if tool in deny else 'ok'}(pilot)"),
        correlation_provider=lambda: corr["current"],
        emit=events.append,
    )
    return {
        "server": server,
        "writer": writer,
        "witness": witness,
        "events": events,
        "deny": deny,
        "corr": corr,
    }


async def main(ledger_path: str) -> None:
    ctx = build_stack(ledger_path)
    server, writer, corr = ctx["server"], ctx["writer"], ctx["corr"]
    args_mail = {"to": "x@example.test", "subject": "s", "body": "b"}

    async with create_connected_server_and_client_session(server._mcp_server) as client:
        # ---- G-7.A ingress + effect, harness-minted correlation --------------
        cid = secrets.token_hex(16)
        corr["current"] = cid
        result = await client.call_tool("mail.send", args_mail)
        entries = read_ledger(ledger_path)
        ingress = [e for e in entries if "ingress_request_digest" in e]
        effects = [e for e in entries if "effect_request_digest" in e]
        expected_digest = h_jcs(args_mail)
        record(
            "G-7.A one call -> ToolIngressEvent + EffectEvent, correlation intact",
            not result.isError
            and len(ingress) == 1
            and len(effects) == 1
            and ingress[0]["correlation_id"] == cid
            and effects[0]["correlation_id"] == cid
            and ingress[0]["ingress_request_digest"] == expected_digest
            and effects[0]["effect_request_digest"] == expected_digest,
            f"ingress=1 effect=1 cid={cid[:16]}.. digest={expected_digest[:16]}.. "
            f"(H_JCS, ADR 0012; recorder-side)",
        )

        # ---- G-7.B SUT-side write/append/delete attempts all fail ------------
        attempts = []
        for label, attack in [
            ("append open('a')", lambda: open(ledger_path, "a")),
            ("truncate open('w')", lambda: open(ledger_path, "w")),
            ("binary append open('ab')", lambda: open(ledger_path, "ab")),
            ("delete os.remove", lambda: os.remove(ledger_path)),
        ]:
            try:
                handle = attack()
                getattr(handle, "close", lambda: None)()
                attempts.append((label, False, "SUCCEEDED (enforcement hole)"))
            except PermissionError as exc:
                attempts.append((label, True, f"PermissionError({exc.winerror})"))
            except OSError as exc:
                attempts.append((label, True, f"{type(exc).__name__}({exc})"))
        # chmod does not help the attacker: the sharing mode is attribute-proof.
        os.chmod(ledger_path, 0o666)
        try:
            open(ledger_path, "ab").close()
            attempts.append(("post-chmod append", False, "SUCCEEDED"))
        except (PermissionError, OSError) as exc:
            attempts.append(("post-chmod append", True, f"{type(exc).__name__}"))
        writer.append(  # positive arm: the harness write path still works
            EffectEvent(
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
        )
        harness_path_alive = len(read_ledger(ledger_path)) == len(entries) + 1
        for label, ok, outcome in attempts:
            print(f"    attack[{label}]: blocked={ok} ({outcome})")
        record(
            "G-7.B SUT cannot write/append/delete; harness write path alive",
            all(ok for _, ok, _ in attempts) and harness_path_alive,
            "; ".join(f"{label}:{'blocked' if ok else 'HOLE'}" for label, ok, _ in attempts)
            + f"; writer.append ok={harness_path_alive}",
        )

        # ---- G-7.C in-place modification rejected; bytes unchanged -----------
        before_bytes = Path(ledger_path).read_bytes()
        try:
            with open(ledger_path, "r+b") as handle:
                handle.seek(0)
                handle.write(b"TAMPERED")
            modified = True
            outcome = "write SUCCEEDED"
        except (PermissionError, OSError) as exc:
            modified = False
            outcome = f"{type(exc).__name__}({getattr(exc, 'winerror', '')})"
        record(
            "G-7.C in-place modification rejected, entries byte-identical",
            not modified and Path(ledger_path).read_bytes() == before_bytes,
            f"open('r+b') -> {outcome}; bytes unchanged={Path(ledger_path).read_bytes() == before_bytes}",
        )

        # ---- G-7.D records survive SUT lying ---------------------------------
        cid = secrets.token_hex(16)
        corr["current"] = cid
        result = await client.call_tool("mail.send", args_mail)
        sut_self_report = {"correlation_id": cid, "verdict": "blocked"}  # the lie
        ledger_effects = [
            e
            for e in read_ledger(ledger_path)
            if e.get("correlation_id") == cid and "effect_request_digest" in e
        ]
        lie_detected = sut_self_report["verdict"] == "blocked" and len(ledger_effects) > 0
        record(
            "G-7.D ledger survives SUT lying (self-report 'blocked', effect recorded)",
            not result.isError and lie_detected,
            f"self_report=blocked ledger_effects={len(ledger_effects)} -> lie detected "
            f"from the ledger alone (no SUT verdict read)",
        )

        # ---- G-7.E non-vacuity: unreached tool -> no ledger entries ----------
        ctx["deny"].add("mail.send")
        cid = secrets.token_hex(16)
        corr["current"] = cid
        count_before = len(read_ledger(ledger_path))
        result = await client.call_tool("mail.send", args_mail)
        count_after = len(read_ledger(ledger_path))
        record(
            "G-7.E denied call -> ZERO new ledger entries (non-vacuity)",
            result.isError
            and count_after == count_before
            and ctx["events"][-1].admitted is False
            and all(e.get("correlation_id") != cid for e in read_ledger(ledger_path)),
            f"isError={result.isError} ledger {count_before}->{count_after} "
            f"boundary_event=denied",
        )

    writer.close()
    # After the exclusive handle is released, the file is an ordinary artifact:
    post_close_appendable = False
    try:
        with open(ledger_path, "ab"):
            post_close_appendable = True
    except OSError:
        pass
    print(f"    (control: file appendable after writer.close() = {post_close_appendable} -- "
          f"the immutability came from the live exclusive handle, not an attribute)")


if __name__ == "__main__":
    tmp_dir = REPO_ROOT / "smoke" / "g7" / "_ledger_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    ledger_file = tmp_dir / f"ledger-{secrets.token_hex(4)}.jsonl"
    try:
        asyncio.run(main(str(ledger_file)))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    failed = [c for c, ok in RESULTS if not ok]
    print(f"\nG-7 spike: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)
    sys.exit(0)
