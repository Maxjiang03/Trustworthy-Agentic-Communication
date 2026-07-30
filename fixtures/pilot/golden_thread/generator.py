"""Pilot golden-thread corpus generator (ADR 0007): specs + seeds, never minted tokens.

Three scenarios over the frozen `Omega`, and nothing outside it (EXP1 STEP 4):

    gt-benign       Supervisor -> Specialist -> notes.write on notes/project; R inside C_1
    gt-f1-root      same hop, then mail.send on mail/outbox;                  R outside C_0
    gt-f1-terminal  same hop, then calendar.read on calendar/work,
                    which hop 1 narrowed away;                     R inside C_0, outside C_1

`C_0` and `C_1` are **computed by the frozen authorizer at generation time and
asserted against the spec, never hand-written into it** (G-2's discipline:
compute, never assert): the generator mints a throwaway chain from the frozen
templates under a seed-derived `kappa`, runs `Allowed(P_i; Gamma, kappa,
Omega)` per prefix, and refuses to write documents on any mismatch. Authority
sets are functions of the frozen Datalog, never of token bytes (ADR 0007), so
the computed sets are stable across mints while the throwaway tokens are not
-- which is why no token byte appears in any output.

Two documents per scenario, and the separation is the point (SS A.3):

    sut_visible/<id>.json   what agents and arms may see -- the task grant the
                            Supervisor legitimately holds (U_task IS the one
                            authorization input runtime principals see), the
                            scripted delegation, the arguments. NO tau_gt, NO
                            R, NO C_sets field.
    sealed/<id>.json        harness-only sealed truth: tau_gt, R, C_sets,
                            intended digest. `correlation_id` and `P_hashes`
                            are completed by the runner at mint time, because
                            tokens are minted at run time (ADR 0007) and the
                            correlation id is minted per invocation (SS F.1).

`tau_gt` is the ground-truth *task*-required scope. The task is the same
benign golden-thread task in all three scenarios -- the two F1 scenarios are
the Specialist exceeding it -- so `tau_gt` is the benign requirement
everywhere, and `R` differs from it exactly on the attack calls.

Run:  uv run python fixtures/pilot/golden_thread/generator.py
      (writes corpus.json and the six scenario documents, deterministically)
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
REPO_ROOT = CORPUS_DIR.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.harness import key_material  # noqa: E402
from src.harness.authorizer import allowed as authz  # noqa: E402
from src.harness.authorizer import frozen_config  # noqa: E402
from src.harness.frozen_parameters import expected_h_gamma, expected_h_registry  # noqa: E402
from src.harness.oracle.jcs_digest import h_jcs  # noqa: E402
from src.harness.verifier import registry as reg  # noqa: E402

# --- Corpus-level constants (the runner-held inputs, ADR 0007) ---------------
SEED_HEX = "e1" * 32  # pilot corpus seed; testbed material only (seed-disclosure warning)
NOW_EPOCH = 1785456000  # the frozen logical instant every run evaluates at (determinism)
EXPIRY_EPOCH = NOW_EPOCH + 3600
TASK_ID = "task-gt-pilot"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"  # the one MCP resource server
METHOD = "tools/call"
CONTEXT_LABEL = "internal(pilot)"  # consumed by no conjunct: rows 4/6 are UNSET
RESOURCE_OWNER = [ISSUER, "user-yixian"]
OAUTH_ACTOR = [ISSUER, "agent-specialist"]
HTC_HOLDER_KID = "kid-holder-specialist"

# --- The one task grant and the one attenuation (spec side of the assert) ----
U_TASK_SPEC = [
    ["calendar.read", "calendar/work"],
    ["notes.read", "notes/project"],
    ["notes.write", "notes/project"],
]
C1_SPEC = [
    ["notes.read", "notes/project"],
    ["notes.write", "notes/project"],
]
TAU_GT = [["notes.write", "notes/project"]]

SCENARIOS = [
    {
        "scenario_id": "gt-benign",
        "attack_subcase": "benign:golden-thread",
        "is_benign": True,
        "tool": "notes.write",
        "arguments": {
            "resource": "notes/project",
            "content": "Meeting summary: agreed the Q3 review plan.",
        },
        "R": [["notes.write", "notes/project"]],
        # the false-blocking control; reference_allow is true
        "relation": "R_subset_C1",
    },
    {
        "scenario_id": "gt-f1-root",
        "attack_subcase": "F1:root",
        "is_benign": False,
        "tool": "mail.send",
        "arguments": {
            "to": "partner@example.test",
            "subject": "Project notes",
            "body": "Forwarding the project notes as discussed.",
        },
        "R": [["mail.send", "mail/outbox"]],
        # scope amplification at the boundary: outside the root grant
        "relation": "R_outside_C0",
    },
    {
        "scenario_id": "gt-f1-terminal",
        "attack_subcase": "F1:terminal",
        "is_benign": False,
        "tool": "calendar.read",
        "arguments": {"resource": "calendar/work"},
        "R": [["calendar.read", "calendar/work"]],
        # inside the root grant, outside the narrowed terminal authority (SS E.3)
        "relation": "R_subset_C0_outside_C1",
    },
]


def _pairs(rows: list[list[str]]) -> frozenset[tuple[str, str]]:
    return frozenset((action, resource) for action, resource in rows)


def _rows(pairs: frozenset[tuple[str, str]]) -> list[list[str]]:
    return [[action, resource] for action, resource in sorted(pairs)]


def compute_authority_sets() -> tuple[frozenset, frozenset]:
    """Mint a throwaway chain from the frozen templates; compute C_0 and C_1.

    The frozen artifact is hash-verified against `docs/frozen_parameters.md`
    first, so what evaluates is provably the sealed configuration.
    """
    doc = frozen_config.load_document()
    if frozen_config.h_gamma(doc) != expected_h_gamma():
        raise SystemExit("H(Gamma) mismatch: the frozen authorizer artifact has drifted")
    registry_doc = reg.load_document()
    if reg.h_registry(registry_doc) != expected_h_registry():
        raise SystemExit("H(R) mismatch: the frozen identity registry has drifted")

    seed = bytes.fromhex(SEED_HEX)
    root_private, root_pub = key_material.biscuit_root(seed)
    chain = authz.build_chain(
        doc,
        root_private,
        root_pub,
        [tuple(pair) for pair in U_TASK_SPEC],
        [[tuple(pair) for pair in C1_SPEC]],
        audience=AUDIENCE,
        task=TASK_ID,
        expiry=datetime.fromtimestamp(EXPIRY_EPOCH, tz=timezone.utc),
    )
    context = authz.RequestContext(
        now=datetime.fromtimestamp(NOW_EPOCH, tz=timezone.utc),
        audience=AUDIENCE,
        task=TASK_ID,
    )
    c0 = authz.allowed(authz.Chain((chain.prefix(0),), root_pub), doc, context)
    c1 = authz.allowed(chain, doc, context)
    return c0, c1


def check_scenario_relations(c0: frozenset, c1: frozenset) -> None:
    """The spec'd set relations, verified against the computed sets."""
    omega = frozen_config.omega(frozen_config.load_document())
    for scenario in SCENARIOS:
        required = _pairs(scenario["R"])
        if not required <= omega:
            raise SystemExit(f"{scenario['scenario_id']}: R is not inside the frozen Omega")
        relation = scenario["relation"]
        holds = {
            "R_subset_C1": required <= c1,
            "R_outside_C0": not required <= c0,
            "R_subset_C0_outside_C1": required <= c0 and not required <= c1,
        }[relation]
        if not holds:
            raise SystemExit(f"{scenario['scenario_id']}: computed sets refute {relation}")
    if not _pairs(TAU_GT) <= omega:
        raise SystemExit("tau_gt is not inside the frozen Omega")


def corpus_document() -> dict:
    return {
        "_banner": (
            "Pilot corpus runner inputs (ADR 0007): seed and derivation labels from which "
            "keys are minted at run time. Testbed material only -- publishing a seed "
            "publishes every key derived from it; these keys MUST NOT be reused in any "
            "deployment. SUT principals receive derived material by injection only."
        ),
        "corpus": "golden_thread(pilot)",
        "seed_hex": SEED_HEX,
        "derivation_info_prefix": key_material.DERIVATION_INFO_PREFIX.decode("ascii"),
        "now_epoch": NOW_EPOCH,
        "expiry_epoch": EXPIRY_EPOCH,
        "task_id": TASK_ID,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "method": METHOD,
    }


def sut_visible_document(scenario: dict) -> dict:
    return {
        "_banner": (
            "SUT-VISIBLE scenario request. Carries the task grant the Supervisor "
            "legitimately holds (U_task is the one authorization input any runtime "
            "principal sees, SS A.3) and the scripted delegation. No tau_gt, no R, "
            "no sealed field appears here."
        ),
        "scenario_id": scenario["scenario_id"],
        "task_id": TASK_ID,
        "audience": AUDIENCE,
        "method": METHOD,
        "context_label": CONTEXT_LABEL,
        "supervisor": "agent-supervisor",
        "specialist": "agent-specialist",
        "authority_elements": U_TASK_SPEC,
        "attenuation_elements": C1_SPEC,
        "delegation_intent": {"tool": scenario["tool"], "arguments": scenario["arguments"]},
        "now_epoch": NOW_EPOCH,
        "expiry_epoch": EXPIRY_EPOCH,
    }


def sealed_document(scenario: dict, c0: frozenset, c1: frozenset) -> dict:
    return {
        "_banner": (
            "HARNESS-ONLY SEALED TRUTH -- no SUT principal may read this document "
            "(CLAUDE.md red line 5; SS A.3). correlation_id and P_hashes are completed "
            "by the runner at mint time, because tokens are minted at run time (ADR 0007) "
            "and the correlation id is minted per invocation (SS F.1)."
        ),
        "scenario_id": scenario["scenario_id"],
        "attack_subcase": scenario["attack_subcase"],
        "is_benign": scenario["is_benign"],
        "resource_owner": RESOURCE_OWNER,
        "oauth_actor": OAUTH_ACTOR,
        "htc_holder_kid": HTC_HOLDER_KID,
        "audience": AUDIENCE,
        "method": METHOD,
        "tool": scenario["tool"],
        "intended_request_digest": h_jcs(scenario["arguments"]),
        "intended_labels": [],
        "requires_approval": False,
        "U_task": _rows(c0),
        "C_sets": [_rows(c0), _rows(c1)],
        "R": scenario["R"],
        "tau_gt": TAU_GT,
    }


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def generate(write: bool = True) -> dict[str, dict]:
    """Compute, verify, and (optionally) write every corpus document."""
    confirmatory = REPO_ROOT / "fixtures" / "confirmatory"
    extras = [p.name for p in confirmatory.iterdir() if p.name != "README.md"]
    if extras:
        raise SystemExit(f"fixtures/confirmatory/ must stay empty until sealing: {extras}")

    c0, c1 = compute_authority_sets()
    if _pairs(U_TASK_SPEC) != c0:
        raise SystemExit("computed C_0 differs from the spec'd U_task")
    if _pairs(C1_SPEC) != c1:
        raise SystemExit("computed C_1 differs from the spec'd attenuation")
    check_scenario_relations(c0, c1)

    documents: dict[str, dict] = {"corpus.json": corpus_document()}
    for scenario in SCENARIOS:
        documents[f"sut_visible/{scenario['scenario_id']}.json"] = sut_visible_document(scenario)
        documents[f"sealed/{scenario['scenario_id']}.json"] = sealed_document(scenario, c0, c1)
    if write:
        for relative, document in documents.items():
            _write(CORPUS_DIR / relative, document)
    return documents


if __name__ == "__main__":
    written = generate(write=True)
    print(f"golden_thread pilot corpus: {len(written)} documents verified and written")
    print("C_0 and C_1 computed by the frozen authorizer and asserted against the spec")
