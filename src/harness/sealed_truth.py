"""The sealed-truth wall: `tau_gt` and every sealed object live behind this accessor.

PROJECT_RULES.md red line 5 / SS A.3: `tau_gt` is oracle-only; **no system-under-test
principal may read it**. Two mechanisms enforce that, layered:

1. **Structural** (the guarantee): `src/sut/` must never import `src/harness/`
   (red line 6, asserted by the AST red-line suite), and this accessor is the
   only reader of `fixtures/pilot/**/sealed/`. SUT modules receive scenario
   material exclusively as the SUT-visible document, injected by the runner.
2. **Runtime** (defense in depth): every accessor call walks the interpreter
   stack and refuses if ANY frame belongs to a `src.sut.*` module -- so even a
   hypothetical harness helper invoked from SUT code cannot launder sealed
   truth through itself. `tests/test_sealed_truth_wall.py` proves the refusal
   fires and that the same call succeeds from harness/test context.

The runtime guard is a tripwire, not the security boundary: a determined
in-process reader could bypass `inspect` (the G-7/G-12 residual about
in-process reachability applies here too, excluded architecturally by SUT
process separation in the campaign). What it guarantees in THIS apparatus is
that no accidental call path from SUT code can ever return sealed truth.
"""

import inspect
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SEALED_DIRS = {
    "golden_thread": REPO_ROOT / "fixtures" / "pilot" / "golden_thread" / "sealed",
}


class SealedTruthAccessError(Exception):
    """A SUT principal reached for sealed truth. Always an error, never a warning."""


def _refuse_sut_frames() -> None:
    for frame_info in inspect.stack():
        module = frame_info.frame.f_globals.get("__name__", "")
        if module == "src.sut" or module.startswith("src.sut."):
            raise SealedTruthAccessError(
                f"sealed truth requested from SUT module {module!r} "
                "(CLAUDE.md red line 5; SS A.3: tau_gt is oracle-only)"
            )


def load_sealed(scenario_id: str, *, corpus: str = "golden_thread") -> dict[str, Any]:
    """The harness-only read path for one scenario's sealed-truth document."""
    _refuse_sut_frames()
    directory = SEALED_DIRS.get(corpus)
    if directory is None:
        raise SealedTruthAccessError(f"unknown corpus {corpus!r}")
    path = directory / f"{scenario_id}.json"
    if not path.is_file():
        raise SealedTruthAccessError(f"no sealed document for scenario {scenario_id!r}")
    return json.loads(path.read_text(encoding="utf-8"))
