"""Compare two campaign snapshots cell by cell. **Not a gate.**

Exits non-zero if any cell moved, so "no §E.4 cell moved" is *asserted* rather
than argued. Every differing field is named with both values; a differing cell
SET is reported separately, because a cell that stopped running and a cell that
changed verdict are different findings.

    uv run python tools/clock_fix/compare_cells.py before.json after.json
"""

import json
import sys
from pathlib import Path


def main() -> int:
    left = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    right = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    if set(left) != set(right):
        print(f"PASS SETS DIFFER: {sorted(set(left) ^ set(right))}")
        return 1

    moved = total = 0
    for pass_name in sorted(left):
        before = {(c["scenario_id"], c["arm"]): c for c in left[pass_name]["cells"]}
        after = {(c["scenario_id"], c["arm"]): c for c in right[pass_name]["cells"]}
        if set(before) != set(after):
            print(f"{pass_name}: CELL SET DIFFERS {sorted(set(before) ^ set(after))}")
            moved += len(set(before) ^ set(after))
        for key in sorted(set(before) & set(after)):
            total += 1
            differing = sorted(k for k in before[key] if before[key][k] != after[key][k])
            if differing:
                moved += 1
                print(f"{pass_name} {key}:")
                for field in differing:
                    print(f"    {field}: {before[key][field]!r} -> {after[key][field]!r}")
        if left[pass_name]["unscorable"] != right[pass_name]["unscorable"]:
            moved += 1
            print(f"{pass_name}: UNSCORABLE DIFFERS")
            print(f"    before: {left[pass_name]['unscorable']}")
            print(f"    after:  {right[pass_name]['unscorable']}")

    print(f"\n{moved} of {total} cells differ")
    return 1 if moved else 0


if __name__ == "__main__":
    sys.exit(main())
