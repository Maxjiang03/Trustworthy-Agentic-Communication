"""Prove the workplan prune removed only enumerated plumbing, and nothing else.

**Not a gate.** Companion in spirit to `tools/reframe/verify_rename.py`: the
`docs/tasks/` → `docs/workplan/` move (the reframe's deferred Tier 2, executed
after the reframe range closed) also stripped the agent plumbing from each
archived work specification, and this script is the proof that the stripping
was a **removal, and only a removal**.

## The property

For every file under `docs/tasks/` at the baseline (plus `BOOTSTRAP_TASK.md`
at the repository root), the file exists under `docs/workplan/` at the revision
under test with the same relative path, and its content differs in exactly two
ways:

1. **whole-line deletions**, every one of which falls in a named category:
   * **A — integrity plumbing**: the STEP 0 self-check lines (line count,
     SHA-256, launch-prompt comparison) and their section furniture;
   * **B — terminal sentinel**: an `END OF …` line (none of the archived
     specifications carried one; the category exists so its emptiness is a
     checked result rather than an assumption);
   * **C — executor address**: standalone sentences instructing an executor
     to execute the file, to stop and wait for review, or to report back;
   blank lines and `---` rules are structural and inherit the category of the
   removed lines they are contiguous with;
2. **line modifications whose only change is the path repoint**
   `docs/tasks` → `docs/workplan` (reverse-substituting the new path back
   yields the old line byte-for-byte).

Insertions inside existing files, deletions of whole files, uncategorizable
removed lines, and any other modification FAIL. The only permitted addition is
`docs/workplan/README.md`, enumerated below. Surviving lines are therefore
byte-identical to the archived bytes, which each `MANIFEST.md` still describes
(the MANIFESTs themselves must come through this comparison unchanged).

## The revision is self-pinning

The proof is a statement about ONE commit — the prune — not about a moving
HEAD (`tools/reframe/` learned that the hard way: its proofs compared HEAD
and turned red on the first later development commit). The default revision
is therefore *the oldest descendant of the baseline on the current branch*,
which is the prune commit itself no matter how far development continues.
`--rev ""` reads the index, so the proof can run before the commit exists.

    uv run python tools/workplan/verify_prune.py            # the prune commit
    uv run python tools/workplan/verify_prune.py --rev ""   # the index
"""

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The commit immediately before the prune. Pinned, not inferred.
BASELINE = "e078d9b"

OLD_DIR = "docs/tasks/"
NEW_DIR = "docs/workplan/"
OLD_PATH_TOKEN = b"docs/tasks"
NEW_PATH_TOKEN = b"docs/workplan"

# Files the prune ADDS, which therefore have no baseline to compare against.
ADDED = frozenset({"docs/workplan/README.md"})

# Renames outside the directory move itself, new -> old.
FILE_RENAMES = {"docs/workplan/BOOTSTRAP_TASK.md": "BOOTSTRAP_TASK.md"}

CATEGORY_A = "A (integrity plumbing)"
CATEGORY_B = "B (terminal sentinel)"
CATEGORY_C = "C (executor address)"

A_PATTERNS = (
    r"wc -l",
    r"sha256sum",
    r"launch prompt",
    r"line count and digest",
    r"nothing was truncated",
    r"^(launch )?prompt\*\*\. If either differs",
    r"^not act on a partial spec\.$",
    r"^## STEP 0 — Self-check \(do this first, report the result\)$",
)
B_PATTERNS = (r"^END OF ",)
C_PATTERNS = (
    r"^\*\*Read this file completely, then execute it exactly",
    r"^\*\*Do not start the smoke tests\.\*\*$",
    r"^\*\*Then stop and wait for Commander review\.",
)
STRUCTURAL = re.compile(r"^(---)?$")


def _git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def _blob(rev: str, path: str) -> "bytes | None":
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=str(REPO_ROOT), capture_output=True, check=False
    )
    return result.stdout if result.returncode == 0 else None


def _tree_paths(rev: str, prefix: str) -> list[str]:
    if rev == "":
        listing = _git("ls-files", "--cached", "--", prefix)
    else:
        listing = _git("ls-tree", "-r", "--name-only", rev, "--", prefix)
    return [line for line in listing.decode().splitlines() if line.strip()]


def _classify(line: str) -> "str | None":
    for pattern in C_PATTERNS:
        if re.search(pattern, line):
            return CATEGORY_C
    for pattern in B_PATTERNS:
        if re.search(pattern, line):
            return CATEGORY_B
    for pattern in A_PATTERNS:
        if re.search(pattern, line):
            return CATEGORY_A
    return None


def _old_path(new_path: str) -> str:
    if new_path in FILE_RENAMES:
        return FILE_RENAMES[new_path]
    if new_path.startswith(NEW_DIR):
        return OLD_DIR + new_path[len(NEW_DIR) :]
    return new_path


def _resolve_rev(requested: str) -> str:
    if requested != "auto":
        return requested
    listing = _git("rev-list", "--reverse", "--first-parent", f"{BASELINE}..HEAD")
    revs = listing.decode().split()
    if not revs:
        raise SystemExit(
            f"no commit after {BASELINE} on this branch: the prune commit does not exist yet "
            '(run with --rev "" to check the index)'
        )
    return revs[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="removal-only proof for the workplan prune")
    parser.add_argument(
        "--rev",
        default="auto",
        help='revision to check (default: the first commit after the baseline; "" = the index)',
    )
    parser.add_argument("--baseline", default=BASELINE)
    args = parser.parse_args()
    rev = _resolve_rev(args.rev)

    old_paths = _tree_paths(args.baseline, OLD_DIR) + ["BOOTSTRAP_TASK.md"]
    new_paths = _tree_paths(rev, NEW_DIR)
    print(f"baseline {args.baseline} -> {rev or 'INDEX'}")
    print(f"files under {OLD_DIR} at baseline (plus BOOTSTRAP_TASK.md): {len(old_paths)}")
    print(f"files under {NEW_DIR} at revision: {len(new_paths)}")

    failures: list[str] = []
    expected_new = {
        (NEW_DIR + p[len(OLD_DIR) :])
        if p.startswith(OLD_DIR)
        else "docs/workplan/BOOTSTRAP_TASK.md"
        for p in old_paths
    }
    for path in sorted(set(new_paths) - expected_new):
        if path in ADDED:
            print(f"  new {path} (enumerated addition; nothing to reproduce)")
        else:
            failures.append(f"{path}: added, and not an enumerated addition")
    for path in sorted(expected_new - set(new_paths)):
        failures.append(f"{path}: missing at {rev or 'INDEX'} — a specification was deleted")

    totals = {CATEGORY_A: 0, CATEGORY_B: 0, CATEGORY_C: 0}
    repointed = 0
    for path in sorted(expected_new & set(new_paths)):
        new_bytes = _blob(rev, path)
        old_bytes = _blob(args.baseline, _old_path(path))
        if new_bytes is None or old_bytes is None:
            failures.append(f"{path}: blob unreadable")
            continue
        old_lines = old_bytes.decode("utf-8").splitlines()
        new_lines = new_bytes.decode("utf-8").splitlines()
        removed: list[tuple[int, str]] = []
        file_ok = True
        matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        for op, a1, a2, b1, b2 in matcher.get_opcodes():
            if op == "equal":
                continue
            if op == "delete":
                removed.extend((i, old_lines[i]) for i in range(a1, a2))
                continue
            if op == "replace" and (a2 - a1) == (b2 - b1):
                for i, j in zip(range(a1, a2), range(b1, b2), strict=True):
                    reverted = new_lines[j].encode().replace(NEW_PATH_TOKEN, OLD_PATH_TOKEN)
                    if reverted == old_lines[i].encode():
                        repointed += 1
                    else:
                        failures.append(
                            f"{path}: line {i + 1} MODIFIED beyond the path repoint:\n"
                            f"      old: {old_lines[i]!r}\n      new: {new_lines[j]!r}"
                        )
                        file_ok = False
                continue
            failures.append(
                f"{path}: lines were INSERTED (opcode {op} at old {a1 + 1}..{a2}, "
                f"new {b1 + 1}..{b2}); the prune adds nothing inside a specification"
            )
            file_ok = False
        # classify removals: contiguous runs, structural lines inherit
        run: list[tuple[int, str]] = []
        runs: list[list[tuple[int, str]]] = []
        for index, text in removed:
            if run and index != run[-1][0] + 1:
                runs.append(run)
                run = []
            run.append((index, text))
        if run:
            runs.append(run)
        for run in runs:
            categories = {c for _, t in run if (c := _classify(t)) is not None}
            for index, text in run:
                category = _classify(text)
                if category is None and STRUCTURAL.match(text) and len(categories) == 1:
                    category = next(iter(categories))
                if category is None:
                    failures.append(f"{path}: removed line {index + 1} fits NO category: {text!r}")
                    file_ok = False
                else:
                    totals[category] += 1
                    print(f"  {path}:{index + 1} [{category}] {text}")
        if file_ok and not removed:
            print(f"  ok  {path} (unchanged{' beyond the repoint' if repointed else ''})")

    print()
    print(
        f"removed: {totals[CATEGORY_A]} x {CATEGORY_A}, {totals[CATEGORY_B]} x {CATEGORY_B}, "
        f"{totals[CATEGORY_C]} x {CATEGORY_C}; repointed lines: {repointed}"
    )
    if failures:
        print(f"FAIL -- {len(failures)} violation(s):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(
        "PASS -- every specification survives with every removed line categorized, every other "
        "change a pure path repoint, and no addition beyond the enumerated README."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
