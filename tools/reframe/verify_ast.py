"""Prove the reframe changed **zero executable lines** of Python.

**Not a gate.** Companion to `verify_rename.py`: that one proves the bytes, this
one proves the semantics, and they fail for different reasons.

Every `.py` file is parsed at the baseline commit and at the revision under
test, **every docstring is replaced by a fixed placeholder**, and the two
abstract syntax trees are compared. Comments never enter an AST at all, so the
citation edits inside them are invisible by construction; the docstring
placeholder makes the citation edits inside docstrings invisible too. What is
left is exactly the executable content — statements, expressions, imports,
values, argument lists, decorators — and it must be identical.

A rename that touched a statement, an import or a literal fails here even if the
byte proof passed, because the byte proof's exception list could in principle
have been widened to admit one. These two are checked against each other.

**This is a statement about a RANGE, `3d2473a..a667ce3`**, so the default
revision is **hard-pinned to `a667ce3`**, the reframe's closing commit — the
same pin, for the same reason, as `verify_rename.py`. Development after
`a667ce3` is outside this proof's scope **by construction, not by oversight**:
a moving HEAD turns it red on the first ordinary development commit, and a red
result at a later HEAD means the script was pointed at the wrong question. The
closed ADDED list is never extended to cover later work.

    uv run python tools/reframe/verify_ast.py               # the range, 3d2473a..a667ce3
    uv run python tools/reframe/verify_ast.py --rev <sha>   # an intermediate reframe commit
"""

import argparse
import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = "3d2473a"
# The reframe's closing commit — the range's end, and the default revision
# (see the module docstring; kept in step with `verify_rename.py`).
RANGE_END = "a667ce3"
PLACEHOLDER = "<docstring elided for this comparison>"

# Path renames, new -> old. Kept in step with `verify_rename.py`.
RENAMES: dict[str, str] = {}
DIRECTORY_RENAMES = {"docs/workplan/": "docs/tasks/"}

# `.py` files this change ADDS, which have no baseline tree to compare against.
ADDED = frozenset({"tools/reframe/verify_rename.py", "tools/reframe/verify_ast.py"})


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


def _old_path(new_path: str) -> str:
    if new_path in RENAMES:
        return RENAMES[new_path]
    for new_prefix, old_prefix in DIRECTORY_RENAMES.items():
        if new_path.startswith(new_prefix):
            return old_prefix + new_path[len(new_prefix) :]
    return new_path


class _ElideDocstrings(ast.NodeTransformer):
    """Replace every docstring with a placeholder, leaving the tree's shape."""

    def _elide(self, node):
        self.generic_visit(node)
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body[0].value.value = PLACEHOLDER
        return node

    visit_Module = _elide
    visit_ClassDef = _elide
    visit_FunctionDef = _elide
    visit_AsyncFunctionDef = _elide


def _normalised(source: bytes) -> str:
    tree = ast.parse(source)
    tree = _ElideDocstrings().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree, annotate_fields=True, include_attributes=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="AST equality proof for the reframe")
    parser.add_argument(
        "--rev",
        default=RANGE_END,
        help=f"the revision to check (default {RANGE_END}, the reframe range's end)",
    )
    parser.add_argument("--baseline", default=BASELINE)
    args = parser.parse_args()

    if args.rev == "":
        listing = _git("diff", "--name-only", "--cached", "-M", args.baseline)
    else:
        listing = _git("diff", "--name-only", "-M", f"{args.baseline}..{args.rev}")
    changed = [line for line in listing.decode().splitlines() if line.strip().endswith(".py")]
    changed = [path for path in changed if _blob(args.rev, path) is not None]

    compared = 0
    differences: list[str] = []
    for path in sorted(changed):
        new_source = _blob(args.rev, path)
        old_source = _blob(args.baseline, _old_path(path))
        if old_source is None:
            if path in ADDED:
                print(f"  new {path} (enumerated addition; no baseline tree)")
                continue
            differences.append(f"{path}: no baseline counterpart and not an enumerated addition")
            continue
        compared += 1
        if _normalised(old_source) != _normalised(new_source):
            differences.append(f"{path}: EXECUTABLE CONTENT CHANGED")
        else:
            print(f"  ok  {path}")

    print()
    print(f"python files compared: {compared}")
    if differences:
        print(f"FAIL -- {len(differences)} difference(s):")
        for difference in differences:
            print(f"  {difference}")
        return 1
    print(
        f"PASS -- {compared} .py files are AST-identical to {args.baseline} with docstrings "
        "elided. ZERO executable lines changed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
