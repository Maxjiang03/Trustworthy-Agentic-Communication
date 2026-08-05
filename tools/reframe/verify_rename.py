"""Prove the reframe changed a NAME and five enumerated lines, and nothing else.

**Not a gate.** It lives in `tools/` and is not named `spike.py`: under `smoke/`
those two together mean *a gate*, and this adjudicates nothing.

## The property

For every file the reframe touched, reverse-substituting `PROJECT_RULES.md` back
to `CLAUDE.md` must reproduce the **pre-change bytes exactly** — with a closed
list of six exceptions. Anything else is a failure and this exits non-zero.

That property is stronger than reading a diff, because it does not depend on
anyone's care: a stray character anywhere in sixty-odd files, in a file the
reviewer skimmed or one they never opened, fails it. A **seventh** exception
fails it too, and the correct response to one is to stop rather than to
enumerate it: six were authorised, so a seventh means something changed that was
not.

**The baseline stays at `3d2473a`, the pre-reframe state, across every commit
of the reframe.** Re-baselining to the intermediate commit would split the claim
across two scripts and two commits, and a claim that needs two artifacts to
state is a claim someone will eventually state wrongly. Held here, one command
establishes the whole of it.

## This is a statement about a RANGE: `3d2473a..a667ce3`

The property proven — the reframe changed nothing but the name and six
enumerated lines — is true of that range and says **nothing about anything
after it**, so the default revision is **hard-pinned to `a667ce3`**, the
reframe's closing commit. Development after `a667ce3` is outside this proof's
scope **by construction, not by oversight**: comparing a moving HEAD turns the
proof red on the first ordinary development commit (it did, at the RQ4
commits), and a red result at a later HEAD means the script was pointed at the
wrong question — not that the reframe stopped being clean. For the same
reason, the closed EXCEPTIONS and ADDED lists are **never extended to cover
later work**: that would make the proof claim commits it does not verify, and
every future commit would need enumerating until someone forgets and it fails
silently.

## Why it compares git blobs rather than working-tree bytes

`core.autocrlf` is on for this checkout, so the working tree holds CRLF and the
object database holds LF. Comparing a working-tree file against a stored blob
would report a difference on every line of every file and prove nothing. Both
sides are therefore read with `git show`, which yields the stored bytes on each.

    uv run python tools/reframe/verify_rename.py               # the range, 3d2473a..a667ce3
    uv run python tools/reframe/verify_rename.py --rev <sha>   # an intermediate reframe commit
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The commit the reframe was performed against. Pinned, not inferred: the proof
# is a statement about a specific pair of states.
BASELINE = "3d2473a"

# The reframe's closing commit — the range's end, and the default revision.
# Pinned for the same reason BASELINE is: the proof spans BASELINE..RANGE_END
# and a later revision is a different question (see the module docstring).
RANGE_END = "a667ce3"

OLD_NAME = b"CLAUDE.md"
NEW_NAME = b"PROJECT_RULES.md"

# Path renames, new -> old. Tier 1 renames one file; Tier 2 (if landed) renames a
# directory, and `_old_path` handles that prefix-wise.
RENAMES = {"PROJECT_RULES.md": "CLAUDE.md"}
DIRECTORY_RENAMES = {"docs/workplan/": "docs/tasks/"}

# Files this change ADDS, which therefore have no baseline to reproduce. A
# closed list for the same reason the exceptions are one: "it is new" must be a
# claim the proof checks, not an excuse it accepts. An addition outside this
# list fails.
ADDED = frozenset(
    {
        "tools/reframe/verify_rename.py",
        "tools/reframe/verify_ast.py",
        "tools/reframe/REPORT.md",
    }
)

# ---------------------------------------------------------------------------
# THE FIVE EXCEPTIONS. Closed list, quoted in full, both sides.
#
# Everything else in this change is a citation following a renamed file. These
# five are the only lines whose WORDS changed, and each changes the addressee
# rather than the content: a document that says "Claude Code runs these" reads
# as agent instructions, and the identical document saying "run these" reads as
# a work plan. No red-line number, step identifier, ADR number, gate name,
# frozen row or commit SHA appears in any of them.
# ---------------------------------------------------------------------------
EXCEPTIONS: tuple[tuple[str, bytes, bytes], ...] = (
    (
        "PROJECT_RULES.md",
        b"# CLAUDE.md \xe2\x80\x94 Project Overview & Working Rules",
        b"# Project Rules \xe2\x80\x94 Overview & Working Rules",
    ),
    (
        "PROJECT_RULES.md",
        b"8. No credentials, tokens, or secrets in the repo or in code. If a push needs auth you"
        b" cannot access, STOP and ask the author.",
        b"8. No credentials, tokens, or secrets in the repo or in code. If a push needs auth that"
        b" is unavailable, STOP and ask the author.",
    ),
    (
        "docs/EXPERIMENT_ARCHITECTURE_FINAL.md",
        b"This is the specification Claude Code follows to run the feasibility smoke tests in"
        b" Part G.",
        b"This is the specification the implementation follows to run the feasibility smoke tests"
        b" in Part G.",
    ),
    (
        "docs/EXPERIMENT_ARCHITECTURE_FINAL.md",
        b"## Part 0 \xe2\x80\x94 How to read this document (for Claude Code)",
        b"## Part 0 \xe2\x80\x94 How to read this document (for the implementer)",
    ),
    (
        "docs/EXPERIMENT_ARCHITECTURE_FINAL.md",
        b"# Part G \xe2\x80\x94 Feasibility smoke-gate checklist (Claude Code runs these)",
        b"# Part G \xe2\x80\x94 Feasibility smoke-gate checklist (run these)",
    ),
    # The fifth addressee line, found by the sweep that followed the first four
    # and reworded once its author confirmed the `four` was an undercount. Every
    # instruction and its force survive; only the addressee goes.
    (
        "docs/EXPERIMENT_ARCHITECTURE_FINAL.md",
        b"Claude Code: run Part G along the DAG; stop and apply the fallback at any failing gate;"
        b" do not author or execute the confirmatory corpus; do not generate v0.5.",
        b"Part G is run along the DAG; work stops and the fallback applies at any failing gate;"
        b" the confirmatory corpus is neither authored nor executed here; v0.5 is not generated.",
    ),
)


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


def _reverse(data: bytes) -> bytes:
    """Undo the rename substitution. The inverse of what the reframe applied."""
    return data.replace(NEW_NAME, OLD_NAME)


def _apply_exceptions(path: str, data: bytes) -> bytes:
    """Undo the five enumerated rewordings, so what remains is name-only.

    Applied to the ALREADY-REVERSED bytes, and each substitution must match
    exactly once. A reworded line that has drifted, or been applied twice,
    fails here rather than silently passing.
    """
    for exception_path, before, after in EXCEPTIONS:
        if exception_path != path:
            continue
        # `after` is post-reframe text; reversing may have rewritten it, so undo
        # the rename in it too before looking for it.
        target = _reverse(after)
        count = data.count(target)
        if count != 1:
            raise SystemExit(
                f"FAIL: exception in {path} matched {count} times, expected exactly 1:\n"
                f"  {target.decode(errors='replace')}"
            )
        data = data.replace(target, _reverse(before), 1)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="reverse-substitution proof for the reframe")
    parser.add_argument(
        "--rev",
        default=RANGE_END,
        help=f"the revision to check (default {RANGE_END}, the reframe range's end)",
    )
    parser.add_argument("--baseline", default=BASELINE)
    args = parser.parse_args()

    # `--rev ""` reads the INDEX (`git show :path`), so the proof can be run
    # before the commit exists rather than after it, which is when a failure is
    # still cheap to act on.
    if args.rev == "":
        listing = _git("diff", "--name-only", "--cached", "-M", args.baseline)
    else:
        listing = _git("diff", "--name-only", "-M", f"{args.baseline}..{args.rev}")
    changed = [line for line in listing.decode().splitlines() if line.strip()]
    # A file deleted by the rename shows up on the old side; the new side is what
    # this proof walks, so drop paths that no longer exist at `rev`.
    changed = [p for p in changed if _blob(args.rev, p) is not None]

    print(f"baseline {args.baseline} -> {args.rev}")
    print(f"files changed: {len(changed)}")

    failures: list[str] = []
    exercised: set[tuple[str, bytes]] = set()
    for path in sorted(changed):
        new_bytes = _blob(args.rev, path)
        old_bytes = _blob(args.baseline, _old_path(path))
        if old_bytes is None:
            if path in ADDED:
                print(f"  new {path} (enumerated addition; nothing to reproduce)")
            else:
                failures.append(
                    f"{path}: no baseline counterpart at {args.baseline}, and it is not an "
                    "enumerated addition"
                )
            continue
        reconstructed = _apply_exceptions(path, _reverse(new_bytes))
        for exception_path, before, _after in EXCEPTIONS:
            if exception_path == path:
                exercised.add((exception_path, before))
        if reconstructed != old_bytes:
            new_lines = reconstructed.decode(errors="replace").splitlines()
            old_lines = old_bytes.decode(errors="replace").splitlines()
            differing = [
                f"      line {i + 1}: {o!r} -> {n!r}"
                for i, (o, n) in enumerate(zip(old_lines, new_lines, strict=False))
                if o != n
            ]
            if len(new_lines) != len(old_lines):
                differing.append(f"      line COUNT {len(old_lines)} -> {len(new_lines)}")
            failures.append(f"{path}: UNLISTED DIFFERENCE\n" + "\n".join(differing[:10]))
        else:
            print(f"  ok  {path}")

    if len(exercised) != len(EXCEPTIONS):
        failures.append(
            f"the exception list has {len(EXCEPTIONS)} entries but only {len(exercised)} were "
            "exercised: an exception that never fires is a claim nobody checked"
        )

    print()
    if failures:
        print(f"FAIL -- {len(failures)} unlisted difference(s):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(
        f"PASS -- reverse-substituting {NEW_NAME.decode()} -> {OLD_NAME.decode()} reproduces "
        f"{args.baseline} byte for byte across all {len(changed)} changed files, with exactly "
        f"{len(EXCEPTIONS)} enumerated exceptions and no others."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
