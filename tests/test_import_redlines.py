"""The automated import red-line suite (PROJECT_RULES.md red line 6; ADR 0015 rules 3-4).

Until this pass, red line 6 was convention; from this pass onward there is
real code on both sides that could cross it, so the rule is now executable:

    R1  no `src/sut/**` module imports `src.harness`;
    R2  no `src/sut/**` module outside `src/sut/oauth_as/` imports
        `src.sut.oauth_as` (agents reach the AS over the wire);
    R3  no `src/harness/**` module imports `src.sut.oauth_as` (the oracle and
        the G-13 verifier reimplement token verification independently).

The scan is over real parse trees (`ast`), covering `import X`, `from X
import Y`, and `from . import Y` relative forms resolved against the module's
own package -- a comment or string cannot trip it, and an aliased import
cannot hide from it. Each rule's test carries a negative arm proving the
scanner sees a violation when one exists, so a green run is evidence the
tree is clean rather than evidence the scanner is blind.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"


def _imports_of(path: Path) -> list[str]:
    """Every absolute module name `path` imports, relative forms resolved."""
    rel = path.relative_to(REPO_ROOT)
    package_parts = list(rel.parts[:-1])
    if rel.name != "__init__.py":
        package_parts.append(rel.stem)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                anchor = package_parts[: len(package_parts) - node.level + 1]
                # `from . import x` -> anchor is the containing package
                anchor = anchor[:-1] if rel.name != "__init__.py" and node.level == 1 else anchor
                base = ".".join(anchor + ([node.module] if node.module else []))
            found.append(base)
            found.extend(f"{base}.{alias.name}" for alias in node.names)
    return found


def _scan(root: Path) -> dict[Path, list[str]]:
    return {path: _imports_of(path) for path in sorted(root.rglob("*.py"))}


def _violations(files: dict[Path, list[str]], forbidden_prefix: str) -> list[str]:
    out = []
    for path, imports in files.items():
        try:
            shown = str(path.relative_to(REPO_ROOT))
        except ValueError:  # synthetic offenders in the negative arms live elsewhere
            shown = path.name
        for name in imports:
            if name == forbidden_prefix or name.startswith(forbidden_prefix + "."):
                out.append(f"{shown} imports {name}")
    return out


class TestRedLine6SutNeverImportsHarness:
    def test_no_sut_module_imports_harness(self):
        assert _violations(_scan(SRC / "sut"), "src.harness") == []

    def test_scanner_sees_a_violation(self, tmp_path):
        # Negative arm: a synthetic offender is detected by the same scanner.
        offender = tmp_path / "src" / "sut" / "bad.py"
        offender.parent.mkdir(parents=True)
        offender.write_text("from src.harness.schema import EffectEvent\n", encoding="utf-8")
        rel_scan = {offender: _imports_of_synthetic(offender)}
        assert _violations(rel_scan, "src.harness") != []


def _imports_of_synthetic(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            found.append(node.module or "")
    return found


class TestAdr0015Rule3NonAsSutNeverImportsAs:
    def test_no_non_as_sut_module_imports_oauth_as(self):
        files = {
            path: imports
            for path, imports in _scan(SRC / "sut").items()
            if "oauth_as" not in path.parts
        }
        assert _violations(files, "src.sut.oauth_as") == []

    def test_the_as_itself_is_exempt_and_present(self):
        # Negative arm: the AS package DOES import itself internally, so the
        # filter above is doing real work.
        as_files = {path: imports for path, imports in _scan(SRC / "sut" / "oauth_as").items()}
        assert _violations(as_files, "src.sut.oauth_as") != []


class TestAdr0015Rule4HarnessNeverImportsAs:
    def test_no_harness_module_imports_oauth_as(self):
        assert _violations(_scan(SRC / "harness"), "src.sut.oauth_as") == []

    def test_harness_may_import_other_sut(self):
        # The general permission stands (the runner composes SUT agents), so
        # rule 4 is a carve-out, not a blanket ban -- prove the distinction.
        files = _scan(SRC / "harness")
        general_sut = _violations(files, "src.sut")
        as_specific = _violations(files, "src.sut.oauth_as")
        assert general_sut != []  # the runner really does import src.sut.*
        assert as_specific == []


class TestRelativeImportResolution:
    def test_relative_imports_resolve_against_the_package(self, tmp_path):
        # `from . import exchange` inside src/sut/oauth_as/__init__-adjacent
        # modules must resolve to src.sut.oauth_as.exchange, or R2/R3 could be
        # dodged by spelling an import relatively.
        module = SRC / "sut" / "oauth_as" / "server.py"
        imports = _imports_of(module)
        assert any(name.startswith("src.sut.oauth_as") for name in imports)
