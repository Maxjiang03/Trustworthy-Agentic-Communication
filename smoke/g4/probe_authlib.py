"""Gate G-4 (Phase 1) — empirical probe of `authlib` against the FIRST limb of IA-4.

Run ephemerally, with nothing pinned (ADR 0004: a pin never precedes its gate):

    uv run --with authlib python smoke/g4/probe_authlib.py

IA-4 (§F.4) is a disjunction: "The OAuth stack (`authlib`) supports RFC 8693 exchange narrowing
to `C_i` + RFC 9396 authorization_details, **or** a behaviourally faithful AS can be built."
This probe tests only the FIRST limb, on recorded evidence, in the G-8 spirit: an off-the-shelf
candidate is examined against the requirement and adopted or rejected on what is actually there,
not on documentation or recollection.

It builds NO authorization server. Every "attempt" below asks the INSTALLED PACKAGE to supply
the piece; the first missing piece is the answer. Hand-writing a missing grant class would be
the Phase 2 build, which this pass is forbidden to start (task STEP 1 item 1).

Exit code: 0 if the probe ran and produced a verdict (whatever the verdict); non-zero only if
the probe itself failed to run.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import inspect
import re
import sys
from pathlib import Path

# The concrete requirement, restated so the probe is self-describing.
GRANT_TYPE_URN = "urn:ietf:params:oauth:grant-type:token-exchange"  # RFC 8693 §2.1
RAR_PARAM = "authorization_details"  # RFC 9396 §2

SYMBOL_RE = re.compile(r"^\s*(class|def|async def)\s+([A-Za-z_][A-Za-z0-9_]*)")


def enclosing_symbol(lines: list[str], index: int) -> str:
    """Nearest enclosing `class`/`def` above `index`, for G-6-style file:symbol citation."""
    for i in range(index, -1, -1):
        match = SYMBOL_RE.match(lines[i])
        if match:
            return match.group(2)
    return f"L{index + 1}"


def grep_tree(root: Path, needle: str, limit: int = 12) -> list[str]:
    """Every occurrence of `needle` in the installed source, as `relpath:symbol` citations."""
    hits: list[str] = []
    for path in sorted(root.rglob("*.py")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines):
            if needle in line:
                rel = path.relative_to(root.parent).as_posix()
                hits.append(f"{rel}:{enclosing_symbol(lines, index)} (line {index + 1})")
                if len(hits) >= limit:
                    return hits
    return hits


def rfc_modules(root: Path) -> list[str]:
    """Which `rfcNNNN` implementation packages the installed distribution actually ships."""
    found: list[str] = []
    for path in sorted(root.rglob("rfc[0-9][0-9][0-9][0-9]")):
        if path.is_dir():
            found.append(path.relative_to(root.parent).as_posix())
    return found


def try_import(name: str) -> tuple[bool, str]:
    try:
        importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 — the exact failure IS the evidence
        return False, f"{type(exc).__name__}: {exc}"
    return True, "imported"


def main() -> int:
    print("=" * 78)
    print("G-4 PHASE 1 — authlib probe (evidence only; NO AS is built here)")
    print("=" * 78)

    # ---------------------------------------------------------------- A. identity
    print("\n[A] Resolved distribution")
    import authlib

    root = Path(authlib.__file__).resolve().parent
    print(f"    authlib.__version__     : {authlib.__version__}")
    print(f"    importlib.metadata      : {md.version('authlib')}")
    print(f"    installed source root   : {root}")
    print(f"    python                  : {sys.version.split()[0]}")

    # ------------------------------------------------- B. what the package ships
    print("\n[B] RFC implementation packages actually shipped (directory inventory)")
    modules = rfc_modules(root)
    for module in modules:
        print(f"    {module}")
    print(f"    -> {len(modules)} rfcNNNN packages")
    has_8693_pkg = any(m.endswith("rfc8693") for m in modules)
    has_9396_pkg = any(m.endswith("rfc9396") for m in modules)
    print(f"    rfc8693 package present : {has_8693_pkg}")
    print(f"    rfc9396 package present : {has_9396_pkg}")

    # ------------------------------------ C. the two required surfaces, by content
    print("\n[C] Source evidence for the two required surfaces")
    urn_hits = grep_tree(root, GRANT_TYPE_URN)
    print(f"    RFC 8693 grant-type URN {GRANT_TYPE_URN!r}:")
    for hit in urn_hits or ["    (no occurrence anywhere in the installed source)"]:
        print(f"        {hit}")
    rar_hits = grep_tree(root, RAR_PARAM)
    print(f"    RFC 9396 parameter {RAR_PARAM!r}:")
    for hit in rar_hits or ["    (no occurrence anywhere in the installed source)"]:
        print(f"        {hit}")
    for token in ("subject_token", "actor_token", "requested_token_type", "issued_token_type"):
        hits = grep_tree(root, token, limit=3)
        print(f"    RFC 8693 parameter {token!r}: {hits or 'ABSENT'}")

    # ------------------------- D0. a directory name is not an implementation
    print("\n[D0] Content of any rfc8693 package found (a name is not an implementation)")
    pkg_8693 = root / "oauth2" / "rfc8693"
    symbols_8693: list[str] = []
    if pkg_8693.is_dir():
        listing = [(p.name, p.stat().st_size) for p in sorted(pkg_8693.iterdir())]
        print(f"    files                   : {listing}")
        module_8693 = importlib.import_module("authlib.oauth2.rfc8693")
        symbols_8693 = [n for n in dir(module_8693) if not n.startswith("_")]
        print(f"    public symbols          : {symbols_8693 or 'NONE'}")
        print(f"    __all__                 : {getattr(module_8693, '__all__', 'ABSENT')}")
        docstring = (module_8693.__doc__ or "").strip().splitlines()
        print(f"    docstring claims        : {' '.join(docstring[2:]) or '(none)'}")
        if not symbols_8693:
            print("    -> the package exists but defines NOTHING; its docstring claims an")
            print("       implementation that is not present. Directory inventory alone would")
            print("       have reported support here; content inspection refutes it.")
    else:
        print("    (no rfc8693 package)")

    # ------------------------------------------- D. concrete attempt 1: the grant
    print("\n[D] Concrete attempt 1 — ask the package for an RFC 8693 grant")
    candidates = [
        "authlib.oauth2.rfc8693",
        "authlib.oauth2.rfc8693.token_exchange",
        "authlib.integrations.flask_oauth2.rfc8693",
    ]
    import_results: dict[str, str] = {}
    for name in candidates:
        ok, detail = try_import(name)
        import_results[name] = detail
        print(f"    import {name:45s} -> {'OK' if ok else detail}")

    grants = importlib.import_module("authlib.oauth2.rfc6749.grants")
    exported = sorted(n for n in dir(grants) if n.endswith("Grant"))
    print(f"    authlib/oauth2/rfc6749/grants exports: {exported}")
    exchange_named = [n for n in exported if "xchang" in n.lower() or "8693" in n]
    print(f"    -> grant classes mentioning 'exchange': {exchange_named or 'NONE'}")

    # ---------------------------------------- E. concrete attempt 2: the RAR half
    print("\n[E] Concrete attempt 2 — ask the package to carry narrowed authority as RAR")
    server_mod = importlib.import_module("authlib.oauth2.rfc6749.authorization_server")
    server_cls = server_mod.AuthorizationServer
    print(f"    AuthorizationServer     : {inspect.getfile(server_cls)}:AuthorizationServer")
    print(f"    .register_grant{inspect.signature(server_cls.register_grant)}")
    generator = importlib.import_module("authlib.oauth2.rfc6750.token").BearerTokenGenerator
    print(f"    BearerTokenGenerator    : {inspect.getfile(generator)}:BearerTokenGenerator")
    print(f"    .__call__{inspect.signature(generator.__call__)}")
    call_src = inspect.getsource(generator.__call__)
    carries_rar = RAR_PARAM in call_src
    print(f"    token response builder emits {RAR_PARAM!r}: {carries_rar}")
    print("    (RFC 9396 §7: 'the AS MUST also return the authorization_details as granted")
    print("     ... and assigned to the respective access token' — this is the surface that")
    print("     must emit it, so its absence is decisive for the second half of limb 1.)")

    # -------------------------------------------------------------- F. the verdict
    print("\n[F] VERDICT")
    # Content, never a directory name: a package that defines nothing implements nothing.
    limb_8693 = bool(urn_hits) or bool(exchange_named) or bool(symbols_8693)
    limb_9396 = bool(rar_hits) or has_9396_pkg or carries_rar
    if limb_8693 and limb_9396:
        verdict = "SUPPORTED"
        detail = "both halves are present off the shelf; ADR 0004's finding is REFUTED"
    elif limb_8693 or limb_9396:
        verdict = "PARTIALLY SUPPORTED"
        half = "RFC 8693 exchange" if limb_8693 else "RFC 9396 authorization_details"
        missing = "RFC 9396 authorization_details" if limb_8693 else "RFC 8693 exchange"
        detail = f"present: {half}; absent (must be written by hand): {missing}"
    else:
        verdict = "UNSUPPORTED"
        detail = (
            "neither half is present; what is present is only the generic extension-grant "
            "framework (AuthorizationServer.register_grant + BaseGrant), so BOTH the RFC 8693 "
            "grant and the RFC 9396 authorization_details plumbing would have to be written "
            "by hand — which is the behaviourally faithful AS of IA-4's SECOND limb"
        )
    print(f"    authlib {md.version('authlib')}: {verdict}")
    print(f"    {detail}")
    print("\n    Exact failures recorded, not summarized:")
    for name, detail in import_results.items():
        print(f"        {name} -> {detail}")
    print("\n    This probe adjudicates NOTHING: IA-4 stays [UNVERIFIED-IA] and G-4 is not")
    print("    marked PASS. Adjudication is Phase 2, on the built AS.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — probe-ran-vs-probe-failed is the exit contract
        print(f"PROBE FAILED TO RUN: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
