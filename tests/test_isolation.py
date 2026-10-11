"""The verifier's independence, checked instead of promised.

core/ may import the standard library and itself. verifier/ may also import
core and the cryptography package. Neither may reach the registry or the AI
helper, by any route.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "proofchain"

FORBIDDEN = ("proofchain.registry", "proofchain.ai", "anthropic", "fastapi")

ALLOWED = {
    "core": ("proofchain.core",),
    "verifier": ("proofchain.core", "proofchain.verifier", "cryptography"),
}


def within(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def imported_modules(path: Path) -> set[str]:
    """Every module a file imports, with relative imports made absolute."""
    package = list(path.relative_to(PACKAGE.parent).with_suffix("").parts[:-1])
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - (node.level - 1)]
                base = ".".join(base + ([node.module] if node.module else []))
            else:
                base = node.module
            found.add(base)
            # "from .. import ai" names a module, not an attribute
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return found


def source_files(package: str) -> list[Path]:
    return sorted((PACKAGE / package).rglob("*.py"))


@pytest.mark.parametrize("package", ["core", "verifier"])
def test_package_has_source_to_check(package):
    assert any(path.stat().st_size for path in source_files(package))


@pytest.mark.parametrize(
    "path",
    source_files("core") + source_files("verifier"),
    ids=lambda p: p.relative_to(PACKAGE).as_posix(),
)
def test_no_import_of_registry_or_ai(path):
    reached = {m for m in imported_modules(path) for bad in FORBIDDEN if within(m, bad)}
    assert not reached, f"{path.name} imports {sorted(reached)}"


@pytest.mark.parametrize(
    "package, path",
    [(package, path) for package in ALLOWED for path in source_files(package)],
    ids=lambda v: v if isinstance(v, str) else v.relative_to(PACKAGE).as_posix(),
)
def test_imports_stay_inside_the_allowed_set(package, path):
    outside = set()
    for module in imported_modules(path):
        top = module.split(".")[0]
        if top in sys.stdlib_module_names:
            continue
        if top == "proofchain" and any(within(allowed, module) for allowed in ALLOWED[package]):
            continue  # "proofchain" itself, on the way to an allowed package
        if any(within(module, allowed) for allowed in ALLOWED[package]):
            continue
        outside.add(module)
    assert not outside, f"{path.name} imports {sorted(outside)}"


def test_the_import_scan_sees_relative_and_absolute_imports(tmp_path, monkeypatch):
    # Guards the guard: a scan that found nothing would pass every test above.
    fake = tmp_path / "proofchain" / "verifier" / "bad.py"
    fake.parent.mkdir(parents=True)
    fake.write_text(
        "from .. import ai\n"
        "from ..registry.db import connect\n"
        "import proofchain.ai.explain\n"
        "def f():\n"
        "    import anthropic\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE", tmp_path / "proofchain")
    found = imported_modules(fake)
    assert {"proofchain.ai", "proofchain.registry.db", "proofchain.ai.explain", "anthropic"} <= found


def test_loading_the_verifier_loads_no_registry_or_ai_code():
    script = (
        "import sys\n"
        "import proofchain.verifier.cli\n"
        f"bad = [m for m in sys.modules for p in {FORBIDDEN!r} if m == p or m.startswith(p + '.')]\n"
        "print(sorted(bad))\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"
