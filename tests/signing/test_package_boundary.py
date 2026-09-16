"""The reusability guarantee, enforced.

`qknot.signing` is meant to be usable by anyone signing anything -- firmware,
datasets, documents, container images -- not just HuggingFace models. That is
only true if it never reaches into the audit code. A guarantee stated in a
docstring decays; one stated as a test does not.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

SIGNING = pathlib.Path(__file__).resolve().parents[2] / "src" / "qknot" / "signing"


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", sorted(SIGNING.rglob("*.py")), ids=lambda p: p.name)
def test_signing_never_imports_the_audit_package(path):
    offenders = {m for m in _imported_modules(path) if m.startswith("qknot.audit")}
    assert not offenders, (
        f"{path.name} imports {offenders}. qknot.signing must stay independent "
        f"of the HuggingFace audit so it can be reused for any artefact."
    )


@pytest.mark.parametrize("path", sorted(SIGNING.rglob("*.py")), ids=lambda p: p.name)
def test_signing_has_no_registry_specific_dependencies(path):
    """No huggingface_hub, no datasets library. Signing bytes needs neither."""
    forbidden = {"huggingface_hub", "datasets", "transformers"}
    offenders = _imported_modules(path) & forbidden
    assert not offenders, (
        f"{path.name} imports {offenders}, which ties the signing pipeline to "
        f"one ecosystem"
    )


def test_signing_package_documents_its_independence():
    init = (SIGNING / "__init__.py").read_text(encoding="utf-8")
    assert "no dependency" in init.lower() or "independence" in init.lower()


class TestTheCliRespectsTheBoundaryToo:
    """`qknot sign` must load without the audit extra."""

    def test_cli_does_not_import_the_audit_package_at_module_level(self):
        import ast
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[2]
                  / "src" / "qknot" / "cli.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        offenders = []
        for node in tree.body:                      # module level only
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("audit") or ".audit" in node.module:
                    offenders.append(node.module)
            elif isinstance(node, ast.Import):
                offenders += [a.name for a in node.names if "qknot.audit" in a.name]

        assert not offenders, (
            f"cli.py imports {offenders} at module level. Move it inside the "
            f"command that needs it, so `qknot sign` runs without the audit "
            f"dependencies."
        )

    def test_the_signing_commands_are_reachable_without_audit_modules(self):
        """Simulate the audit stack being absent and check the CLI still loads."""
        import importlib
        import sys

        blocked = ("tenacity", "huggingface_hub", "pydantic")
        saved = {name: sys.modules.pop(name, None) for name in blocked}
        for name in list(sys.modules):
            if name.startswith("qknot.cli") or name.startswith("qknot.audit"):
                sys.modules.pop(name, None)

        class _Blocker:
            def find_module(self, fullname, path=None):
                return self if fullname.split(".")[0] in blocked else None

            def load_module(self, fullname):
                raise ImportError(f"{fullname} is blocked for this test")

        sys.meta_path.insert(0, _Blocker())
        try:
            cli = importlib.import_module("qknot.cli")
            names = {c.callback.__name__ for c in cli.app.registered_commands}
            assert "sign_artefact" in names and "verify_artefact" in names
        finally:
            sys.meta_path.pop(0)
            for name, module in saved.items():
                if module is not None:
                    sys.modules[name] = module
            sys.modules.pop("qknot.cli", None)


def _toml_array(text: str, key: str) -> str:
    token = f"{key} = ["
    start = text.index(token) + len(token)
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
        i += 1
    return text[start : i - 1]


def _pkg_names(block: str) -> set[str]:
    names: set[str] = set()
    for raw in block.splitlines():
        line = raw.split("#", 1)[0].strip().strip(",").strip('"').strip("'")
        if not line:
            continue
        names.add(line.split(">=")[0].split("==")[0].split("[")[0].strip())
    return names


class TestCoreInstallDoesNotPullTheAuditStack:
    """`pip install qknot` must not pull huggingface_hub. Signing does not
    import it; the audit extra does."""

    def test_core_dependencies_exclude_audit_packages(self):
        text = (pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        project, _, extras = text.partition("[project.optional-dependencies]")
        core = _pkg_names(_toml_array(project, "dependencies"))
        forbidden = {"huggingface_hub", "tenacity", "pydantic"}
        assert not (core & forbidden), (
            f"core install pulls {core & forbidden}; those belong in extra `audit`"
        )
        assert "cryptography" in core and "dilithium-py" in core

    def test_audit_extra_lists_the_audit_only_packages(self):
        text = (pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        _, _, extras = text.partition("[project.optional-dependencies]")
        audit = _pkg_names(_toml_array(extras, "audit"))
        assert {"huggingface_hub", "tenacity", "pydantic"} <= audit
        assert "register" in extras and "transparency" in extras

    def test_readme_documents_the_split_extras(self):
        readme = (pathlib.Path(__file__).resolve().parents[2] / "README.md").read_text(
            encoding="utf-8"
        )
        assert "qknot[audit]" in readme
        assert "qknot[register]" in readme
        assert "pip install qknot" in readme


class TestAuditCommandsNameTheExtraWhenItIsMissing:
    """Audit CLI must not surface an opaque ImportError if qknot[audit] is
    absent. The message names the extra."""

    @pytest.mark.parametrize(
        "args",
        [
            ["scan", "--n", "1"],
            ["scan-ids", "--ids", "missing.txt"],
            ["audit-npm", "--out", "x.jsonl", "--ranking", "r.json", "--frame", "f.txt"],
            ["audit-pypi", "--out", "x.jsonl"],
            ["summarise", "--in", "missing.jsonl"],
        ],
        ids=["scan", "scan-ids", "audit-npm", "audit-pypi", "summarise"],
    )
    def test_missing_audit_extra_is_an_install_hint_not_a_traceback(self, monkeypatch, args):
        import sys

        from typer.testing import CliRunner

        from qknot.cli import app

        for name in ("huggingface_hub", "pydantic", "tenacity"):
            monkeypatch.setitem(sys.modules, name, None)

        result = CliRunner().invoke(app, args)
        assert result.exit_code == 2, result.output
        assert "qknot[audit]" in result.output
        assert "Traceback" not in result.output
        assert "ImportError" not in result.output
