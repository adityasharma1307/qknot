"""The reusability guarantee, enforced.

`qresp.signing` is meant to be usable by anyone signing anything -- firmware,
datasets, documents, container images -- not just HuggingFace models. That is
only true if it never reaches into the audit code. A guarantee stated in a
docstring decays; one stated as a test does not.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

SIGNING = pathlib.Path(__file__).resolve().parents[2] / "src" / "qresp" / "signing"


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
    offenders = {m for m in _imported_modules(path) if m.startswith("qresp.audit")}
    assert not offenders, (
        f"{path.name} imports {offenders}. qresp.signing must stay independent "
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
    """`qresp.signing` avoiding `qresp.audit` is worth little if the CLI
    reunites them at import time.

    It did. `cli.py` imported `HfClient`, `QLabel` and the scanner at module
    level, so `qresp sign` -- a pure signing operation on a local directory --
    refused to start without `tenacity`, `huggingface_hub` and `pydantic`
    installed. Someone signing a firmware image had to install a HuggingFace
    client first, which is precisely the coupling the boundary exists to
    prevent.

    Found by running the demo notebook in an environment with only the signing
    dependencies, where the CLI crashed on `tenacity`.
    """

    def test_cli_does_not_import_the_audit_package_at_module_level(self):
        import ast
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[2]
                  / "src" / "qresp" / "cli.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        offenders = []
        for node in tree.body:                      # module level only
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("audit") or ".audit" in node.module:
                    offenders.append(node.module)
            elif isinstance(node, ast.Import):
                offenders += [a.name for a in node.names if "qresp.audit" in a.name]

        assert not offenders, (
            f"cli.py imports {offenders} at module level. Move it inside the "
            f"command that needs it, so `qresp sign` runs without the audit "
            f"dependencies."
        )

    def test_the_signing_commands_are_reachable_without_audit_modules(self):
        """Simulate the audit stack being absent and check the CLI still loads."""
        import importlib
        import sys

        blocked = ("tenacity", "huggingface_hub", "pydantic")
        saved = {name: sys.modules.pop(name, None) for name in blocked}
        for name in list(sys.modules):
            if name.startswith("qresp.cli") or name.startswith("qresp.audit"):
                sys.modules.pop(name, None)

        class _Blocker:
            def find_module(self, fullname, path=None):
                return self if fullname.split(".")[0] in blocked else None

            def load_module(self, fullname):
                raise ImportError(f"{fullname} is blocked for this test")

        sys.meta_path.insert(0, _Blocker())
        try:
            cli = importlib.import_module("qresp.cli")
            names = {c.callback.__name__ for c in cli.app.registered_commands}
            assert "sign_artefact" in names and "verify_artefact" in names
        finally:
            sys.meta_path.pop(0)
            for name, module in saved.items():
                if module is not None:
                    sys.modules[name] = module
            sys.modules.pop("qresp.cli", None)
