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
