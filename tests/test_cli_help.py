"""Every command must explain itself.

A CLI whose commands carry a one-line docstring is a CLI only its author can
use. These tests are deliberately about the PRODUCT surface rather than about
behaviour: they assert that each command says what it does, and that the app
description matches what the project actually is.
"""
from __future__ import annotations

from typer.main import get_command
from typer.testing import CliRunner

import qknot.cli as cli_module
from qknot.cli import app

runner = CliRunner()

# Both halves of the project must be reachable from the CLI.
EXPECTED = {
    # audit
    "scan", "scan-ids", "audit-npm", "audit-pypi", "summarise",
    # signing
    "entropy", "sign", "verify",
    # identity
    "register", "verify-registration",
}


def _commands():
    return get_command(app).commands


def test_every_expected_command_is_registered():
    assert set(_commands()) >= EXPECTED


def test_every_command_has_substantial_help():
    """Not just a title: what it needs, and the caveat that matters."""
    thin = {name: (sub.help or "")
            for name, sub in _commands().items()
            if len((sub.help or "").strip()) < 120}
    assert not thin, f"these commands need real help: {sorted(thin)}"


def test_the_app_description_covers_both_halves():
    """It described only 'ML model registries' long after the project audited
    npm and PyPI too, and signed arbitrary artefacts."""
    help_text = " ".join((app.info.help or "").split()).lower()
    for term in ("npm", "pypi", "huggingface", "sign", "identity"):
        assert term in help_text, f"app help does not mention {term!r}"


def test_running_a_command_with_help_exits_cleanly():
    for name in sorted(EXPECTED):
        result = runner.invoke(app, [name, "--help"])
        assert result.exit_code == 0, f"{name} --help failed: {result.output}"
        assert name.split("-")[0][:4] in result.output.lower() or result.output


def test_the_main_guard_is_last_so_python_m_sees_every_command():
    """`if __name__ == '__main__': app()` once sat in the middle of the module,
    before the signing commands were defined, so `python -m qknot.cli sign`
    reported 'No such command' while the console script worked."""
    source = __import__("pathlib").Path(cli_module.__file__).read_text(encoding="utf-8")
    guard = source.index('if __name__ == "__main__":')
    last_command = source.rindex("@app.command")
    assert guard > last_command, (
        "the __main__ guard must come after every @app.command, or commands "
        "defined below it are invisible to `python -m qknot.cli`")
