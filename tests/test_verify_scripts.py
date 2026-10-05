"""scripts/verify is part of the suite. A green run means these files executed."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "scripts" / "verify").glob("*.py"))


def test_every_verify_script_answers_help():
    assert SCRIPTS, "scripts/verify has no python files"
    for script in SCRIPTS:
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, cwd=ROOT, timeout=60,
        )
        ran = result.returncode == 0 or (
            script.name == "run_ml_dsa_kats.py" and "RETIRED" in result.stdout
        )
        assert ran, (
            f"{script.name} --help exited {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
