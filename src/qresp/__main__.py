"""Entry point for `python -m qresp`.

Exists so the CLI is reachable without depending on the console script being on
PATH. On Windows the Scripts directory frequently is not, and a 20,000-model
audit is not the moment to be debugging PATH.
"""
from .cli import app

if __name__ == "__main__":
    app()
