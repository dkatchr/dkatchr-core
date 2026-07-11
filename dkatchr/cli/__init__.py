"""CLI surface — argparse, run orchestration, dry-run reporting. This is the
ONLY package allowed to touch sys.argv, sys.exit, and the CSV file path.
Everything underneath is library code the web app reuses unchanged."""

from dkatchr.cli.main import main  # re-export for `python -m dkatchr` and shims

__all__ = ["main"]
