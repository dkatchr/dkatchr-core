"""
CLI entry point — argparse + delegate to runner.

REPLACES: the old dkatchr/cli.py (316 lines, mixed concerns).
The new file is tiny on purpose — it only parses args and calls run_cli.
"""

from dkatchr.cli.args import build_arg_parser
from dkatchr.cli.run import run_cli


def main() -> None:
    args = build_arg_parser().parse_args()
    run_cli(args)
