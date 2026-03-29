"""CLI entrypoint for HomeAdmin."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from homeadmin.config import load_config
from homeadmin.logging import configure_logging


def _cmd_discover(_: argparse.Namespace) -> int:
    print("discover: not yet implemented")
    return 0


def _cmd_reconcile(_: argparse.Namespace) -> int:
    print("reconcile: not yet implemented")
    return 0


def _cmd_report(_: argparse.Namespace) -> int:
    print("report: not yet implemented")
    return 0


def _cmd_baseline_create(_: argparse.Namespace) -> int:
    print("baseline create: not yet implemented")
    return 0


def _cmd_drift(_: argparse.Namespace) -> int:
    print("drift: not yet implemented")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level HomeAdmin parser."""
    parser = argparse.ArgumentParser(prog="homeadmin")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover", help="Discover assets")
    discover_parser.set_defaults(handler=_cmd_discover)

    reconcile_parser = subparsers.add_parser("reconcile", help="Reconcile data")
    reconcile_parser.set_defaults(handler=_cmd_reconcile)

    report_parser = subparsers.add_parser("report", help="Generate reports")
    report_parser.set_defaults(handler=_cmd_report)

    baseline_parser = subparsers.add_parser("baseline", help="Baseline management")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command", required=True)
    baseline_create_parser = baseline_subparsers.add_parser(
        "create", help="Create a baseline"
    )
    baseline_create_parser.set_defaults(handler=_cmd_baseline_create)

    drift_parser = subparsers.add_parser("drift", help="Detect drift")
    drift_parser.set_defaults(handler=_cmd_drift)

    return parser


def app(argv: Sequence[str] | None = None) -> int:
    """Run the HomeAdmin CLI application."""
    configure_logging()
    _ = load_config()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))


def main() -> None:
    """Console script entrypoint."""
    raise SystemExit(app())


if __name__ == "__main__":
    main()
