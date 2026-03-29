"""CLI entrypoint for HomeAdmin."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path

from homeadmin.baseline import create_baseline_snapshot
from homeadmin.config import load_config, validate_discovery_scope
from homeadmin.discovery import run_discovery
from homeadmin.drift import calculate_drift
from homeadmin.logging import configure_logging
from homeadmin.reconcile import load_discovery_assets, reconcile_assets
from homeadmin.reporting import write_reports
from homeadmin.storage.db import Storage


def _state_paths(state_dir: Path) -> tuple[Path, Path, Path]:
    db_path = state_dir / "homeadmin.db"
    discovery_latest = state_dir / "discovery" / "latest.json"
    reports_dir = state_dir / "reports"
    return db_path, discovery_latest, reports_dir


def _cmd_discover(args: argparse.Namespace) -> int:
    config = load_config()
    try:
        validate_discovery_scope(config)
    except ValueError as exc:
        print(f"discover: invalid scope configuration: {exc}")
        return 2

    state_dir = args.state_dir or config.state_dir
    db_path, _, _ = _state_paths(state_dir)

    storage = Storage(db_path)
    storage.initialize()

    result = run_discovery(config, storage, state_dir=state_dir)
    print(
        "discover: "
        f"run_id={result.run_id} run_uuid={result.run_uuid} "
        f"jobs={result.collection_jobs} observations={result.observation_count} "
        f"assets={result.asset_count} wrote={result.discovery_path}"
    )
    return 0


def _cmd_reconcile(args: argparse.Namespace) -> int:
    config = load_config()
    state_dir = args.state_dir or config.state_dir
    db_path, discovery_latest, _ = _state_paths(state_dir)

    storage = Storage(db_path)
    storage.initialize()

    if not discovery_latest.exists():
        print(f"reconcile: discovery snapshot missing at {discovery_latest}")
        return 2

    assets = load_discovery_assets(discovery_latest)
    result = reconcile_assets(storage, assets, run_uuid=args.run_uuid)
    print(f"reconcile: run_id={result.run_id} run_uuid={result.run_uuid} assets={result.asset_count}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    config = load_config()
    state_dir = args.state_dir or config.state_dir
    db_path, _, reports_dir = _state_paths(state_dir)

    storage = Storage(db_path)
    storage.initialize()

    result = calculate_drift(storage)
    artifacts = write_reports(result, reports_dir)
    print(f"report: json={artifacts.json_path} markdown={artifacts.markdown_path}")
    return 0


def _cmd_baseline_create(args: argparse.Namespace) -> int:
    config = load_config()
    state_dir = args.state_dir or config.state_dir
    db_path, _, _ = _state_paths(state_dir)

    storage = Storage(db_path)
    storage.initialize()

    result = create_baseline_snapshot(storage)
    print(
        f"baseline create: version={result.baseline_version} baselines={result.baseline_count}"
    )
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    config = load_config()
    state_dir = args.state_dir or config.state_dir
    db_path, _, reports_dir = _state_paths(state_dir)

    storage = Storage(db_path)
    storage.initialize()

    result = calculate_drift(storage)
    if args.write_report:
        artifacts = write_reports(result, reports_dir)
        print(f"drift: report json={artifacts.json_path} markdown={artifacts.markdown_path}")

    summary = {
        "generated_at": result.generated_at,
        "reference_type": result.reference_type,
        "latest_run_id": result.latest_run_id,
        "counts": {
            "current": len(result.current),
            "new": len(result.new),
            "missing": len(result.missing),
            "unresolved_unknowns": len(result.unresolved_unknowns),
            "source_contradictions": len(result.source_contradictions),
        },
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _cmd_pipeline(args: argparse.Namespace) -> int:
    discover_args = argparse.Namespace(state_dir=args.state_dir, input=args.input)
    reconcile_args = argparse.Namespace(state_dir=args.state_dir, run_uuid=args.run_uuid)
    baseline_args = argparse.Namespace(state_dir=args.state_dir)
    drift_args = argparse.Namespace(state_dir=args.state_dir, write_report=False)
    report_args = argparse.Namespace(state_dir=args.state_dir)

    for handler, local_args in (
        (_cmd_discover, discover_args),
        (_cmd_reconcile, reconcile_args),
        (_cmd_baseline_create, baseline_args),
        (_cmd_drift, drift_args),
        (_cmd_report, report_args),
    ):
        status = handler(local_args)
        if status != 0:
            return status
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level HomeAdmin parser."""
    parser = argparse.ArgumentParser(prog="homeadmin")
    parser.add_argument("--state-dir", type=Path, default=None, help="Override state directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover", help="Discover assets")
    discover_parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional JSON list of discovered assets",
    )
    discover_parser.set_defaults(handler=_cmd_discover)

    reconcile_parser = subparsers.add_parser("reconcile", help="Reconcile data")
    reconcile_parser.add_argument("--run-uuid", default=None, help="Optional explicit run UUID")
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
    drift_parser.add_argument(
        "--write-report",
        action="store_true",
        help="Also write JSON/Markdown drift report artifacts",
    )
    drift_parser.set_defaults(handler=_cmd_drift)

    pipeline_parser = subparsers.add_parser(
        "pipeline", help="Run discover -> reconcile -> baseline create -> drift -> report"
    )
    pipeline_parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional JSON list of discovered assets",
    )
    pipeline_parser.add_argument("--run-uuid", default=None, help="Optional explicit run UUID")
    pipeline_parser.set_defaults(handler=_cmd_pipeline)

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
