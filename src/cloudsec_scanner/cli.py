"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from cloudsec_scanner import __version__
from cloudsec_scanner.config import load_config, write_default_config
from cloudsec_scanner.comparison import (
    ComparisonError,
    compare_report_documents,
    compare_reports,
    render_comparison_text,
)
from cloudsec_scanner.image_scan import ImageScanError, scan_image
from cloudsec_scanner.history import (
    HistoryError,
    default_history_db_path,
    get_scan,
    get_trends,
    list_scans,
    record_scan,
)
from cloudsec_scanner.models import SEVERITY_ORDER
from cloudsec_scanner.report import write_report, render_text, terminal_color
from cloudsec_scanner.scanner import scan_target

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
EXIT_ERROR = 3


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", help="write report to this path")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="terminal text colors; NO_COLOR disables colors")
    parser.add_argument("--relative-paths", action="store_true", help="remove local absolute scan roots from exported reports")
    parser.add_argument("--exceptions", help="explicit YAML policy with expiring finding exceptions")
    parser.add_argument(
        "--severity", choices=tuple(SEVERITY_ORDER), help="override configured failure threshold"
    )
    parser.add_argument(
        "--fail-on-findings", action="store_true", help="fail when any finding meets the threshold"
    )
    parser.add_argument(
        "--baseline",
        help="previous CloudSec JSON report; use with --fail-on-new for baseline-aware gating",
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="fail only when new findings meet the configured severity threshold (requires --baseline)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="always return success for findings (scan errors still fail)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudsec", description="Cloud infrastructure and configuration security scanner"
    )
    parser.add_argument("--version", action="version", version=f"cloudsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("target", help="file or directory to scan")
    scan.add_argument("--config", help="YAML configuration file")
    scan.add_argument(
        "--scanner",
        action="append",
        choices=("iac", "secrets", "dependencies"),
        help="scanner(s) to enable; repeat to select multiple",
    )
    scan.add_argument("--no-history", action="store_true", help="do not persist this scan in local history")
    scan.add_argument("--history-db", help="SQLite history database path (overrides the default)")
    _add_report_options(scan)

    image = sub.add_parser("image", help="scan a built container image using Trivy")
    image.add_argument("target", help="container image reference, such as nginx:1.27")
    image.add_argument("--trivy-path", help="explicit path to the Trivy executable")
    image.add_argument(
        "--timeout", type=int, default=900, help="scan timeout in seconds (default: 900)"
    )
    image.add_argument("--config", help="YAML configuration file (failure threshold only)")
    image.add_argument("--no-history", action="store_true", help="do not persist this scan in local history")
    image.add_argument("--history-db", help="SQLite history database path (overrides the default)")
    _add_report_options(image)

    history = sub.add_parser("history", help="inspect persistent scan history and trends")
    history_actions = history.add_subparsers(dest="history_action", required=True)

    history_list = history_actions.add_parser("list", help="list recent scan runs")
    history_list.add_argument("--database", help="SQLite history database path")
    history_list.add_argument("--limit", type=int, default=20, help="number of runs to show (1-1000)")
    history_list.add_argument("--target", help="filter by exact scan target")
    history_list.add_argument("--format", choices=("text", "json"), default="text")

    history_show = history_actions.add_parser("show", help="show one scan run and its findings")
    history_show.add_argument("run_id", type=int, help="scan run ID from history list")
    history_show.add_argument("--database", help="SQLite history database path")
    history_show.add_argument("--format", choices=("text", "json"), default="text")

    history_trends = history_actions.add_parser("trends", help="show scan posture trends over time")
    history_trends.add_argument("--database", help="SQLite history database path")
    history_trends.add_argument("--days", type=int, default=30, help="history window in days (1-3650)")
    history_trends.add_argument("--target", help="filter by exact scan target")
    history_trends.add_argument("--format", choices=("text", "json"), default="text")

    compare = sub.add_parser(
        "compare", help="compare two JSON scan reports using stable finding identities"
    )
    compare.add_argument("baseline", help="previous scan JSON report")
    compare.add_argument("current", help="current scan JSON report")
    compare.add_argument("--format", choices=("text", "json"), default="text")
    compare.add_argument("--output", help="write comparison report to this path")

    cloud = sub.add_parser("cloud", help="read-only live cloud inventory and posture")
    cloud.add_argument("provider", choices=("aws",))
    cloud.add_argument("--region", action="append", required=True, help="AWS region; repeat to scan multiple regions")
    cloud.add_argument("--output", help="output inventory JSON path")
    cloud.add_argument("--redact-identifiers", action="store_true", help="pseudonymize account and resource identifiers in exported AWS inventory")
    cloud.add_argument("--no-fail", action="store_true", help="ignore findings exit code, not collection errors")

    sbom = sub.add_parser("sbom", help="export resolved dependency inventory as CycloneDX JSON")
    sbom.add_argument("target", help="lockfile or directory")
    sbom.add_argument("--output", help="output SBOM JSON path")

    init = sub.add_parser("config-init", help="write a starter YAML configuration")
    init.add_argument("--output", default=".cloudsec.yml", help="configuration file path")
    return parser


def _apply_policy(result, config) -> None:
    """Apply configured rule exclusions and severity overrides to scan findings."""
    excluded = set(config.get("exclude_rules", []))
    overrides = config.get("severity_overrides", {})
    result.findings = [
        replace(finding, severity=overrides.get(finding.rule_id, finding.severity))
        for finding in result.findings
        if finding.rule_id not in excluded
    ]


def _finish_report(result, args, config, scan_type: str) -> int:
    _apply_policy(result, config)
    accepted = set()
    if args.exceptions:
        from cloudsec_scanner.policy import apply_exceptions, load_exceptions
        accepted = apply_exceptions(result, load_exceptions(args.exceptions))

    baseline_gate = bool(args.fail_on_new or config.get("fail_on_new_findings", False))
    if baseline_gate and not args.baseline:
        raise ValueError("baseline-aware gating requires --baseline when --fail-on-new is enabled")

    comparison = None
    if args.baseline:
        try:
            baseline_doc = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except OSError as exc:
            raise ComparisonError(f"could not read baseline report {args.baseline}: {exc}") from exc
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ComparisonError("baseline report is not valid UTF-8 JSON") from exc
        if not isinstance(baseline_doc, dict):
            raise ComparisonError("baseline report must contain a JSON object")
        comparison = compare_report_documents(baseline_doc, result.to_dict())

    export_result = result
    if args.relative_paths:
        from cloudsec_scanner.privacy import relative_report
        export_result = relative_report(result)
    exclusions = bool(config.get("exclude_rules"))
    rendered = write_report(export_result, args.format, args.output, exclusions=exclusions)
    if args.format == "text":
        print(render_text(export_result, color=terminal_color(args.color, sys.stdout), exclusions=exclusions), end="")
    elif not args.output:
        print(rendered, end="")

    if not args.no_history:
        try:
            history_record = record_scan(
                default_history_db_path(args.history_db), result, scan_type=scan_type
            )
            print(
                f"Scan history: run #{history_record['id']} "
                f"({history_record['lifecycle']['status']})",
                file=sys.stderr,
            )
        except HistoryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if result.errors or not result.coverage_complete:
        print("error: scan incomplete; see report for coverage and errors", file=sys.stderr)
        return EXIT_ERROR

    threshold = config["severity_threshold"]
    threshold_order = SEVERITY_ORDER[threshold]
    if baseline_gate and not args.no_fail:
        assert comparison is not None
        revoked = {entry["finding_id"] for entry in result.exceptions if entry["status"] in {"EXPIRED", "AMBIGUOUS", "SEVERITY_ESCALATED", "REVIEW_REQUIRED"}}
        # A formerly accepted baseline finding must not become permanently exempt.
        if baseline_doc is not None:
            revoked.update(entry["finding_id"] for entry in baseline_doc.get("exceptions", []) if isinstance(entry, dict) and entry.get("status") == "ACCEPTED" and isinstance(entry.get("finding_id"), str) and entry["finding_id"] not in accepted)
        blocking_findings = [
            item
            for item in comparison["new"] + [entry for entry in comparison["changed"] if SEVERITY_ORDER[entry["current_severity"]] < SEVERITY_ORDER[entry["previous_severity"]]]
            if item["finding_id"] not in accepted and SEVERITY_ORDER.get(
                str(item["finding"].get("severity", "INFO")).upper(), 99
            )
            <= threshold_order
        ]
        from cloudsec_scanner.comparison import finding_identity, _relative_finding
        if any(finding_identity(_relative_finding(f.to_dict(), {"target": result.target})) in revoked and SEVERITY_ORDER[f.severity] <= threshold_order for f in result.findings):
            print("Baseline gate: a current blocking finding has a revoked or invalid exception.", file=sys.stderr)
            return EXIT_FINDINGS
        print(
            f"Baseline gate: {len(comparison['new'])} new finding(s); "
            f"{len(blocking_findings)} meet the {threshold} failure threshold.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS if blocking_findings else EXIT_OK

    from cloudsec_scanner.comparison import finding_identity, _relative_finding
    has_blocking = any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold_order
        and finding_identity(_relative_finding(f.to_dict(), {"target": result.target})) not in accepted
        for f in result.findings
    )
    if args.no_fail:
        return EXIT_OK
    should_fail = args.fail_on_findings or config.get("fail_on_findings", True)
    return EXIT_FINDINGS if should_fail and has_blocking else EXIT_OK


def _history_summary(record: dict) -> dict:
    """Return compact metadata for history list/trend output."""
    lifecycle = record.get("lifecycle", {})
    lifecycle_summary = {
        key: lifecycle.get(key)
        for key in (
            "status",
            "new_count",
            "resolved_count",
            "persistent_count",
            "changed_count",
            "severity_escalation_count",
        )
    }
    return {
        "id": record["id"],
        "scanned_at": record["scanned_at"],
        "target": record["target"],
        "scan_type": record["scan_type"],
        "files_scanned": record["files_scanned"],
        "files_skipped": record["files_skipped"],
        "finding_count": record["finding_count"],
        "severity_counts": record["severity_counts"],
        "lifecycle": lifecycle_summary,
        "complete": record["complete"],
    }


def _render_history_text(records: list[dict], heading: str) -> str:
    lines = [heading]
    if not records:
        lines.append("No scan history found for the selected filters.")
        return "\n".join(lines) + "\n"
    for record in records:
        lifecycle = record.get("lifecycle", {})
        status = lifecycle.get("status", "unknown")
        if status == "complete":
            change_text = (
                f"new={lifecycle.get('new_count', 0)}, "
                f"resolved={lifecycle.get('resolved_count', 0)}, "
                f"changed={lifecycle.get('changed_count', 0)}"
            )
        elif status == "initial":
            change_text = "initial baseline (no previous complete scan)"
        else:
            change_text = "lifecycle unavailable (incomplete scan)"
        counts = record.get("severity_counts", {})
        severity_text = " ".join(
            f"{severity}={counts.get(severity, 0)}"
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )
        lines.append(
            f"#{record['id']} {record['scanned_at']} [{record['scan_type']}] "
            f"{record['target']}"
        )
        lines.append(
            f"  findings={record['finding_count']} | {severity_text} | {change_text}"
        )
    return "\n".join(lines) + "\n"


def _run_history_command(args) -> int:
    database = default_history_db_path(args.database)
    if args.history_action == "list":
        records = list_scans(database, limit=args.limit, target=args.target)
        payload = [_history_summary(record) for record in records]
        rendered = (
            json.dumps(payload, indent=2) + "\n"
            if args.format == "json"
            else _render_history_text(records, "CloudSec Scan History")
        )
    elif args.history_action == "show":
        record = get_scan(database, args.run_id)
        if args.format == "json":
            rendered = json.dumps(record, indent=2) + "\n"
        else:
            rendered = _render_history_text([record], f"CloudSec Scan Run #{record['id']}")
            if record["findings"]:
                rendered += "\nFindings\n"
                for finding in record["findings"]:
                    rendered += (
                        f"  [{finding.get('severity', 'INFO')}] "
                        f"{finding.get('rule_id', 'UNKNOWN-RULE')} — "
                        f"{finding.get('title', 'Untitled finding')} "
                        f"({finding.get('path', '')}:{finding.get('line') or 1})\n"
                    )
            if record["errors"]:
                rendered += "\nErrors\n" + "\n".join(
                    f"  {error}" for error in record["errors"]
                ) + "\n"
    else:
        records = get_trends(database, days=args.days, target=args.target)
        payload = [_history_summary(record) for record in records]
        rendered = (
            json.dumps(payload, indent=2) + "\n"
            if args.format == "json"
            else _render_history_text(
                records, f"CloudSec Security Trends — last {args.days} days"
            )
        )
    print(rendered, end="")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "cloud":
            from cloudsec_scanner.providers.aws import scan_aws
            inventory = scan_aws(args.region)
            if args.redact_identifiers:
                from cloudsec_scanner.providers.aws import redact_inventory
                inventory = redact_inventory(inventory)
            rendered = json.dumps(inventory.to_dict(), indent=2) + "\n"
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            if not inventory.result.coverage_complete:
                return EXIT_ERROR
            return EXIT_FINDINGS if not args.no_fail and any(f.severity in {"HIGH", "CRITICAL"} for f in inventory.result.findings) else EXIT_OK

        if args.command == "sbom":
            from cloudsec_scanner.sbom import build_sbom
            rendered = json.dumps(build_sbom(args.target), indent=2) + "\n"
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            return EXIT_OK

        if args.command == "compare":
            comparison = compare_reports(args.baseline, args.current)
            rendered = (
                json.dumps(comparison, indent=2) + "\n"
                if args.format == "json"
                else render_comparison_text(comparison)
            )
            if args.output:
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rendered, encoding="utf-8")
            if args.format == "text" or not args.output:
                print(rendered, end="")
            return EXIT_OK

        if args.command == "history":
            return _run_history_command(args)

        if args.command == "config-init":
            if Path(args.output).exists():
                print(f"error: refusing to overwrite existing file: {args.output}", file=sys.stderr)
                return EXIT_INPUT
            write_default_config(args.output)
            print(f"Wrote starter configuration: {args.output}")
            return EXIT_OK

        config = load_config(args.config)
        if args.severity:
            config["severity_threshold"] = args.severity

        if args.command == "image":
            if args.timeout <= 0:
                raise ValueError("--timeout must be a positive integer")
            result = scan_image(args.target, trivy_path=args.trivy_path, timeout=args.timeout)
        else:
            if args.scanner:
                config["scanners"] = args.scanner
            result = scan_target(args.target, config)
        return _finish_report(result, args, config, scan_type=args.command)
    except HistoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except (ImageScanError, ComparisonError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
