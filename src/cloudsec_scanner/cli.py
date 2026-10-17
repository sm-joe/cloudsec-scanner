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
from cloudsec_scanner.models import SEVERITY_ORDER
from cloudsec_scanner.report import write_report
from cloudsec_scanner.scanner import scan_target

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
EXIT_ERROR = 3


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", help="write report to this path")
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
    _add_report_options(scan)

    image = sub.add_parser("image", help="scan a built container image using Trivy")
    image.add_argument("target", help="container image reference, such as nginx:1.27")
    image.add_argument("--trivy-path", help="explicit path to the Trivy executable")
    image.add_argument(
        "--timeout", type=int, default=900, help="scan timeout in seconds (default: 900)"
    )
    image.add_argument("--config", help="YAML configuration file (failure threshold only)")
    _add_report_options(image)

    compare = sub.add_parser(
        "compare", help="compare two JSON scan reports using stable finding identities"
    )
    compare.add_argument("baseline", help="previous scan JSON report")
    compare.add_argument("current", help="current scan JSON report")
    compare.add_argument("--format", choices=("text", "json"), default="text")
    compare.add_argument("--output", help="write comparison report to this path")

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


def _finish_report(result, args, config) -> int:
    _apply_policy(result, config)

    baseline_gate = bool(args.fail_on_new or config.get("fail_on_new_findings", False))
    if baseline_gate and not args.baseline:
        raise ValueError("baseline-aware gating requires --baseline when --fail-on-new is enabled")

    comparison = None
    if args.baseline:
        try:
            baseline_doc = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except OSError as exc:
            raise ComparisonError(f"could not read baseline report {args.baseline}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ComparisonError(f"baseline report {args.baseline} is not valid JSON: {exc}") from exc
        if not isinstance(baseline_doc, dict):
            raise ComparisonError("baseline report must contain a JSON object")
        comparison = compare_report_documents(baseline_doc, result.to_dict())

    rendered = write_report(result, args.format, args.output)
    if args.format == "text" or not args.output:
        print(rendered, end="")
    if result.errors:
        return EXIT_ERROR

    threshold = config["severity_threshold"]
    threshold_order = SEVERITY_ORDER[threshold]
    if baseline_gate and not args.no_fail:
        assert comparison is not None
        blocking_findings = [
            item
            for item in comparison["new"]
            if SEVERITY_ORDER.get(
                str(item["finding"].get("severity", "INFO")).upper(), 99
            )
            <= threshold_order
        ]
        print(
            f"Baseline gate: {len(comparison['new'])} new finding(s); "
            f"{len(blocking_findings)} meet the {threshold} failure threshold.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS if blocking_findings else EXIT_OK

    has_blocking = any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold_order for f in result.findings
    )
    if args.no_fail:
        return EXIT_OK
    should_fail = args.fail_on_findings or config.get("fail_on_findings", True)
    return EXIT_FINDINGS if should_fail and has_blocking else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
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
        return _finish_report(result, args, config)
    except (ImageScanError, ComparisonError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
