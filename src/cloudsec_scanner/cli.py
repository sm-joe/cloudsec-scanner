"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cloudsec_scanner import __version__
from cloudsec_scanner.config import load_config, write_default_config
from cloudsec_scanner.models import SEVERITY_ORDER
from cloudsec_scanner.report import write_report
from cloudsec_scanner.scanner import scan_target

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudsec", description="Cloud infrastructure and configuration security scanner"
    )
    parser.add_argument("--version", action="version", version=f"cloudsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("target", help="file or directory to scan")
    scan.add_argument("--config", help="YAML configuration file")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--output",
        help="write report to this path (terminal output is still shown for text format)",
    )
    scan.add_argument(
        "--severity", choices=tuple(SEVERITY_ORDER), help="override configured failure threshold"
    )
    scan.add_argument(
        "--scanner",
        action="append",
        choices=("iac", "secrets", "dependencies"),
        help="scanner(s) to enable; repeat to select multiple",
    )
    scan.add_argument(
        "--fail-on-findings", action="store_true", help="fail when any finding meets the threshold"
    )
    scan.add_argument(
        "--no-fail",
        action="store_true",
        help="always return success for findings (scan errors still fail)",
    )
    init = sub.add_parser("config-init", help="write a starter YAML configuration")
    init.add_argument("--output", default=".cloudsec.yml", help="configuration file path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
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
        if args.scanner:
            config["scanners"] = args.scanner
        result = scan_target(args.target, config)
        rendered = write_report(result, args.format, args.output)
        if args.format == "text" or not args.output:
            print(rendered, end="")
        if result.errors:
            return EXIT_ERROR
        threshold = config["severity_threshold"]
        has_blocking = any(
            SEVERITY_ORDER.get(f.severity, 99) <= SEVERITY_ORDER[threshold] for f in result.findings
        )
        if args.no_fail:
            return EXIT_OK
        should_fail = args.fail_on_findings or config.get("fail_on_findings", True)
        return EXIT_FINDINGS if should_fail and has_blocking else EXIT_OK
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
