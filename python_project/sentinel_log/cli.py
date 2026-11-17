"""Command-line interface for SentinelLog."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from sentinel_log.detectors import analyze_events
from sentinel_log.reporter import format_terminal_summary, to_csv, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-log",
        description="Analyze auth.log, web access, and firewall logs for security threats.",
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to log file, or '-' to read from stdin.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=("text", "json", "csv", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file path. Defaults to stdout.",
    )
    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        help="Failed SSH attempts required to trigger brute-force alert (default: 5).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=120,
        help="Sliding window in seconds for brute-force correlation (default: 120).",
    )
    parser.add_argument(
        "--port-threshold",
        type=int,
        default=5,
        help="Distinct blocked destination ports required to flag a port scan (default: 5).",
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=2.0,
        help="Z-score threshold for minute-bucket burst anomalies (default: 2.0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.input == "-":
        lines = sys.stdin
        report = analyze_events(
            lines,
            bf_threshold=args.bf_threshold,
            bf_window_seconds=args.window,
            port_scan_threshold=args.port_threshold,
            z_threshold=args.z_threshold,
        )
    else:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Error: log file not found: {input_path}", file=sys.stderr)
            return 2
        with input_path.open("r", encoding="utf-8", errors="replace") as fh:
            report = analyze_events(
                fh,
                bf_threshold=args.bf_threshold,
                bf_window_seconds=args.window,
                port_scan_threshold=args.port_threshold,
                z_threshold=args.z_threshold,
            )

    if args.format == "json":
        rendered = to_json(report)
    elif args.format == "csv":
        rendered = to_csv(report)
    elif args.format == "markdown":
        rendered = to_markdown(report)
    else:
        rendered = format_terminal_summary(report)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
