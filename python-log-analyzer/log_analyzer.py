"""Analyze normalized authentication CSV logs using only Python's standard library."""

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    username: str
    source_ip: str
    event: str
    line: int


def read_events(path):
    """Reject invalid rows visibly; normalize valid timestamps and IP addresses."""
    events, errors = [], []
    required = {"timestamp", "username", "source_ip", "event"}
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        fields = reader.fieldnames or []
        if len(fields) != len(set(fields)) or not required.issubset(fields):
            raise ValueError("CSV needs unique headers: timestamp,username,source_ip,event")
        for row in reader:
            try:
                if None in row or any(row[key] is None for key in required):
                    raise ValueError("wrong number of CSV fields")
                stamp = datetime.fromisoformat(row["timestamp"].strip().replace("Z", "+00:00"))
                if stamp.utcoffset() is None:
                    raise ValueError("timestamp needs a timezone, such as Z or -05:00")
                username = row["username"].strip()
                if not username:
                    raise ValueError("username cannot be empty")
                source_ip = str(ipaddress.ip_address(row["source_ip"].strip()))
                event = row["event"].strip().upper()
                if event not in {"LOGIN_SUCCESS", "LOGIN_FAILURE"}:
                    raise ValueError("event must be LOGIN_SUCCESS or LOGIN_FAILURE")
                events.append(Event(stamp.astimezone(timezone.utc), username,
                                    source_ip, event, reader.line_num))
            except ValueError as exc:
                errors.append({"line": reader.line_num, "reason": str(exc)})
    return events, errors


def analyze(events, failure_threshold=5, user_threshold=3, window_seconds=300):
    """Use sliding windows per IP; sort first so CSV row order does not matter."""
    if min(failure_threshold, user_threshold, window_seconds) < 1:
        raise ValueError("thresholds and window must be positive")
    events = sorted(events, key=lambda event: (event.timestamp, event.line))
    recent = defaultdict(deque)
    alerted = set()
    alerts = []
    window = timedelta(seconds=window_seconds)

    def add_alert(rule, event, evidence):
        alerts.append({
            "rule": rule,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "username": event.username,
            "evidence_lines": [item.line for item in evidence],
            "failure_count": len(evidence),
            "distinct_users": sorted({item.username for item in evidence}),
        })

    for event in events:
        failures = recent[event.source_ip]
        cutoff = event.timestamp - window
        while failures and failures[0].timestamp < cutoff:
            failures.popleft()
        if event.event == "LOGIN_FAILURE":
            failures.append(event)
            checks = (
                ("REPEATED_FAILURES", len(failures) >= failure_threshold),
                ("MULTIPLE_ACCOUNTS_TARGETED",
                 len({item.username for item in failures}) >= user_threshold),
            )
            for rule, matched in checks:
                key = (rule, event.source_ip)
                if matched and key not in alerted:
                    add_alert(rule, event, list(failures))
                    alerted.add(key)
        else:
            matching = [item for item in failures if item.username == event.username]
            if len(matching) >= failure_threshold:
                add_alert("SUCCESS_AFTER_FAILURES", event, matching)
            # A success ends the failure sequence for this IP/user pair.
            recent[event.source_ip] = deque(
                item for item in failures if item.username != event.username
            )

    failed = [event for event in events if event.event == "LOGIN_FAILURE"]
    return {
        "settings": {"failure_threshold": failure_threshold,
                     "user_threshold": user_threshold, "window_seconds": window_seconds},
        "summary": {"valid_events": len(events), "failed_logins": len(failed),
                    "successful_logins": len(events) - len(failed),
                    "unique_source_ips": len({event.source_ip for event in events}),
                    "alert_count": len(alerts)},
        "failed_logins_by_ip": dict(sorted(Counter(event.source_ip for event in failed).items())),
        "alerts": alerts,
    }


def render_markdown(report):
    lines = ["# Authentication log analysis", "",
             "Rule matches are investigation leads; they do not establish compromise.", "",
             "## Summary", ""]
    lines.extend(f"- {key.replace('_', ' ').title()}: {value}"
                 for key, value in report["summary"].items())
    lines.extend(["", "## Settings", "", "```json",
                  json.dumps(report["settings"], indent=2), "```", "", "## Alerts", ""])
    if not report["alerts"]:
        lines.append("No configured rules matched.")
    for alert in report["alerts"]:
        # JSON fences preserve untrusted log values without interpreting Markdown.
        lines.extend(["```json", json.dumps(alert, indent=2), "```", ""])
    lines.extend(["", "## Rejected records", "", "```json",
                  json.dumps(report["rejected_records"], indent=2), "```", ""])
    return "\n".join(lines)


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--failure-threshold", type=positive_int, default=5)
    parser.add_argument("--user-threshold", type=positive_int, default=3)
    parser.add_argument("--window-seconds", type=positive_int, default=300)
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    args = parser.parse_args(argv)
    try:
        events, rejected = read_events(args.logfile)
        report = analyze(events, args.failure_threshold, args.user_threshold, args.window_seconds)
        report["summary"]["rejected_records"] = len(rejected)
        report["rejected_records"] = rejected
        report["input_file"] = args.logfile.name
        if args.logfile.resolve() in {
            (args.output_dir / "report.json").resolve(),
            (args.output_dir / "report.md").resolve(),
        }:
            raise ValueError("output would overwrite the input file")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (args.output_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    except (OSError, ValueError, csv.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for key, value in report["summary"].items():
        print(f"{key}: {value}")
    print(f"Reports written to {args.output_dir}")
    # Partial analysis is distinguishable from a fully valid input.
    return 2 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
