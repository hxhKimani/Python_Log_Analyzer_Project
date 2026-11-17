"""Incident report exporters for JSON, CSV, Markdown, and CLI stdout."""

from __future__ import annotations

import csv
import io
import json

from sentinel_log.models import AnalysisReport


def to_json(report: AnalysisReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent)


def to_csv(report: AnalysisReport) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "rule_id",
        "severity",
        "title",
        "source_ip",
        "mitre_id",
        "mitre_tactic",
        "event_count",
        "first_seen",
        "last_seen",
        "description",
        "remediation",
    ])
    for alert in report.alerts:
        writer.writerow([
            alert.rule_id,
            alert.severity.value,
            alert.title,
            alert.source_ip,
            alert.mitre_id,
            alert.mitre_tactic,
            alert.event_count,
            alert.first_seen.isoformat(),
            alert.last_seen.isoformat(),
            alert.description,
            alert.remediation,
        ])
    return buf.getvalue()


def to_markdown(report: AnalysisReport) -> str:
    lines = [
        "# SentinelLog Security Incident Report",
        "",
        "## Executive Summary",
        f"- **Total Lines Scanned:** {report.total_lines}",
        f"- **Normalized Events:** {report.parsed_events}",
        f"- **Unparsed Lines:** {report.unparsed_lines}",
        f"- **Alerts Triggered:** {len(report.alerts)}",
        f"- **Analysis Duration:** {report.duration_ms:.2f} ms",
        "",
        "## Findings by Severity",
    ]
    for sev, count in report.severity_counts.items():
        if count > 0:
            lines.append(f"- **{sev.upper()}**: {count}")

    lines.extend(["", "## Detailed Security Alerts", ""])
    if not report.alerts:
        lines.append("No malicious patterns exceeded configured detection thresholds.")
    else:
        for idx, alert in enumerate(report.alerts, start=1):
            lines.extend([
                f"### {idx}. [{alert.severity.value.upper()}] {alert.title}",
                f"- **Source IP:** `{alert.source_ip}`",
                f"- **MITRE ATT&CK:** {alert.mitre_id} — {alert.mitre_technique} ({alert.mitre_tactic})",
                f"- **Events:** {alert.event_count} ({alert.first_seen.isoformat()} to {alert.last_seen.isoformat()})",
                f"- **Summary:** {alert.description}",
                f"- **Remediation:** {alert.remediation}",
                "",
            ])
    return "\n".join(lines)


def format_terminal_summary(report: AnalysisReport) -> str:
    lines = [
        "SentinelLog Security Analysis Summary",
        "=" * 48,
        f"Lines scanned : {report.total_lines}",
        f"Parsed events : {report.parsed_events}",
        f"Alerts found  : {len(report.alerts)}",
        f"Elapsed       : {report.duration_ms:.2f} ms",
        "",
    ]
    for alert in report.alerts:
        lines.append(
            f"[{alert.severity.value.upper():8}] {alert.mitre_id:9} | {alert.source_ip:15} | {alert.title} ({alert.event_count} events)"
        )
    return "\n".join(lines)
