"""Sliding-window behavioral and signature-based security detectors."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
import math
import re
import time
from typing import Iterable
from urllib.parse import unquote_plus

from sentinel_log.mitre import lookup_mitre
from sentinel_log.models import Alert, AnalysisReport, LogEvent, Severity
from sentinel_log.parsers import parse_stream

# ---------------------------------------------------------------------------
# Pre-compiled Web Attack Signatures & Sensitive Ports
# Compiled once at import time to avoid repeated regex compilation per log line
# and to use bounded patterns that prevent catastrophic backtracking (ReDoS).
# ---------------------------------------------------------------------------
SQLI_PATTERNS = re.compile(
    r"(?i)(?:\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1\b|'\s*or\s*'|--\s*$|;\s*drop\s+table|\bsleep\s*\(\d+\)|\bbenchmark\s*\(|information_schema)"
)
XSS_PATTERNS = re.compile(
    r"(?i)(?:<script\b|javascript:|onerror\s*=|onload\s*=|<svg\b[^>]*on\w+=|alert\s*\()"
)
TRAVERSAL_PATTERNS = re.compile(
    r"(?i)(?:\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|boot\.ini)"
)
SCANNER_PATHS_RE = re.compile(
    r"(?i)(?:/\.env|/\.git/config|/wp-admin|/wp-login\.php|/phpmyadmin|/actuator/health|/xmlrpc\.php|/shell\.php)"
)
SCANNER_UA_RE = re.compile(
    r"(?i)(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei|wpscan|hydra|zgrab)"
)

# High-value remote administration and database ports frequently targeted first
SENSITIVE_PORTS = {22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}


def _normalize_url(path: str | None) -> str:
    """Decode URL-encoded characters twice to catch evasion like %2527 (' )."""
    if not path:
        return ""
    # Attackers often double-encode quotes/brackets so single-pass WAFs miss them.
    return unquote_plus(unquote_plus(path))


def _build_alert(
    rule_id: str,
    title: str,
    severity: Severity,
    source_ip: str,
    description: str,
    events: list[LogEvent],
    remediation: str,
) -> Alert:
    """Construct a MITRE-enriched Alert with bounded raw-line forensic evidence."""
    mitre = lookup_mitre(rule_id)
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    # Keep up to 5 truncated sample lines so JSON reports stay concise and readable.
    evidence = [f"L{e.line_number}: {e.raw_line[:180]}" for e in sorted_events[:5]]
    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        source_ip=source_ip,
        description=description,
        mitre_id=mitre.technique_id,
        mitre_tactic=mitre.tactic,
        mitre_technique=mitre.technique_name,
        event_count=len(events),
        first_seen=sorted_events[0].timestamp,
        last_seen=sorted_events[-1].timestamp,
        evidence=evidence,
        remediation=remediation,
    )


def detect_ssh_bruteforce(
    events: list[LogEvent],
    threshold: int = 5,
    window_seconds: int = 120,
) -> list[Alert]:
    """Detect high-rate failed SSH logins per source IP using a deque sliding window."""
    alerts: list[Alert] = []
    failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    # Group all failed/invalid-user SSH authentication attempts by attacker IP.
    for ev in events:
        if ev.event_type in ("ssh_failed_login", "ssh_invalid_user"):
            failures_by_ip[ev.source_ip].append(ev)

    window = timedelta(seconds=window_seconds)

    for ip, ip_events in failures_by_ip.items():
        # Sort chronologically because multi-source logs may arrive slightly out of order.
        ip_events.sort(key=lambda e: e.timestamp)
        q: deque[LogEvent] = deque()
        burst_events: list[LogEvent] = []
        triggered = False

        # O(1) amortized sliding window: push new event, evict events older than window.
        for ev in ip_events:
            q.append(ev)
            while q and (ev.timestamp - q[0].timestamp) > window:
                q.popleft()
            if len(q) >= threshold:
                triggered = True
                burst_events.extend(q)

        if triggered:
            # Distinguish targeted brute force (1-3 accounts) from credential stuffing (4+ accounts).
            unique_users = sorted({e.username for e in ip_events if e.username})
            is_stuffing = len(unique_users) >= 4
            rule_id = "AUTH_CREDENTIAL_STUFFING" if is_stuffing else "AUTH_BRUTE_FORCE"
            title = (
                "Distributed Username Spraying / Credential Stuffing"
                if is_stuffing
                else "SSH Brute-Force Authentication Burst"
            )
            severity = Severity.CRITICAL if len(ip_events) >= threshold * 2 else Severity.HIGH
            alerts.append(
                _build_alert(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{len(ip_events)} failed SSH attempts from {ip} within {window_seconds}s window "
                        f"targeting {len(unique_users)} account(s): {', '.join(unique_users[:5])}."
                    ),
                    events=ip_events,
                    remediation="Block offending IP at perimeter firewall, enforce key-only SSH auth, and verify targeted accounts for compromise.",
                )
            )

    # Correlation rule: flag any IP that succeeded in logging in AFTER repeated failures
    # (strong indicator that a brute-force or credential-stuffing attack succeeded).
    accepted_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.event_type == "ssh_accepted_login":
            accepted_by_ip[ev.source_ip].append(ev)

    for ip, logins in accepted_by_ip.items():
        if ip in failures_by_ip and len(failures_by_ip[ip]) >= max(3, threshold // 2):
            alerts.append(
                _build_alert(
                    rule_id="AUTH_PRIVILEGED_LOGIN",
                    title="Successful SSH Login Following Failed Attempts",
                    severity=Severity.CRITICAL,
                    source_ip=ip,
                    description=(
                        f"Source {ip} authenticated as '{logins[0].username}' after {len(failures_by_ip[ip])} prior failed login attempts."
                    ),
                    events=failures_by_ip[ip] + logins,
                    remediation="Immediately isolate host, revoke active SSH sessions, rotate credentials, and inspect bash history/persistence.",
                )
            )

    return alerts


def detect_web_attacks(events: list[LogEvent], scanner_threshold: int = 6) -> list[Alert]:
    """Detect SQLi, XSS, path traversal, and automated vulnerability scanning."""
    alerts: list[Alert] = []
    sqli_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    xss_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    lfi_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    scanner_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if ev.source_type != "web":
            continue
        # Normalize path before running signatures so encoded payloads are exposed.
        decoded_path = _normalize_url(ev.http_path)
        ua = ev.user_agent or ""

        if SQLI_PATTERNS.search(decoded_path):
            sqli_by_ip[ev.source_ip].append(ev)
        if XSS_PATTERNS.search(decoded_path):
            xss_by_ip[ev.source_ip].append(ev)
        if TRAVERSAL_PATTERNS.search(decoded_path):
            lfi_by_ip[ev.source_ip].append(ev)
        # Flag requests matching offensive scanner user-agents or probing exposed admin/config files.
        if SCANNER_UA_RE.search(ua) or SCANNER_PATHS_RE.search(decoded_path) or (ev.http_status == 404):
            if SCANNER_UA_RE.search(ua) or SCANNER_PATHS_RE.search(decoded_path):
                scanner_by_ip[ev.source_ip].append(ev)

    for ip, evs in sqli_by_ip.items():
        alerts.append(
            _build_alert(
                rule_id="WEB_SQL_INJECTION",
                title="SQL Injection Payload Detected",
                severity=Severity.CRITICAL,
                source_ip=ip,
                description=f"Detected {len(evs)} HTTP request(s) from {ip} containing SQL injection syntax after URL normalization.",
                events=evs,
                remediation="Verify parameterized queries on affected endpoints, inspect WAF logs, and audit database query logs for data exfiltration.",
            )
        )

    for ip, evs in xss_by_ip.items():
        alerts.append(
            _build_alert(
                rule_id="WEB_XSS_PROBE",
                title="Cross-Site Scripting (XSS) Probe",
                severity=Severity.HIGH,
                source_ip=ip,
                description=f"Detected {len(evs)} HTTP request(s) from {ip} injecting script or DOM event-handler payloads.",
                events=evs,
                remediation="Validate output encoding and Content-Security-Policy headers on targeted routes.",
            )
        )

    for ip, evs in lfi_by_ip.items():
        alerts.append(
            _build_alert(
                rule_id="WEB_PATH_TRAVERSAL",
                title="Path Traversal / Local File Inclusion Attempt",
                severity=Severity.HIGH,
                source_ip=ip,
                description=f"Detected {len(evs)} request(s) from {ip} attempting directory traversal or sensitive OS file disclosure.",
                events=evs,
                remediation="Enforce canonical path allowlists in file-serving handlers and verify web root permissions.",
            )
        )

    for ip, evs in scanner_by_ip.items():
        # Trigger immediately if a known scanner User-Agent is seen, or after multiple sensitive path hits.
        if len(evs) >= min(scanner_threshold, 3) or any(SCANNER_UA_RE.search(e.user_agent or "") for e in evs):
            alerts.append(
                _build_alert(
                    rule_id="WEB_VULN_SCANNER",
                    title="Automated Web Vulnerability Scanning",
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    description=f"Source {ip} probed {len(evs)} sensitive paths or used known offensive scanner signatures.",
                    events=evs,
                    remediation="Rate-limit or block scanner IP/ASN and ensure sensitive dotfiles (.env, .git) are non-routable.",
                )
            )

    return alerts


def detect_port_scans(events: list[LogEvent], distinct_port_threshold: int = 5) -> list[Alert]:
    """Detect horizontal/vertical port scanning across firewall drop events."""
    alerts: list[Alert] = []
    fw_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if ev.source_type == "firewall" and ev.action == "BLOCK":
            fw_by_ip[ev.source_ip].append(ev)

    for ip, evs in fw_by_ip.items():
        # Deduplicate destination ports touched by this IP to measure reconnaissance breadth.
        ports = sorted({e.target_port for e in evs if e.target_port is not None})
        sensitive_hits = [p for p in ports if p in SENSITIVE_PORTS]

        if len(ports) >= distinct_port_threshold:
            alerts.append(
                _build_alert(
                    rule_id="FW_PORT_SCAN",
                    title="Multi-Port Reconnaissance Scan",
                    severity=Severity.HIGH if len(ports) >= distinct_port_threshold * 2 else Severity.MEDIUM,
                    source_ip=ip,
                    description=(
                        f"Source {ip} triggered {len(evs)} firewall blocks across {len(ports)} distinct destination ports "
                        f"({', '.join(str(p) for p in ports[:10])}{'...' if len(ports) > 10 else ''})."
                    ),
                    events=evs,
                    remediation="Add dynamic block rule for scanning source IP and confirm no unintended services are exposed.",
                )
            )
        elif sensitive_hits and len(evs) >= 3:
            # Catch targeted single-port hammering (e.g., repeated RDP 3389 probes) below the multi-port threshold.
            alerts.append(
                _build_alert(
                    rule_id="FW_SENSITIVE_PORT_PROBE",
                    title="Repeated Probing of Administrative / Database Ports",
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    description=f"Source {ip} repeatedly probed sensitive service port(s): {', '.join(str(p) for p in sensitive_hits)}.",
                    events=evs,
                    remediation="Restrict administrative and database ports to VPN/bastion CIDR ranges.",
                )
            )

    return alerts


def detect_traffic_spikes(events: list[LogEvent], z_threshold: float = 2.0) -> list[Alert]:
    """Use per-minute z-score statistical analysis to flag anomalous request bursts."""
    if len(events) < 10:
        return []

    # Bucket all events by minute to establish a baseline event rate across the log window.
    buckets: dict[datetime, list[LogEvent]] = defaultdict(list)
    for ev in events:
        minute_bucket = ev.timestamp.replace(second=0, microsecond=0)
        buckets[minute_bucket].append(ev)

    if len(buckets) < 3:
        return []

    counts = [len(v) for v in buckets.values()]
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    std_dev = math.sqrt(variance)

    # Guard against division by zero when every minute has identical event volume.
    if std_dev == 0:
        return []

    alerts: list[Alert] = []
    for bucket_dt, bucket_events in sorted(buckets.items()):
        # Standard score z = (x - mean) / std_dev measures how extreme a minute's volume is.
        z_score = (len(bucket_events) - mean) / std_dev
        if z_score >= z_threshold and len(bucket_events) >= 10:
            top_ip, top_count = Counter(e.source_ip for e in bucket_events).most_common(1)[0]
            alerts.append(
                _build_alert(
                    rule_id="TRAFFIC_SPIKE_ANOMALY",
                    title="Statistical Event Burst Anomaly",
                    severity=Severity.MEDIUM,
                    source_ip=top_ip,
                    description=(
                        f"Minute bucket {bucket_dt.strftime('%H:%M UTC')} recorded {len(bucket_events)} events "
                        f"(mean={mean:.1f}, z={z_score:.2f}); primary contributor: {top_ip} ({top_count} events)."
                    ),
                    events=[e for e in bucket_events if e.source_ip == top_ip] or bucket_events,
                    remediation="Inspect rate-limiting thresholds and upstream traffic distribution during the spike window.",
                )
            )
    return alerts


def analyze_events(
    lines: Iterable[str],
    bf_threshold: int = 5,
    bf_window_seconds: int = 120,
    port_scan_threshold: int = 5,
    z_threshold: float = 2.0,
) -> AnalysisReport:
    """Run full parsing and multi-stage threat detection over an iterable of log lines."""
    started = time.perf_counter()

    total_lines = 0
    parsed_events: list[LogEvent] = []
    unparsed_lines = 0
    format_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    ip_sources: dict[str, set[str]] = defaultdict(set)
    timeline_counter: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "suspicious": 0})

    # Stream lines one by one from parse_stream so unparsed/blank lines are counted safely.
    for _line_num, ev in parse_stream(lines):
        total_lines += 1
        if ev is None:
            unparsed_lines += 1
            continue
        parsed_events.append(ev)
        format_counts[ev.source_type] += 1
        ip_counts[ev.source_ip] += 1
        ip_sources[ev.source_ip].add(ev.source_type)

        # Build per-minute total vs. suspicious activity counts for timeline visualization.
        bucket_label = ev.timestamp.strftime("%Y-%m-%d %H:%M")
        timeline_counter[bucket_label]["total"] += 1
        if ev.event_type in ("ssh_failed_login", "ssh_invalid_user", "fw_block") or (
            ev.http_status is not None and ev.http_status >= 400
        ):
            timeline_counter[bucket_label]["suspicious"] += 1

    # Execute all independent detection stages over the normalized LogEvent stream.
    alerts: list[Alert] = []
    alerts.extend(detect_ssh_bruteforce(parsed_events, threshold=bf_threshold, window_seconds=bf_window_seconds))
    alerts.extend(detect_web_attacks(parsed_events))
    alerts.extend(detect_port_scans(parsed_events, distinct_port_threshold=port_scan_threshold))
    alerts.extend(detect_traffic_spikes(parsed_events, z_threshold=z_threshold))

    # Prioritize highest-severity findings first, breaking ties by total event volume.
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    alerts.sort(key=lambda a: (severity_order[a.severity], -a.event_count))

    severity_counts = {sev.value: 0 for sev in Severity}
    ip_alert_counts: Counter[str] = Counter()
    for alert in alerts:
        severity_counts[alert.severity.value] += 1
        ip_alert_counts[alert.source_ip] += 1

    top_source_ips = [
        {
            "ip": ip,
            "event_count": count,
            "alert_count": ip_alert_counts[ip],
            "sources": sorted(ip_sources[ip]),
        }
        for ip, count in ip_counts.most_common(10)
    ]

    timeline_buckets = [
        {"bucket": k, "total": v["total"], "suspicious": v["suspicious"]}
        for k, v in sorted(timeline_counter.items())
    ]

    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return AnalysisReport(
        total_lines=total_lines,
        parsed_events=len(parsed_events),
        unparsed_lines=unparsed_lines,
        detected_formats=dict(format_counts),
        alerts=alerts,
        top_source_ips=top_source_ips,
        timeline_buckets=timeline_buckets,
        severity_counts=severity_counts,
        duration_ms=elapsed_ms,
    )
