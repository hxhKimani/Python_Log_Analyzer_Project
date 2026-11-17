"""Streaming multi-format log parsers for auth.log, Nginx/Apache access logs, and UFW/iptables."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Iterable, Iterator

from sentinel_log.models import LogEvent

# Linux OpenSSH / PAM syslog patterns
# Example: Nov 17 09:14:22 prod-web-01 sshd[4812]: Failed password for invalid user admin from 185.220.101.4 port 51234 ssh2
SYSLOG_PREFIX = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[\d+\])?:\s+(?P<msg>.+)$"
SYSLOG_RE = re.compile(SYSLOG_PREFIX)

SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
SUDO_AUTH_FAIL_RE = re.compile(
    r"authentication failure;.*?\buser=(?P<user>\S*)"
)

# Apache / Nginx Combined Log Format
# Example: 198.51.100.42 - - [17/Nov/2026:09:15:03 +0000] "GET /login?id=1%27%20OR%201=1 HTTP/1.1" 403 512 "-" "sqlmap/1.7"
WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# UFW / iptables Kernel Firewall Logs
# Example: Nov 17 09:18:10 gw-fw-01 kernel: [12034.12] [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.0.1.15 PROTO=TCP SPT=49822 DPT=22 SYN
UFW_BLOCK_RE = re.compile(
    r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\].*?\bSRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\b.*?\bPROTO=(?P<proto>\S+)(?:.*?\bDPT=(?P<dpt>\d+))?"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_timestamp(month_str: str, day_str: str, time_str: str, year: int) -> datetime:
    month = MONTH_MAP.get(month_str, 1)
    hour, minute, second = (int(part) for part in time_str.split(":"))
    return datetime(year, month, int(day_str), hour, minute, second, tzinfo=timezone.utc)


def _parse_clf_timestamp(ts_str: str) -> datetime:
    # Format: 17/Nov/2026:09:15:03 +0000
    clean = ts_str.split()[0]
    dt = datetime.strptime(clean, "%d/%b/%Y:%H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def detect_log_format(line: str) -> str:
    """Identify log source category from a raw line."""
    if WEB_ACCESS_RE.match(line):
        return "web"
    if "[UFW " in line or ("SRC=" in line and "PROTO=" in line):
        return "firewall"
    if SYSLOG_RE.match(line):
        return "auth"
    return "unknown"


def parse_line(line: str, line_number: int = 1, default_year: int | None = None) -> LogEvent | None:
    """Parse a single raw log line into a normalized LogEvent, or return None if unrecognized."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    year = default_year or datetime.now(timezone.utc).year

    # 1. Try Nginx / Apache Combined Access Log
    web_match = WEB_ACCESS_RE.match(stripped)
    if web_match:
        try:
            ts = _parse_clf_timestamp(web_match.group("ts"))
        except ValueError:
            ts = datetime.now(timezone.utc)
        raw_user = web_match.group("user")
        return LogEvent(
            timestamp=ts,
            source_type="web",
            source_ip=web_match.group("ip"),
            event_type="http_request",
            raw_line=stripped,
            line_number=line_number,
            username=None if raw_user == "-" else raw_user,
            http_method=web_match.group("method"),
            http_path=web_match.group("path"),
            http_status=int(web_match.group("status")),
            user_agent=web_match.group("ua") or "",
        )

    # 2. Try Syslog (auth.log & UFW kernel logs)
    sys_match = SYSLOG_RE.match(stripped)
    if sys_match:
        ts = _parse_syslog_timestamp(
            sys_match.group("month"),
            sys_match.group("day"),
            sys_match.group("time"),
            year,
        )
        msg = sys_match.group("msg")

        ufw_match = UFW_BLOCK_RE.search(msg)
        if ufw_match:
            dpt = ufw_match.group("dpt")
            return LogEvent(
                timestamp=ts,
                source_type="firewall",
                source_ip=ufw_match.group("src"),
                event_type=f"fw_{ufw_match.group('action').lower()}",
                raw_line=stripped,
                line_number=line_number,
                target_port=int(dpt) if dpt else None,
                protocol=ufw_match.group("proto"),
                action=ufw_match.group("action"),
            )

        failed_match = SSH_FAILED_RE.search(msg)
        if failed_match:
            return LogEvent(
                timestamp=ts,
                source_type="auth",
                source_ip=failed_match.group("ip"),
                event_type="ssh_failed_login",
                raw_line=stripped,
                line_number=line_number,
                username=failed_match.group("user"),
                target_port=int(failed_match.group("port")),
            )

        accepted_match = SSH_ACCEPTED_RE.search(msg)
        if accepted_match:
            return LogEvent(
                timestamp=ts,
                source_type="auth",
                source_ip=accepted_match.group("ip"),
                event_type="ssh_accepted_login",
                raw_line=stripped,
                line_number=line_number,
                username=accepted_match.group("user"),
                target_port=int(accepted_match.group("port")),
            )

        invalid_match = SSH_INVALID_USER_RE.search(msg)
        if invalid_match:
            return LogEvent(
                timestamp=ts,
                source_type="auth",
                source_ip=invalid_match.group("ip"),
                event_type="ssh_invalid_user",
                raw_line=stripped,
                line_number=line_number,
                username=invalid_match.group("user"),
                target_port=int(invalid_match.group("port")),
            )

        sudo_match = SUDO_AUTH_FAIL_RE.search(msg)
        if sudo_match:
            return LogEvent(
                timestamp=ts,
                source_type="auth",
                source_ip="127.0.0.1",
                event_type="sudo_auth_failure",
                raw_line=stripped,
                line_number=line_number,
                username=sudo_match.group("user") or "unknown",
            )

    return None


def parse_stream(lines: Iterable[str], default_year: int | None = None) -> Iterator[tuple[int, LogEvent | None]]:
    """Generator yielding (line_number, LogEvent | None) for memory-efficient streaming."""
    for idx, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        yield idx, parse_line(raw_line, line_number=idx, default_year=default_year)
