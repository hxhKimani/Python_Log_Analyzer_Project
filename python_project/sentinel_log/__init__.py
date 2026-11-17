"""SentinelLog: Modular cybersecurity log analyzer for SOC triage and threat detection."""

from sentinel_log.models import Alert, AnalysisReport, LogEvent, Severity
from sentinel_log.parsers import detect_log_format, parse_line, parse_stream
from sentinel_log.detectors import analyze_events

__all__ = [
    "Alert",
    "AnalysisReport",
    "LogEvent",
    "Severity",
    "analyze_events",
    "detect_log_format",
    "parse_line",
    "parse_stream",
]
