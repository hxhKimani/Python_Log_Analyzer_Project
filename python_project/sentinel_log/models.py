"""Data models for normalized log events, security alerts, and analysis reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(slots=True)
class LogEvent:
    """Normalized representation of a single parsed log record."""

    timestamp: datetime
    source_type: str  # "auth", "web", "firewall"
    source_ip: str
    event_type: str
    raw_line: str
    line_number: int
    username: str | None = None
    target_port: int | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    protocol: str | None = None
    action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass(slots=True)
class Alert:
    """Security finding produced by a detection rule."""

    rule_id: str
    title: str
    severity: Severity
    source_ip: str
    description: str
    mitre_id: str
    mitre_tactic: str
    mitre_technique: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "description": self.description,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(slots=True)
class AnalysisReport:
    """Aggregated summary of parsed telemetry and triggered detections."""

    total_lines: int
    parsed_events: int
    unparsed_lines: int
    detected_formats: dict[str, int]
    alerts: list[Alert]
    top_source_ips: list[dict[str, Any]]
    timeline_buckets: list[dict[str, Any]]
    severity_counts: dict[str, int]
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "unparsed_lines": self.unparsed_lines,
            "detected_formats": self.detected_formats,
            "alerts": [alert.to_dict() for alert in self.alerts],
            "top_source_ips": self.top_source_ips,
            "timeline_buckets": self.timeline_buckets,
            "severity_counts": self.severity_counts,
            "duration_ms": round(self.duration_ms, 2),
        }
