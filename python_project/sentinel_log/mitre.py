"""MITRE ATT&CK mappings for security detection rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MitreMapping:
    technique_id: str
    tactic: str
    technique_name: str


MITRE_CATALOG: dict[str, MitreMapping] = {
    "AUTH_BRUTE_FORCE": MitreMapping(
        technique_id="T1110.001",
        tactic="Credential Access",
        technique_name="Brute Force: Password Guessing",
    ),
    "AUTH_CREDENTIAL_STUFFING": MitreMapping(
        technique_id="T1110.004",
        tactic="Credential Access",
        technique_name="Brute Force: Credential Stuffing",
    ),
    "AUTH_PRIVILEGED_LOGIN": MitreMapping(
        technique_id="T1078.003",
        tactic="Persistence / Privilege Escalation",
        technique_name="Valid Accounts: Local Accounts",
    ),
    "WEB_SQL_INJECTION": MitreMapping(
        technique_id="T1190",
        tactic="Initial Access",
        technique_name="Exploit Public-Facing Application (SQLi)",
    ),
    "WEB_XSS_PROBE": MitreMapping(
        technique_id="T1190",
        tactic="Initial Access",
        technique_name="Exploit Public-Facing Application (XSS)",
    ),
    "WEB_PATH_TRAVERSAL": MitreMapping(
        technique_id="T1083",
        tactic="Discovery",
        technique_name="File and Directory Discovery (LFI/Traversal)",
    ),
    "WEB_VULN_SCANNER": MitreMapping(
        technique_id="T1595.002",
        tactic="Reconnaissance",
        technique_name="Active Scanning: Vulnerability Scanning",
    ),
    "FW_PORT_SCAN": MitreMapping(
        technique_id="T1046",
        tactic="Discovery",
        technique_name="Network Service Discovery",
    ),
    "FW_SENSITIVE_PORT_PROBE": MitreMapping(
        technique_id="T1021",
        tactic="Lateral Movement",
        technique_name="Remote Services Probing",
    ),
    "TRAFFIC_SPIKE_ANOMALY": MitreMapping(
        technique_id="T1498",
        tactic="Impact",
        technique_name="Network Denial of Service / Burst Anomaly",
    ),
}


def lookup_mitre(rule_key: str) -> MitreMapping:
    """Return the MITRE ATT&CK mapping for a given rule key."""
    return MITRE_CATALOG.get(
        rule_key,
        MitreMapping(
            technique_id="T1000",
            tactic="Unknown",
            technique_name="Unclassified Security Event",
        ),
    )
