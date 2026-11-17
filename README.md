# SentinelLog — Python Cybersecurity Log Analyzer & Workbench

A modular Python 3.11+ cybersecurity log analyzer paired with a local web workbench for testing detections, inspecting MITRE ATT&CK mappings, running unit tests, and exporting SOC incident reports.

## Features
- **Multi-Format Log Parsing:** OpenSSH/PAM (`auth.log`), Nginx/Apache Combined Access Logs, and UFW kernel firewall drops.
- **Threat Detection Engine:** `deque` sliding-window SSH brute-force & credential stuffing detection, post-failure login compromise correlation, double URL-decoded SQLi/XSS/LFI signatures, port-scan detection, and per-minute z-score burst anomalies.
- **MITRE ATT&CK Enrichment:** Every finding maps to its MITRE ATT&CK technique ID, tactic, raw log evidence, and remediation steps.
- **Interactive Web Workbench:** Paste or upload logs, tune detection thresholds, run `unittest`, and export JSON, CSV, or Markdown reports.

---

## Option 1: Run the Web Workbench (Browser UI)

**Prerequisites:** Node.js (v20+) and Python (3.11+)

1. **Install dependencies** from the repository root:
   ```bash
   npm install --legacy-peer-deps