# SentinelLog — Python Cybersecurity Log Analyzer & Workbench

A modular Python 3.11+ cybersecurity log analyzer paired with a local web workbench for testing detections, inspecting MITRE ATT&CK mappings, running unit tests, and exporting SOC incident reports. Mix of independent code with the help of pre-existing sources and Google Ai studio.

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
   ```
   *(Windows PowerShell users: if script execution is blocked, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once first.)*

2. **Start the local server:**
   ```bash
   npm run dev
   ```

3. **Open the site in your browser:**
   Navigate to **[http://localhost:3000](http://localhost:3000)**
   *(Note: Use `localhost:3000` or `127.0.0.1:3000`—do not browse directly to `0.0.0.0:3000` on Windows.)*

---

## Option 2: Run the Python CLI Directly (No Node.js Required)

Navigate into the Python package folder (`python_project/`):

```bash
cd python_project
```

**Windows (`py`):**
```powershell
# Run all unit tests
py -m unittest discover -s tests -t . -v

# Analyze sample logs
py -m sentinel_log.cli -i samples/auth_bruteforce.log

# Combine all sample logs and export a Markdown incident report
Get-Content samples/*.log | py -m sentinel_log.cli -i - -f markdown -o incident_report.md
```

**macOS / Linux (`python3`):**
```bash
python3 -m unittest discover -s tests -t . -v
python3 -m sentinel_log.cli -i samples/auth_bruteforce.log
cat samples/*.log | python3 -m sentinel_log.cli -i - -f markdown -o incident_report.md
```

---

## Project Structure

```text
python_project/
  sentinel_log/
    __init__.py     # Public package exports
    models.py       # LogEvent, Alert, AnalysisReport dataclasses
    mitre.py        # MITRE ATT&CK tactic & technique catalog
    parsers.py      # Streaming regex parsers & format detection
    detectors.py    # Sliding-window, signature, and z-score rules
    reporter.py     # JSON, CSV, Markdown, and CLI formatters
    cli.py          # argparse CLI entrypoint
  tests/
    test_analyzer.py
  samples/
    auth_bruteforce.log
    web_attacks.log
    firewall_portscan.log
server.ts           # Express + Vite server invoking Python CLI
src/                # React TypeScript workbench UI
```
