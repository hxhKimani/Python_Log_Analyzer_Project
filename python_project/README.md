# SentinelLog — Python Cybersecurity Log Analyzer

A lightweight, streaming-first security log analysis CLI built with Python 3.11 standard library primitives. Designed for SOC triage, incident response, and automated threat hunting across Linux authentication (`auth.log`), web server (`Nginx/Apache`), and perimeter firewall (`UFW/iptables`) logs.

## Key Capabilities

- **Memory-Efficient Streaming Parser**: Uses Python generators (`parse_stream`) and `collections.deque` sliding windows so multi-gigabyte log files can be processed in constant memory.
- **Multi-Format Normalization**: Automatically distinguishes and normalizes OpenSSH/PAM syslog records, Apache/Nginx Combined Log Format entries, and UFW kernel firewall drops into typed `LogEvent` dataclasses.
- **Behavioral & Signature Detections**:
  - **SSH Brute Force & Credential Stuffing** (`T1110.001` / `T1110.004`): Sliding time-window tracking per source IP, plus post-failure compromise correlation (`T1078.003`).
  - **Web Attack Detection** (`T1190` / `T1083` / `T1595.002`): Double URL-decoding normalization before matching SQLi, XSS, path traversal, and automated vulnerability scanners.
  - **Firewall Reconnaissance** (`T1046` / `T1021`): Distinct destination port aggregation and sensitive management port probing.
  - **Statistical Burst Anomalies** (`T1498`): Per-minute z-score spike detection across event timelines.
- **SOC-Ready Reporting**: Exports incident summaries to JSON, CSV, Markdown, or structured terminal output.

## Quick Start

```bash
# Run against sample SSH brute-force logs
python3 -m sentinel_log.cli --input samples/auth_bruteforce.log

# Export web attack findings as JSON with custom thresholds
python3 -m sentinel_log.cli -i samples/web_attacks.log -f json -o report.json

# Pipe live logs via stdin
cat samples/*.log | python3 -m sentinel_log.cli -i - -f markdown

# Run the unit test suite
python3 -m unittest discover -s tests -v
```

## Project Structure

```text
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
```
