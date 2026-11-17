# Python Authentication Log Analyzer

A beginner-friendly cybersecurity portfolio project that analyzes normalized CSV
authentication logs and creates JSON and Markdown reports. All included logs are
synthetic. No extra packages, credentials, network connection, or live attacks are needed.

## Start on Windows

1. Install Python 3.11 or newer if needed. Enable the Python launcher during installation.
2. Extract this ZIP. Open the extracted `python-log-analyzer` folder in VS Code.
   The folder you open should contain `log_analyzer.py` and this README.
3. In VS Code, select **Terminal > New Terminal**.
4. Check Python and run the sample:

```powershell
py --version
py log_analyzer.py sample_logs/auth.csv
```

If `py` is unavailable but `python --version` works, replace `py` with `python`.
On macOS/Linux, use `python3`.

Expected summary:

```text
valid_events: 12
failed_logins: 9
successful_logins: 3
unique_source_ips: 3
alert_count: 3
rejected_records: 0
Reports written to reports
```

Open `reports/report.md` in VS Code and use **Ctrl+Shift+V** to preview it.
The machine-readable version is `reports/report.json`. These files are overwritten
on each run; use `--output-dir reports/experiment1` to keep a separate run.

## What it detects

| Rule | Default trigger | Interpretation |
| --- | --- | --- |
| REPEATED_FAILURES | 5 failures from one IP within 300 seconds | Repeated guessing or a misconfigured client |
| MULTIPLE_ACCOUNTS_TARGETED | Failures involving 3 distinct usernames from one IP within 300 seconds | Multiple-account targeting; possible spraying |
| SUCCESS_AFTER_FAILURES | Success after 5 failures for the same IP and username within 300 seconds | A sequence worth investigating |

These are configurable heuristics. A match does not prove an attack or account
compromise. Shared IPs, mistyped passwords, and automation can cause false positives.
Passwords are absent, so the tool cannot verify that the same password was tried
across accounts. The report's evidence lines point back to the CSV.

```powershell
py log_analyzer.py sample_logs/auth.csv --failure-threshold 3 --user-threshold 2 --window-seconds 120 --output-dir reports/custom
py -m unittest discover -s tests -v
```

## Input contract

```csv
timestamp,username,source_ip,event
2026-11-17T14:00:00Z,alex,192.0.2.10,LOGIN_FAILURE
2026-11-17T14:01:00Z,alex,192.0.2.10,LOGIN_SUCCESS
```

- UTF-8 CSV, optionally with a byte-order mark; exact, unique header names above.
- ISO timestamps must have a timezone. Values are converted to UTC before analysis.
- IPs may be IPv4 or IPv6. Usernames are case-sensitive and surrounding whitespace is trimmed.
- Supported events: `LOGIN_FAILURE` and `LOGIN_SUCCESS`; casing is normalized.
- Extra named columns are ignored. Missing fields, extra unnamed fields, invalid IPs,
  invalid timestamps, and unknown events are reported as rejected records.
- Records are sorted chronologically. Equal timestamps retain file order.
- Header-only CSV is valid and produces an empty report.
- This version does **not** directly parse raw Windows Event Logs or Linux auth.log.
  Export and map those records to the schema first, or add a parser as an extension.

Exit status: `0` = completed with valid input; `1` = file/header/CSV processing error;
`2` = report generated with rejected rows, or CLI usage error (see console message).
A fatal CSV syntax error stops processing and does not write a new report.

## Design and limitations

`read_events()` validates input and returns Event objects plus row errors.
`analyze()` sorts events, maintains per-IP sliding windows with deque, and records
rule evidence. `render_markdown()` formats findings; `main()` handles CLI arguments
and report files. Only the Python standard library is used.

Window endpoints are inclusive: an event exactly 300 seconds old still counts.
A successful login clears prior failures for its IP/user pair, so counters represent
failures since the last success for each account. Repeated-failure and multiple-account
rules each emit only their **first** match per source IP per run. Success correlation
can emit again after a new qualifying sequence. This deliberately simple alert
suppression can hide later bursts; change it as a follow-up exercise.

The program keeps the input and row errors in memory and sorts valid records
(O(n log n) time). It is an educational batch tool, not a production SIEM. It does
not deduplicate events, detect distributed attacks, establish account identity across
hosts, block traffic, or continuously monitor logs. Only analyze logs you are
authorized to use. Keep real logs out of a public repository.

## Project layout

- `log_analyzer.py`: commented working application
- `sample_logs/auth.csv`: deterministic synthetic scenario
- `tests/test_analyzer.py`: detection, boundary, validation, and CLI tests
- `docs/BUILD_GUIDE.md`: learning plan and exercises
- `docs/INCIDENT_REPORT.md`: worked investigation of the sample
- `docs/CAREER_NOTES.md`: resume and interview guidance
- `examples/`: saved output of the default sample run

## Publish your portfolio

After you complete the walkthrough, create a GitHub repository named
`python-log-analyzer`. Upload the source, tests, docs, sample logs, `.gitignore`, and
the sanitized example reports. Keep this README as the repository homepage.
Do not upload real employer logs or the ZIP itself. Run the tests and sample before
each upload. This project has not been published to GitHub automatically.
