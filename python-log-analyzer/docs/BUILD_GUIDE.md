# Build and understand the project

The working version is included so you can run it immediately. To learn it from
scratch, create a separate file called `practice.py` and rebuild one stage at a time.
Keep the supplied application as a reference. Expect several short sessions rather
than memorizing the whole file at once.

## 1. Read a CSV (20–30 minutes)

Start with this complete small program:

```python
import csv

with open("sample_logs/auth.csv", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)
    for row in reader:
        print(row["username"], row["event"])
```

Run `py practice.py` from the project folder. Explain why each row is a dictionary
and why a `with` statement is useful. Change the print statement to show only
failed logins. Expected: nine printed rows.

## 2. Count failures (20–30 minutes)

Add `from collections import Counter`. Before opening the file, create
`failures = Counter()`. Inside your failure condition, increment
`failures[row["source_ip"]] += 1`. After the loop, print the counter.

Expected counts: `203.0.113.50: 5`, `198.51.100.20: 3`, `192.0.2.10: 1`.
This is a whole-file count. It does not yet answer whether failures happened close
together. Explain how five failures in one minute differ from five over one week.

## 3. Validate and normalize (30–45 minutes)

Read `Event` and `read_events()` in the working application. Trace one sample row
through timestamp parsing, timezone conversion, username validation, IP validation,
and event validation. Make a copy of the sample and insert one bad IP. Run the
application against that copy and find its line number in the report.

Explain the difference between a rejected row and a fatal file error. Do not catch
every exception indiscriminately: errors in your own program should remain visible.

## 4. Understand the sliding window (45–60 minutes)

Read `analyze()` and trace the five admin failures on paper. For each event:

1. Select the queue for that source IP.
2. Calculate the timestamp minus the configured window.
3. Remove failures older than that cutoff from the left of the queue.
4. Append a failure, or correlate a success with failures for the same username.
5. Evaluate rules and store evidence line numbers.

A deque is useful because removing the oldest item from its left is efficient.
Sorting first makes out-of-order input predictable. The `alerted` set suppresses
repeated alerts for the first two rules; explain the tradeoff this introduces.

## 5. Run experiments (30–45 minutes)

Use copies of the synthetic CSV and a separate output directory per experiment.

- Move the fifth admin failure to 14:20. Predict which alerts disappear, then run.
- Change the admin success username. Explain why success correlation disappears.
- Give all three targeted usernames the same source username. Predict the multi-account result.
- Reverse the CSV data rows, keeping the header first. Verify the detections persist.
- Change a timestamp to an equivalent `-05:00` value. Verify UTC normalization.
- Lower the failure threshold to 3. Inspect how evidence and alert timing change.

## 6. Make an improvement you own

Choose one, implement it, document it, and write a test with a clear expected result:

- Add `--username` to analyze one user's records.
- Add a separate parser for a real log format using a small sanitized fixture.
- Add alert cooldowns so later bursts can generate new alerts.
- Add detection for one account targeted from several IP addresses.

Update the README to distinguish your new behavior from the original. Commit each
working stage to GitHub once you create the repository. Keep a short learning log
of a bug you found, the cause, the fix, and how you verified it.

## Ready to discuss in interviews

You should be able to run the demo, change a threshold, trace one alert to source
rows, explain the time window, describe a false positive, and explain a limitation
without reading this guide. Use `docs/CAREER_NOTES.md` after completing these steps.
