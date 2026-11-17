import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer import Event, analyze, read_events


ROOT = Path(__file__).resolve().parents[1]


def event(seconds, user="admin", ip="203.0.113.50", kind="LOGIN_FAILURE", line=1):
    return Event(datetime(2026, 11, 17, tzinfo=timezone.utc) + timedelta(seconds=seconds),
                 user, ip, kind, line)


class DetectionTests(unittest.TestCase):
    def test_demo_has_expected_alerts(self):
        events, errors = read_events(ROOT / "sample_logs/auth.csv")
        report = analyze(events)
        self.assertEqual(errors, [])
        self.assertEqual(report["summary"]["valid_events"], 12)
        self.assertEqual(report["summary"]["failed_logins"], 9)
        self.assertEqual(report["summary"]["unique_source_ips"], 3)
        self.assertEqual([a["rule"] for a in report["alerts"]],
                         ["REPEATED_FAILURES", "SUCCESS_AFTER_FAILURES", "MULTIPLE_ACCOUNTS_TARGETED"])
        self.assertEqual(report["alerts"][0]["evidence_lines"], [3, 4, 5, 6, 7])

    def test_time_window_boundary_is_inclusive(self):
        for end, expected in [(300, 1), (301, 0)]:
            with self.subTest(end=end):
                report = analyze([event(0), event(end)], failure_threshold=2)
                self.assertEqual(len(report["alerts"]), expected)

    def test_unsorted_events_and_ip_isolation(self):
        report = analyze([event(3), event(0, ip="192.0.2.1"), event(1)], failure_threshold=2)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["source_ip"], "203.0.113.50")

    def test_spray_needs_distinct_users(self):
        self.assertEqual(analyze([event(i) for i in range(4)])["alerts"], [])
        report = analyze([event(i, user=str(i)) for i in range(3)])
        self.assertEqual(report["alerts"][0]["rule"], "MULTIPLE_ACCOUNTS_TARGETED")

    def test_success_requires_same_account_and_source(self):
        failures = [event(i) for i in range(5)]
        other = [event(6, user="other", kind="LOGIN_SUCCESS"),
                 event(7, ip="192.0.2.1", kind="LOGIN_SUCCESS")]
        self.assertEqual(len(analyze(failures + other)["alerts"]), 1)

    def test_success_resets_account_sequence(self):
        events = [event(i) for i in range(5)] + [
            event(6, kind="LOGIN_SUCCESS"), event(7, kind="LOGIN_SUCCESS")]
        rules = [a["rule"] for a in analyze(events)["alerts"]]
        self.assertEqual(rules.count("SUCCESS_AFTER_FAILURES"), 1)

    def test_empty_input_has_no_alerts(self):
        self.assertEqual(analyze([])["summary"]["alert_count"], 0)

    def test_nonpositive_settings_rejected(self):
        with self.assertRaises(ValueError):
            analyze([], window_seconds=0)


class InputAndCliTests(unittest.TestCase):
    def test_validation_and_timezone_normalization(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.csv"
            path.write_text(
                "timestamp,username,source_ip,event\n"
                "2026-11-17T09:00:00-05:00,alex,2001:db8::1,LOGIN_SUCCESS\n"
                "2026-11-17T14:00:00,alex,192.0.2.1,LOGIN_FAILURE\n"
                "2026-11-17T14:00:00Z,alex,bad-ip,LOGIN_FAILURE\n"
                "2026-11-17T14:00:00Z,,192.0.2.1,LOGIN_FAILURE\n"
                "2026-11-17T14:00:00Z,alex,192.0.2.1,UNKNOWN\n"
                "2026-11-17T14:00:00Z,alex\n", encoding="utf-8")
            events, errors = read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].timestamp.hour, 14)
            self.assertEqual(len(errors), 5)
            result = subprocess.run([sys.executable, str(ROOT / "log_analyzer.py"),
                                     str(path), "--output-dir", str(Path(folder) / "out")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            report = json.loads((Path(folder) / "out/report.json").read_text())
            self.assertEqual(report["summary"]["rejected_records"], 5)

    def test_missing_headers_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.csv"
            path.write_text("wrong,headers\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_events(path)

    def test_cli_clean_run_and_invalid_argument(self):
        with tempfile.TemporaryDirectory() as folder:
            command = [sys.executable, str(ROOT / "log_analyzer.py"),
                       str(ROOT / "sample_logs/auth.csv"), "--output-dir", folder]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(folder) / "report.md").is_file())
            result = subprocess.run(command + ["--failure-threshold", "0"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
