"""Unit tests for SentinelLog parsers, sliding-window detectors, and reporters."""

import unittest

from sentinel_log.detectors import analyze_events
from sentinel_log.parsers import detect_log_format, parse_line
from sentinel_log.reporter import to_csv, to_json, to_markdown


class TestParsers(unittest.TestCase):
    def test_parse_ssh_failed_line(self) -> None:
        line = "Nov 17 09:14:22 prod-bastion-01 sshd[4812]: Failed password for invalid user admin from 185.220.101.4 port 51234 ssh2"
        self.assertEqual(detect_log_format(line), "auth")
        ev = parse_line(line, line_number=1, default_year=2026)
        self.assertIsNotNone(ev)
        assert ev is not None
        self.assertEqual(ev.source_type, "auth")
        self.assertEqual(ev.event_type, "ssh_failed_login")
        self.assertEqual(ev.source_ip, "185.220.101.4")
        self.assertEqual(ev.username, "admin")
        self.assertEqual(ev.target_port, 51234)

    def test_parse_web_access_line(self) -> None:
        line = '198.51.100.42 - - [17/Nov/2026:09:15:03 +0000] "GET /login?id=1%27%20OR%201=1 HTTP/1.1" 403 512 "-" "sqlmap/1.7"'
        self.assertEqual(detect_log_format(line), "web")
        ev = parse_line(line, line_number=7)
        self.assertIsNotNone(ev)
        assert ev is not None
        self.assertEqual(ev.source_type, "web")
        self.assertEqual(ev.http_method, "GET")
        self.assertEqual(ev.http_status, 403)
        self.assertEqual(ev.user_agent, "sqlmap/1.7")

    def test_parse_ufw_firewall_line(self) -> None:
        line = "Nov 17 09:18:10 gw-fw-01 kernel: [12034.12] [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.0.1.15 PROTO=TCP SPT=49822 DPT=3389 SYN"
        self.assertEqual(detect_log_format(line), "firewall")
        ev = parse_line(line, line_number=3, default_year=2026)
        self.assertIsNotNone(ev)
        assert ev is not None
        self.assertEqual(ev.source_type, "firewall")
        self.assertEqual(ev.source_ip, "45.155.205.91")
        self.assertEqual(ev.target_port, 3389)
        self.assertEqual(ev.action, "BLOCK")


class TestDetectors(unittest.TestCase):
    def test_ssh_bruteforce_sliding_window_and_compromise(self) -> None:
        lines = [
            "Nov 17 09:00:01 bastion sshd[101]: Failed password for root from 203.0.113.9 port 44001 ssh2",
            "Nov 17 09:00:12 bastion sshd[101]: Failed password for root from 203.0.113.9 port 44002 ssh2",
            "Nov 17 09:00:25 bastion sshd[101]: Failed password for root from 203.0.113.9 port 44003 ssh2",
            "Nov 17 09:00:40 bastion sshd[101]: Failed password for root from 203.0.113.9 port 44004 ssh2",
            "Nov 17 09:00:55 bastion sshd[101]: Failed password for root from 203.0.113.9 port 44005 ssh2",
            "Nov 17 09:01:05 bastion sshd[101]: Accepted password for root from 203.0.113.9 port 44006 ssh2",
        ]
        report = analyze_events(lines, bf_threshold=5, bf_window_seconds=120)
        rule_ids = {a.rule_id for a in report.alerts}
        self.assertIn("AUTH_BRUTE_FORCE", rule_ids)
        self.assertIn("AUTH_PRIVILEGED_LOGIN", rule_ids)

    def test_url_encoded_sqli_evasion_detected(self) -> None:
        lines = [
            '198.51.100.77 - - [17/Nov/2026:10:00:01 +0000] "GET /items?q=1%2527%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        ]
        report = analyze_events(lines)
        rule_ids = {a.rule_id for a in report.alerts}
        self.assertIn("WEB_SQL_INJECTION", rule_ids)

    def test_port_scan_detection(self) -> None:
        lines = [
            f"Nov 17 09:10:0{i} fw kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.0.0.5 PROTO=TCP SPT=5100{i} DPT={port} SYN"
            for i, port in enumerate([21, 22, 23, 80, 443, 3389])
        ]
        report = analyze_events(lines, port_scan_threshold=5)
        rule_ids = {a.rule_id for a in report.alerts}
        self.assertIn("FW_PORT_SCAN", rule_ids)

    def test_report_exporters(self) -> None:
        lines = [
            '198.51.100.77 - - [17/Nov/2026:10:00:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 320 "-" "curl/8.0"'
        ]
        report = analyze_events(lines)
        self.assertIn("WEB_XSS_PROBE", to_json(report))
        self.assertIn("rule_id,severity", to_csv(report))
        self.assertIn("# SentinelLog Security Incident Report", to_markdown(report))


if __name__ == "__main__":
    unittest.main()
