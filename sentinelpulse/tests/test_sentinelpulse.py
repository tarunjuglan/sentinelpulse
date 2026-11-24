"""Unit and integration tests for SentinelPulse."""

from pathlib import Path
import tempfile
import unittest

from main import main as cli_main
from sentinelpulse.detector import DetectionEngine
from sentinelpulse.log_generator import generate_sample_logs
from sentinelpulse.parsers import parse_auth_log, parse_web_log
from sentinelpulse.threat_intel import ThreatIntelEngine

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT_DIR / "rules" / "detection_rules.json"
INTEL_PATH = ROOT_DIR / "threat_intel" / "known_bad_ips.json"


class SentinelPulseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.intel = ThreatIntelEngine(INTEL_PATH)
        self.engine = DetectionEngine(RULES_PATH, self.intel)

    def test_ssh_post_bruteforce_compromise_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_file = Path(tmp) / "auth.log"
            auth_file.write_text(
                "\n".join(
                    [
                        "Nov 24 10:00:01 srv sshd[1]: Failed password for root from 203.0.113.99 port 1111 ssh2",
                        "Nov 24 10:00:05 srv sshd[2]: Failed password for root from 203.0.113.99 port 1112 ssh2",
                        "Nov 24 10:00:09 srv sshd[3]: Failed password for root from 203.0.113.99 port 1113 ssh2",
                        "Nov 24 10:00:12 srv sshd[4]: Failed password for admin from 203.0.113.99 port 1114 ssh2",
                        "Nov 24 10:00:15 srv sshd[5]: Failed password for admin from 203.0.113.99 port 1115 ssh2",
                        "Nov 24 10:00:20 srv sshd[6]: Accepted password for admin from 203.0.113.99 port 1116 ssh2",
                    ]
                ),
                encoding="utf-8",
            )
            events, skipped = parse_auth_log(auth_file, year=2026)
            self.assertEqual(skipped, 0)
            self.assertEqual(len(events), 6)

            alerts, incidents = self.engine.analyze(events)
            rule_ids = {a.rule_id for a in alerts}
            self.assertIn("SP-SSH-001", rule_ids)
            self.assertIn("SP-CORR-001", rule_ids)
            self.assertEqual(incidents[0].severity, "CRITICAL")
            self.assertIn("Account Compromise", incidents[0].kill_chain_stages)

    def test_web_sqli_and_lfi_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            web_file = Path(tmp) / "access.log"
            web_file.write_text(
                "\n".join(
                    [
                        '198.51.100.7 - - [24/Nov/2026:12:00:01 +0000] "GET /item?id=1%20UNION%20SELECT%201,2 HTTP/1.1" 500 200 "-" "sqlmap/1.8"',
                        '198.51.100.7 - - [24/Nov/2026:12:00:04 +0000] "GET /read?f=../../../../etc/passwd HTTP/1.1" 403 150 "-" "curl/8.0"',
                        '198.51.100.8 - - [24/Nov/2026:12:00:10 +0000] "GET /home HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
                    ]
                ),
                encoding="utf-8",
            )
            events, skipped = parse_web_log(web_file)
            self.assertEqual(skipped, 0)
            self.assertEqual(len(events), 3)

            alerts, incidents = self.engine.analyze(events)
            rule_ids = {a.rule_id for a in alerts}
            self.assertIn("SP-WEB-001", rule_ids)
            self.assertIn("SP-WEB-003", rule_ids)
            self.assertIn("SP-WEB-006", rule_ids)
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0].src_ip, "198.51.100.7")

    def test_internal_ip_playbook_avoids_blind_external_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            web_file = Path(tmp) / "access.log"
            web_file.write_text(
                '10.0.0.45 - - [24/Nov/2026:12:05:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n',
                encoding="utf-8",
            )
            events, _ = parse_web_log(web_file)
            _, incidents = self.engine.analyze(events)
            self.assertEqual(incidents[0].threat_intel.reputation, "INTERNAL")
            self.assertTrue(
                any("INTERNAL host" in act for act in incidents[0].recommended_actions)
            )

    def test_end_to_end_demo_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            auth_path, web_path = generate_sample_logs(tmp_path / "logs")
            out_dir = tmp_path / "reports"
            rc = cli_main(
                [
                    "--auth-log",
                    str(auth_path),
                    "--web-log",
                    str(web_path),
                    "--output-dir",
                    str(out_dir),
                    "--year",
                    "2026",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "soc_report.html").exists())
            self.assertTrue((out_dir / "alerts.json").exists())
            self.assertTrue((out_dir / "incident_summary.md").exists())
            html_content = (out_dir / "soc_report.html").read_text(encoding="utf-8")
            self.assertIn("185.220.101.42", html_content)
            self.assertIn("T1078 - Valid Accounts", html_content)


if __name__ == "__main__":
    unittest.main()
