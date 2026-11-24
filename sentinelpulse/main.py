"""CLI entrypoint for SentinelPulse SOC Detection & Correlation Engine."""

import argparse
from pathlib import Path
import sys

from sentinelpulse.detector import DetectionEngine
from sentinelpulse.log_generator import generate_sample_logs
from sentinelpulse.parsers import parse_auth_log, parse_web_log
from sentinelpulse.reporter import export_all_reports
from sentinelpulse.threat_intel import ThreatIntelEngine

BASE_DIR = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelpulse",
        description="SentinelPulse: Multi-Source SOC Detection, Correlation & Incident Triage Engine",
    )
    parser.add_argument("--auth-log", type=Path, help="Path to Linux SSH auth.log file")
    parser.add_argument("--web-log", type=Path, help="Path to Nginx/Apache combined access.log file")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate realistic sample attack logs and run full SOC analysis",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=BASE_DIR / "rules" / "detection_rules.json",
        help="Path to JSON detection rules file",
    )
    parser.add_argument(
        "--intel",
        type=Path,
        default=BASE_DIR / "threat_intel" / "known_bad_ips.json",
        help="Path to local threat intelligence JSON feed",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=BASE_DIR / "reports",
        help="Directory where HTML, JSON, and Markdown reports will be saved",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Override year for syslog timestamps (default: current year)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    auth_log = args.auth_log
    web_log = args.web_log

    if args.demo:
        auth_log, web_log = generate_sample_logs(BASE_DIR / "sample_logs")
        print(f"[+] Generated demo logs in: {BASE_DIR / 'sample_logs'}")

    if not auth_log and not web_log:
        parser.error("Provide --auth-log, --web-log, or --demo to run analysis.")

    events = []
    skipped = 0
    ssh_count = 0
    web_count = 0

    if auth_log:
        if not auth_log.exists():
            print(f"[!] Auth log not found: {auth_log}", file=sys.stderr)
            return 1
        ssh_events, ssh_skipped = parse_auth_log(auth_log, year=args.year)
        events.extend(ssh_events)
        ssh_count = len(ssh_events)
        skipped += ssh_skipped

    if web_log:
        if not web_log.exists():
            print(f"[!] Web log not found: {web_log}", file=sys.stderr)
            return 1
        web_events, web_skipped = parse_web_log(web_log)
        events.extend(web_events)
        web_count = len(web_events)
        skipped += web_skipped

    if not args.rules.exists():
        print(f"[!] Detection rules file not found: {args.rules}", file=sys.stderr)
        return 1

    intel_engine = ThreatIntelEngine(args.intel)
    detector = DetectionEngine(args.rules, intel_engine)
    alerts, incidents = detector.analyze(events)

    outputs = export_all_reports(
        output_dir=args.output_dir,
        total_events=len(events),
        ssh_events=ssh_count,
        web_events=web_count,
        skipped_lines=skipped,
        alerts=alerts,
        incidents=incidents,
    )

    print("\n=== SentinelPulse Triage Summary ===")
    print(f"Events parsed : {len(events)} (SSH: {ssh_count}, Web: {web_count}, Skipped: {skipped})")
    print(f"Alerts fired  : {len(alerts)}")
    print(f"Incidents     : {len(incidents)}")
    print("-" * 40)
    for inc in incidents:
        print(
            f"[{inc.severity:<8}] {inc.incident_id} | Risk {inc.risk_score:>3}/100 | "
            f"{inc.src_ip:<15} | {inc.title}"
        )
    print("-" * 40)
    print(f"HTML Dashboard : {outputs['html']}")
    print(f"JSON Feed      : {outputs['json']}")
    print(f"Markdown Brief : {outputs['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
