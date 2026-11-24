"""Rule-based detection engine and multi-stage kill-chain correlator."""

from collections import defaultdict, deque
from datetime import timedelta
import json
from pathlib import Path
import re

from .models import (
    SEVERITY_RANK,
    SEVERITY_WEIGHTS,
    Alert,
    CorrelatedIncident,
    LogEvent,
)
from .playbooks import build_playbook
from .threat_intel import ThreatIntelEngine

# Maps rule IDs to normalized Cyber Kill Chain stages for correlation storytelling.
_RULE_TO_KILL_CHAIN = {
    "SP-WEB-004": "Reconnaissance",
    "SP-WEB-005": "Reconnaissance",
    "SP-WEB-006": "Reconnaissance",
    "SP-SSH-002": "Reconnaissance",
    "SP-SSH-001": "Credential Access",
    "SP-SSH-003": "Privilege Escalation",
    "SP-WEB-001": "Exploitation / Initial Access",
    "SP-WEB-002": "Exploitation / Execution",
    "SP-WEB-003": "Exploitation / Collection",
    "SP-CORR-001": "Account Compromise",
}


class DetectionEngine:
    """Evaluates normalized LogEvents against detection rules and correlates incidents."""

    def __init__(self, rules_path: Path, threat_intel: ThreatIntelEngine) -> None:
        with rules_path.open("r", encoding="utf-8") as handle:
            self.rules: dict[str, dict] = json.load(handle)
        self.threat_intel = threat_intel
        self._alert_seq = 0

    def _next_alert_id(self) -> str:
        self._alert_seq += 1
        return f"ALT-{self._alert_seq:04d}"

    def analyze(self, events: list[LogEvent]) -> tuple[list[Alert], list[CorrelatedIncident]]:
        """Run all detection rules and correlate alerts into prioritized incidents."""
        ordered = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []

        ssh_events = [e for e in ordered if e.source == "ssh"]
        web_events = [e for e in ordered if e.source == "web"]

        alerts.extend(self._detect_ssh_threshold_rules(ssh_events))
        alerts.extend(self._detect_ssh_post_bruteforce_success(ssh_events))
        alerts.extend(self._detect_web_dir_bruteforce(web_events))
        alerts.extend(self._detect_web_signatures(web_events))

        incidents = self._correlate_incidents(alerts)
        return alerts, incidents

    def _detect_sliding_window(
        self,
        events: list[LogEvent],
        rule_key: str,
        source: str,
    ) -> list[Alert]:
        """Group matching events per IP using a sliding time window and emit deduplicated alerts."""
        rule = self.rules.get(rule_key)
        if not rule:
            return []

        threshold = int(rule.get("threshold", 5))
        window = timedelta(seconds=int(rule.get("window_seconds", 300)))
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in events:
            by_ip[ev.src_ip].append(ev)

        triggered: list[Alert] = []
        for ip, ip_events in by_ip.items():
            window_q: deque[LogEvent] = deque()
            matched_events: list[LogEvent] = []

            for ev in ip_events:
                window_q.append(ev)
                while window_q and (ev.timestamp - window_q[0].timestamp) > window:
                    window_q.popleft()
                if len(window_q) >= threshold:
                    matched_events.extend(window_q)
                    window_q.clear()

            # Deduplicate matched lines while preserving chronological order.
            unique_events = list({ev.line_number: ev for ev in matched_events}.values())
            unique_events.sort(key=lambda e: e.timestamp)
            if not unique_events:
                continue

            triggered.append(
                Alert(
                    alert_id=self._next_alert_id(),
                    rule_id=rule["rule_id"],
                    title=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    src_ip=ip,
                    source=source,
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    first_seen=unique_events[0].timestamp,
                    last_seen=unique_events[-1].timestamp,
                    event_count=len(ip_events),
                    evidence=[f"L{ev.line_number}: {ev.raw_line}" for ev in unique_events[:5]],
                )
            )
        return triggered

    def _detect_ssh_threshold_rules(self, ssh_events: list[LogEvent]) -> list[Alert]:
        """Evaluate SSH brute-force, invalid user spray, and root login rules."""
        alerts: list[Alert] = []
        failed = [e for e in ssh_events if e.event_type in {"ssh_failed", "ssh_invalid_user"}]
        invalid_users = [e for e in ssh_events if e.event_type == "ssh_invalid_user"]
        root_attempts = [e for e in ssh_events if e.username == "root"]

        alerts.extend(self._detect_sliding_window(failed, "ssh_bruteforce", "ssh"))
        alerts.extend(self._detect_sliding_window(invalid_users, "ssh_invalid_user_spray", "ssh"))
        alerts.extend(self._detect_sliding_window(root_attempts, "ssh_root_login_attempt", "ssh"))
        return alerts

    def _detect_ssh_post_bruteforce_success(self, ssh_events: list[LogEvent]) -> list[Alert]:
        """Detect a successful SSH login from an IP that previously failed repeatedly."""
        alerts: list[Alert] = []
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in ssh_events:
            by_ip[ev.src_ip].append(ev)

        for ip, ip_events in by_ip.items():
            failures: list[LogEvent] = []
            for ev in ip_events:
                if ev.event_type in {"ssh_failed", "ssh_invalid_user"}:
                    failures.append(ev)
                elif ev.event_type == "ssh_success" and len(failures) >= 3:
                    evidence = [f"L{f.line_number}: {f.raw_line}" for f in failures[-3:]]
                    evidence.append(f"L{ev.line_number}: {ev.raw_line}")
                    alerts.append(
                        Alert(
                            alert_id=self._next_alert_id(),
                            rule_id="SP-CORR-001",
                            title="Possible Account Compromise: SSH Success After Brute-Force",
                            description=(
                                f"IP {ip} succeeded in authenticating as '{ev.username}' "
                                f"after {len(failures)} prior failed attempts."
                            ),
                            severity="CRITICAL",
                            src_ip=ip,
                            source="ssh",
                            mitre_tactic="Initial Access",
                            mitre_technique="T1078 - Valid Accounts",
                            first_seen=failures[0].timestamp,
                            last_seen=ev.timestamp,
                            event_count=len(failures) + 1,
                            evidence=evidence,
                        )
                    )
                    failures.clear()
        return alerts

    def _detect_web_dir_bruteforce(self, web_events: list[LogEvent]) -> list[Alert]:
        """Detect rapid bursts of HTTP 404 responses indicating directory enumeration."""
        not_found_events = [e for e in web_events if e.status_code == 404]
        return self._detect_sliding_window(not_found_events, "web_dir_bruteforce", "web")

    def _detect_web_signatures(self, web_events: list[LogEvent]) -> list[Alert]:
        """Match web request paths and User-Agents against attack payload signatures."""
        signature_rules = [
            ("web_sqli_probe", "path"),
            ("web_xss_probe", "path"),
            ("web_path_traversal", "path"),
            ("web_sensitive_file_scan", "path"),
            ("web_scanner_ua", "user_agent"),
        ]

        alerts: list[Alert] = []
        for rule_key, target_field in signature_rules:
            rule = self.rules.get(rule_key)
            if not rule or "patterns" not in rule:
                continue

            compiled = [re.compile(pat, re.IGNORECASE) for pat in rule["patterns"]]
            hits_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

            for ev in web_events:
                haystack = (ev.path or "") if target_field == "path" else (ev.user_agent or "")
                if any(rx.search(haystack) for rx in compiled):
                    hits_by_ip[ev.src_ip].append(ev)

            for ip, hits in hits_by_ip.items():
                alerts.append(
                    Alert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule["rule_id"],
                        title=rule["name"],
                        description=rule["description"],
                        severity=rule["severity"],
                        src_ip=ip,
                        source="web",
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        first_seen=hits[0].timestamp,
                        last_seen=hits[-1].timestamp,
                        event_count=len(hits),
                        evidence=[f"L{h.line_number}: {h.raw_line}" for h in hits[:5]],
                    )
                )
        return alerts

    def _correlate_incidents(self, alerts: list[Alert]) -> list[CorrelatedIncident]:
        """Aggregate alerts by source IP into risk-scored, playbook-backed incidents."""
        grouped: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            grouped[alert.src_ip].append(alert)

        incidents: list[CorrelatedIncident] = []
        for idx, (ip, ip_alerts) in enumerate(grouped.items(), start=1):
            ip_alerts.sort(key=lambda a: (SEVERITY_RANK[a.severity], a.event_count), reverse=True)
            intel = self.threat_intel.lookup(ip)

            kill_chain: list[str] = []
            for alert in sorted(ip_alerts, key=lambda a: a.first_seen):
                stage = _RULE_TO_KILL_CHAIN.get(alert.rule_id, alert.mitre_tactic)
                if stage not in kill_chain:
                    kill_chain.append(stage)

            compromise_suspected = any(a.rule_id == "SP-CORR-001" for a in ip_alerts)
            max_sev = max(ip_alerts, key=lambda a: SEVERITY_RANK[a.severity]).severity
            if len(kill_chain) >= 3 and SEVERITY_RANK[max_sev] < SEVERITY_RANK["CRITICAL"]:
                # Multi-stage attacks spanning 3+ kill-chain phases escalate to CRITICAL.
                max_sev = "CRITICAL"

            risk_score = self._calculate_risk_score(ip_alerts, kill_chain, intel.reputation)
            is_internal = intel.reputation == "INTERNAL"
            actions, commands = build_playbook(ip, ip_alerts, is_internal, compromise_suspected)

            mitre_list = sorted({a.mitre_technique for a in ip_alerts})
            top_title = ip_alerts[0].title
            if compromise_suspected:
                title = f"CRITICAL Compromise Chain from {ip}"
            elif len(ip_alerts) > 1:
                title = f"Multi-Vector Attack ({len(ip_alerts)} Rules Triggered) from {ip}"
            else:
                title = f"{top_title} ({ip})"

            summary = (
                f"Detected {len(ip_alerts)} alert(s) across {len(kill_chain)} kill-chain stage(s) "
                f"({', '.join(kill_chain)}). Threat Intel: {intel.reputation} ({intel.category})."
            )

            incidents.append(
                CorrelatedIncident(
                    incident_id=f"INC-{idx:03d}",
                    title=title,
                    summary=summary,
                    severity=max_sev,
                    risk_score=risk_score,
                    src_ip=ip,
                    kill_chain_stages=kill_chain,
                    mitre_techniques=mitre_list,
                    alerts=ip_alerts,
                    threat_intel=intel,
                    recommended_actions=actions,
                    containment_commands=commands,
                    first_seen=min(a.first_seen for a in ip_alerts),
                    last_seen=max(a.last_seen for a in ip_alerts),
                )
            )

        incidents.sort(key=lambda i: (i.risk_score, SEVERITY_RANK[i.severity]), reverse=True)
        # Re-number incident IDs cleanly after priority sorting.
        for idx, inc in enumerate(incidents, start=1):
            inc.incident_id = f"INC-{idx:03d}"
        return incidents

    @staticmethod
    def _calculate_risk_score(
        alerts: list[Alert],
        kill_chain: list[str],
        reputation: str,
    ) -> int:
        """Compute bounded 0-100 risk score combining rule severity, multi-stage breadth, and intel."""
        base = sum(SEVERITY_WEIGHTS.get(a.severity, 0) for a in alerts)
        stage_bonus = max(0, (len(kill_chain) - 1) * 12)
        intel_bonus = 20 if reputation == "MALICIOUS" else (10 if reputation == "SUSPICIOUS" else 0)
        return min(100, base + stage_bonus + intel_bonus)
