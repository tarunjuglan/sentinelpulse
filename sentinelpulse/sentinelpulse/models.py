"""Core data models for SentinelPulse log events, alerts, and correlated incidents."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 0,
}

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass(frozen=True)
class LogEvent:
    """Normalized security event parsed from a raw log line."""

    timestamp: datetime
    source: str  # "ssh" or "web"
    event_type: str  # e.g., "ssh_failed", "ssh_success", "http_request"
    src_ip: str
    raw_line: str
    line_number: int
    username: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None


@dataclass(frozen=True)
class ThreatIntelMatch:
    """Local threat intelligence enrichment metadata for an IP address."""

    ip: str
    reputation: str  # MALICIOUS, SUSPICIOUS, CLEAN, INTERNAL
    confidence: int
    category: str
    country: str
    asn: str
    tags: list[str] = field(default_factory=list)


@dataclass
class Alert:
    """Single rule-triggered security alert."""

    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    src_ip: str
    source: str
    mitre_tactic: str
    mitre_technique: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class CorrelatedIncident:
    """Multi-alert or kill-chain correlated incident enriched with threat intel and playbooks."""

    incident_id: str
    title: str
    summary: str
    severity: str
    risk_score: int
    src_ip: str
    kill_chain_stages: list[str]
    mitre_techniques: list[str]
    alerts: list[Alert]
    threat_intel: ThreatIntelMatch
    recommended_actions: list[str]
    containment_commands: list[str]
    first_seen: datetime
    last_seen: datetime
