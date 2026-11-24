"""Local threat intelligence lookup and IP classification."""

import ipaddress
import json
from pathlib import Path
from typing import Optional

from .models import ThreatIntelMatch


class ThreatIntelEngine:
    """Enriches source IP addresses against local threat feeds and RFC1918 checks."""

    def __init__(self, feed_path: Optional[Path] = None) -> None:
        self._feed: dict[str, dict] = {}
        if feed_path and feed_path.exists():
            with feed_path.open("r", encoding="utf-8") as handle:
                self._feed = json.load(handle)

    def lookup(self, ip: str) -> ThreatIntelMatch:
        """Return threat intelligence context for a given IPv4 address."""
        if ip in self._feed:
            entry = self._feed[ip]
            return ThreatIntelMatch(
                ip=ip,
                reputation=entry.get("reputation", "SUSPICIOUS"),
                confidence=int(entry.get("confidence", 75)),
                category=entry.get("category", "Known Threat Indicator"),
                country=entry.get("country", "Unknown"),
                asn=entry.get("asn", "Unknown"),
                tags=list(entry.get("tags", [])),
            )

        if self._is_private_ip(ip):
            return ThreatIntelMatch(
                ip=ip,
                reputation="INTERNAL",
                confidence=100,
                category="Internal / RFC1918 Network Host",
                country="LOCAL",
                asn="PRIVATE",
                tags=["internal-host"],
            )

        return ThreatIntelMatch(
            ip=ip,
            reputation="UNKNOWN",
            confidence=0,
            category="Unlisted External IP (Behavioral Detection Only)",
            country="External",
            asn="N/A",
            tags=[],
        )

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check whether an IP belongs to private, loopback, or reserved ranges."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False
