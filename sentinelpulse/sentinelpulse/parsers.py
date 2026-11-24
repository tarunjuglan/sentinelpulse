"""Log parsers for SSH auth logs and Nginx/Apache combined access logs."""

from datetime import datetime
from pathlib import Path
import re
from typing import Optional
from urllib.parse import unquote

from .models import LogEvent

# Standard syslog timestamp: "Nov 24 14:22:01"
_SSH_FAILED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
)

_SSH_INVALID_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_SSH_SUCCESS_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
)

# Combined log format: 1.2.3.4 - - [24/Nov/2026:14:22:05 +0000] "GET /path HTTP/1.1" 200 1234 "-" "UA"
_WEB_LOG_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)


def _parse_syslog_ts(ts_str: str, default_year: int) -> Optional[datetime]:
    """Parse syslog month-day-time string using the provided year."""
    normalized = " ".join(ts_str.split())
    try:
        return datetime.strptime(f"{default_year} {normalized}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _parse_clf_ts(ts_str: str) -> Optional[datetime]:
    """Parse Common/Combined Log Format timestamp, stripping timezone offset for uniform comparison."""
    base_ts = ts_str.split()[0]
    try:
        return datetime.strptime(base_ts, "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def parse_auth_log(file_path: Path, year: Optional[int] = None) -> tuple[list[LogEvent], int]:
    """Parse an SSH auth.log file into normalized LogEvent objects.

    Returns:
        Tuple of (parsed_events, skipped_lines_count).
    """
    target_year = year or datetime.now().year
    events: list[LogEvent] = []
    skipped = 0

    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            event = _match_ssh_line(line, idx, target_year)
            if event is None:
                skipped += 1
            else:
                events.append(event)

    return events, skipped


def _match_ssh_line(line: str, line_number: int, year: int) -> Optional[LogEvent]:
    """Match a single auth.log line against known sshd event patterns."""
    patterns = (
        (_SSH_FAILED_RE, "ssh_failed"),
        (_SSH_INVALID_RE, "ssh_invalid_user"),
        (_SSH_SUCCESS_RE, "ssh_success"),
    )
    for regex, event_type in patterns:
        match = regex.search(line)
        if not match:
            continue
        ts = _parse_syslog_ts(match.group("ts"), year)
        if ts is None:
            return None
        return LogEvent(
            timestamp=ts,
            source="ssh",
            event_type=event_type,
            src_ip=match.group("ip"),
            raw_line=line,
            line_number=line_number,
            username=match.group("user"),
        )
    return None


def parse_web_log(file_path: Path) -> tuple[list[LogEvent], int]:
    """Parse an Nginx/Apache combined access log into normalized LogEvent objects.

    Returns:
        Tuple of (parsed_events, skipped_lines_count).
    """
    events: list[LogEvent] = []
    skipped = 0

    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            match = _WEB_LOG_RE.search(line)
            if not match:
                skipped += 1
                continue

            ts = _parse_clf_ts(match.group("ts"))
            if ts is None:
                skipped += 1
                continue

            decoded_path = unquote(match.group("path"))
            events.append(
                LogEvent(
                    timestamp=ts,
                    source="web",
                    event_type="http_request",
                    src_ip=match.group("ip"),
                    raw_line=line,
                    line_number=idx,
                    method=match.group("method"),
                    path=decoded_path,
                    status_code=int(match.group("status")),
                    user_agent=match.group("ua") or "-",
                )
            )

    return events, skipped
