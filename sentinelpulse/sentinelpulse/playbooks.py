"""SOC remediation playbooks and containment command generator."""

from .models import Alert


def build_playbook(
    src_ip: str,
    alerts: list[Alert],
    is_internal: bool,
    compromise_suspected: bool,
) -> tuple[list[str], list[str]]:
    """Generate actionable SOC analyst steps and CLI containment commands.

    Returns:
        Tuple of (recommended_actions, containment_commands).
    """
    actions: list[str] = []
    commands: list[str] = []
    rule_ids = {a.rule_id for a in alerts}

    if compromise_suspected:
        actions.append(
            f"ESCALATE IMMEDIATELY (P1): Confirmed SSH login after brute-force from {src_ip}. "
            "Treat target account as compromised."
        )
        actions.append("Terminate active SSH sessions for the affected user and rotate SSH keys/passwords.")
        actions.append("Audit recent sudo history (~/.bash_history, /var/log/syslog) for persistence or lateral movement.")
        commands.append(f"sudo pkill -KILL -u <compromised_user>  # Terminate active user sessions")
        commands.append(f"sudo passwd -l <compromised_user>       # Lock potentially compromised account")

    if not is_internal:
        actions.append(f"Block external offending IP {src_ip} at host firewall / perimeter WAF.")
        commands.append(f"sudo ufw deny from {src_ip} to any comment 'SentinelPulse block'")
        commands.append(f"sudo iptables -I INPUT -s {src_ip} -j DROP")
    else:
        actions.append(
            f"Source {src_ip} is an INTERNAL host — do not auto-drop blindly; "
            "isolate endpoint and check for lateral movement or misconfigured automation."
        )
        commands.append(f"# Verify internal host owner before isolating: arp -a | grep {src_ip}")

    if any(rid.startswith("SP-SSH") for rid in rule_ids):
        actions.append("Harden SSH: disable password authentication, enforce key-only login, and enable Fail2Ban.")
        commands.append("sudo fail2ban-client set sshd banip " + src_ip)

    if any(rid in {"SP-WEB-001", "SP-WEB-002", "SP-WEB-003"} for rid in rule_ids):
        actions.append("Review WAF/reverse-proxy logs for HTTP 200/500 responses on injection/LFI payloads.")
        actions.append("Verify parameterized queries (SQLi) and strict path sanitization (LFI) in application code.")

    if "SP-WEB-004" in rule_ids or "SP-WEB-005" in rule_ids:
        actions.append("Confirm .env, .git, and backup files are blocked at Nginx/Apache level (return 404/403).")

    return actions, commands
