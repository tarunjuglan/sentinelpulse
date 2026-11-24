"""Realistic multi-stage attack & baseline traffic log generator for demos and testing."""

from datetime import datetime, timedelta
from pathlib import Path


def generate_sample_logs(output_dir: Path) -> tuple[Path, Path]:
    """Generate realistic auth.log and access.log files with normal traffic + multi-stage attacks."""
    output_dir.mkdir(parents=True, exist_ok=True)
    auth_path = output_dir / "auth.log"
    web_path = output_dir / "access.log"

    base_dt = datetime(2026, 11, 24, 14, 10, 0)

    def ssh_ts(offset_sec: int) -> str:
        return (base_dt + timedelta(seconds=offset_sec)).strftime("%b %d %H:%M:%S")

    def web_ts(offset_sec: int) -> str:
        return (base_dt + timedelta(seconds=offset_sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")

    auth_lines = [
        # Legitimate admin login
        f"{ssh_ts(5)} prod-web-01 sshd[1021]: Accepted publickey for deploy from 10.0.1.15 port 51200 ssh2",
        f"{ssh_ts(15)} prod-web-01 systemd-logind[512]: New session 42 of user deploy.",
        # Malicious IP 185.220.101.42: Invalid user spray -> brute force -> root -> COMPROMISE
        f"{ssh_ts(30)} prod-web-01 sshd[1102]: Invalid user oracle from 185.220.101.42 port 40112",
        f"{ssh_ts(34)} prod-web-01 sshd[1103]: Invalid user postgres from 185.220.101.42 port 40118",
        f"{ssh_ts(38)} prod-web-01 sshd[1104]: Invalid user admin from 185.220.101.42 port 40125",
        f"{ssh_ts(42)} prod-web-01 sshd[1105]: Invalid user testuser from 185.220.101.42 port 40131",
        f"{ssh_ts(48)} prod-web-01 sshd[1106]: Failed password for root from 185.220.101.42 port 40140 ssh2",
        f"{ssh_ts(52)} prod-web-01 sshd[1107]: Failed password for root from 185.220.101.42 port 40145 ssh2",
        f"{ssh_ts(56)} prod-web-01 sshd[1108]: Failed password for root from 185.220.101.42 port 40152 ssh2",
        f"{ssh_ts(60)} prod-web-01 sshd[1109]: Failed password for deploy from 185.220.101.42 port 40160 ssh2",
        f"{ssh_ts(65)} prod-web-01 sshd[1110]: Accepted password for deploy from 185.220.101.42 port 40177 ssh2",
        # Second attacker 91.240.118.168: Failed SSH brute-force without success
        f"{ssh_ts(120)} prod-web-01 sshd[1201]: Failed password for ubuntu from 91.240.118.168 port 53210 ssh2",
        f"{ssh_ts(124)} prod-web-01 sshd[1202]: Failed password for ubuntu from 91.240.118.168 port 53215 ssh2",
        f"{ssh_ts(128)} prod-web-01 sshd[1203]: Failed password for ubuntu from 91.240.118.168 port 53220 ssh2",
        f"{ssh_ts(132)} prod-web-01 sshd[1204]: Failed password for ubuntu from 91.240.118.168 port 53225 ssh2",
        f"{ssh_ts(136)} prod-web-01 sshd[1205]: Failed password for ubuntu from 91.240.118.168 port 53230 ssh2",
        # Normal traffic
        f"{ssh_ts(200)} prod-web-01 sshd[1300]: Accepted publickey for alice from 10.0.1.22 port 49152 ssh2",
    ]

    web_lines = [
        # Normal user traffic
        f'203.0.113.50 - - [{web_ts(10)}] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
        f'203.0.113.50 - - [{web_ts(14)}] "GET /assets/app.css HTTP/1.1" 200 1890 "https://example.com/" "Mozilla/5.0"',
        f'203.0.113.50 - - [{web_ts(20)}] "POST /api/login HTTP/1.1" 200 320 "https://example.com/login" "Mozilla/5.0"',
        # Multi-stage Web Attacker: 45.155.205.9 (Dir brute-force + sensitive files + SQLi + sqlmap UA)
        f'45.155.205.9 - - [{web_ts(40)}] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"',
        f'45.155.205.9 - - [{web_ts(42)}] "GET /.git/config HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(44)}] "GET /backup.sql HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(46)}] "GET /phpinfo.php HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(48)}] "GET /admin/config.php HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(50)}] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(52)}] "GET /server-status HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(54)}] "GET /actuator/env HTTP/1.1" 404 162 "-" "Gobuster/3.6"',
        f'45.155.205.9 - - [{web_ts(65)}] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 512 "-" "sqlmap/1.8"',
        f'45.155.205.9 - - [{web_ts(68)}] "GET /products?id=1\'%20OR%20\'1\'=\'1 HTTP/1.1" 200 2840 "-" "sqlmap/1.8"',
        # Attacker 194.26.135.71: Path traversal / LFI probes
        f'194.26.135.71 - - [{web_ts(95)}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 210 "-" "Nuclei - Open-source project"',
        f'194.26.135.71 - - [{web_ts(98)}] "GET /view?tpl=%2e%2e%2f%2e%2e%2fetc/shadow HTTP/1.1" 403 210 "-" "Nuclei - Open-source project"',
        # Attacker 103.145.254.11: XSS probing
        f'103.145.254.11 - - [{web_ts(140)}] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1420 "-" "Mozilla/5.0"',
        f'103.145.254.11 - - [{web_ts(145)}] "GET /profile?bio=<img%20src=x%20onerror=alert(1)> HTTP/1.1" 200 1420 "-" "Mozilla/5.0"',
        # Attacker 185.220.101.42 also probing web endpoint (cross-log correlation!)
        f'185.220.101.42 - - [{web_ts(160)}] "GET /admin/config HTTP/1.1" 404 162 "-" "curl/8.0"',
    ]

    auth_path.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    web_path.write_text("\n".join(web_lines) + "\n", encoding="utf-8")
    return auth_path, web_path
