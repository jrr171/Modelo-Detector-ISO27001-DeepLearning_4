"""
Sample log generator — creates realistic test logs for all supported formats.
Run: python samples/generate_samples.py
"""

import random
import os
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent

random.seed(42)

# ── Helpers ───────────────────────────────────────────────────────────────────

FAKE_IPS = [
    "192.168.1.10", "192.168.1.15", "10.0.0.22", "172.16.5.4",
    "203.0.113.77", "198.51.100.1", "45.33.32.156", "80.82.77.33",
    "185.220.101.5", "103.21.244.0",
]
FAKE_USERS = ["alice", "bob", "carol", "dave", "eve", "root", "admin", "postgres"]

def rand_ts(days_back: int = 30) -> datetime:
    return datetime.now() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )

def apache_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


# ── Apache access log ─────────────────────────────────────────────────────────

def make_apache_log(path: Path, n: int = 600) -> None:
    paths_ok  = ["/", "/index.html", "/api/v1/users", "/api/v1/orders",
                 "/login", "/dashboard", "/static/app.js"]
    paths_bad = ["/admin", "/.env", "/wp-login.php", "/../etc/passwd",
                 "/api/v1/admin", "/phpmyadmin"]
    agents    = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Wget/1.21.1",
    ]

    lines = []
    for _ in range(n):
        ip   = random.choice(FAKE_IPS)
        user = random.choice(["-"] + FAKE_USERS[:4])
        ts   = apache_ts(rand_ts())
        is_attack = random.random() < 0.18
        if is_attack:
            path   = random.choice(paths_bad)
            status = random.choice([400, 401, 403, 404, 500])
        else:
            path   = random.choice(paths_ok)
            status = random.choice([200, 200, 200, 301, 304])
        size  = random.randint(200, 50_000)
        agent = random.choice(agents)
        lines.append(
            f'{ip} - {user} [{ts}] "GET {path} HTTP/1.1" {status} {size}'
            f' "https://example.com" "{agent}"'
        )

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  ✓ {Path(path).name}  ({n} líneas)")


# ── Linux auth.log ────────────────────────────────────────────────────────────

def make_auth_log(path: Path, n: int = 500) -> None:
    hostname = "srv-comercio-01"
    events_ok = [
        "Accepted password for {user} from {ip} port {port} ssh2",
        "Accepted publickey for {user} from {ip} port {port} ssh2",
        "pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        "New session 5 of user {user}.",
    ]
    events_bad = [
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for invalid user {user} from {ip} port {port} ssh2",
        "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
        "Invalid user {user} from {ip} port {port}",
        "Connection closed by authenticating user {user} {ip} port {port} [preauth]",
        "PAM 3 more authentication failures; logname= uid=0 euid=0 user={user}",
        "Disconnecting invalid user {user} {ip} port {port}: Too many authentication failures",
    ]

    lines = []
    for _ in range(n):
        ip   = random.choice(FAKE_IPS)
        user = random.choice(FAKE_USERS)
        port = random.randint(30_000, 65_000)
        ts   = syslog_ts(rand_ts())
        pid  = random.randint(1000, 9999)
        is_fail = random.random() < 0.40
        tpl  = random.choice(events_bad if is_fail else events_ok)
        msg  = tpl.format(user=user, ip=ip, port=port)
        lines.append(f"{ts} {hostname} sshd[{pid}]: {msg}")

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  ✓ {Path(path).name}  ({n} líneas)")


# ── System syslog ──────────────────────────────────────────────────────────────

def make_syslog(path: Path, n: int = 400) -> None:
    hostname = "srv-comercio-01"
    events = [
        ("kernel", "INFO",     "Firewall rule applied: ACCEPT tcp from {ip}"),
        ("kernel", "WARNING",  "iptables DROP: SYN packet from {ip} port 22"),
        ("kernel", "CRITICAL", "Out of memory: Kill process {pid} (python)"),
        ("sshd",   "INFO",     "Server listening on 0.0.0.0 port 22"),
        ("cron",   "INFO",     "pam_unix(cron:session): session opened for user root"),
        ("systemd","INFO",     "Started Daily backup service"),
        ("systemd","ERROR",    "Failed to start backup.service — timeout"),
        ("kernel", "WARNING",  "possible SYN flooding on port 80. Sending cookies"),
        ("kernel", "INFO",     "SSL handshake completed with {ip}"),
        ("kernel", "ERROR",    "SSL_ERROR_RX_RECORD_TOO_LONG from {ip}"),
        ("kernel", "WARNING",  "Certificate expired: CN=example.com"),
        ("auditd", "INFO",     "type=USER_AUTH msg=audit: user={user} res=success"),
        ("auditd", "WARNING",  "type=USER_AUTH msg=audit: user={user} res=failed"),
        ("kernel", "INFO",     "USB device plugged in — authorized"),
        ("kernel", "WARNING",  "USB storage device blocked by policy"),
        ("kernel", "INFO",     "UPS battery status: charging"),
        ("kernel", "CRITICAL", "UPS power failure — running on battery"),
    ]

    lines = []
    for _ in range(n):
        ip   = random.choice(FAKE_IPS)
        user = random.choice(FAKE_USERS)
        pid  = random.randint(1000, 9999)
        ts   = syslog_ts(rand_ts())
        proc, level, tpl = random.choice(events)
        msg = tpl.format(ip=ip, user=user, pid=pid)
        lines.append(f"{ts} {hostname} {proc}[{pid}]: {msg}")

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  ✓ {Path(path).name}  ({n} líneas)")


# ── Windows Event Log CSV ──────────────────────────────────────────────────────

def make_windows_csv(path: Path, n: int = 300) -> None:
    import csv
    events = [
        ("4624", "Information",  "An account was successfully logged on. Subject: {user}"),
        ("4625", "Warning",      "An account failed to log on. User: {user} IP: {ip}"),
        ("4648", "Information",  "A logon was attempted using explicit credentials. {user}"),
        ("4720", "Information",  "A user account was created. New account: {user}"),
        ("4740", "Warning",      "A user account was locked out. Account: {user}"),
        ("4776", "Warning",      "The domain controller attempted to validate credentials. Error: 0xC000006A"),
        ("5156", "Information",  "The Windows Filtering Platform permitted a connection. {ip}"),
        ("5157", "Warning",      "The Windows Filtering Platform blocked a connection from {ip}"),
        ("7045", "Information",  "A new service was installed in the system."),
        ("1102", "Warning",      "The audit log was cleared. Subject: {user}"),
        ("4698", "Information",  "A scheduled task was created."),
        ("4672", "Information",  "Special privileges assigned to new logon. {user}"),
    ]

    rows = []
    for _ in range(n):
        ip   = random.choice(FAKE_IPS)
        user = random.choice(FAKE_USERS)
        eid, level, tpl = random.choice(events)
        ts = rand_ts().isoformat()
        msg = tpl.format(user=user, ip=ip)
        rows.append({
            "TimeCreated": ts,
            "Id": eid,
            "LevelDisplayName": level,
            "Message": msg,
            "UserName": user,
            "Computer": "WIN-SERVER01",
        })

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"  ✓ {Path(path).name}  ({n} filas)")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generando logs de muestra…")
    OUTPUT_DIR.mkdir(exist_ok=True)
    make_apache_log(OUTPUT_DIR / "sample_apache.log")
    make_auth_log(OUTPUT_DIR   / "sample_auth.log")
    make_syslog(OUTPUT_DIR     / "sample_syslog.log")
    make_windows_csv(OUTPUT_DIR / "sample_windows_events.csv")
    print("Listo. Los archivos se encuentran en ./samples/")
