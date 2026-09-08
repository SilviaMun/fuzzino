"""
Security module.
- Brute force protection (login rate limiting)
- SSRF guard (block private/internal IPs)
- CSRF token generation/validation
- Audit logging
- Self-signed TLS certificate generation
"""

import os
import re
import time
import secrets
import socket
import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

import db as database


# ════════════════════════════════════════════
# 1. BRUTE FORCE PROTECTION
# ════════════════════════════════════════════

class BruteForceGuard:
    """Rate-limit login attempts per IP and per username."""

    def __init__(self, max_attempts=5, window_seconds=300, lockout_seconds=900):
        self.max_attempts = max_attempts
        self.window = window_seconds          # 5 min window
        self.lockout = lockout_seconds         # 15 min lockout
        self._attempts_by_ip: dict[str, list[float]] = defaultdict(list)
        self._attempts_by_user: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}

    def _cleanup(self, attempts: list[float], now: float):
        cutoff = now - self.window
        return [t for t in attempts if t > cutoff]

    def is_locked(self, ip: str, username: str = "") -> tuple[bool, int]:
        """Check if IP or username is locked out. Returns (locked, seconds_remaining)."""
        now = time.time()
        for key in [f"ip:{ip}", f"user:{username}"]:
            if key in self._lockouts:
                remaining = self._lockouts[key] - now
                if remaining > 0:
                    return True, int(remaining)
                else:
                    del self._lockouts[key]
        return False, 0

    def record_attempt(self, ip: str, username: str, success: bool):
        """Record a login attempt. Returns True if now locked out."""
        now = time.time()

        if success:
            # Clear on success
            self._attempts_by_ip.pop(ip, None)
            self._attempts_by_user.pop(username, None)
            self._lockouts.pop(f"ip:{ip}", None)
            self._lockouts.pop(f"user:{username}", None)
            return False

        # Record failure
        self._attempts_by_ip[ip] = self._cleanup(self._attempts_by_ip[ip], now) + [now]
        self._attempts_by_user[username] = self._cleanup(self._attempts_by_user[username], now) + [now]

        # Check thresholds
        locked = False
        if len(self._attempts_by_ip[ip]) >= self.max_attempts:
            self._lockouts[f"ip:{ip}"] = now + self.lockout
            locked = True
        if len(self._attempts_by_user[username]) >= self.max_attempts:
            self._lockouts[f"user:{username}"] = now + self.lockout
            locked = True

        return locked


brute_force_guard = BruteForceGuard()


# ════════════════════════════════════════════
# 2. SSRF GUARD
# ════════════════════════════════════════════

# Ranges that should NEVER be scanned
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),           # this network
    ipaddress.ip_network("100.64.0.0/10"),       # shared address space
    ipaddress.ip_network("198.18.0.0/15"),       # benchmarking
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

# Hostnames that should never be scanned
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Cloud metadata IPs
BLOCKED_IPS = {
    "169.254.169.254",    # AWS/GCP/Azure metadata
    "169.254.170.2",      # AWS ECS metadata
    "fd00:ec2::254",      # AWS IPv6 metadata
}


def check_ssrf(url: str) -> tuple[bool, str]:
    """
    Check if a URL targets an internal/private address.
    Returns (safe, reason). safe=True means OK to scan.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"

        # Check blocked hostnames
        hostname_lower = hostname.lower()
        for blocked in BLOCKED_HOSTNAMES:
            if hostname_lower == blocked or hostname_lower.endswith("." + blocked):
                return False, f"Blocked hostname: {hostname}"

        # Resolve hostname to IP
        try:
            resolved_ips = socket.getaddrinfo(hostname, None)
            ips = set()
            for family, type_, proto, canonname, sockaddr in resolved_ips:
                ips.add(sockaddr[0])
        except socket.gaierror:
            # Can't resolve — allow (could be target is on VPN, DNS will resolve there)
            return True, ""

        # Check each resolved IP
        for ip_str in ips:
            if ip_str in BLOCKED_IPS:
                return False, f"Blocked IP (cloud metadata): {ip_str}"
            try:
                ip = ipaddress.ip_address(ip_str)
                for network in BLOCKED_RANGES:
                    if ip in network:
                        return False, f"Private/internal IP: {ip_str} ({network})"
            except ValueError:
                continue

        return True, ""

    except Exception as e:
        return False, f"URL validation error: {e}"


# ════════════════════════════════════════════
# 3. CSRF PROTECTION
# ════════════════════════════════════════════

def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def validate_csrf(session_token: str, request_token: str) -> bool:
    if not session_token or not request_token:
        return False
    return secrets.compare_digest(session_token, request_token)


# ════════════════════════════════════════════
# 4. AUDIT LOG
# ════════════════════════════════════════════

def init_audit_table():
    """Create audit log table if it doesn't exist."""
    conn = database.get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            user_id INTEGER,
            username TEXT,
            ip TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            severity TEXT DEFAULT 'info'
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)
    """)
    conn.commit()
    conn.close()


def audit(action: str, detail: str = "", user_id: int | None = None,
          username: str = "", ip: str = "", severity: str = "info"):
    """Write an audit log entry."""
    try:
        conn = database.get_db()
        conn.execute(
            """INSERT INTO audit_log (user_id, username, ip, action, detail, severity)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, username, ip, action, detail, severity),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # audit should never crash the app


def get_audit_log(limit: int = 200, user_id: int | None = None,
                  action: str | None = None, severity: str | None = None) -> list[dict]:
    """Query audit log with optional filters."""
    conn = database.get_db()
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []

    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if action:
        query += " AND action = ?"
        params.append(action)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ════════════════════════════════════════════
# 5. TLS CERTIFICATE GENERATION
# ════════════════════════════════════════════

def ensure_tls_cert(cert_dir: str | None = None) -> tuple[str, str]:
    """
    Generate a self-signed TLS certificate if one doesn't exist.
    Returns (cert_path, key_path).
    """
    if cert_dir is None:
        cert_dir = str(Path(__file__).parent / "certs")

    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    os.makedirs(cert_dir, exist_ok=True)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Fuzzino"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Team"),
        ])

        # SAN: localhost + common LAN IPs
        san_names = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
        # Try to add the machine's LAN IP
        try:
            hostname = socket.gethostname()
            lan_ip = socket.gethostbyname(hostname)
            if lan_ip and lan_ip != "127.0.0.1":
                san_names.append(x509.IPAddress(ipaddress.ip_address(lan_ip)))
                san_names.append(x509.DNSName(hostname))
        except:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        os.chmod(key_path, 0o600)

        return cert_path, key_path

    except ImportError:
        # Fallback: use openssl CLI
        import subprocess
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=Fuzzino/O=Security Team",
        ], check=True, capture_output=True)
        os.chmod(key_path, 0o600)
        return cert_path, key_path