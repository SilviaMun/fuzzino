"""
SQLite database for users, scans, and findings.
- Encryption at rest for report_json and findings evidence
- Restrictive file permissions (0600)
- Row-level access: users see own scans, admin sees all
- Retention policy
"""

import os
import sys
import json
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from crypto import encrypt, decrypt, is_encrypted

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "scanner.db"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    # Set restrictive permissions before creating
    db_dir = os.path.dirname(DB_PATH) or "."
    os.makedirs(db_dir, exist_ok=True)

    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            model TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            progress INTEGER DEFAULT 0,
            progress_msg TEXT DEFAULT '',
            files_scanned INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            severity_counts TEXT DEFAULT '{}',
            report_json TEXT,
            started_at TEXT DEFAULT (datetime('now')),
            finished_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            severity TEXT,
            category TEXT,
            description TEXT,
            evidence TEXT,
            impact TEXT,
            recommendation TEXT,
            source_url TEXT,
            file_type TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

    # Lock down file permissions (owner only)
    try:
        if sys.platform != "win32":
            os.chmod(DB_PATH, 0o600)
            wal = DB_PATH + "-wal"
            shm = DB_PATH + "-shm"
            if os.path.exists(wal):
                os.chmod(wal, 0o600)
            if os.path.exists(shm):
                os.chmod(shm, 0o600)
    except OSError:
        pass


# ── Users ──

def create_user(username, password, role="user"):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def verify_user(username, password):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password):
        return dict(row)
    return None


def get_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def user_count():
    conn = get_db()
    c = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return c


# ── Scans ──

def create_scan(user_id: int, target_url: str, model: str) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO scans (user_id, target_url, model) VALUES (?, ?, ?)",
        (user_id, target_url, model),
    )
    scan_id = cur.lastrowid or 0
    conn.commit()
    conn.close()
    return scan_id


def update_scan_progress(scan_id, progress, message):
    conn = get_db()
    conn.execute(
        "UPDATE scans SET progress = ?, progress_msg = ? WHERE id = ?",
        (progress, message, scan_id),
    )
    conn.commit()
    conn.close()


def finish_scan(scan_id, report):
    """Finish scan and store report with encryption on sensitive fields."""
    # Encrypt the full report JSON
    report_str = json.dumps(report)
    encrypted_report = encrypt(report_str)

    # Encrypt individual finding evidence
    encrypted_findings = []
    for f in report.get("findings", []):
        encrypted_findings.append({
            **f,
            "evidence": encrypt(f.get("evidence", "")),
        })

    conn = get_db()
    conn.execute(
        """UPDATE scans SET
            status = 'done',
            progress = 100,
            progress_msg = 'Complete',
            files_scanned = ?,
            total_findings = ?,
            severity_counts = ?,
            report_json = ?,
            finished_at = datetime('now')
        WHERE id = ?""",
        (
            report["files_scanned"],
            report["total_findings"],
            json.dumps(report.get("severity_counts", {})),
            encrypted_report,
            scan_id,
        ),
    )

    for f in encrypted_findings:
        conn.execute(
            """INSERT INTO findings
                (scan_id, severity, category, description, evidence, impact, recommendation, source_url, file_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("severity"),
                f.get("category"),
                f.get("description"),
                f.get("evidence"),
                f.get("impact"),
                f.get("recommendation"),
                f.get("source_url"),
                f.get("file_type"),
            ),
        )
    conn.commit()
    conn.close()


def fail_scan(scan_id, error_msg):
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status = 'error', progress_msg = ?, finished_at = datetime('now') WHERE id = ?",
        (error_msg, scan_id),
    )
    conn.commit()
    conn.close()


def get_scan(scan_id):
    """Get scan by ID. Decrypts report_json if encrypted."""
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    if result.get("report_json") and is_encrypted(result["report_json"]):
        result["report_json"] = decrypt(result["report_json"])
    return result


def get_scan_with_user(scan_id):
    conn = get_db()
    row = conn.execute(
        """SELECT s.*, u.username FROM scans s
           JOIN users u ON s.user_id = u.id
           WHERE s.id = ?""",
        (scan_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    if result.get("report_json") and is_encrypted(result["report_json"]):
        result["report_json"] = decrypt(result["report_json"])
    return result


def list_scans(limit=50, user_id=None, is_admin=False):
    """
    List scans with row-level access control.
    - Admin sees all scans
    - Regular user sees only their own scans
    """
    conn = get_db()
    if is_admin:
        rows = conn.execute(
            """SELECT s.id, s.user_id, s.target_url, s.model, s.status, s.progress, s.progress_msg,
                      s.files_scanned, s.total_findings, s.severity_counts,
                      s.started_at, s.finished_at, u.username
               FROM scans s JOIN users u ON s.user_id = u.id
               ORDER BY s.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT s.id, s.user_id, s.target_url, s.model, s.status, s.progress, s.progress_msg,
                      s.files_scanned, s.total_findings, s.severity_counts,
                      s.started_at, s.finished_at, u.username
               FROM scans s JOIN users u ON s.user_id = u.id
               WHERE s.user_id = ?
               ORDER BY s.id DESC LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_active_scan(user_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE user_id = ? AND status = 'running' ORDER BY id DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def can_access_scan(scan_id, user_id, is_admin=False):
    """Check if a user can access a specific scan."""
    if is_admin:
        return True
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    return row and row["user_id"] == user_id


def delete_scan(scan_id):
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


# ── Retention ──

def cleanup_old_scans(max_age_days=90):
    """Delete scans older than max_age_days. Returns count deleted."""
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat()
    conn = get_db()
    cur = conn.execute(
        "DELETE FROM scans WHERE finished_at < ? AND status IN ('done', 'error')",
        (cutoff,),
    )
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted


def cleanup_old_audit(max_age_days=180):
    """Delete audit log entries older than max_age_days."""
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat()
    conn = get_db()
    try:
        cur = conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
        deleted = cur.rowcount
        conn.commit()
    except:
        deleted = 0
    conn.close()
    return deleted


def vacuum():
    """Reclaim disk space after deletions."""
    conn = get_db()
    conn.execute("VACUUM")
    conn.close()


# ── False Positives ──

def init_false_positives_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS false_positives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_pattern TEXT NOT NULL,
            finding_description TEXT NOT NULL,
            finding_evidence_hash TEXT NOT NULL,
            reason TEXT DEFAULT '',
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(target_pattern, finding_evidence_hash)
        )
    """)
    conn.commit()
    conn.close()


def add_false_positive(target_pattern, description, evidence, reason="", user_id=None):
    """Mark a finding as false positive. target_pattern can be exact URL or wildcard."""
    import hashlib
    evidence_hash = hashlib.sha256(evidence.encode()).hexdigest()[:32]
    conn = get_db()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO false_positives
               (target_pattern, finding_description, finding_evidence_hash, reason, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (target_pattern, description, evidence_hash, reason, user_id),
        )
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


def remove_false_positive(fp_id):
    conn = get_db()
    conn.execute("DELETE FROM false_positives WHERE id = ?", (fp_id,))
    conn.commit()
    conn.close()


def list_false_positives(target_pattern=None):
    conn = get_db()
    if target_pattern:
        rows = conn.execute(
            "SELECT * FROM false_positives WHERE target_pattern = ? ORDER BY id DESC",
            (target_pattern,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM false_positives ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def is_false_positive(target_url, description, evidence):
    """Check if a finding is marked as false positive."""
    import hashlib
    evidence_hash = hashlib.sha256(evidence.encode()).hexdigest()[:32]
    conn = get_db()
    # Check exact target match and wildcard *
    row = conn.execute(
        """SELECT id FROM false_positives
           WHERE (target_pattern = ? OR target_pattern = '*')
           AND finding_evidence_hash = ?
           LIMIT 1""",
        (target_url, evidence_hash),
    ).fetchone()
    conn.close()
    return row is not None


def filter_false_positives(findings, target_url):
    """Remove false positives from a findings list. Returns (filtered, fp_count)."""
    filtered = []
    fp_count = 0
    for f in findings:
        if is_false_positive(target_url, f.get("description", ""), f.get("evidence", "")):
            fp_count += 1
        else:
            filtered.append(f)
    return filtered, fp_count