"""Optional anonymous scan history (SQLite). Stores metadata only: never full URLs or images."""
import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create the table if it does not exist."""
    with _connect(db_path) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, score INTEGER NOT NULL,
            category TEXT NOT NULL, domain_hash TEXT NOT NULL, rule_names TEXT NOT NULL)""")


def hash_domain(domain: str, salt: str) -> str:
    """Salted SHA-256 of the registered domain (the real domain cannot be read back)."""
    return hashlib.sha256((salt + domain.lower()).encode("utf-8")).hexdigest()


def save_scan(db_path: str, salt: str, domain: str, score: int, category: str, rule_names: list[str]) -> str:
    """Save one anonymous scan record and return its ID."""
    init_db(db_path)
    scan_id = uuid.uuid4().hex[:12]
    with _connect(db_path) as conn:
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
                     (scan_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), score, category,
                      hash_domain(domain, salt), ",".join(rule_names)))
    return scan_id


def list_scans(db_path: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent scan records."""
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def delete_all(db_path: str) -> int:
    """Delete every history record; returns how many were removed."""
    init_db(db_path)
    with _connect(db_path) as conn:
        return conn.execute("DELETE FROM scans").rowcount
