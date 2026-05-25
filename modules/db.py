"""
BBAT SQLite database module.
Handles large-scale scan data without memory crashes.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional


class BBATDatabase:
    """Lightweight SQLite backend for BBAT scan results."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        subdomain TEXT,
        ip TEXT,
        source TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        type TEXT,
        severity TEXT,
        description TEXT,
        url TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        url TEXT,
        status_code INTEGER,
        content_length INTEGER,
        source TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        name TEXT,
        category TEXT,
        confidence TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        port INTEGER,
        service TEXT,
        state TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    CREATE TABLE IF NOT EXISTS dns_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        record_type TEXT,
        value TEXT,
        created_at TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """

    def __init__(self, db_path: str = "./output/bbat.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._ensure_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self):
        with self._get_conn() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()

    def insert_target(self, domain: str) -> int:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO targets (domain, created_at) VALUES (?, ?)",
                (domain, datetime.utcnow().isoformat() + "Z")
            )
            conn.commit()
            row = conn.execute(
                "SELECT id FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            return row["id"]

    def get_target_id(self, domain: str) -> Optional[int]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT id FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            return row["id"] if row else None

    def insert_subdomains(self, target_id: int, subdomains: List[Dict]):
        with self._get_conn() as conn:
            for sub in subdomains:
                conn.execute(
                    "INSERT INTO subdomains (target_id, subdomain, ip, source, created_at) VALUES (?, ?, ?, ?, ?)",
                    (target_id, sub.get("subdomain"), sub.get("ip"), "recon", datetime.utcnow().isoformat() + "Z")
                )
            conn.commit()

    def insert_findings(self, target_id: int, findings: List[Dict]):
        with self._get_conn() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO findings (target_id, type, severity, description, url, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (target_id, f.get("type", ""), f.get("severity", "info"), f.get("description", ""), f.get("url", ""), datetime.utcnow().isoformat() + "Z")
                )
            conn.commit()

    def insert_endpoints(self, target_id: int, endpoints: List[Dict], source: str = "crawler"):
        with self._get_conn() as conn:
            for ep in endpoints:
                url = ep if isinstance(ep, str) else ep.get("url", "")
                conn.execute(
                    "INSERT INTO endpoints (target_id, url, source, created_at) VALUES (?, ?, ?, ?)",
                    (target_id, url, source, datetime.utcnow().isoformat() + "Z")
                )
            conn.commit()

    def insert_technologies(self, target_id: int, technologies: List[Dict]):
        with self._get_conn() as conn:
            for t in technologies:
                conn.execute(
                    "INSERT INTO technologies (target_id, name, category, confidence, created_at) VALUES (?, ?, ?, ?, ?)",
                    (target_id, t.get("name"), t.get("category", ""), t.get("confidence", "medium"), datetime.utcnow().isoformat() + "Z")
                )
            conn.commit()

    def insert_ports(self, target_id: int, ports: List[Dict]):
        with self._get_conn() as conn:
            for p in ports:
                conn.execute(
                    "INSERT INTO ports (target_id, port, service, state, created_at) VALUES (?, ?, ?, ?, ?)",
                    (target_id, p.get("port", 0), p.get("service", ""), p.get("state", ""), datetime.utcnow().isoformat() + "Z")
                )
            conn.commit()

    def insert_dns_records(self, target_id: int, records: Dict):
        with self._get_conn() as conn:
            for rtype, values in records.items():
                if isinstance(values, list):
                    for v in values:
                        conn.execute(
                            "INSERT INTO dns_records (target_id, record_type, value, created_at) VALUES (?, ?, ?, ?)",
                            (target_id, rtype, r, datetime.utcnow().isoformat() + "Z")
                        )
            conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]
            critical = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='critical'").fetchone()["c"]
            high = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='high'").fetchone()["c"]
            medium = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='medium'").fetchone()["c"]
            low = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='low'").fetchone()["c"]
            info = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='info'").fetchone()["c"]
            endpoints = conn.execute("SELECT COUNT(DISTINCT url) as c FROM endpoints").fetchone()["c"]
            subdomains = conn.execute("SELECT COUNT(DISTINCT subdomain) as c FROM subdomains").fetchone()["c"]
            return {
                "total_scans": total, "critical": critical, "high": high,
                "medium": medium, "low": low, "info": info,
                "endpoints": endpoints, "subdomains": subdomains
            }

    def get_findings(self, limit: int = 1000) -> List[Dict]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT type, severity, description, url FROM findings ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_endpoints(self, limit: int = 1000) -> List[str]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT DISTINCT url FROM endpoints ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [r["url"] for r in rows]

    def get_subdomains(self) -> List[str]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT DISTINCT subdomain FROM subdomains").fetchall()
            return [r["subdomain"] for r in rows]

    def get_technologies(self) -> List[Dict]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT name, category, confidence FROM technologies").fetchall()
            return [dict(r) for r in rows]
