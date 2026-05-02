"""db.py — SQLite persistence for SecureDep v2"""

import sqlite3
from datetime import datetime

DB = "securedep.db"

def _cx():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init():
    with _cx() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id    TEXT PRIMARY KEY,
            name       TEXT,
            path       TEXT,
            status     TEXT DEFAULT 'queued',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS findings (
            id             TEXT PRIMARY KEY,
            scan_id        TEXT NOT NULL,
            type           TEXT,
            severity       TEXT,
            confidence     TEXT,
            file           TEXT,
            line           INTEGER DEFAULT 0,
            tool           TEXT,
            vuln_id        TEXT DEFAULT '',
            package        TEXT DEFAULT '',
            description    TEXT,
            impact         TEXT DEFAULT '',
            fix_suggestion TEXT DEFAULT '',
            code_snippet   TEXT DEFAULT '',
            fixed_code     TEXT DEFAULT '',
            suppressed     INTEGER DEFAULT 0,
            suppress_reason TEXT DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );
        """)

# ── Scans ─────────────────────────────────────────────────────────────────────

def create_scan(scan_id: str, path: str, name: str = ""):
    with _cx() as c:
        c.execute(
            "INSERT INTO scans (scan_id, path, name) VALUES (?,?,?)",
            (scan_id, path, name or path)
        )

def set_status(scan_id: str, status: str):
    with _cx() as c:
        c.execute("UPDATE scans SET status=? WHERE scan_id=?", (status, scan_id))

def get_scan(scan_id: str) -> dict | None:
    with _cx() as c:
        row = c.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

def list_scans() -> list[dict]:
    with _cx() as c:
        rows = c.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        return [dict(r) for r in rows]

# ── Findings ──────────────────────────────────────────────────────────────────

_SEV_ORDER = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END"

def insert_finding(f: dict):
    with _cx() as c:
        c.execute("""
            INSERT OR IGNORE INTO findings
            (id,scan_id,type,severity,confidence,file,line,tool,vuln_id,
             package,description,impact,fix_suggestion,code_snippet,fixed_code)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            f["id"], f["scan_id"], f["type"], f["severity"], f["confidence"],
            f["file"], f["line"], f["tool"], f.get("vuln_id",""),
            f.get("package",""), f["description"], f.get("impact",""),
            f.get("fix_suggestion",""), f.get("code_snippet",""),
            f.get("fixed_code",""),
        ))

def get_findings(scan_id: str) -> list[dict]:
    with _cx() as c:
        rows = c.execute(
            f"SELECT * FROM findings WHERE scan_id=? ORDER BY {_SEV_ORDER}, file, line",
            (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def suppress_finding(finding_id: str, reason: str):
    with _cx() as c:
        c.execute(
            "UPDATE findings SET suppressed=1, suppress_reason=? WHERE id=?",
            (reason, finding_id)
        )

def unsuppress_finding(finding_id: str):
    with _cx() as c:
        c.execute(
            "UPDATE findings SET suppressed=0, suppress_reason='' WHERE id=?",
            (finding_id,)
        )
