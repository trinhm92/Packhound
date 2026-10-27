"""Scan history in SQLite, used for "new since last scan" and `scs report`."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from scs.models import finding_key
from scs.util import data_dir, normalize_host

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started TEXT NOT NULL,
  host TEXT NOT NULL,
  summary TEXT NOT NULL,
  data TEXT NOT NULL
)
"""


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(data_dir() / "scs.db")
    c.execute(SCHEMA)
    return c


def save(result: dict) -> int:
    with closing(_conn()) as c, c:
        cur = c.execute("INSERT INTO scans (started, host, summary, data) VALUES (?, ?, ?, ?)",
                        (result["started"], result["host"], json.dumps(result["summary"]), json.dumps(result)))
        return int(cur.lastrowid)


def load(scan_id: int | None = None, host: str | None = None) -> dict | None:
    with closing(_conn()) as c:
        if scan_id is not None:
            row = c.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        elif host:
            # compare normalized names so "Mac.local" and "mac" are the same machine (older rows kept raw names)
            row = None
            for rid, h in c.execute("SELECT id, host FROM scans ORDER BY id DESC"):
                if normalize_host(h) == normalize_host(host):
                    row = c.execute("SELECT data FROM scans WHERE id = ?", (rid,)).fetchone()
                    break
        else:
            row = c.execute("SELECT data FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def previous_keys(host: str) -> dict[str, set[str]]:
    last = load(host=host)
    if not last:
        return {}
    return {finding_key(f): {a["id"] for a in f.get("advisories", [])} for f in last.get("findings", [])}


def listing(limit: int = 20) -> list[tuple]:
    with closing(_conn()) as c:
        return c.execute("SELECT id, started, host, summary FROM scans ORDER BY id DESC LIMIT ?",
                         (limit,)).fetchall()
