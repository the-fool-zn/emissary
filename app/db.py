"""SQLite storage: uploads, alerts, incidents, the tool-call audit trail and analyst feedback."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app import config

STATUSES = ("open", "closed", "false_positive")
LABELS = ("true_positive", "false_positive")

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL, source_type TEXT NOT NULL, content TEXT NOT NULL,
  event_count INTEGER NOT NULL, parse_errors INTEGER NOT NULL, alert_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  alert_key TEXT NOT NULL, detector TEXT, title TEXT, src_ip TEXT, severity TEXT, score INTEGER,
  count INTEGER, first_seen TEXT, last_seen TEXT, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  title TEXT, severity TEXT, verdict TEXT, confidence TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  model TEXT, rounds INTEGER, tokens INTEGER, fallback INTEGER,
  json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tool_calls(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  round INTEGER, tool TEXT, arguments TEXT, result TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  label TEXT NOT NULL CHECK(label IN ('true_positive','false_positive')),
  note TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, ip TEXT, username TEXT, outcome TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, severity);
CREATE INDEX IF NOT EXISTS idx_tool_calls_incident ON tool_calls(incident_id);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Optional[Path] = None) -> sqlite3.Connection:
    path = Path(path or config.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    return conn


# ---- writes ----
def create_upload(conn, filename, source_type, content, event_count, parse_errors) -> int:
    cur = conn.execute("INSERT INTO uploads(filename, source_type, content, event_count, parse_errors, created_at)"
                       " VALUES (?,?,?,?,?,?)", (filename, source_type, content, event_count, parse_errors, now()))
    conn.commit()
    return cur.lastrowid


def add_alert(conn, upload_id, alert) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(upload_id, alert_key, detector, title, src_ip, severity, score, count,"
        " first_seen, last_seen, json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (upload_id, alert.id, alert.detector, alert.title, alert.src_ip, alert.severity, alert.score,
         alert.count, alert.first_seen.isoformat(), alert.last_seen.isoformat(), alert.model_dump_json()))
    conn.execute("UPDATE uploads SET alert_count = alert_count + 1 WHERE id = ?", (upload_id,))
    conn.commit()
    return cur.lastrowid


def add_incident(conn, upload_id, alert_row_id, run) -> int:
    """Save an AgentRun: the incident plus one audit row per tool call."""
    inc, t = run.incident, now()
    cur = conn.execute(
        "INSERT INTO incidents(upload_id, alert_id, title, severity, verdict, confidence, model, rounds,"
        " tokens, fallback, json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (upload_id, alert_row_id, inc.title, inc.severity, inc.verdict, inc.confidence, run.model,
         run.rounds, run.tokens, int(run.fallback), inc.model_dump_json(), t, t))
    incident_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO tool_calls(incident_id, round, tool, arguments, result, created_at) VALUES (?,?,?,?,?,?)",
        [(incident_id, c["round"], c["tool"], json.dumps(c["arguments"]), c["result"], t) for c in run.trace])
    conn.commit()
    return incident_id


def set_status(conn, incident_id: int, status: str):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?", (status, now(), incident_id))
    conn.commit()


def add_feedback(conn, incident_id: int, label: str, note: str = ""):
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}")
    conn.execute("INSERT INTO feedback(incident_id, label, note, created_at) VALUES (?,?,?,?)",
                 (incident_id, label, note[:1000], now()))
    conn.commit()


# ---- reads ----
def list_incidents(conn, status=None, severity=None, limit=100) -> list:
    sql, args = "SELECT id, title, severity, verdict, confidence, status, fallback, created_at FROM incidents", []
    where = []
    if status:
        where.append("status = ?"); args.append(status)
    if severity:
        where.append("severity = ?"); args.append(severity)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY severity ASC, id DESC LIMIT ?"
    return [dict(r) for r in conn.execute(sql, (*args, limit))]


def get_incident(conn, incident_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["incident"] = json.loads(d.pop("json"))
    a = conn.execute("SELECT json FROM alerts WHERE id = ?", (d["alert_id"],)).fetchone()
    d["alert"] = json.loads(a["json"]) if a else {}
    d["tool_calls"] = [dict(r) for r in conn.execute(
        "SELECT round, tool, arguments, result, created_at FROM tool_calls WHERE incident_id = ? ORDER BY id",
        (incident_id,))]
    d["feedback"] = [dict(r) for r in conn.execute(
        "SELECT label, note, created_at FROM feedback WHERE incident_id = ? ORDER BY id", (incident_id,))]
    return d


def list_tool_calls(conn, limit=200) -> list:
    """The audit trail across all incidents, newest first."""
    return [dict(r) for r in conn.execute(
        "SELECT t.id, t.incident_id, i.title AS incident_title, i.model, t.round, t.tool, t.arguments,"
        " t.result, t.created_at FROM tool_calls t JOIN incidents i ON i.id = t.incident_id"
        " ORDER BY t.id DESC LIMIT ?", (limit,))]


def dashboard_counts(conn) -> dict:
    by_sev = {s: 0 for s in ("P1", "P2", "P3", "P4")}
    for r in conn.execute("SELECT severity, COUNT(*) n FROM incidents WHERE status = 'open' GROUP BY severity"):
        by_sev[r["severity"]] = r["n"]
    return {"open_by_severity": by_sev,
            "total_incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "uploads": conn.execute("SELECT COUNT(*) FROM uploads").fetchone()[0]}


# ---- uploads and login audit (Phase 5) ----
def get_upload(conn, upload_id: int) -> Optional[dict]:
    row = conn.execute("SELECT id, filename, source_type, event_count, parse_errors, alert_count, created_at"
                       " FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["incidents"] = [dict(r) for r in conn.execute(
        "SELECT id, title, severity, verdict, fallback FROM incidents WHERE upload_id = ?"
        " ORDER BY severity ASC, id", (upload_id,))]
    return d


def list_uploads(conn, limit=10) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT id, filename, source_type, event_count, alert_count, created_at FROM uploads"
        " ORDER BY id DESC LIMIT ?", (limit,))]


def log_auth_event(conn, ip: str, username: str, outcome: str):
    conn.execute("INSERT INTO auth_events(ts, ip, username, outcome) VALUES (?,?,?,?)",
                 (now(), (ip or "")[:64], (username or "")[:64], outcome))
    conn.commit()


def list_auth_events(conn, limit=50) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT ts, ip, username, outcome FROM auth_events ORDER BY id DESC LIMIT ?", (limit,))]


def incident_exists(conn, incident_id: int) -> bool:
    return conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is not None


def get_upload_content(conn, upload_id: int) -> Optional[str]:
    row = conn.execute("SELECT content FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    return row["content"] if row else None
