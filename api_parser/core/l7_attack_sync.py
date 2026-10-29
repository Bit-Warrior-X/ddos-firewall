# core/l7_attack_sync.py
"""
L7 attack incidents: Athens (resty.l7_attack) -> local store -> panel.

Polls the Athens internal listener every L7_ATTACK_POLL_INTERVAL seconds:
  GET /l7_attack            detector view, current incident, recently closed ids
  GET /l7_attack?id=<id>    full incident snapshot

Every incident is upserted into SQLite (L7_ATTACK_DB) and archived as JSON in
L7_ATTACK_ARCHIVE_DIR once it ends. Panel reports (POST report_l7_attack):
attack_start once, attack_update every L7_ATTACK_UPDATE_INTERVAL while the
attack is active, attack_stop with the final snapshot. Undelivered start/stop
reports are retried on later polls with backoff, so incidents that happen
while the panel or angelos is down are still delivered.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

import config
from core.api_client import APIClient
from utils.auth import get_token

ATHENS_BASE = getattr(config, "L7_CACHE_PURGE_BASE", "http://127.0.0.1:9000").rstrip("/")
POLL_INTERVAL = int(getattr(config, "L7_ATTACK_POLL_INTERVAL", 5))
UPDATE_INTERVAL = int(getattr(config, "L7_ATTACK_UPDATE_INTERVAL", 30))
RETENTION_DAYS = int(getattr(config, "L7_ATTACK_RETENTION_DAYS", 180))
DATA_DIR = getattr(config, "L7_ATTACK_DATA_DIR", "/usr/local/share/dorian/athens/attacks")
DB_PATH = getattr(config, "L7_ATTACK_DB", os.path.join(DATA_DIR, "l7_attacks.db"))
ARCHIVE_DIR = getattr(config, "L7_ATTACK_ARCHIVE_DIR", os.path.join(DATA_DIR, "archive"))
REQUEST_TIMEOUT = float(getattr(config, "ATHENS_STATS_TIMEOUT", 5))
RETRY_MAX_DELAY = 600
RETRY_GIVE_UP_DAYS = 7
STALE_ACTIVE_SECONDS = 300

_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS l7_attacks (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    duration        INTEGER,
    vectors         TEXT,
    peak_rps        INTEGER,
    total_requests  INTEGER,
    unique_ips      INTEGER,
    total_blocked   INTEGER,
    total_passed    INTEGER,
    snapshot        TEXT,
    archive_path    TEXT,
    start_reported  INTEGER NOT NULL DEFAULT 0,
    stop_reported   INTEGER NOT NULL DEFAULT 0,
    last_update_at  INTEGER NOT NULL DEFAULT 0,
    next_retry_at   INTEGER NOT NULL DEFAULT 0,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_l7_attacks_started ON l7_attacks(started_at);
"""

_SUMMARY_COLUMNS = (
    "id", "status", "started_at", "ended_at", "duration", "vectors", "peak_rps",
    "total_requests", "total_blocked", "total_passed", "unique_ips", "archive_path",
    "start_reported", "stop_reported",
)
# Columns added after the first release; created on startup when missing.
_MIGRATIONS = (
    ("total_blocked", "INTEGER"),
    ("total_passed", "INTEGER"),
)


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            have = {row["name"] for row in conn.execute("PRAGMA table_info(l7_attacks)")}
            for name, sql_type in _MIGRATIONS:
                if name not in have:
                    conn.execute(f"ALTER TABLE l7_attacks ADD COLUMN {name} {sql_type}")
            for row in conn.execute(
                "SELECT id, snapshot FROM l7_attacks WHERE total_passed IS NULL"
            ).fetchall():
                totals = _normalize_snapshot(json.loads(row["snapshot"] or "{}")).get("totals") or {}
                conn.execute(
                    "UPDATE l7_attacks SET total_blocked = ?, total_passed = ? WHERE id = ?",
                    (int(totals.get("blocked") or 0), int(totals.get("passed") or 0), row["id"]),
                )
            conn.commit()
        finally:
            conn.close()


def _athens_get(params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any]:
    try:
        resp = requests.get(f"{ATHENS_BASE}/l7_attack", params=params or {}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return False, "not_found"
        resp.raise_for_status()
        return True, resp.json()
    except (requests.exceptions.RequestException, ValueError) as exc:
        return False, str(exc)


def _get_row(conn: sqlite3.Connection, incident_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM l7_attacks WHERE id = ?", (incident_id,)).fetchone()


_LIST_FIELDS = ("vector_list", "top_ips", "top_urls", "top_user_agents", "top_countries",
                "sites", "timeline")
_MAP_FIELDS = ("vectors", "totals", "status_codes", "protocols", "methods", "block_rules",
               "sampling", "detector")


def _normalize_snapshot(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Pin list/object field types so the panel always gets the documented shape
    (an empty Lua table can come through as either [] or {})."""
    for key in _LIST_FIELDS:
        if key in snap and not isinstance(snap[key], list):
            snap[key] = []
    for key in _MAP_FIELDS:
        if key in snap and not isinstance(snap[key], dict):
            snap[key] = {}
    esc = snap.get("escalations")
    if isinstance(esc, dict):
        if not isinstance(esc.get("ips"), list):
            esc["ips"] = []
        if not isinstance(esc.get("by_reason"), dict):
            esc["by_reason"] = {}
    elif "escalations" in snap:
        snap["escalations"] = {"total": 0, "by_reason": {}, "ips": [], "xdp": False}

    # Incidents recorded before blocked/passed accounting: derive passed.
    totals = snap.get("totals")
    if isinstance(totals, dict) and "passed" not in totals:
        totals["passed"] = max(0, int(totals.get("requests") or 0) - sum(
            int(totals.get(k) or 0) for k in ("blocked", "malformed", "rapid_reset")))
    if isinstance(totals, dict) and "blocked_ratio" not in snap:
        requests = int(totals.get("requests") or 0)
        snap["blocked_ratio"] = round(int(totals.get("blocked") or 0) / requests, 4) if requests else 0
    return snap


def _upsert(conn: sqlite3.Connection, snap: Dict[str, Any]) -> None:
    _normalize_snapshot(snap)
    totals = snap.get("totals") or {}
    now = int(time.time())
    ended_at = snap.get("ended_at")
    conn.execute(
        """
        INSERT INTO l7_attacks (id, status, started_at, ended_at, duration, vectors, peak_rps,
                                total_requests, total_blocked, total_passed, unique_ips,
                                snapshot, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            status = excluded.status, ended_at = excluded.ended_at, duration = excluded.duration,
            vectors = excluded.vectors, peak_rps = excluded.peak_rps,
            total_requests = excluded.total_requests, total_blocked = excluded.total_blocked,
            total_passed = excluded.total_passed, unique_ips = excluded.unique_ips,
            snapshot = excluded.snapshot, updated_at = excluded.updated_at
        """,
        (
            str(snap["id"]), snap.get("status") or "active", int(snap.get("started_at") or now),
            int(ended_at) if isinstance(ended_at, (int, float)) else None,
            int(snap.get("duration") or 0), ",".join(snap.get("vector_list") or []),
            int(snap.get("peak_rps") or 0), int(totals.get("requests") or 0),
            int(totals.get("blocked") or 0), int(totals.get("passed") or 0),
            int(snap.get("unique_ips") or 0), json.dumps(snap, separators=(",", ":")), now, now,
        ),
    )


def _write_archive(snap: Dict[str, Any]) -> Optional[str]:
    try:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(int(snap.get("started_at") or 0)))
        path = os.path.join(ARCHIVE_DIR, f"{stamp}-l7_{snap['id']}.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(snap, fh, indent=2)
        os.replace(tmp, path)
        return path
    except OSError as exc:
        print(f"[L7_ATTACK] archive write failed for {snap.get('id')}: {exc}", flush=True)
        return None


def _payload(token: str, data: str, snap: Dict[str, Any]) -> Dict[str, Any]:
    attack = _normalize_snapshot(dict(snap))
    if data != "attack_stop":
        attack.pop("timeline", None)
    return {
        "token": token,
        "command": "report_l7_attack",
        "data": data,
        "req_id": str(snap["id"]),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reported_at": int(time.time()),
        "attack": attack,
    }


def _report(token: str, data: str, snap: Dict[str, Any]) -> bool:
    return APIClient.report_l7_attack(_payload(token, data, snap))


def _schedule_retry(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    count = int(row["retry_count"] or 0) + 1
    delay = min(RETRY_MAX_DELAY, 15 * (2 ** min(count - 1, 6)))
    conn.execute(
        "UPDATE l7_attacks SET retry_count = ?, next_retry_at = ? WHERE id = ?",
        (count, int(time.time()) + delay, row["id"]),
    )


def _handle_active(conn: sqlite3.Connection, token: str, snap: Dict[str, Any]) -> None:
    _upsert(conn, snap)
    row = _get_row(conn, str(snap["id"]))
    now = int(time.time())
    if not row["start_reported"]:
        if row["retry_count"] == 0:
            print(
                f"[L7_ATTACK] attack START id={snap['id']} vectors={row['vectors']} "
                f"peak_rps={row['peak_rps']}",
                flush=True,
            )
        if now < row["next_retry_at"]:
            return
        if _report(token, "attack_start", snap):
            conn.execute(
                "UPDATE l7_attacks SET start_reported = 1, last_update_at = ?, retry_count = 0, "
                "next_retry_at = 0 WHERE id = ?",
                (now, row["id"]),
            )
        else:
            _schedule_retry(conn, row)
    elif now - row["last_update_at"] >= UPDATE_INTERVAL:
        # Updates are best-effort; the next one carries fresher data anyway.
        _report(token, "attack_update", snap)
        conn.execute("UPDATE l7_attacks SET last_update_at = ? WHERE id = ?", (now, row["id"]))


def _handle_closed(conn: sqlite3.Connection, token: str, incident_id: str) -> None:
    row = _get_row(conn, incident_id)
    if row is not None and row["status"] == "ended" and row["stop_reported"]:
        return
    now = int(time.time())
    if row is not None and now < row["next_retry_at"]:
        return

    if row is None or row["status"] != "ended":
        ok, snap = _athens_get({"id": incident_id})
        if not ok:
            if snap == "not_found" and row is not None:
                # Expired from Athens before we saw the end: close with what we have.
                snap = json.loads(row["snapshot"] or "{}") or {"id": incident_id}
                snap["status"] = "ended"
            else:
                return
        _upsert(conn, snap)
        path = _write_archive(snap)
        if path:
            conn.execute("UPDATE l7_attacks SET archive_path = ? WHERE id = ?", (path, incident_id))
        row = _get_row(conn, incident_id)
        print(
            f"[L7_ATTACK] attack END id={incident_id} duration={row['duration']}s "
            f"vectors={row['vectors']} peak_rps={row['peak_rps']} requests={row['total_requests']} "
            f"unique_ips={row['unique_ips']} archive={path}",
            flush=True,
        )

    snap = json.loads(row["snapshot"] or "{}")
    if not row["start_reported"]:
        if not _report(token, "attack_start", snap):
            _schedule_retry(conn, row)
            return
        conn.execute("UPDATE l7_attacks SET start_reported = 1 WHERE id = ?", (incident_id,))
    if _report(token, "attack_stop", snap):
        conn.execute(
            "UPDATE l7_attacks SET stop_reported = 1, retry_count = 0, next_retry_at = 0 WHERE id = ?",
            (incident_id,),
        )
    else:
        _schedule_retry(conn, row)


def sync_once() -> bool:
    ok, summary = _athens_get()
    if not ok or not isinstance(summary, dict):
        return False
    token = get_token()

    with _db_lock:
        conn = _connect()
        try:
            current = summary.get("current")
            current_id = summary.get("current_id")
            if current_id and not isinstance(current, dict):
                ok_cur, current = _athens_get({"id": current_id})
                if not ok_cur:
                    current = None
            if isinstance(current, dict) and current.get("id"):
                _handle_active(conn, token, current)
                conn.commit()

            known = {str(current_id)} if current_id else set()
            for item in summary.get("recent") or []:
                incident_id = str((item or {}).get("id") or "")
                if incident_id:
                    known.add(incident_id)
                    _handle_closed(conn, token, incident_id)
                    conn.commit()

            _reconcile_local(conn, token, known)
            conn.commit()
        finally:
            conn.close()
    return True


def _reconcile_local(conn: sqlite3.Connection, token: str, known: set) -> None:
    """Close incidents Athens no longer knows (nginx restart lost its shm) and
    keep retrying undelivered stop reports for up to RETRY_GIVE_UP_DAYS."""
    now = int(time.time())
    for row in conn.execute(
        "SELECT id, snapshot FROM l7_attacks WHERE status = 'active' AND updated_at < ?",
        (now - STALE_ACTIVE_SECONDS,),
    ).fetchall():
        if row["id"] in known:
            continue
        snap = json.loads(row["snapshot"] or "{}") or {"id": row["id"]}
        snap["status"] = "ended"
        snap["ended_at"] = int(snap.get("updated_at") or now)
        snap["end_reason"] = "detector_state_lost"
        _upsert(conn, snap)
        path = _write_archive(snap)
        if path:
            conn.execute("UPDATE l7_attacks SET archive_path = ? WHERE id = ?", (path, row["id"]))
        print(f"[L7_ATTACK] closed stale incident id={row['id']} (no longer known to Athens)", flush=True)

    give_up = now - RETRY_GIVE_UP_DAYS * 86400
    for row in conn.execute(
        "SELECT id FROM l7_attacks WHERE status = 'ended' AND stop_reported = 0 "
        "AND next_retry_at <= ? AND started_at >= ? ORDER BY started_at LIMIT 20",
        (now, give_up),
    ).fetchall():
        if row["id"] not in known:
            _handle_closed(conn, token, row["id"])


def _cleanup_old() -> None:
    cutoff = int(time.time()) - RETENTION_DAYS * 86400
    with _db_lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, archive_path FROM l7_attacks WHERE started_at < ? AND status = 'ended'",
                (cutoff,),
            ).fetchall()
            for row in rows:
                if row["archive_path"]:
                    try:
                        os.remove(row["archive_path"])
                    except OSError:
                        pass
            conn.execute("DELETE FROM l7_attacks WHERE started_at < ? AND status = 'ended'", (cutoff,))
            conn.commit()
        finally:
            conn.close()


def list_attacks(since: Optional[int] = None, until: Optional[int] = None,
                 status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    sql = f"SELECT {', '.join(_SUMMARY_COLUMNS)} FROM l7_attacks WHERE 1=1"
    params: List[Any] = []
    if since is not None:
        sql += " AND started_at >= ?"
        params.append(int(since))
    if until is not None:
        sql += " AND started_at <= ?"
        params.append(int(until))
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY started_at DESC LIMIT ?"
    params.append(int(limit))
    with _db_lock:
        conn = _connect()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    out = []
    for row in rows:
        item = dict(row)
        item["vectors"] = [v for v in (item.get("vectors") or "").split(",") if v]
        requests = int(item.get("total_requests") or 0)
        item["blocked_ratio"] = round(int(item.get("total_blocked") or 0) / requests, 4) if requests else 0
        item["start_reported"] = bool(item["start_reported"])
        item["stop_reported"] = bool(item["stop_reported"])
        out.append(item)
    return out


def get_attack(incident_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        conn = _connect()
        try:
            row = _get_row(conn, incident_id)
        finally:
            conn.close()
    if row is None:
        return None
    if row["status"] == "active":
        ok, snap = _athens_get({"id": incident_id})
        if ok and isinstance(snap, dict):
            return _normalize_snapshot(snap)
    return _normalize_snapshot(json.loads(row["snapshot"] or "{}"))


def detector_status() -> Tuple[bool, Any]:
    ok, summary = _athens_get()
    if not ok or not isinstance(summary, dict):
        return False, summary
    return True, {"current_id": summary.get("current_id"), "detector": summary.get("detector")}


def _run_sync_loop() -> None:
    print(
        f"[L7_ATTACK] pid={os.getpid()} starting incident sync "
        f"(poll={POLL_INTERVAL}s update={UPDATE_INTERVAL}s db={DB_PATH})",
        flush=True,
    )
    try:
        init_db()
    except Exception as exc:
        print(f"[L7_ATTACK] init_db failed: {exc}", flush=True)
    last_cleanup = 0.0
    while True:
        try:
            sync_once()
            if time.time() - last_cleanup >= 3600:
                _cleanup_old()
                last_cleanup = time.time()
        except Exception as exc:
            print(f"[L7_ATTACK] Unexpected error: {exc}", flush=True)
        time.sleep(POLL_INTERVAL)


def start_l7_attack_sync() -> threading.Thread:
    thread = threading.Thread(target=_run_sync_loop, daemon=True, name="l7_attack_sync")
    thread.start()
    return thread
