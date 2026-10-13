"""SQLite persistence layer for PoViShield multi-device management, pairing, and auditing."""
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT / "results" / "povishield.db"

_LOCK = threading.RLock()


def get_db_path() -> Path:
    custom = os.environ.get("POVISHIELD_DATABASE_URL") or os.environ.get("POVISHIELD_DB_PATH")
    if custom:
        if custom.startswith("sqlite:///"):
            return Path(custom[len("sqlite:///"):]).resolve()
        return Path(custom).resolve()
    return DEFAULT_DB_PATH


def get_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    """Initializes tables, indexes, and default admin user if not present."""
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT,
                        created_at TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pairing_codes (
                        code TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        is_consumed INTEGER NOT NULL DEFAULT 0,
                        consumed_by_device_id TEXT,
                        device_name_hint TEXT,
                        max_uses INTEGER NOT NULL DEFAULT 0,
                        use_count INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pairing_code_uses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        code TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        paired_at TEXT NOT NULL,
                        FOREIGN KEY (code) REFERENCES pairing_codes(code) ON DELETE CASCADE
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        os_info TEXT NOT NULL,
                        kernel_version TEXT NOT NULL,
                        arch TEXT NOT NULL,
                        capabilities_json TEXT NOT NULL,
                        permissions_json TEXT NOT NULL,
                        token_hash TEXT NOT NULL UNIQUE,
                        status TEXT NOT NULL DEFAULT 'online',
                        last_heartbeat_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        revoked_at TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_tasks (
                        id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        command_json TEXT NOT NULL,
                        mode TEXT NOT NULL DEFAULT 'enforce',
                        status TEXT NOT NULL DEFAULT 'queued',
                        created_at TEXT NOT NULL,
                        completed_at TEXT,
                        result_json TEXT,
                        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id TEXT NOT NULL,
                        task_id TEXT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pairing_rate_limits (
                        ip_address TEXT NOT NULL,
                        attempt_time REAL NOT NULL
                    );
                """)

                # Indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_device ON device_tasks(device_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON device_tasks(device_id, status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_device ON device_events(device_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_ip_time ON pairing_rate_limits(ip_address, attempt_time);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pairing_uses_code ON pairing_code_uses(code);")

                # Schema migrations for existing databases to support multi-device fleet enrollment
                for col_stmt in [
                    "ALTER TABLE pairing_codes ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 0",
                    "ALTER TABLE pairing_codes ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0"
                ]:
                    try:
                        conn.execute(col_stmt)
                    except sqlite3.OperationalError:
                        pass

                # Default user for single-operator / local console workflow
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("""
                    INSERT OR IGNORE INTO users (id, username, email, created_at)
                    VALUES ('usr_operator', 'operator', 'operator@povishield.local', ?);
                """, (now,))
        finally:
            conn.close()


# --- User Helpers ---

def get_or_create_user(user_id: str, username: str, email: Optional[str] = None) -> Dict[str, Any]:
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                if row:
                    return dict(row)
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO users (id, username, email, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, username, email or f"{username}@local", now)
                )
                return {
                    "id": user_id,
                    "username": username,
                    "email": email or f"{username}@local",
                    "created_at": now
                }
        finally:
            conn.close()


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# --- Pairing Codes ---

def create_pairing_code(
    user_id: str,
    expires_in_seconds: int = 600,
    device_name_hint: Optional[str] = None,
    max_uses: int = 0
) -> Dict[str, Any]:
    """Generates a secure pairing code.
    max_uses=0 allows unlimited multi-device enrollment until expires_at.
    max_uses=1 enforces single-use pairing.
    """
    import secrets
    # 8-char uppercase/digits secure pairing code format e.g. PVS-7X8K
    code_suffix = secrets.token_hex(3).upper()
    code = f"PVS-{code_suffix}"
    now_dt = datetime.now(timezone.utc)
    expires_dt = now_dt + timedelta(seconds=expires_in_seconds)

    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO pairing_codes (
                        code, user_id, created_at, expires_at, is_consumed,
                        device_name_hint, max_uses, use_count
                    )
                    VALUES (?, ?, ?, ?, 0, ?, ?, 0)
                """, (code, user_id, now_dt.isoformat(), expires_dt.isoformat(), device_name_hint, max_uses))
            return {
                "code": code,
                "user_id": user_id,
                "created_at": now_dt.isoformat(),
                "expires_at": expires_dt.isoformat(),
                "expires_in_seconds": expires_in_seconds,
                "device_name_hint": device_name_hint,
                "max_uses": max_uses,
                "use_count": 0,
                "is_multi_device": (max_uses == 0 or max_uses > 1)
            }
        finally:
            conn.close()


def get_pairing_code(code: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM pairing_codes WHERE code = ?", (code,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def consume_pairing_code(code: str, device_id: str) -> bool:
    """Atomically records device pairing for the code.
    If max_uses > 0 and use_count reaches max_uses, marks is_consumed = 1.
    If max_uses == 0, allows unlimited multi-device enrollment until expires_at.
    Returns True if successfully claimed, False if expired, exhausted, or invalid.
    """
    now_str = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                row = conn.execute("""
                    SELECT is_consumed, expires_at, max_uses, use_count
                    FROM pairing_codes
                    WHERE code = ?
                """, (code,)).fetchone()
                if not row:
                    return False
                if row["is_consumed"] == 1 or row["expires_at"] <= now_str:
                    return False

                current_uses = row["use_count"] or 0
                max_u = row["max_uses"] or 0
                new_use_count = current_uses + 1
                should_consume = 1 if (max_u > 0 and new_use_count >= max_u) else 0

                conn.execute("""
                    UPDATE pairing_codes
                    SET use_count = ?,
                        is_consumed = ?,
                        consumed_by_device_id = ?
                    WHERE code = ?
                """, (new_use_count, should_consume, device_id, code))

                try:
                    conn.execute("""
                        INSERT INTO pairing_code_uses (code, device_id, paired_at)
                        VALUES (?, ?, ?)
                    """, (code, device_id, now_str))
                except sqlite3.OperationalError:
                    pass

                return True
        finally:
            conn.close()


def get_devices_for_pairing_code(code: str) -> List[Dict[str, Any]]:
    """Returns all devices enrolled using a specific pairing code."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT d.*, u.paired_at as enrollment_time
            FROM pairing_code_uses u
            JOIN devices d ON u.device_id = d.id
            WHERE u.code = ?
            ORDER BY u.paired_at DESC
        """, (code,)).fetchall()
        return [_row_to_device(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# --- Device Management ---

def create_device(
    user_id: str,
    device_id: str,
    name: str,
    hostname: str,
    os_info: str,
    kernel_version: str,
    arch: str,
    capabilities: Dict[str, Any],
    permissions: Dict[str, Any],
    token_hash: str
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                # Disambiguate name if another device already shares this exact name for this user
                existing = conn.execute(
                    "SELECT id FROM devices WHERE user_id = ? AND name = ?",
                    (user_id, name)
                ).fetchall()
                if existing:
                    name = f"{name} ({arch} · {device_id[-4:]})"

                conn.execute("""
                    INSERT INTO devices (
                        id, user_id, name, hostname, os_info, kernel_version, arch,
                        capabilities_json, permissions_json, token_hash, status,
                        last_heartbeat_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
                """, (
                    device_id, user_id, name, hostname, os_info, kernel_version, arch,
                    json.dumps(capabilities), json.dumps(permissions), token_hash,
                    now, now
                ))
            return get_device(device_id) or {}
        finally:
            conn.close()


def _row_to_device(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["capabilities"] = json.loads(d.pop("capabilities_json", "{}"))
    d["permissions"] = json.loads(d.pop("permissions_json", "{}"))
    # Compute active live state based on last_heartbeat
    last_hb = d.get("last_heartbeat_at")
    is_live = False
    if last_hb and d.get("status") == "online":
        try:
            hb_dt = datetime.fromisoformat(last_hb)
            if datetime.now(timezone.utc) - hb_dt < timedelta(seconds=25):
                is_live = True
        except Exception:
            is_live = False
    d["is_live"] = is_live
    return d


def get_device(device_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return _row_to_device(row) if row else None
    finally:
        conn.close()


def get_device_by_token_hash(token_hash: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM devices WHERE token_hash = ?", (token_hash,)).fetchone()
        return _row_to_device(row) if row else None
    finally:
        conn.close()


def list_devices_for_user(user_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        return [_row_to_device(r) for r in rows]
    finally:
        conn.close()


get_user_devices = list_devices_for_user


def update_device_heartbeat(device_id: str, status: str = "online", updated_capabilities: Optional[Dict[str, Any]] = None) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                if updated_capabilities:
                    cur = conn.execute("""
                        UPDATE devices
                        SET last_heartbeat_at = ?, status = ?, capabilities_json = ?
                        WHERE id = ? AND status != 'revoked'
                    """, (now, status, json.dumps(updated_capabilities), device_id))
                else:
                    cur = conn.execute("""
                        UPDATE devices
                        SET last_heartbeat_at = ?, status = ?
                        WHERE id = ? AND status != 'revoked'
                    """, (now, status, device_id))
                return cur.rowcount > 0
        finally:
            conn.close()


def revoke_device(device_id: str, user_id: Optional[str] = None) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                if user_id:
                    cur = conn.execute("""
                        UPDATE devices
                        SET status = 'revoked', revoked_at = ?
                        WHERE id = ? AND user_id = ?
                    """, (now, device_id, user_id))
                else:
                    cur = conn.execute("""
                        UPDATE devices
                        SET status = 'revoked', revoked_at = ?
                        WHERE id = ?
                    """, (now, device_id))
                return cur.rowcount > 0
        finally:
            conn.close()


def delete_device(device_id: str, user_id: Optional[str] = None) -> bool:
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                if user_id:
                    cur = conn.execute("DELETE FROM devices WHERE id = ? AND user_id = ?", (device_id, user_id))
                else:
                    cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
                return cur.rowcount > 0
        finally:
            conn.close()


# --- Device Tasks ---

def create_task(device_id: str, user_id: str, task_id: str, command: List[str], mode: str = "enforce") -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO device_tasks (id, device_id, user_id, command_json, mode, status, created_at)
                    VALUES (?, ?, ?, ?, ?, 'queued', ?)
                """, (task_id, device_id, user_id, json.dumps(command), mode, now))
            return get_task(task_id) or {}
        finally:
            conn.close()


def _row_to_task(row: sqlite3.Row) -> Dict[str, Any]:
    t = dict(row)
    t["command"] = json.loads(t.pop("command_json", "[]") or "[]")
    raw_res = t.pop("result_json", None)
    t["result"] = json.loads(raw_res) if raw_res else None
    return t


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM device_tasks WHERE id = ?", (task_id,)).fetchone()
        return _row_to_task(row) if row else None
    finally:
        conn.close()


def get_pending_tasks_for_device(device_id: str, limit: int = 5) -> List[Dict[str, Any]]:
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                rows = conn.execute("""
                    SELECT * FROM device_tasks
                    WHERE device_id = ? AND status = 'queued'
                    ORDER BY created_at ASC LIMIT ?
                """, (device_id, limit)).fetchall()
                task_ids = [r["id"] for r in rows]
                if task_ids:
                    placeholders = ",".join(["?"] * len(task_ids))
                    conn.execute(f"""
                        UPDATE device_tasks SET status = 'dispatched'
                        WHERE id IN ({placeholders})
                    """, task_ids)
                return [_row_to_task(r) for r in rows]
        finally:
            conn.close()


def update_task_result(task_id: str, device_id: str, status: str, result: Dict[str, Any]) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                cur = conn.execute("""
                    UPDATE device_tasks
                    SET status = ?, result_json = ?, completed_at = ?
                    WHERE id = ? AND device_id = ?
                """, (status, json.dumps(result), now, task_id, device_id))
                return cur.rowcount > 0
        finally:
            conn.close()


def list_tasks_for_device(device_id: str, limit: int = 25) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM device_tasks
            WHERE device_id = ?
            ORDER BY created_at DESC LIMIT ?
        """, (device_id, limit)).fetchall()
        return [_row_to_task(r) for r in rows]
    finally:
        conn.close()


# --- Device Events & Audit ---

def record_device_event(device_id: str, event_type: str, payload: Dict[str, Any], task_id: Optional[str] = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                cur = conn.execute("""
                    INSERT INTO device_events (device_id, task_id, timestamp, event_type, payload_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (device_id, task_id, now, event_type, json.dumps(payload)))
                return cur.lastrowid
        finally:
            conn.close()


def get_device_events(device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM device_events
            WHERE device_id = ?
            ORDER BY id DESC LIMIT ?
        """, (device_id, limit)).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["payload"] = json.loads(item.pop("payload_json", "{}"))
            result.append(item)
        return result
    finally:
        conn.close()


# --- Pairing Rate Limiting ---

def check_pairing_rate_limit(ip_address: str, max_attempts: int = 6, window_seconds: int = 60) -> bool:
    """Enforces rate limiting on device pairing to prevent brute-forcing pairing codes."""
    now = time.time()
    cutoff = now - window_seconds
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                # Purge old records
                conn.execute("DELETE FROM pairing_rate_limits WHERE attempt_time < ?", (cutoff,))
                count = conn.execute(
                    "SELECT COUNT(*) as c FROM pairing_rate_limits WHERE ip_address = ? AND attempt_time >= ?",
                    (ip_address, cutoff)
                ).fetchone()["c"]
                if count >= max_attempts:
                    return False
                conn.execute(
                    "INSERT INTO pairing_rate_limits (ip_address, attempt_time) VALUES (?, ?)",
                    (ip_address, now)
                )
                return True
        finally:
            conn.close()
