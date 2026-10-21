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
                    CREATE TABLE IF NOT EXISTS live_events (
                        id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        device_name TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        target TEXT NOT NULL,
                        command_json TEXT NOT NULL,
                        pid INTEGER,
                        ppid INTEGER,
                        exit_code INTEGER,
                        duration_ms REAL,
                        stdout TEXT,
                        stderr TEXT,
                        policy_decision_json TEXT,
                        risk_classification TEXT,
                        delivery_status TEXT NOT NULL DEFAULT 'delivered',
                        is_live INTEGER NOT NULL DEFAULT 1,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS command_requests (
                        id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        command_json TEXT NOT NULL,
                        working_dir TEXT NOT NULL DEFAULT '',
                        requested_privileges TEXT NOT NULL DEFAULT 'user',
                        reason TEXT NOT NULL DEFAULT '',
                        mode TEXT NOT NULL DEFAULT 'enforce',
                        local_consent_required INTEGER NOT NULL DEFAULT 1,
                        web_approval_required INTEGER NOT NULL DEFAULT 0,
                        local_consent_status TEXT NOT NULL DEFAULT 'pending',
                        web_approval_status TEXT NOT NULL DEFAULT 'approved',
                        status TEXT NOT NULL DEFAULT 'pending',
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        completed_at TEXT,
                        result_json TEXT,
                        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
                conn.execute("CREATE INDEX IF NOT EXISTS idx_live_events_device ON live_events(device_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_live_events_timestamp ON live_events(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_live_events_type ON live_events(event_type);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cmd_req_device ON command_requests(device_id, status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cmd_req_status ON command_requests(status);")
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


def list_all_devices() -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM devices ORDER BY created_at DESC").fetchall()
        return [_row_to_device(r) for r in rows]
    finally:
        conn.close()


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


def list_all_tasks(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM device_tasks
            ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
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


# --- Live Telemetry & Event Persistence ---

def record_live_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Persists a live telemetry event from a local terminal hook, agent, or tracer."""
    import uuid
    event_id = str(event.get("id") or f"evt_{uuid.uuid4().hex[:12]}")
    now = datetime.now(timezone.utc).isoformat()
    ts = str(event.get("timestamp") or now)
    device_id = str(event.get("device_id") or "laptop_terminal")
    device_name = str(event.get("device_name") or event.get("hostname") or "Local Terminal")
    event_type = str(event.get("event_type") or "local_shell_cmd")
    source = str(event.get("source") or "terminal_hook")
    target = str(event.get("target") or "")
    command = event.get("command") or []
    if isinstance(command, str):
        command = [command]
    if not target and command:
        target = Path(str(command[0])).name

    pid = event.get("pid")
    ppid = event.get("ppid")
    exit_code = event.get("exit_code")
    duration_ms = float(event.get("duration_ms") or 0.0)
    stdout = str(event.get("stdout") or "")
    stderr = str(event.get("stderr") or "")
    policy_dec = event.get("policy_decision") or event.get("decision") or {}
    risk_class = str(event.get("risk_classification") or policy_dec.get("action") or "UNKNOWN")
    delivery_status = str(event.get("delivery_status") or "delivered")
    is_live = 1 if event.get("is_live", True) else 0

    record = {
        "id": event_id,
        "device_id": device_id,
        "device_name": device_name,
        "event_type": event_type,
        "source": source,
        "timestamp": ts,
        "target": target,
        "command": command,
        "pid": pid,
        "ppid": ppid,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "policy_decision": policy_dec,
        "risk_classification": risk_class,
        "delivery_status": delivery_status,
        "is_live": bool(is_live),
        "created_at": now,
    }

    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO live_events (
                        id, device_id, device_name, event_type, source, timestamp,
                        target, command_json, pid, ppid, exit_code, duration_ms,
                        stdout, stderr, policy_decision_json, risk_classification,
                        delivery_status, is_live, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id, device_id, device_name, event_type, source, ts,
                    target, json.dumps(command), pid, ppid, exit_code, duration_ms,
                    stdout, stderr, json.dumps(policy_dec), risk_class,
                    delivery_status, is_live, json.dumps(event), now
                ))
            return record
        finally:
            conn.close()


def list_live_events(
    device_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 50,
    since_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves live telemetry events in reverse chronological order."""
    conn = get_connection()
    try:
        query = "SELECT * FROM live_events WHERE 1=1"
        params: List[Any] = []
        if device_id and device_id != "all":
            query += " AND (device_id = ? OR device_name = ?)"
            params.extend([device_id, device_id])
        if event_type and event_type != "all":
            query += " AND event_type = ?"
            params.append(event_type)
        if since_id:
            query += " AND id != ?"
            params.append(since_id)

        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(limit, 200)))

        rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            item = dict(r)
            item["command"] = json.loads(item.pop("command_json", "[]"))
            item["policy_decision"] = json.loads(item.pop("policy_decision_json", "{}"))
            item["payload"] = json.loads(item.pop("payload_json", "{}"))
            item["is_live"] = bool(item.get("is_live", 1))
            results.append(item)
        return results
    finally:
        conn.close()


def get_live_event(event_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single live event by its unique ID."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM live_events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["command"] = json.loads(item.pop("command_json", "[]"))
        item["policy_decision"] = json.loads(item.pop("policy_decision_json", "{}"))
        item["payload"] = json.loads(item.pop("payload_json", "{}"))
        item["is_live"] = bool(item.get("is_live", 1))
        return item
    finally:
        conn.close()


# --- Consent-Gated Command Requests ---

def create_command_request(
    device_id: str,
    command: List[str],
    user_id: str = "usr_operator",
    working_dir: str = "",
    requested_privileges: str = "user",
    reason: str = "",
    mode: str = "enforce",
    local_consent_required: bool = True,
    web_approval_required: bool = False,
    expiry_seconds: int = 120
) -> Dict[str, Any]:
    """Creates a new structured command request requiring explicit local/web consent."""
    import uuid
    req_id = f"cmd_req_{uuid.uuid4().hex[:12]}"
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    expires_at = (now_dt + timedelta(seconds=expiry_seconds)).isoformat()

    web_status = "pending" if web_approval_required else "approved"
    local_status = "pending" if local_consent_required else "approved"
    overall_status = "pending"

    record = {
        "id": req_id,
        "device_id": device_id,
        "user_id": user_id,
        "command": command,
        "working_dir": working_dir,
        "requested_privileges": requested_privileges,
        "reason": reason,
        "mode": mode,
        "local_consent_required": local_consent_required,
        "web_approval_required": web_approval_required,
        "local_consent_status": local_status,
        "web_approval_status": web_status,
        "status": overall_status,
        "created_at": now,
        "expires_at": expires_at,
        "completed_at": None,
        "result": None,
    }

    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO command_requests (
                        id, device_id, user_id, command_json, working_dir,
                        requested_privileges, reason, mode, local_consent_required,
                        web_approval_required, local_consent_status, web_approval_status,
                        status, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    req_id, device_id, user_id, json.dumps(command), working_dir,
                    requested_privileges, reason, mode,
                    1 if local_consent_required else 0,
                    1 if web_approval_required else 0,
                    local_status, web_status, overall_status, now, expires_at
                ))
            return record
        finally:
            conn.close()


def get_command_request(request_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves command request details and checks for expiry."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM command_requests WHERE id = ?", (request_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["command"] = json.loads(item.pop("command_json", "[]"))
        item["result"] = json.loads(item.pop("result_json", "null")) if item.get("result_json") else None
        item["local_consent_required"] = bool(item.get("local_consent_required", 1))
        item["web_approval_required"] = bool(item.get("web_approval_required", 0))

        # Check if expired
        if item["status"] in ("pending", "approved") and item["expires_at"]:
            now = datetime.now(timezone.utc).isoformat()
            if now > item["expires_at"]:
                with _LOCK:
                    with conn:
                        conn.execute("UPDATE command_requests SET status = 'expired' WHERE id = ?", (request_id,))
                item["status"] = "expired"
        return item
    finally:
        conn.close()


def update_command_request_local_consent(
    request_id: str,
    consent: str,  # 'approved' or 'denied'
    local_user: str = "local_operator"
) -> Optional[Dict[str, Any]]:
    """Records local Linux operator consent decision."""
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                req = conn.execute("SELECT * FROM command_requests WHERE id = ?", (request_id,)).fetchone()
                if not req:
                    return None
                if req["status"] in ("completed", "failed", "denied", "expired"):
                    return None
                if now > req["expires_at"]:
                    conn.execute("UPDATE command_requests SET status = 'expired' WHERE id = ?", (request_id,))
                    return None

                new_local_status = "approved" if consent.lower() in ("approved", "yes", "grant") else "denied"
                if new_local_status == "denied":
                    new_status = "denied"
                else:
                    new_status = "approved" if req["web_approval_status"] == "approved" else "pending"

                conn.execute("""
                    UPDATE command_requests
                    SET local_consent_status = ?, status = ?
                    WHERE id = ?
                """, (new_local_status, new_status, request_id))
            return get_command_request(request_id)
        finally:
            conn.close()


def update_command_request_web_approval(
    request_id: str,
    approval: str  # 'approved' or 'denied'
) -> Optional[Dict[str, Any]]:
    """Records dashboard operator approval decision."""
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                req = conn.execute("SELECT * FROM command_requests WHERE id = ?", (request_id,)).fetchone()
                if not req:
                    return None
                if req["status"] in ("completed", "failed", "denied", "expired"):
                    return None
                if now > req["expires_at"]:
                    conn.execute("UPDATE command_requests SET status = 'expired' WHERE id = ?", (request_id,))
                    return None

                new_web_status = "approved" if approval.lower() in ("approved", "grant") else "denied"
                if new_web_status == "denied":
                    new_status = "denied"
                else:
                    new_status = "approved" if req["local_consent_status"] == "approved" else "pending"

                conn.execute("""
                    UPDATE command_requests
                    SET web_approval_status = ?, status = ?
                    WHERE id = ?
                """, (new_web_status, new_status, request_id))
            return get_command_request(request_id)
        finally:
            conn.close()


def update_command_request_result(
    request_id: str,
    result: Dict[str, Any],
    status: str = "completed"
) -> Optional[Dict[str, Any]]:
    """Records execution outcome for an approved command request."""
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    UPDATE command_requests
                    SET result_json = ?, status = ?, completed_at = ?
                    WHERE id = ?
                """, (json.dumps(result), status, now, request_id))
            return get_command_request(request_id)
        finally:
            conn.close()


def list_command_requests(
    device_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """Lists recent command requests."""
    conn = get_connection()
    try:
        query = "SELECT * FROM command_requests WHERE 1=1"
        params: List[Any] = []
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            item = dict(r)
            item["command"] = json.loads(item.pop("command_json", "[]"))
            item["result"] = json.loads(item.pop("result_json", "null")) if item.get("result_json") else None
            results.append(item)
        return results
    finally:
        conn.close()
