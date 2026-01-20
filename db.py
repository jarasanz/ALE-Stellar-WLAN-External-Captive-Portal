import os, sqlite3, time
import json
from typing import Optional
from typing import Any
from typing import List, Dict, Any

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db(db_path: str) -> None:
    conn = connect(db_path)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS allow_macs (
        mac TEXT PRIMARY KEY,
        added_ts INTEGER
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS mac_cache (
        mac TEXT PRIMARY KEY,
        expires_ts INTEGER
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER,
        source TEXT,
        type TEXT,
        mac TEXT,
        ip TEXT,
        detail TEXT
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS admin_settings (
        k TEXT PRIMARY KEY,
        v TEXT
      )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mac_roles (
            mac TEXT PRIMARY KEY,
            arp TEXT,
            updated_ts INTEGER
        )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS mac_roles (
        mac TEXT PRIMARY KEY,
        arp TEXT,
        updated_ts INTEGER
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS sessions (
        session_key TEXT PRIMARY KEY,      -- stable key for updates (acct_session_id preferred)
        acct_session_id TEXT,
        acct_multi_session_id TEXT,

        mac TEXT,
        calling_station_id TEXT,
        nas_ip TEXT,
        nas_id TEXT,
        src_ip TEXT,

        framed_ip TEXT,
        ap_mac TEXT,
        ssid TEXT,

        status TEXT,                        -- start | interim | stop
        start_ts INTEGER,
        last_seen_ts INTEGER,
        stop_ts INTEGER,

        raw_json TEXT
      )
    """)


    conn.commit()
    conn.close()

def get_setting(db_path: str, key: str, default: str = "") -> str:
    conn = connect(db_path)
    row = conn.execute("SELECT v FROM admin_settings WHERE k=?", (key,)).fetchone()
    conn.close()
    return (row[0] if row and row[0] is not None else default)


def set_setting(db_path: str, key: str, value: str) -> None:
    conn = connect(db_path)
    conn.execute(
        "INSERT INTO admin_settings(k,v) VALUES(?,?) "
        "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (key, value),
    )
    conn.commit()
    conn.close()

def now_ts() -> int:
    return int(time.time())

def normalize_mac_any(s: str) -> str:
    """
    Accepts many formats. Returns canonical uppercase no-delimiter format:
    AABBCCDDEEFF
    """
    if not s:
        return ""
    s = s.strip()
    # Keep only hex chars
    hex_only = "".join(ch for ch in s if ch.lower() in "0123456789abcdef")
    if len(hex_only) != 12:
        return ""
    return hex_only.upper()

def mac_to_portal_param(mac12: str) -> str:
    """
    Convert AABBCCDDEEFF to aa:bb:cc:dd:ee:ff (lowercase colon)
    """
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return ""
    parts = [mac12[i:i+2] for i in range(0, 12, 2)]
    return ":".join(p.lower() for p in parts)

def log_event(db_path: str, source: str, typ: str, mac: str = "", ip: str = "", detail: Any = None) -> None:
    """
    Store events.detail as JSON text.
    - If detail is a dict/list/etc -> json.dumps(detail)
    - If detail is a string -> store {"msg": "<string>"} for consistency
    """
    if detail is None:
        detail_obj = {}
    elif isinstance(detail, (dict, list, int, float, bool)):
        detail_obj = detail
    elif isinstance(detail, str):
        detail_obj = {"msg": detail}
    else:
        # fallback for unknown types
        detail_obj = {"repr": repr(detail)}

    conn = connect(db_path)
    conn.execute(
        "INSERT INTO events(ts,source,type,mac,ip,detail) VALUES (?,?,?,?,?,?)",
        (now_ts(), source, typ, mac, ip, json.dumps(detail_obj))
    )
    conn.commit()
    conn.close()

def is_allowed(db_path: str, mac12: str) -> bool:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return False
    now = now_ts()
    conn = connect(db_path)

    # Cache first
    row = conn.execute(
        "SELECT 1 FROM mac_cache WHERE mac=? AND expires_ts>?",
        (mac12, now)
    ).fetchone()
    if row:
        conn.close()
        return True

    # Allowlist
    row = conn.execute(
        "SELECT 1 FROM allow_macs WHERE mac=?",
        (mac12,)
    ).fetchone()
    if row:
        # refresh cache
        conn.execute(
            "INSERT INTO mac_cache(mac,expires_ts) VALUES(?,?) "
            "ON CONFLICT(mac) DO UPDATE SET expires_ts=excluded.expires_ts",
            (mac12, now + 6*3600)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

def allow_and_cache(db_path: str, mac12: str, cache_ttl: int) -> None:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return
    now = now_ts()
    conn = connect(db_path)
    conn.execute(
        "INSERT INTO allow_macs(mac,added_ts) VALUES(?,?) "
        "ON CONFLICT(mac) DO NOTHING",
        (mac12, now)
    )
    conn.execute(
        "INSERT INTO mac_cache(mac,expires_ts) VALUES(?,?) "
        "ON CONFLICT(mac) DO UPDATE SET expires_ts=excluded.expires_ts",
        (mac12, now + cache_ttl)
    )
    conn.commit()
    conn.close()

def allowed_decision(db_path: str, mac12: str, cache_ttl: int) -> str:
    """
    Returns:
      - "cache-hit" if MAC exists in mac_cache and not expired
      - "allowlist" if MAC exists in allow_macs (and refreshes cache)
      - "reject" otherwise
    """
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return "reject"

    now = now_ts()
    conn = connect(db_path)

    # 1) Cache first
    row = conn.execute(
        "SELECT 1 FROM mac_cache WHERE mac=? AND expires_ts>?",
        (mac12, now)
    ).fetchone()
    if row:
        conn.close()
        return "cache-hit"

    # 2) Allowlist second
    row = conn.execute(
        "SELECT 1 FROM allow_macs WHERE mac=?",
        (mac12,)
    ).fetchone()
    if row:
        # refresh cache using provided TTL (no hardcode)
        conn.execute(
            "INSERT INTO mac_cache(mac,expires_ts) VALUES(?,?) "
            "ON CONFLICT(mac) DO UPDATE SET expires_ts=excluded.expires_ts",
            (mac12, now + cache_ttl)
        )
        conn.commit()
        conn.close()
        return "allowlist"

    conn.close()
    return "reject"

def list_allow_macs(db_path: str, limit: int = 500) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT mac, added_ts FROM allow_macs ORDER BY added_ts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"mac": r[0], "added_ts": r[1]} for r in rows]

def list_cache(db_path: str, limit: int = 500) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT mac, expires_ts FROM mac_cache ORDER BY expires_ts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"mac": r[0], "expires_ts": r[1]} for r in rows]

def list_events(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT ts, source, type, mac, ip, detail FROM events ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [
        {"ts": r[0], "source": r[1], "type": r[2], "mac": r[3], "ip": r[4], "detail": r[5]}
        for r in rows
    ]

def delete_allow_mac(db_path: str, mac12: str) -> None:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return
    conn = connect(db_path)
    conn.execute("DELETE FROM allow_macs WHERE mac=?", (mac12,))
    conn.commit()
    conn.close()

def delete_cache_mac(db_path: str, mac12: str) -> None:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return
    conn = connect(db_path)
    conn.execute("DELETE FROM mac_cache WHERE mac=?", (mac12,))
    conn.commit()
    conn.close()

def clear_cache(db_path: str) -> None:
    conn = connect(db_path)
    conn.execute("DELETE FROM mac_cache")
    conn.commit()
    conn.close()

def clear_events(db_path: str) -> None:
    conn = connect(db_path)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()

def expire_cache_now(db_path: str) -> None:
    """
    Mark all cache entries as expired by setting expires_ts to (now - 1).
    Keeps rows for debugging/visibility.
    """
    conn = connect(db_path)
    conn.execute("UPDATE mac_cache SET expires_ts = ?", (now_ts() - 1,))
    conn.commit()
    conn.close()
    
def get_mac_role(db_path: str, mac12: str) -> str:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return ""
    conn = connect(db_path)
    row = conn.execute("SELECT arp FROM mac_roles WHERE mac=?", (mac12,)).fetchone()
    conn.close()
    return (row[0] or "") if row else ""

def set_mac_role(db_path: str, mac12: str, arp: str) -> None:
    mac12 = normalize_mac_any(mac12)
    arp = (arp or "").strip()
    if not mac12:
        return
    conn = connect(db_path)
    conn.execute(
        "INSERT INTO mac_roles(mac, arp, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET arp=excluded.arp, updated_ts=excluded.updated_ts",
        (mac12, arp, now_ts())
    )
    conn.commit()
    conn.close()

def get_mac_role(db_path: str, mac12: str) -> str:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return ""
    conn = connect(db_path)
    row = conn.execute("SELECT arp FROM mac_roles WHERE mac=?", (mac12,)).fetchone()
    conn.close()
    return (row[0] or "") if row else ""


def set_mac_role(db_path: str, mac12: str, arp: str) -> None:
    mac12 = normalize_mac_any(mac12)
    arp = (arp or "").strip()
    if not mac12:
        return
    conn = connect(db_path)
    conn.execute(
        "INSERT INTO mac_roles(mac, arp, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET arp=excluded.arp, updated_ts=excluded.updated_ts",
        (mac12, arp, now_ts()),
    )
    conn.commit()
    conn.close()

def list_mac_roles(db_path: str, limit: int = 500):
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT mac, arp, updated_ts FROM mac_roles ORDER BY updated_ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [{"mac": r[0], "arp": r[1], "updated_ts": r[2]} for r in rows]


def delete_mac_role(db_path: str, mac12: str) -> None:
    mac12 = normalize_mac_any(mac12)
    if not mac12:
        return
    conn = connect(db_path)
    conn.execute("DELETE FROM mac_roles WHERE mac=?", (mac12,))
    conn.commit()
    conn.close()

def upsert_session(
    db_path: str,
    session_key: str,
    acct_session_id: str = "",
    acct_multi_session_id: str = "",
    mac: str = "",
    calling_station_id: str = "",
    nas_ip: str = "",
    nas_id: str = "",
    src_ip: str = "",
    framed_ip: str = "",
    ap_mac: str = "",
    ssid: str = "",
    status: str = "",
    start_ts: int | None = None,
    stop_ts: int | None = None,
    raw: dict | None = None,
) -> None:
    session_key = (session_key or "").strip()
    if not session_key:
        return

    mac12 = normalize_mac_any(mac) or ""
    calling_norm = normalize_mac_any(calling_station_id) or calling_station_id
    now = now_ts()
    raw_json = json.dumps(raw or {}, ensure_ascii=False)

    conn = connect(db_path)
    conn.execute(
        """
        INSERT INTO sessions(
          session_key, acct_session_id, acct_multi_session_id,
          mac, calling_station_id, nas_ip, nas_id, src_ip,
          framed_ip, ap_mac, ssid,
          status, start_ts, last_seen_ts, stop_ts, raw_json
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(session_key) DO UPDATE SET
          acct_session_id=excluded.acct_session_id,
          acct_multi_session_id=excluded.acct_multi_session_id,
          mac=excluded.mac,
          calling_station_id=excluded.calling_station_id,
          nas_ip=excluded.nas_ip,
          nas_id=excluded.nas_id,
          src_ip=excluded.src_ip,
          framed_ip=excluded.framed_ip,
          ap_mac=excluded.ap_mac,
          ssid=excluded.ssid,
          status=excluded.status,
          start_ts=COALESCE(sessions.start_ts, excluded.start_ts),
          last_seen_ts=excluded.last_seen_ts,
          stop_ts=COALESCE(excluded.stop_ts, sessions.stop_ts),
          raw_json=excluded.raw_json
        """,
        (
            session_key,
            acct_session_id,
            acct_multi_session_id,
            mac12,
            calling_norm,
            nas_ip,
            nas_id,
            src_ip,
            framed_ip,
            ap_mac,
            ssid,
            status,
            start_ts,
            now,
            stop_ts,
            raw_json,
        ),
    )
    conn.commit()
    conn.close()

def list_sessions(db_path: str, limit: int = 50):
    conn = connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT session_key, acct_session_id, acct_multi_session_id,
               mac, calling_station_id, nas_ip, nas_id, src_ip,
               framed_ip, ap_mac, ssid,
               status, start_ts, last_seen_ts, stop_ts
        FROM sessions
        ORDER BY last_seen_ts DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows

def clear_sessions(db_path: str) -> None:
    conn = connect(db_path)
    conn.execute("DELETE FROM sessions")
    conn.commit()
    conn.close()


def prune_sessions(db_path: str, max_age_seconds: int = 24*3600) -> None:
    cutoff = now_ts() - max_age_seconds
    conn = connect(db_path)
    conn.execute(
        "DELETE FROM sessions WHERE last_seen_ts < ?",
        (cutoff,)
    )
    conn.commit()
    conn.close()

def get_session(db_path: str, session_key: str):
    conn = connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT session_key, acct_session_id, acct_multi_session_id,
               mac, calling_station_id, nas_ip, nas_id, src_ip,
               framed_ip, ap_mac, ssid,
               status, start_ts, last_seen_ts, stop_ts
        FROM sessions
        WHERE session_key = ?
        """,
        (session_key,),
    ).fetchone()
    conn.close()
    return row

def delete_session(db_path: str, session_key: str) -> None:
    session_key = (session_key or "").strip()
    if not session_key:
        return
    conn = connect(db_path)
    conn.execute("DELETE FROM sessions WHERE session_key = ?", (session_key,))
    conn.commit()
    conn.close()

def clear_stop_sessions(db_path: str) -> int:
    """
    Delete sessions that are in 'stop' status (and optionally those with stop_ts set).
    Returns number of rows deleted.
    """
    import sqlite3
    with sqlite3.connect(db_path) as con:
        cur = con.cursor()
        cur.execute("""
            DELETE FROM sessions
            WHERE status = 'stop'
               OR (stop_ts IS NOT NULL AND stop_ts > 0)
        """)
        con.commit()
        return cur.rowcount

