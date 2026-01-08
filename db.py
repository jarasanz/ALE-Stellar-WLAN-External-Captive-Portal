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
