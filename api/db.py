"""
Supabase + local JSON persistence layer.
Uses Supabase when SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are set;
falls back to local JSON files for offline/localhost testing.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
UPLOADS_DIR = BASE_DIR / "public" / "downloads"
CONFIG_FILE = DATA_DIR / "config.json"
KEYS_FILE = DATA_DIR / "keys.json"
BANNED_FILE = DATA_DIR / "banned.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
LOGIN_ATTEMPTS_FILE = DATA_DIR / "login_attempts.json"

DEFAULT_CONFIG = {
    "version": "2.1.1",
    "download_url": "",
    "sha256": "",
    "release_date": "2026-09-17",
    "changelog": "- Pulse Optimizer v2.1.1\n- Auth polish, freeze lock fixes, and stability improvements",
    "maintenance_tweaks": [],
}

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def _supabase_configured() -> bool:
    return bool(os.environ.get("SUPABASE_URL", "").strip() and os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip())


def _sb_base() -> str:
    return os.environ["SUPABASE_URL"].rstrip("/")


def _sb_headers(prefer: str | None = None) -> dict:
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    h = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if prefer:
        h["Prefer"] = prefer
    return h


def _sb_request(
    method: str,
    path: str,
    body: Any = None,
    query: dict | None = None,
    prefer: str | None = None,
) -> Any:
    url = f"{_sb_base()}/rest/v1/{path.lstrip('/')}"
    if query:
        url += "?" + urllib.parse.urlencode(query, doseq=True)
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=_sb_headers(prefer))
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase {method} {path} failed ({e.code}): {err_body}") from e


def _sb_storage_upload(bucket: str, object_path: str, file_bytes: bytes, content_type: str) -> str:
    """Upload bytes to Supabase Storage and return a public URL."""
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    url = f"{_sb_base()}/storage/v1/object/{bucket}/{object_path}"
    req = urllib.request.Request(
        url,
        data=file_bytes,
        method="POST",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": content_type,
            "x-upsert": "true",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        # Retry as PUT for overwrite
        if e.code in (400, 409):
            req.get_method = lambda: "PUT"  # type: ignore
            req2 = urllib.request.Request(
                url,
                data=file_bytes,
                method="PUT",
                headers={
                    "apikey": key,
                    "Authorization": f"Bearer {key}",
                    "Content-Type": content_type,
                    "x-upsert": "true",
                },
            )
            with urllib.request.urlopen(req2, timeout=120) as resp:
                resp.read()
        else:
            raise RuntimeError(f"Storage upload failed ({e.code}): {e.read().decode('utf-8', errors='replace')}") from e

    return f"{_sb_base()}/storage/v1/object/public/{bucket}/{object_path}"


def _load_json(file_path: Path, default: Any) -> Any:
    if not file_path.exists():
        _save_json(file_path, default)
        return dict(default) if isinstance(default, dict) else list(default)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dict(default) if isinstance(default, dict) else list(default)


def _save_json(file_path: Path, data: Any) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if _supabase_configured():
        rows = _sb_request("GET", "app_config", query={"id": "eq.1", "select": "*"})
        if rows:
            row = rows[0]
            return {
                "version": row.get("version") or DEFAULT_CONFIG["version"],
                "download_url": row.get("download_url") or "",
                "sha256": row.get("sha256") or "",
                "release_date": row.get("release_date") or "",
                "changelog": row.get("changelog") or "",
                "maintenance_tweaks": row.get("maintenance_tweaks") or [],
            }
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    return _load_json(CONFIG_FILE, DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    if _supabase_configured():
        payload = {
            "id": 1,
            "version": cfg.get("version", ""),
            "download_url": cfg.get("download_url", ""),
            "sha256": cfg.get("sha256", ""),
            "release_date": cfg.get("release_date", ""),
            "changelog": cfg.get("changelog", ""),
            "maintenance_tweaks": cfg.get("maintenance_tweaks", []),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        _sb_request("POST", "app_config", body=payload, prefer="resolution=merge-duplicates,return=minimal")
        return
    _save_json(CONFIG_FILE, cfg)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def load_keys() -> dict:
    if _supabase_configured():
        rows = _sb_request("GET", "license_keys", query={"select": "*"}) or []
        out = {}
        for row in rows:
            key = row["key"]
            out[key] = {
                "key": key,
                "duration_days": row.get("duration_days", 0),
                "is_activated": bool(row.get("is_activated")),
                "activated_at": row.get("activated_at"),
                "expires_at": row.get("expires_at"),
                "is_frozen": bool(row.get("is_frozen")),
                "freeze_count": row.get("freeze_count", 0),
                "frozen_remaining_seconds": row.get("frozen_remaining_seconds", 0),
                "last_frozen_at": row.get("last_frozen_at"),
                "last_unfrozen_at": row.get("last_unfrozen_at"),
                "username": row.get("username") or "",
                "bound_hwid": row.get("bound_hwid") or "",
                "bound_serials": row.get("bound_serials") or [],
                "bound_ip": row.get("bound_ip") or "",
                "created_at": row.get("created_at") or "",
                "revoked": bool(row.get("revoked")),
            }
        return out
    return _load_json(KEYS_FILE, {})


def save_keys(keys: dict) -> None:
    if _supabase_configured():
        # Upsert all keys (admin ops are infrequent)
        existing = {r["key"] for r in (_sb_request("GET", "license_keys", query={"select": "key"}) or [])}
        current = set(keys.keys())
        for deleted in existing - current:
            _sb_request("DELETE", "license_keys", query={"key": f"eq.{deleted}"})
        for key, k in keys.items():
            payload = {
                "key": key,
                "duration_days": k.get("duration_days", 0),
                "is_activated": bool(k.get("is_activated")),
                "activated_at": k.get("activated_at"),
                "expires_at": k.get("expires_at"),
                "is_frozen": bool(k.get("is_frozen")),
                "freeze_count": k.get("freeze_count", 0),
                "frozen_remaining_seconds": k.get("frozen_remaining_seconds", 0),
                "last_frozen_at": k.get("last_frozen_at"),
                "last_unfrozen_at": k.get("last_unfrozen_at"),
                "username": k.get("username") or "",
                "bound_hwid": k.get("bound_hwid") or "",
                "bound_serials": k.get("bound_serials") or [],
                "bound_ip": k.get("bound_ip") or "",
                "created_at": k.get("created_at") or "",
                "revoked": bool(k.get("revoked")),
            }
            _sb_request("POST", "license_keys", body=payload, prefer="resolution=merge-duplicates,return=minimal")
        return
    _save_json(KEYS_FILE, keys)


def upsert_key(key_str: str, k: dict) -> None:
    keys = load_keys()
    keys[key_str] = k
    if _supabase_configured():
        payload = {
            "key": key_str,
            "duration_days": k.get("duration_days", 0),
            "is_activated": bool(k.get("is_activated")),
            "activated_at": k.get("activated_at"),
            "expires_at": k.get("expires_at"),
            "is_frozen": bool(k.get("is_frozen")),
            "freeze_count": k.get("freeze_count", 0),
            "frozen_remaining_seconds": k.get("frozen_remaining_seconds", 0),
            "last_frozen_at": k.get("last_frozen_at"),
            "last_unfrozen_at": k.get("last_unfrozen_at"),
            "username": k.get("username") or "",
            "bound_hwid": k.get("bound_hwid") or "",
            "bound_serials": k.get("bound_serials") or [],
            "bound_ip": k.get("bound_ip") or "",
            "created_at": k.get("created_at") or "",
            "revoked": bool(k.get("revoked")),
        }
        _sb_request("POST", "license_keys", body=payload, prefer="resolution=merge-duplicates,return=minimal")
        return
    _save_json(KEYS_FILE, keys)


def delete_key(key_str: str) -> bool:
    keys = load_keys()
    if key_str not in keys:
        return False
    del keys[key_str]
    if _supabase_configured():
        _sb_request("DELETE", "license_keys", query={"key": f"eq.{key_str}"})
        _sb_request("DELETE", "user_logs", query={"key": f"eq.{key_str}"})
        return True
    _save_json(KEYS_FILE, keys)
    log_file = LOGS_DIR / f"{key_str}.json"
    if log_file.exists():
        try:
            os.remove(log_file)
        except Exception:
            pass
    return True


# ---------------------------------------------------------------------------
# Banned
# ---------------------------------------------------------------------------

def load_banned() -> dict:
    if _supabase_configured():
        rows = _sb_request("GET", "banned", query={"id": "eq.1", "select": "*"})
        if rows:
            row = rows[0]
            return {
                "hwids": row.get("hwids") or [],
                "serials": row.get("serials") or [],
                "ips": row.get("ips") or [],
            }
        default = {"hwids": [], "serials": [], "ips": []}
        save_banned(default)
        return default
    return _load_json(BANNED_FILE, {"hwids": [], "serials": [], "ips": []})


def save_banned(banned: dict) -> None:
    if _supabase_configured():
        payload = {
            "id": 1,
            "hwids": banned.get("hwids", []),
            "serials": banned.get("serials", []),
            "ips": banned.get("ips", []),
        }
        _sb_request("POST", "banned", body=payload, prefer="resolution=merge-duplicates,return=minimal")
        return
    _save_json(BANNED_FILE, banned)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def load_sessions() -> dict:
    if _supabase_configured():
        rows = _sb_request("GET", "admin_sessions", query={"select": "*"}) or []
        out = {}
        for row in rows:
            out[row["token"]] = {
                "username": row.get("username", ""),
                "created_at": row.get("created_at", 0),
                "expires_at": row.get("expires_at", 0),
                "ip": row.get("ip", ""),
            }
        return out
    return _load_json(SESSIONS_FILE, {})


def save_sessions(sessions: dict) -> None:
    if _supabase_configured():
        existing = {r["token"] for r in (_sb_request("GET", "admin_sessions", query={"select": "token"}) or [])}
        current = set(sessions.keys())
        for deleted in existing - current:
            _sb_request("DELETE", "admin_sessions", query={"token": f"eq.{deleted}"})
        for token, s in sessions.items():
            payload = {
                "token": token,
                "username": s.get("username", ""),
                "created_at": s.get("created_at", 0),
                "expires_at": s.get("expires_at", 0),
                "ip": s.get("ip", ""),
            }
            _sb_request("POST", "admin_sessions", body=payload, prefer="resolution=merge-duplicates,return=minimal")
        return
    _save_json(SESSIONS_FILE, sessions)


def create_session(token: str, username: str, ip: str, ttl_seconds: int = 86400) -> None:
    now = time.time()
    entry = {
        "username": username,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "ip": ip,
    }
    if _supabase_configured():
        _sb_request(
            "POST",
            "admin_sessions",
            body={"token": token, **entry},
            prefer="resolution=merge-duplicates,return=minimal",
        )
        return
    sessions = load_sessions()
    sessions[token] = entry
    save_sessions(sessions)


def get_session(token: str) -> dict | None:
    if not token:
        return None
    if _supabase_configured():
        rows = _sb_request("GET", "admin_sessions", query={"token": f"eq.{token}", "select": "*"})
        if not rows:
            return None
        row = rows[0]
        return {
            "username": row.get("username", ""),
            "created_at": float(row.get("created_at") or 0),
            "expires_at": float(row.get("expires_at") or 0),
            "ip": row.get("ip", ""),
        }
    return load_sessions().get(token)


def delete_session(token: str) -> None:
    if not token:
        return
    if _supabase_configured():
        _sb_request("DELETE", "admin_sessions", query={"token": f"eq.{token}"})
        return
    sessions = load_sessions()
    if token in sessions:
        del sessions[token]
        save_sessions(sessions)


# ---------------------------------------------------------------------------
# Login attempts (rate limiting)
# ---------------------------------------------------------------------------

def load_login_attempts() -> dict:
    if _supabase_configured():
        rows = _sb_request("GET", "login_attempts", query={"select": "*"}) or []
        return {r["ip"]: {"fails": r.get("fails", 0), "locked_until": float(r.get("locked_until") or 0)} for r in rows}
    return _load_json(LOGIN_ATTEMPTS_FILE, {})


def save_login_attempt(ip: str, fails: int, locked_until: float) -> None:
    if _supabase_configured():
        _sb_request(
            "POST",
            "login_attempts",
            body={"ip": ip, "fails": fails, "locked_until": locked_until},
            prefer="resolution=merge-duplicates,return=minimal",
        )
        return
    data = load_login_attempts()
    data[ip] = {"fails": fails, "locked_until": locked_until}
    _save_json(LOGIN_ATTEMPTS_FILE, data)


def clear_login_attempt(ip: str) -> None:
    if _supabase_configured():
        _sb_request("DELETE", "login_attempts", query={"ip": f"eq.{ip}"})
        return
    data = load_login_attempts()
    if ip in data:
        del data[ip]
        _save_json(LOGIN_ATTEMPTS_FILE, data)


# ---------------------------------------------------------------------------
# User logs
# ---------------------------------------------------------------------------

def load_user_logs(key: str) -> list:
    if _supabase_configured():
        rows = _sb_request(
            "GET",
            "user_logs",
            query={"key": f"eq.{key}", "select": "*", "order": "created_at.asc"},
        ) or []
        return [
            {
                "timestamp": r.get("timestamp", ""),
                "username": r.get("username", ""),
                "action": r.get("action", ""),
                "details": r.get("details", ""),
            }
            for r in rows
        ]
    return _load_json(LOGS_DIR / f"{key}.json", [])


def append_user_log(key: str, entry: dict) -> None:
    if _supabase_configured():
        _sb_request(
            "POST",
            "user_logs",
            body={
                "key": key,
                "timestamp": entry.get("timestamp", ""),
                "username": entry.get("username", ""),
                "action": entry.get("action", ""),
                "details": entry.get("details", ""),
            },
            prefer="return=minimal",
        )
        return
    log_file = LOGS_DIR / f"{key}.json"
    logs = _load_json(log_file, [])
    logs.append(entry)
    _save_json(log_file, logs)


def count_releases() -> int:
    if _supabase_configured():
        cfg = load_config()
        return 1 if cfg.get("download_url") else 0
    return len(list(UPLOADS_DIR.glob("*.exe")))


def store_release_file(filename: str, file_data: bytes) -> str:
    """Store release binary; returns public download URL path or absolute URL."""
    if _supabase_configured():
        return _sb_storage_upload("releases", filename, file_data, "application/octet-stream")
    out_path = UPLOADS_DIR / filename
    with open(out_path, "wb") as f:
        f.write(file_data)
    return f"/downloads/{filename}"


def backend_mode() -> str:
    return "supabase" if _supabase_configured() else "local"
