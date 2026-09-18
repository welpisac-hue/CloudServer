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
RELEASES_FILE = DATA_DIR / "releases.json"
STORAGE_SETTINGS_FILE = DATA_DIR / "storage_settings.json"

# Soft storage limits — defaults; overridable via UI (persisted) or env
_DEFAULT_STORAGE_SETTINGS = {
    "soft_cap_bytes": int(os.environ.get("STORAGE_SOFT_CAP_BYTES", str(500 * 1024 * 1024))),
    "warn_bytes": int(os.environ.get("STORAGE_WARN_BYTES", str(400 * 1024 * 1024))),
    "crit_bytes": int(os.environ.get("STORAGE_CRIT_BYTES", str(480 * 1024 * 1024))),
    "warn_count": int(os.environ.get("STORAGE_WARN_COUNT", "8")),
    "crit_count": int(os.environ.get("STORAGE_CRIT_COUNT", "12")),
}

DEFAULT_CONFIG = {
    "version": "1.0.0",
    "download_url": "",
    "sha256": "",
    "release_date": "",
    "changelog": "- Pulse Hardware Suite v1.0.0\n- Initial public release",
    "maintenance_tweaks": [],
    "file_size": 0,
    "mandatory": True,
}

def _ensure_local_dirs() -> None:
    """Create local data folders when the filesystem is writable.

    On Vercel the deploy tree is read-only (only /tmp is writable). Eager
    mkdir at import previously crashed the whole serverless function with
    FUNCTION_INVOCATION_FAILED. Production persistence must use Supabase.
    """
    if os.environ.get("VERCEL"):
        return
    for path in (DATA_DIR, LOGS_DIR, UPLOADS_DIR):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


_ensure_local_dirs()


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

    return public_release_url(object_path)


def public_release_url(object_path: str) -> str:
    """Canonical public URL for a releases-bucket object."""
    return f"{_sb_base()}/storage/v1/object/public/releases/{object_path.lstrip('/')}"


def create_signed_upload_url(filename: str) -> dict:
    """
    Create a short-lived signed upload URL so the browser can PUT the .exe
    straight to Supabase (bypasses Vercel request body size limits).
    """
    if not _supabase_configured():
        raise RuntimeError("Signed uploads require Supabase")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in (filename or "").strip())
    if not safe or ".." in safe:
        raise RuntimeError("Invalid filename")
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    url = f"{_sb_base()}/storage/v1/object/upload/sign/releases/{safe}"
    req = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Signed upload URL failed ({e.code}): {err}") from e

    signed_path = data.get("url") or data.get("Url") or ""
    token = data.get("token") or data.get("Token") or ""
    if not signed_path:
        raise RuntimeError(f"Signed upload response missing url: {data}")

    if signed_path.startswith("http"):
        upload_url = signed_path
    else:
        upload_url = f"{_sb_base()}/storage/v1{signed_path if signed_path.startswith('/') else '/' + signed_path}"
    if token and "token=" not in upload_url:
        sep = "&" if "?" in upload_url else "?"
        upload_url = f"{upload_url}{sep}token={token}"

    return {
        "file_name": safe,
        "upload_url": upload_url,
        "public_url": public_release_url(safe),
        "token": token,
    }


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
                "file_size": int(row.get("file_size") or 0),
                "mandatory": bool(row.get("mandatory") if row.get("mandatory") is not None else True),
            }
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    cfg = _load_json(CONFIG_FILE, DEFAULT_CONFIG)
    cfg.setdefault("file_size", 0)
    cfg.setdefault("mandatory", True)
    return cfg


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
            "file_size": int(cfg.get("file_size") or 0),
            "mandatory": bool(cfg.get("mandatory", True)),
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


def _sb_storage_list(bucket: str, prefix: str = "") -> list[dict]:
    """List objects in a Supabase Storage bucket."""
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    url = f"{_sb_base()}/storage/v1/object/list/{bucket}"
    body = json.dumps({"prefix": prefix, "limit": 200, "offset": 0}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            if not raw:
                return []
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, list) else []
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Storage list failed ({e.code}): {err}") from e


def _sb_storage_delete(bucket: str, paths: list[str]) -> None:
    if not paths:
        return
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    url = f"{_sb_base()}/storage/v1/object/{bucket}"
    body = json.dumps({"prefixes": paths}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="DELETE",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Storage delete failed ({e.code}): {err}") from e


def list_release_history() -> list[dict]:
    """Newest-first release history entries."""
    if _supabase_configured():
        try:
            rows = _sb_request(
                "GET",
                "release_history",
                query={"select": "*", "order": "created_at.desc"},
            ) or []
            return [
                {
                    "id": r.get("id"),
                    "version": r.get("version", ""),
                    "download_url": r.get("download_url", ""),
                    "sha256": r.get("sha256", ""),
                    "release_date": r.get("release_date", ""),
                    "changelog": r.get("changelog", ""),
                    "file_name": r.get("file_name", ""),
                    "file_size": int(r.get("file_size") or 0),
                    "is_active": bool(r.get("is_active")),
                    "created_at": r.get("created_at", ""),
                }
                for r in rows
            ]
        except RuntimeError:
            # Table may not exist yet — fall through to empty
            return []
    entries = _load_json(RELEASES_FILE, [])
    if not isinstance(entries, list):
        entries = []
    return sorted(entries, key=lambda e: e.get("created_at", ""), reverse=True)


def append_release_history(entry: dict) -> dict:
    """Record a published build and mark it active."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = {
        "version": entry.get("version", ""),
        "download_url": entry.get("download_url", ""),
        "sha256": entry.get("sha256", ""),
        "release_date": entry.get("release_date", ""),
        "changelog": entry.get("changelog", ""),
        "file_name": entry.get("file_name", ""),
        "file_size": int(entry.get("file_size") or 0),
        "is_active": True,
        "created_at": now,
    }
    if _supabase_configured():
        try:
            # Clear prior active flags
            _sb_request(
                "PATCH",
                "release_history",
                body={"is_active": False},
                query={"is_active": "eq.true"},
                prefer="return=minimal",
            )
        except RuntimeError:
            pass
        try:
            rows = _sb_request(
                "POST",
                "release_history",
                body=record,
                prefer="return=representation",
            )
            if isinstance(rows, list) and rows:
                record["id"] = rows[0].get("id")
        except RuntimeError as e:
            raise RuntimeError(
                f"Could not write release_history (run supabase/schema.sql): {e}"
            ) from e
        return record

    entries = _load_json(RELEASES_FILE, [])
    if not isinstance(entries, list):
        entries = []
    for e in entries:
        e["is_active"] = False
    record["id"] = int(time.time() * 1000)
    entries.append(record)
    _save_json(RELEASES_FILE, entries)
    return record


def get_release_by_version(version: str) -> dict | None:
    version = (version or "").strip()
    for entry in list_release_history():
        if entry.get("version") == version:
            return entry
    return None


def set_active_release(version: str) -> dict | None:
    """Mark a historical release as active (used by rollback)."""
    target = get_release_by_version(version)
    if not target:
        return None
    if _supabase_configured():
        try:
            _sb_request(
                "PATCH",
                "release_history",
                body={"is_active": False},
                query={"is_active": "eq.true"},
                prefer="return=minimal",
            )
            _sb_request(
                "PATCH",
                "release_history",
                body={"is_active": True},
                query={"version": f"eq.{version}"},
                prefer="return=minimal",
            )
        except RuntimeError:
            pass
        return target
    entries = _load_json(RELEASES_FILE, [])
    for e in entries:
        e["is_active"] = e.get("version") == version
    _save_json(RELEASES_FILE, entries)
    return target


def delete_release_binary(file_name: str) -> bool:
    """Delete a stored binary from local downloads or Supabase Storage."""
    file_name = (file_name or "").strip()
    if not file_name or "/" in file_name or "\\" in file_name:
        return False
    if _supabase_configured():
        try:
            _sb_storage_delete("releases", [file_name])
            return True
        except RuntimeError:
            return False
    path = UPLOADS_DIR / file_name
    if path.exists():
        path.unlink()
        return True
    return False


def remove_release_from_history(version: str) -> bool:
    version = (version or "").strip()
    if not version:
        return False
    entry = get_release_by_version(version)
    if not entry:
        return False
    if entry.get("is_active"):
        return False  # never delete the live channel build via this path
    if entry.get("file_name"):
        delete_release_binary(entry["file_name"])
    if _supabase_configured():
        try:
            _sb_request(
                "DELETE",
                "release_history",
                query={"version": f"eq.{version}"},
                prefer="return=minimal",
            )
            return True
        except RuntimeError:
            return False
    entries = [e for e in _load_json(RELEASES_FILE, []) if e.get("version") != version]
    _save_json(RELEASES_FILE, entries)
    return True


def purge_old_releases(keep: int = 3) -> dict:
    """Keep the newest `keep` builds; delete older inactive binaries."""
    keep = max(1, int(keep))
    history = list_release_history()
    kept = history[:keep]
    removed = []
    for entry in history[keep:]:
        if entry.get("is_active"):
            continue
        ver = entry.get("version", "")
        if remove_release_from_history(ver):
            removed.append(ver)
    return {"kept": [e.get("version") for e in kept], "removed": removed}


def load_storage_settings() -> dict:
    """Bucket capacity / warn thresholds (MB-editable in the panel)."""
    if _supabase_configured():
        try:
            rows = _sb_request("GET", "panel_settings", query={"id": "eq.1", "select": "*"}) or []
            if rows:
                row = rows[0]
                raw = {
                    "soft_cap_bytes": int(row.get("soft_cap_bytes") or _DEFAULT_STORAGE_SETTINGS["soft_cap_bytes"]),
                    "warn_bytes": int(row.get("warn_bytes") or _DEFAULT_STORAGE_SETTINGS["warn_bytes"]),
                    "crit_bytes": int(row.get("crit_bytes") or _DEFAULT_STORAGE_SETTINGS["crit_bytes"]),
                    "warn_count": int(row.get("warn_count") or _DEFAULT_STORAGE_SETTINGS["warn_count"]),
                    "crit_count": int(row.get("crit_count") or _DEFAULT_STORAGE_SETTINGS["crit_count"]),
                }
            else:
                raw = dict(_DEFAULT_STORAGE_SETTINGS)
        except RuntimeError:
            raw = dict(_DEFAULT_STORAGE_SETTINGS)
    else:
        raw = _load_json(STORAGE_SETTINGS_FILE, dict(_DEFAULT_STORAGE_SETTINGS))
    if not isinstance(raw, dict):
        raw = dict(_DEFAULT_STORAGE_SETTINGS)
    out = dict(_DEFAULT_STORAGE_SETTINGS)
    for key in ("soft_cap_bytes", "warn_bytes", "crit_bytes", "warn_count", "crit_count"):
        if key in raw:
            try:
                out[key] = int(raw[key])
            except (TypeError, ValueError):
                pass
    # Keep thresholds sane relative to each other
    if out["soft_cap_bytes"] < 1024 * 1024:
        out["soft_cap_bytes"] = 1024 * 1024
    if out["warn_bytes"] > out["soft_cap_bytes"]:
        out["warn_bytes"] = max(1024 * 1024, int(out["soft_cap_bytes"] * 0.8))
    if out["crit_bytes"] > out["soft_cap_bytes"]:
        out["crit_bytes"] = max(out["warn_bytes"], int(out["soft_cap_bytes"] * 0.95))
    if out["crit_bytes"] < out["warn_bytes"]:
        out["crit_bytes"] = out["warn_bytes"]
    if out["warn_count"] < 1:
        out["warn_count"] = 1
    if out["crit_count"] < out["warn_count"]:
        out["crit_count"] = out["warn_count"]
    return out


def save_storage_settings(settings: dict) -> dict:
    """Persist editable bucket capacity settings and return normalized values."""
    current = load_storage_settings()

    def _as_bytes(value, fallback):
        if value is None:
            return fallback
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return fallback

    # Accept either bytes or megabytes from the UI
    if "soft_cap_mb" in settings:
        soft = max(1, int(float(settings["soft_cap_mb"]))) * 1024 * 1024
    else:
        soft = _as_bytes(settings.get("soft_cap_bytes"), current["soft_cap_bytes"])

    if "warn_mb" in settings:
        warn = max(1, int(float(settings["warn_mb"]))) * 1024 * 1024
    else:
        warn = _as_bytes(settings.get("warn_bytes"), current["warn_bytes"])

    if "crit_mb" in settings:
        crit = max(1, int(float(settings["crit_mb"]))) * 1024 * 1024
    else:
        crit = _as_bytes(settings.get("crit_bytes"), current["crit_bytes"])

    warn_count = _as_bytes(settings.get("warn_count"), current["warn_count"])
    crit_count = _as_bytes(settings.get("crit_count"), current["crit_count"])

    payload = {
        "soft_cap_bytes": soft,
        "warn_bytes": warn,
        "crit_bytes": crit,
        "warn_count": warn_count,
        "crit_count": crit_count,
    }

    if _supabase_configured():
        try:
            _sb_request(
                "POST",
                "panel_settings",
                body={
                    "id": 1,
                    **payload,
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                prefer="resolution=merge-duplicates,return=minimal",
            )
        except RuntimeError:
            # Table may not exist yet — still return normalized local values
            pass
    else:
        _save_json(STORAGE_SETTINGS_FILE, payload)
    return load_storage_settings()


def get_storage_usage() -> dict:
    """Aggregate release-bucket size and emit warn/critical flags."""
    files: list[dict] = []
    total_bytes = 0
    limits = load_storage_settings()

    if _supabase_configured():
        try:
            objects = _sb_storage_list("releases")
            for obj in objects:
                name = obj.get("name") or ""
                if not name or name.endswith("/"):
                    continue
                meta = obj.get("metadata") or {}
                size = int(meta.get("size") or obj.get("size") or 0)
                files.append({
                    "name": name,
                    "size": size,
                    "updated_at": obj.get("updated_at") or obj.get("created_at") or "",
                })
                total_bytes += size
        except RuntimeError:
            # Fall back to history sizes if storage list fails
            for entry in list_release_history():
                size = int(entry.get("file_size") or 0)
                files.append({
                    "name": entry.get("file_name") or entry.get("version", "unknown"),
                    "size": size,
                    "updated_at": entry.get("created_at", ""),
                })
                total_bytes += size
    else:
        for path in sorted(UPLOADS_DIR.glob("*.exe")):
            size = path.stat().st_size
            files.append({
                "name": path.name,
                "size": size,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)),
            })
            total_bytes += size

    file_count = len(files)
    soft_cap = limits["soft_cap_bytes"]
    warn_bytes = limits["warn_bytes"]
    crit_bytes = limits["crit_bytes"]
    warn_count = limits["warn_count"]
    crit_count = limits["crit_count"]
    pct = (total_bytes / soft_cap * 100.0) if soft_cap > 0 else 0.0

    level = "ok"
    message = ""
    if total_bytes >= crit_bytes or file_count >= crit_count:
        level = "critical"
        message = (
            f"Release storage is nearly full ({_fmt_bytes(total_bytes)} / {_fmt_bytes(soft_cap)}, "
            f"{file_count} builds). Purge old versions soon or uploads will fail."
        )
    elif total_bytes >= warn_bytes or file_count >= warn_count:
        level = "warning"
        message = (
            f"Release storage is filling up ({_fmt_bytes(total_bytes)} / {_fmt_bytes(soft_cap)}, "
            f"{file_count} builds). Clear old versions when you can."
        )

    return {
        "backend": backend_mode(),
        "total_bytes": total_bytes,
        "total_human": _fmt_bytes(total_bytes),
        "soft_cap_bytes": soft_cap,
        "soft_cap_human": _fmt_bytes(soft_cap),
        "soft_cap_mb": round(soft_cap / (1024 * 1024), 1),
        "warn_mb": round(warn_bytes / (1024 * 1024), 1),
        "crit_mb": round(crit_bytes / (1024 * 1024), 1),
        "percent_used": round(pct, 1),
        "file_count": file_count,
        "warn_bytes": warn_bytes,
        "crit_bytes": crit_bytes,
        "warn_count": warn_count,
        "crit_count": crit_count,
        "level": level,
        "message": message,
        "files": sorted(files, key=lambda f: f.get("size", 0), reverse=True),
        "settings": {
            "soft_cap_mb": round(soft_cap / (1024 * 1024), 1),
            "warn_mb": round(warn_bytes / (1024 * 1024), 1),
            "crit_mb": round(crit_bytes / (1024 * 1024), 1),
            "warn_count": warn_count,
            "crit_count": crit_count,
        },
    }


def _fmt_bytes(n: int) -> str:
    n = float(max(0, int(n or 0)))
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0 or unit == "GB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def count_releases() -> int:
    history = list_release_history()
    if history:
        return len(history)
    usage = get_storage_usage()
    if usage["file_count"]:
        return usage["file_count"]
    cfg = load_config()
    return 1 if cfg.get("download_url") else 0


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
