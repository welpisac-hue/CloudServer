"""
Pulse Control Panel — request handler (shared by local server + Vercel).
Admin credentials come ONLY from environment variables.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from db import (
    append_release_history,
    append_user_log,
    backend_mode,
    clear_login_attempt,
    count_releases,
    create_session,
    create_signed_upload_url,
    delete_key,
    delete_session,
    get_release_by_version,
    get_session,
    get_storage_usage,
    list_release_history,
    load_banned,
    load_config,
    load_keys,
    load_login_attempts,
    load_user_logs,
    purge_old_releases,
    remove_release_from_history,
    save_banned,
    save_config,
    save_login_attempt,
    save_storage_settings,
    set_active_release,
    store_release_file,
    upsert_key,
)

# ---------------------------------------------------------------------------
# Security config from env (never hardcode credentials)
# ---------------------------------------------------------------------------

MAX_LOGIN_FAILURES = int(os.environ.get("MAX_LOGIN_FAILURES", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "900"))  # 15 min
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))  # 24h


def _admin_username() -> str:
    return os.environ.get("ADMIN_USERNAME", "").strip()


def _admin_password() -> str:
    return os.environ.get("ADMIN_PASSWORD", "").strip()


def _session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET", "").strip()
    if secret:
        return secret
    # On Vercel / production, refusing to mint a random secret per cold start
    # (that would invalidate every session).
    if os.environ.get("VERCEL") or os.environ.get("SUPABASE_URL"):
        raise RuntimeError("SESSION_SECRET environment variable is required in production")
    return secrets.token_hex(32)


def _allowed_ips() -> set[str]:
    raw = os.environ.get("ADMIN_IP_ALLOWLIST", "").strip()
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def _is_production() -> bool:
    return bool(os.environ.get("VERCEL") or os.environ.get("NODE_ENV") == "production")


def _safe_error(exc: Exception) -> str:
    """Never leak internals to clients in production."""
    if _is_production():
        return "Internal server error"
    return str(exc)


def _cors_headers(request_headers: dict) -> dict:
    """
    Credentialed CORS must never use *. Echo Origin only when allowlisted,
    or when CORS_ORIGIN is unset (same-origin / local reflect).
    """
    origin = (request_headers.get("Origin") or request_headers.get("origin") or "").strip()
    configured = os.environ.get("CORS_ORIGIN", "").strip()
    out: dict[str, str] = {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "600",
    }
    if not origin:
        return out

    if not configured or configured == "*":
        # Reflect request origin (needed for credentialed same-site tooling).
        # Prefer setting CORS_ORIGIN to your exact Vercel URL in production.
        out["Access-Control-Allow-Origin"] = origin
        out["Access-Control-Allow-Credentials"] = "true"
        out["Vary"] = "Origin"
        return out

    allowed = {o.strip() for o in configured.split(",") if o.strip()}
    if origin in allowed:
        out["Access-Control-Allow-Origin"] = origin
        out["Access-Control-Allow-Credentials"] = "true"
        out["Vary"] = "Origin"
    return out


PUBLIC_CONFIG_KEYS = (
    "version",
    "download_url",
    "sha256",
    "release_date",
    "changelog",
    "file_size",
    "mandatory",
    "maintenance_tweaks",
)


def _public_config(cfg: dict) -> dict:
    return {k: cfg.get(k) for k in PUBLIC_CONFIG_KEYS}


def get_freeze_limit(duration_days: int):
    if duration_days == 0:
        return 12, 7 * 86400
    if duration_days <= 1:
        return 1, 2 * 86400
    if duration_days <= 7:
        return 1, 3 * 86400
    if duration_days <= 30:
        return 2, 7 * 86400
    if duration_days <= 365:
        return 6, 14 * 86400
    return 99, 0


def parse_multipart(data: bytes, boundary: str):
    fields, files = {}, {}
    b = boundary.encode()
    parts = data.split(b"--" + b)
    for part in parts[1:]:
        if part.startswith(b"--") or part.strip() == b"":
            continue
        try:
            header_block, body = part.split(b"\r\n\r\n", 1)
        except ValueError:
            continue
        if body.endswith(b"\r\n"):
            body = body[:-2]
        headers = header_block.decode("utf-8", errors="replace")
        name_match = re.search(r'name="([^"]+)"', headers)
        filename_match = re.search(r'filename="([^"]+)"', headers)
        if not name_match:
            continue
        name = name_match.group(1)
        if filename_match:
            files[name] = {"filename": filename_match.group(1), "data": body}
        else:
            fields[name] = body.decode("utf-8", errors="replace")
    return fields, files


def _parse_cookies(cookie_header: str) -> dict:
    out = {}
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sanitize_changelog(text: str, max_len: int = 4000) -> str:
    """Normalize changelog for desktop clients: plain text, no emoji/markdown junk."""
    if not text:
        return ""
    s = str(text).replace("\r\n", "\n").replace("\r", "\n")
    # Drop emoji / dingbat ranges
    s = re.sub(r"[\U0001F300-\U0001FAFF]", "", s)
    s = re.sub(r"[\u2600-\u27BF]", "", s)
    # Markdown headings / emphasis
    s = re.sub(r"^#{1,6}\s*", "", s, flags=re.MULTILINE)
    s = re.sub(r"[*_`]+", "", s)
    # Fancy bullets / dashes / quotes
    s = re.sub(r"^[ \t]*[•●▪◦·]\s*", "- ", s, flags=re.MULTILINE)
    s = s.replace("–", "-").replace("—", "-")
    s = s.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    # Control chars except newline/tab
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len].rstrip() + "\n..."
    return s


def _client_ip(headers: dict, fallback: str = "") -> str:
    forwarded = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = headers.get("X-Real-IP") or headers.get("x-real-ip") or ""
    if real:
        return real.strip()
    return fallback or "0.0.0.0"


def _is_login_locked(ip: str) -> tuple[bool, int]:
    attempts = load_login_attempts()
    info = attempts.get(ip) or {}
    locked_until = float(info.get("locked_until") or 0)
    now = time.time()
    if locked_until > now:
        return True, int(locked_until - now)
    return False, 0


def _register_failed_login(ip: str) -> None:
    attempts = load_login_attempts()
    info = attempts.get(ip) or {"fails": 0, "locked_until": 0}
    fails = int(info.get("fails") or 0) + 1
    locked_until = 0.0
    if fails >= MAX_LOGIN_FAILURES:
        locked_until = time.time() + LOGIN_LOCKOUT_SECONDS
        fails = 0
    save_login_attempt(ip, fails, locked_until)


def _extract_session_token(headers: dict) -> str | None:
    cookies = _parse_cookies(headers.get("Cookie") or headers.get("cookie") or "")
    if cookies.get("admin_session"):
        return cookies["admin_session"]
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def is_authenticated(headers: dict) -> bool:
    token = _extract_session_token(headers)
    if not token:
        return False
    session = get_session(token)
    if not session:
        return False
    if time.time() > float(session.get("expires_at") or 0):
        delete_session(token)
        return False
    return True


def _json_response(
    data: Any,
    status: int = 200,
    extra_headers: dict | None = None,
    request_headers: dict | None = None,
) -> tuple[int, dict, bytes]:
    body = json.dumps(data).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body)),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }
    headers.update(_cors_headers(request_headers if request_headers is not None else _CURRENT_REQ_HEADERS))
    if extra_headers:
        headers.update(extra_headers)
    return status, headers, body


# Populated per-request in handle_request (used by _json_response CORS)
_CURRENT_REQ_HEADERS: dict = {}


def handle_request(
    method: str,
    path: str,
    headers: dict,
    body: bytes,
    client_address: str = "0.0.0.0",
) -> tuple[int, dict, bytes]:
    """Dispatch one HTTP request. Returns (status, headers, body_bytes)."""
    global _CURRENT_REQ_HEADERS
    method = method.upper()
    parsed = urlparse(path)
    route = parsed.path
    query = parse_qs(parsed.query)
    hdrs = {k: v for k, v in headers.items()}
    _CURRENT_REQ_HEADERS = hdrs
    ip = _client_ip(hdrs, client_address)

    if method == "OPTIONS":
        return _json_response({"ok": True})

    # Normalize path (Vercel sometimes prefixes)
    if route.startswith("/api/index"):
        route = "/api" + route[len("/api/index") :]
    if not route.startswith("/"):
        route = "/" + route

    try:
        if method == "GET":
            return _handle_get(route, query, hdrs, ip)
        if method == "POST":
            return _handle_post(route, hdrs, body, ip)
        return _json_response({"error": "Method not allowed"}, 405)
    except Exception as e:
        return _json_response({"error": _safe_error(e)}, 500)


def _require_admin(headers: dict, ip: str) -> tuple[int, dict, bytes] | None:
    allow = _allowed_ips()
    if allow and ip not in allow:
        return _json_response({"error": "Access denied"}, 403)
    if not is_authenticated(headers):
        return _json_response({"error": "Authentication required"}, 401)
    return None


def _handle_get(route: str, query: dict, headers: dict, ip: str) -> tuple[int, dict, bytes]:
    if route in ("/api/health", "/api/ping"):
        admin_ok = bool(_admin_username() and _admin_password())
        secret_ok = bool(os.environ.get("SESSION_SECRET", "").strip())
        return _json_response({
            "ok": True,
            "service": "pulse-control-panel",
            "backend": backend_mode(),
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "ready": {
                "admin_credentials": admin_ok,
                "session_secret": secret_ok,
                "supabase": backend_mode() == "supabase",
            },
        })

    if route == "/api/config":
        config = load_config()
        # Always serve a desktop-safe changelog (covers old messy releases too)
        if "changelog" in config:
            config = dict(config)
            config["changelog"] = sanitize_changelog(config.get("changelog", ""))
        return _json_response(_public_config(config))

    if route == "/api/admin/session":
        if is_authenticated(headers):
            return _json_response({"authenticated": True})
        return _json_response({"authenticated": False}, 401)

    if route == "/api/stats":
        denied = _require_admin(headers, ip)
        if denied:
            return denied
        config = load_config()
        keys = load_keys()
        banned = load_banned()
        return _json_response({
            "version": config.get("version", "1.0.0"),
            "release_date": config.get("release_date", ""),
            "maintenance_count": len(config.get("maintenance_tweaks", [])),
            "total_releases": count_releases(),
            "total_keys": len(keys),
            "active_users": sum(1 for k in keys.values() if k.get("is_activated") and not k.get("revoked")),
            "total_banned": len(banned.get("hwids", [])),
            "sha256": config.get("sha256", ""),
            "download_url": config.get("download_url", ""),
            "file_size": config.get("file_size", 0),
            "backend": backend_mode(),
            "storage": get_storage_usage(),
        })

    if route.startswith("/api/admin/"):
        denied = _require_admin(headers, ip)
        if denied:
            return denied

        if route == "/api/admin/keys":
            return _json_response(load_keys())

        if route == "/api/admin/users":
            keys = load_keys()
            users = [v for v in keys.values() if v.get("is_activated")]
            return _json_response(users)

        if route == "/api/admin/banned":
            return _json_response(load_banned())

        if route == "/api/admin/user-logs":
            key = (query.get("key") or [""])[0]
            return _json_response(load_user_logs(key))

        if route == "/api/admin/releases":
            config = load_config()
            history = list_release_history()
            # Soft-seed history from live config if the channel exists but history is empty
            if not history and config.get("download_url"):
                url = config.get("download_url", "")
                file_name = url.rsplit("/", 1)[-1] if url else ""
                history = [append_release_history({
                    "version": config.get("version", ""),
                    "download_url": url,
                    "sha256": config.get("sha256", ""),
                    "release_date": config.get("release_date", ""),
                    "changelog": config.get("changelog", ""),
                    "file_name": file_name,
                    "file_size": int(config.get("file_size") or 0),
                })]
                history = list_release_history()
            storage = get_storage_usage()
            return _json_response({
                "current": config,
                "releases": history,
                "storage": storage,
            })

        if route == "/api/admin/storage":
            return _json_response(get_storage_usage())

    return _json_response({"error": "Endpoint not found"}, 404)


def _handle_post(route: str, headers: dict, body: bytes, ip: str) -> tuple[int, dict, bytes]:
    # ---- Admin login ----
    if route == "/api/admin/login":
        try:
            data = json.loads(body or b"{}")
        except Exception:
            return _json_response({"error": "Invalid JSON"}, 400)

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        allow = _allowed_ips()
        if allow and ip not in allow:
            return _json_response({"error": "Access denied"}, 403)

        locked, rem = _is_login_locked(ip)
        if locked:
            return _json_response({
                "error": f"Too many failed attempts. Try again in {max(1, rem // 60)} minute(s).",
            }, 429)

        expected_user = _admin_username()
        expected_pass = _admin_password()
        if not expected_user or not expected_pass:
            return _json_response({"error": "Server credentials not configured"}, 500)

        # Constant-time compare for both fields to reduce timing leaks
        user_ok = _constant_time_eq(username, expected_user)
        pass_ok = _constant_time_eq(password, expected_pass)

        if not (user_ok and pass_ok):
            _register_failed_login(ip)
            # Uniform delay to slow brute force
            time.sleep(0.35 + secrets.randbelow(250) / 1000.0)
            return _json_response({"error": "Invalid credentials"}, 401)

        clear_login_attempt(ip)
        token = secrets.token_urlsafe(48)
        # Bind token integrity to session secret (detect tampering if stored oddly)
        _ = hmac.new(_session_secret().encode(), token.encode(), hashlib.sha256).hexdigest()
        create_session(token, username, ip, SESSION_TTL_SECONDS)

        secure = os.environ.get("COOKIE_SECURE", "true").lower() != "false"
        cookie = (
            f"admin_session={token}; HttpOnly; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
            f"SameSite=Strict{'; Secure' if secure else ''}"
        )
        return _json_response(
            {"success": True, "message": "Login successful"},
            200,
            {"Set-Cookie": cookie},
        )

    if route == "/api/admin/logout":
        token = _extract_session_token(headers)
        if token:
            delete_session(token)
        cookie = "admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
        return _json_response({"success": True}, 200, {"Set-Cookie": cookie})

    # ---- Public client auth APIs ----
    if route == "/api/auth/check-ban":
        try:
            data = json.loads(body or b"{}")
            hwid = data.get("hwid", "")
            serials = data.get("serials", []) or []
            banned = load_banned()
            is_banned = False
            reason = "Your device or IP has been banned by administrators."
            if hwid and hwid in banned.get("hwids", []):
                is_banned = True
            if ip and ip in banned.get("ips", []):
                is_banned = True
            for s in serials:
                if s and s in banned.get("serials", []):
                    is_banned = True
                    break
            return _json_response({"banned": is_banned, "reason": reason if is_banned else ""})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/auth/verify":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            hwid = data.get("hwid", "")
            serials = data.get("serials", []) or []

            banned = load_banned()
            if hwid in banned.get("hwids", []) or ip in banned.get("ips", []):
                return _json_response({"valid": False, "status": "BANNED", "error": "Device or IP is banned."}, 403)

            keys = load_keys()
            if key_str not in keys:
                return _json_response({"valid": False, "status": "INVALID_KEY", "error": "Invalid Product Key."}, 400)

            k = keys[key_str]
            if k.get("revoked"):
                return _json_response({"valid": False, "status": "REVOKED", "error": "Product Key has been revoked."}, 403)

            now = time.time()
            if not k.get("is_activated"):
                k["is_activated"] = True
                k["activated_at"] = now
                k["expires_at"] = (now + k["duration_days"] * 86400) if k.get("duration_days", 0) > 0 else 0
                k["bound_hwid"] = hwid
                k["bound_serials"] = serials
                k["bound_ip"] = ip
                upsert_key(key_str, k)

            if k.get("bound_hwid") and k["bound_hwid"] != hwid:
                return _json_response({
                    "valid": False,
                    "status": "HWID_MISMATCH",
                    "error": "Key is locked to another PC hardware profile.",
                }, 403)

            if k.get("is_frozen"):
                status = "FROZEN"
            elif k.get("duration_days", 0) > 0 and now > k.get("expires_at", 0):
                return _json_response({
                    "valid": False,
                    "status": "EXPIRED",
                    "error": "Product Key subscription has expired.",
                }, 403)
            else:
                status = "ACTIVE"

            rem_seconds = 0
            if k.get("duration_days", 0) > 0:
                if k.get("is_frozen"):
                    rem_seconds = k.get("frozen_remaining_seconds", 0)
                else:
                    rem_seconds = max(0, int(k.get("expires_at", 0) - now))

            max_freezes, _cooldown = get_freeze_limit(k.get("duration_days", 0))
            expires_iso = (
                datetime.datetime.fromtimestamp(k.get("expires_at", 0)).strftime("%Y-%m-%d %H:%M")
                if k.get("expires_at")
                else "Lifetime"
            )
            return _json_response({
                "valid": True,
                "status": status,
                "key": key_str,
                "username": k.get("username", ""),
                "is_frozen": k.get("is_frozen", False),
                "remaining_seconds": rem_seconds,
                "duration_days": k.get("duration_days", 0),
                "freeze_count": k.get("freeze_count", 0),
                "max_freezes": max_freezes,
                "bound_hwid": k.get("bound_hwid", ""),
                "expires_at_iso": expires_iso,
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/user/set-username":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            username = str(data.get("username", "")).strip()
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            k["username"] = username
            upsert_key(key_str, k)
            return _json_response({"success": True, "username": username})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/user/freeze-key":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            freeze = bool(data.get("freeze", True))
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            now = time.time()
            dur = k.get("duration_days", 0)
            max_freezes, cooldown = get_freeze_limit(dur)

            if freeze:
                if k.get("is_frozen"):
                    return _json_response({"error": "Key is already frozen."}, 400)
                if k.get("freeze_count", 0) >= max_freezes:
                    return _json_response({"error": f"Maximum freeze quota ({max_freezes}) reached for your key tier."}, 400)
                if k.get("last_unfrozen_at") and (now - k["last_unfrozen_at"]) < cooldown:
                    rem_cd = int(cooldown - (now - k["last_unfrozen_at"]))
                    hours = rem_cd // 3600
                    return _json_response({"error": f"Freeze on cooldown. Please wait {hours} hours before freezing again."}, 400)
                k["is_frozen"] = True
                k["frozen_remaining_seconds"] = max(0, int(k.get("expires_at", 0) - now))
                k["freeze_count"] = k.get("freeze_count", 0) + 1
                k["last_frozen_at"] = now
                upsert_key(key_str, k)
                return _json_response({
                    "success": True,
                    "is_frozen": True,
                    "remaining_seconds": k["frozen_remaining_seconds"],
                    "freeze_count": k["freeze_count"],
                })

            if not k.get("is_frozen"):
                return _json_response({"error": "Key is not frozen."}, 400)
            k["is_frozen"] = False
            k["expires_at"] = now + k.get("frozen_remaining_seconds", 0)
            k["last_unfrozen_at"] = now
            remaining = max(0, int(k["expires_at"] - now))
            upsert_key(key_str, k)
            return _json_response({
                "success": True,
                "is_frozen": False,
                "remaining_seconds": remaining,
                "freeze_count": k.get("freeze_count", 0),
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/user/log":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            if not key_str:
                return _json_response({"error": "Missing key"}, 400)
            append_user_log(key_str, {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": data.get("username", "Anonymous"),
                "action": data.get("action", ""),
                "details": data.get("details", ""),
            })
            return _json_response({"success": True})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    # ---- Admin-only below ----
    if route.startswith("/api/admin/") or route in ("/api/maintenance", "/api/save-config", "/api/publish-update"):
        denied = _require_admin(headers, ip)
        if denied:
            return denied

    if route == "/api/admin/rollback":
        try:
            data = json.loads(body or b"{}")
            version = str(data.get("version", "")).strip()
            if not version:
                return _json_response({"error": "version is required"}, 400)
            entry = get_release_by_version(version)
            if not entry:
                return _json_response({"error": f"No release found for v{version}"}, 404)
            if not entry.get("download_url"):
                return _json_response({"error": "Release has no download URL — cannot roll back"}, 400)

            config = load_config()
            config["version"] = entry.get("version", version)
            config["download_url"] = entry.get("download_url", "")
            config["sha256"] = entry.get("sha256", "")
            config["changelog"] = sanitize_changelog(entry.get("changelog", ""))
            config["release_date"] = entry.get("release_date") or datetime.date.today().isoformat()
            config["file_size"] = int(entry.get("file_size") or 0)
            config["mandatory"] = True
            save_config(config)
            set_active_release(version)
            storage = get_storage_usage()
            return _json_response({
                "success": True,
                "config": config,
                "rolled_back_to": version,
                "releases": list_release_history(),
                "storage": storage,
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/delete-release":
        try:
            data = json.loads(body or b"{}")
            version = str(data.get("version", "")).strip()
            if not version:
                return _json_response({"error": "version is required"}, 400)
            cfg = load_config()
            if cfg.get("version") == version:
                return _json_response({"error": "Cannot delete the currently live version. Rollback first."}, 400)
            ok = remove_release_from_history(version)
            if not ok:
                return _json_response({"error": "Could not delete release (missing or still active)"}, 400)
            return _json_response({
                "success": True,
                "deleted": version,
                "releases": list_release_history(),
                "storage": get_storage_usage(),
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/purge-releases":
        try:
            data = json.loads(body or b"{}")
            keep = int(data.get("keep", 3))
            result = purge_old_releases(keep=keep)
            return _json_response({
                "success": True,
                **result,
                "releases": list_release_history(),
                "storage": get_storage_usage(),
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/storage-settings":
        try:
            data = json.loads(body or b"{}")
            saved = save_storage_settings(data if isinstance(data, dict) else {})
            return _json_response({
                "success": True,
                "settings": {
                    "soft_cap_mb": round(saved["soft_cap_bytes"] / (1024 * 1024), 1),
                    "warn_mb": round(saved["warn_bytes"] / (1024 * 1024), 1),
                    "crit_mb": round(saved["crit_bytes"] / (1024 * 1024), 1),
                    "warn_count": saved["warn_count"],
                    "crit_count": saved["crit_count"],
                },
                "storage": get_storage_usage(),
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/generate-key":
        try:
            data = json.loads(body or b"{}")
            days = int(data.get("duration_days", 30))
            rand_part = hashlib.sha256(os.urandom(32)).hexdigest().upper()
            new_key = f"PULSE-{rand_part[:4]}-{rand_part[4:8]}-{rand_part[8:12]}"
            record = {
                "key": new_key,
                "duration_days": days,
                "is_activated": False,
                "activated_at": None,
                "expires_at": None,
                "is_frozen": False,
                "freeze_count": 0,
                "username": "",
                "bound_hwid": "",
                "bound_serials": [],
                "bound_ip": "",
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "revoked": False,
            }
            upsert_key(new_key, record)
            return _json_response({"success": True, "key": record})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/add-time":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            add_days = int(data.get("days", 30))
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            if k.get("is_activated") and k.get("expires_at"):
                if k.get("is_frozen"):
                    k["frozen_remaining_seconds"] = int(k.get("frozen_remaining_seconds", 0)) + add_days * 86400
                else:
                    k["expires_at"] += add_days * 86400
            k["duration_days"] = int(k.get("duration_days", 0)) + add_days
            upsert_key(key_str, k)
            return _json_response({"success": True, "key": k})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/freeze-key":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            freeze = bool(data.get("freeze", True))
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            now = time.time()
            if freeze and not k.get("is_frozen"):
                k["is_frozen"] = True
                k["frozen_remaining_seconds"] = max(0, int(k.get("expires_at", now) - now))
            elif not freeze and k.get("is_frozen"):
                k["is_frozen"] = False
                k["expires_at"] = now + k.get("frozen_remaining_seconds", 0)
            upsert_key(key_str, k)
            return _json_response({"success": True, "key": k})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/revoke-key":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            k["revoked"] = True
            upsert_key(key_str, k)
            return _json_response({"success": True, "key": k})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/delete-key":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            if not delete_key(key_str):
                return _json_response({"error": "Key not found"}, 404)
            return _json_response({"success": True})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/reset-freezes":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            keys = load_keys()
            if key_str not in keys:
                return _json_response({"error": "Key not found"}, 404)
            k = keys[key_str]
            if k.get("is_frozen"):
                now = time.time()
                k["is_frozen"] = False
                k["expires_at"] = now + k.get("frozen_remaining_seconds", 0)
                k["frozen_remaining_seconds"] = 0
            k["freeze_count"] = 0
            k["last_freeze_time"] = 0
            k["last_unfrozen_at"] = 0
            k["last_frozen_at"] = 0
            upsert_key(key_str, k)
            return _json_response({"success": True, "key": k})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/ban-user":
        try:
            data = json.loads(body or b"{}")
            key_str = str(data.get("key", "")).strip().upper()
            hwid = data.get("hwid", "")
            ban_ip = data.get("ip", "")
            banned = load_banned()
            if hwid and hwid not in banned["hwids"]:
                banned["hwids"].append(hwid)
            if ban_ip and ban_ip not in banned["ips"]:
                banned["ips"].append(ban_ip)
            save_banned(banned)
            keys = load_keys()
            if key_str in keys:
                k = keys[key_str]
                k["revoked"] = True
                upsert_key(key_str, k)
            return _json_response({"success": True, "banned": banned})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/maintenance":
        try:
            data = json.loads(body or b"{}")
            config = load_config()
            if "maintenance_tweaks" in data and isinstance(data["maintenance_tweaks"], list):
                config["maintenance_tweaks"] = [int(x) for x in data["maintenance_tweaks"]]
                save_config(config)
                return _json_response({"success": True, "maintenance_tweaks": config["maintenance_tweaks"]})
            return _json_response({"error": "Expected maintenance_tweaks array"}, 400)
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/save-config":
        try:
            data = json.loads(body or b"{}")
            save_config(data)
            return _json_response({"success": True, "config": data})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/admin/prepare-upload":
        """Return a signed Supabase upload URL so large .exe files bypass Vercel body limits."""
        try:
            data = json.loads(body or b"{}")
            version = str(data.get("version", "")).strip()
            if not version:
                return _json_response({"error": "version is required"}, 400)
            if not re.match(r"^[0-9]+(\.[0-9]+){1,3}[a-zA-Z0-9_-]*$", version):
                return _json_response({"error": "Invalid version format"}, 400)
            out_name = f"PulseOptimizer_v{version}.exe"
            if backend_mode() != "supabase":
                return _json_response({
                    "success": True,
                    "mode": "local",
                    "file_name": out_name,
                    "message": "Local mode — use multipart /api/publish-update",
                })
            signed = create_signed_upload_url(out_name)
            return _json_response({"success": True, "mode": "supabase", **signed})
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    if route == "/api/publish-update":
        try:
            ct = headers.get("Content-Type") or headers.get("content-type") or ""

            # ---- Path A: JSON finalize after direct-to-Supabase upload ----
            if "application/json" in ct:
                data = json.loads(body or b"{}")
                version = str(data.get("version", "")).strip()
                if not version:
                    return _json_response({"error": "version is required"}, 400)
                changelog = sanitize_changelog(str(data.get("changelog", "- Performance update")))
                if not changelog:
                    changelog = "- Performance update"
                mandatory = str(data.get("mandatory", "true")).strip().lower() in ("1", "true", "yes", "on")
                sha256_hash = str(data.get("sha256", "")).strip().lower()
                if not re.match(r"^[a-f0-9]{64}$", sha256_hash):
                    return _json_response({"error": "Valid sha256 (64 hex chars) is required"}, 400)
                file_size = int(data.get("file_size") or 0)
                out_name = str(data.get("file_name") or f"PulseOptimizer_v{version}.exe").strip()
                if "/" in out_name or "\\" in out_name or ".." in out_name:
                    return _json_response({"error": "Invalid file_name"}, 400)
                download_url = str(data.get("download_url") or "").strip()
                if not download_url:
                    return _json_response({"error": "download_url is required for JSON publish"}, 400)
                if not download_url.startswith("https://"):
                    return _json_response({"error": "download_url must be https"}, 400)
                if backend_mode() == "supabase":
                    allowed_prefix = os.environ.get("SUPABASE_URL", "").rstrip("/") + "/storage/"
                    if allowed_prefix.startswith("https://") and not download_url.startswith(allowed_prefix):
                        return _json_response({"error": "download_url must point at this project's storage"}, 400)

                storage = get_storage_usage()
                if storage.get("level") == "critical":
                    projected = storage["total_bytes"] + max(0, file_size)
                    if projected > storage["soft_cap_bytes"]:
                        return _json_response({
                            "error": (
                                "Release storage is full. Purge old builds before publishing. "
                                + (storage.get("message") or "")
                            ),
                            "storage": storage,
                        }, 507)

                release_date = datetime.date.today().isoformat()
                config = load_config()
                config["version"] = version
                config["changelog"] = changelog
                config["download_url"] = download_url
                config["sha256"] = sha256_hash
                config["release_date"] = release_date
                config["file_size"] = file_size
                config["mandatory"] = mandatory
                save_config(config)

                history_entry = append_release_history({
                    "version": version,
                    "download_url": download_url,
                    "sha256": sha256_hash,
                    "release_date": release_date,
                    "changelog": changelog,
                    "file_name": out_name,
                    "file_size": file_size,
                })
                return _json_response({
                    "success": True,
                    "config": config,
                    "release": history_entry,
                    "releases": list_release_history(),
                    "storage": get_storage_usage(),
                })

            # ---- Path B: classic multipart (local / small files) ----
            if "multipart/form-data" not in ct:
                return _json_response({
                    "error": "Content-Type must be multipart/form-data or application/json",
                }, 400)
            m = re.search(r"boundary=([^\s;]+)", ct)
            if not m:
                return _json_response({"error": "Missing multipart boundary"}, 400)
            boundary = m.group(1).strip('"')
            fields, files = parse_multipart(body, boundary)
            if "file" not in files:
                return _json_response({"error": "No file field in upload"}, 400)
            file_data = files["file"]["data"]
            if len(file_data) == 0:
                return _json_response({"error": "Uploaded file is empty"}, 400)

            storage = get_storage_usage()
            if storage.get("level") == "critical":
                projected = storage["total_bytes"] + len(file_data)
                if projected > storage["soft_cap_bytes"]:
                    return _json_response({
                        "error": (
                            "Release storage is full. Purge old builds before publishing. "
                            + (storage.get("message") or "")
                        ),
                        "storage": storage,
                    }, 507)

            sha256_hash = hashlib.sha256(file_data).hexdigest()
            version = fields.get("version", "1.0.0").strip()
            changelog = sanitize_changelog(fields.get("changelog", "- Performance update"))
            if not changelog:
                changelog = "- Performance update"
            mandatory_raw = fields.get("mandatory", "true").strip().lower()
            mandatory = mandatory_raw in ("1", "true", "yes", "on")
            out_name = f"PulseOptimizer_v{version}.exe"
            download_url = store_release_file(out_name, file_data)
            release_date = datetime.date.today().isoformat()
            file_size = len(file_data)

            config = load_config()
            config["version"] = version
            config["changelog"] = changelog
            config["download_url"] = download_url
            config["sha256"] = sha256_hash
            config["release_date"] = release_date
            config["file_size"] = file_size
            config["mandatory"] = mandatory
            save_config(config)

            history_entry = append_release_history({
                "version": version,
                "download_url": download_url,
                "sha256": sha256_hash,
                "release_date": release_date,
                "changelog": changelog,
                "file_name": out_name,
                "file_size": file_size,
            })

            return _json_response({
                "success": True,
                "config": config,
                "release": history_entry,
                "releases": list_release_history(),
                "storage": get_storage_usage(),
            })
        except Exception as e:
            return _json_response({"error": _safe_error(e)}, 500)

    return _json_response({"error": "Endpoint not found"}, 404)
