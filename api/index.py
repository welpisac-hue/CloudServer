"""
Vercel serverless entrypoint.
Routes: /api/* → this handler (see vercel.json).
"""
from http.server import BaseHTTPRequestHandler
import os
import sys
from urllib.parse import parse_qs, urlparse

SYS_DIR = os.path.dirname(os.path.abspath(__file__))
if SYS_DIR not in sys.path:
    sys.path.insert(0, SYS_DIR)

from handler import handle_request  # noqa: E402


def _is_entrypoint_path(path: str) -> bool:
    """True when path points at this serverless file, not a real API route."""
    p = (urlparse(path).path or path).rstrip("/")
    return p in ("/api", "/api/index", "/api/index.py") or p.endswith("/index.py")


def _usable_api_path(path: str) -> str | None:
    """Return a concrete /api/... route, or None if this is only the entrypoint."""
    if not path:
        return None
    only = urlparse(path).path or path
    if not only.startswith("/"):
        only = "/" + only
    if not only.startswith("/api"):
        only = "/api" + (only if only.startswith("/") else "/" + only)
    if _is_entrypoint_path(only):
        return None
    if only.startswith("/api/") or only == "/api":
        return only
    return None


def _resolve_api_path(raw_path: str, headers) -> str:
    """Recover the original /api/... path across Vercel rewrite variants."""
    # Explicit rewrite query: /api/index.py?__path=/api/auth/verify
    parsed = urlparse(raw_path)
    qs = parse_qs(parsed.query)

    def _with_remaining_query(api_path: str) -> str:
        extras = []
        for key, values in qs.items():
            if key == "__path":
                continue
            for value in values:
                extras.append(f"{key}={value}")
        if not extras:
            return api_path
        sep = "&" if "?" in api_path else "?"
        return api_path + sep + "&".join(extras)

    if "__path" in qs and qs["__path"]:
        recovered = _usable_api_path(qs["__path"][0])
        if recovered:
            return _with_remaining_query(recovered)

    # Prefer headers that carry the browser URL; skip ones that only name this file.
    for header in (
        "x-forwarded-uri",
        "x-url",
        "x-original-url",
        "x-vercel-original-path",
        "x-invoke-path",
        "x-matched-path",
    ):
        val = headers.get(header) or headers.get(header.title())
        if not val:
            continue
        recovered = _usable_api_path(val)
        if recovered:
            header_q = urlparse(val).query
            if header_q:
                return recovered + ("&" if "?" in recovered else "?") + header_q
            return _with_remaining_query(recovered)

    path = parsed.path or raw_path
    recovered = _usable_api_path(path)
    if recovered:
        return _with_remaining_query(recovered)

    # Last resort: bare leftover segment e.g. /auth/verify after strip
    if path.endswith("/index.py"):
        path = path[: -len("/index.py")] or "/api"
    if path.endswith("/index"):
        path = path[: -len("/index")] or "/api"
    recovered = _usable_api_path(path)
    if recovered:
        return _with_remaining_query(recovered)
    return _with_remaining_query("/api")


class handler(BaseHTTPRequestHandler):
    def _dispatch(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        path = _resolve_api_path(self.path, self.headers)

        status, headers_out, resp_body = handle_request(
            method=self.command,
            path=path,
            headers=dict(self.headers),
            body=body,
            client_address=self.client_address[0] if self.client_address else "0.0.0.0",
        )

        self.send_response(status)
        for k, v in headers_out.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_OPTIONS(self):
        self._dispatch()

    def log_message(self, fmt, *args):
        print(f"[vercel] {self.address_string()} {fmt % args}")
