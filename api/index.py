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


def _resolve_api_path(raw_path: str, headers) -> str:
    """Recover the original /api/... path across Vercel rewrite variants."""
    # Explicit rewrite query: /api/index.py?__path=/api/auth/verify
    parsed = urlparse(raw_path)
    qs = parse_qs(parsed.query)
    if "__path" in qs and qs["__path"]:
        return qs["__path"][0]

    for header in (
        "x-forwarded-uri",
        "x-invoke-path",
        "x-vercel-original-path",
        "x-matched-path",
    ):
        val = headers.get(header)
        if val and "/api/" in val:
            only = urlparse(val).path
            if only.startswith("/api/"):
                return only

    path = parsed.path or raw_path
    # Strip Vercel function filename if present
    if path.endswith("/index.py"):
        path = path[: -len("/index.py")] or "/api"
    if path.endswith("/index"):
        path = path[: -len("/index")] or "/api"
    if path.startswith("/api/") or path == "/api":
        return path
    # Bare leftover segment e.g. /auth/verify
    if not path.startswith("/api"):
        return "/api" + (path if path.startswith("/") else "/" + path)
    return path


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
