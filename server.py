"""
Local development server for the Pulse Control Panel.
Loads .env from this folder, then serves public/ + API on PORT (default 3000).
"""
from __future__ import annotations

import http.server
import os
import socketserver
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
API_DIR = BASE_DIR / "api"
# Prefer editable frontend/ sources locally; public/ is the Vercel build output
FRONTEND_DIR = BASE_DIR / "frontend"
PUBLIC_DIR = BASE_DIR / "public"
STATIC_DIR = FRONTEND_DIR if (FRONTEND_DIR / "index.html").exists() else PUBLIC_DIR
DOWNLOADS_DIR = PUBLIC_DIR / "downloads"

# Load local .env if present
env_path = BASE_DIR / ".env"
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val

sys.path.insert(0, str(API_DIR))
from handler import handle_request  # noqa: E402

PORT = int(os.environ.get("PORT", "3000"))


class ControlPanelHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt, *args):
        print(f"  [{self.address_string()}] {fmt % args}")

    def _api(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        status, headers, resp = handle_request(
            method=self.command,
            path=self.path,
            headers=dict(self.headers),
            body=body,
            client_address=self.client_address[0],
        )
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp)

    def do_OPTIONS(self):
        if urlparse(self.path).path.startswith("/api/"):
            self._api()
            return
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._api()
            return
        # Local release binaries live under public/downloads even when UI is served from frontend/
        if path.startswith("/downloads/"):
            name = path[len("/downloads/"):]
            if name and "/" not in name and "\\" not in name:
                target = DOWNLOADS_DIR / name
                if target.exists() and target.is_file():
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(target.stat().st_size))
                    self.end_headers()
                    with open(target, "rb") as f:
                        self.wfile.write(f.read())
                    return
            self.send_error(404)
            return
        super().do_GET()

    def do_POST(self):
        if urlparse(self.path).path.startswith("/api/"):
            self._api()
            return
        self.send_error(404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    # Local cookies work over http
    os.environ.setdefault("COOKIE_SECURE", "false")

    user = os.environ.get("ADMIN_USERNAME", "")
    mode = "supabase" if os.environ.get("SUPABASE_URL") else "local-json"
    print("=" * 60)
    print("  PULSE OPTIMIZER — CONTROL PANEL (LOCAL)")
    print("=" * 60)
    print(f"  Dashboard :  http://localhost:{PORT}")
    print(f"  Health    :  http://localhost:{PORT}/api/health")
    print(f"  Backend   :  {mode}")
    print(f"  Admin user configured: {'yes' if user else 'NO — set ADMIN_USERNAME in .env'}")
    print("=" * 60)
    server = ThreadedHTTPServer(("0.0.0.0", PORT), ControlPanelHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
        server.server_close()
