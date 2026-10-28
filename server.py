"""Local web server for the instrument panel. Listens on 127.0.0.1 only."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB = Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "web"


class Handler(BaseHTTPRequestHandler):
    engine = None

    def log_message(self, *_a) -> None:  # keep the console quiet
        pass

    def _host_ok(self) -> bool:
        # Blocks DNS-rebinding: only answer requests addressed to localhost.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ("127.0.0.1", "localhost")

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._send(403, b"{}")
        if self.path in ("/", "/index.html"):
            return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            return self._send(200, json.dumps(self.engine.snapshot()).encode())
        self._send(404, b"{}")

    def do_POST(self) -> None:
        # The custom header can't be sent cross-site without a CORS preflight,
        # which we never approve, so other websites can't press our buttons.
        if not self._host_ok() or self.headers.get("X-Oistins") != "1":
            return self._send(403, b"{}")
        n = min(int(self.headers.get("Content-Length") or 0), 10_000)
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            data = {}
        e = self.engine
        actions = {
            "/api/ack": lambda: e.ack(data.get("key")),
            "/api/trust": lambda: e.trust_port(int(data["port"])),
            "/api/speedtest": e.wake_speed.set,
            "/api/retrace": e.wake_trace.set,
            "/api/recheck": e.wake_sec.set,
            "/api/rebaseline": e.rebaseline,
        }
        fn = actions.get(self.path)
        if not fn:
            return self._send(404, b"{}")
        try:
            fn()
        except (KeyError, ValueError, TypeError):
            return self._send(400, b'{"ok":false}')
        self._send(200, b'{"ok":true}')


def serve(engine, port: int) -> ThreadingHTTPServer:
    Handler.engine = engine
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    return httpd
