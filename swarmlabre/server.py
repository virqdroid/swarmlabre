"""`swarmlabre serve`: the web UI and the /api/swarm/* routes, on the standard library's http.server.

Four jobs: serve the page, check the bearer token, cap and parse JSON bodies, gzip big text. The routes themselves live in
`Swarms.api` (live) or `player.Replay.api` (a recorded run); this file only dispatches to a *backend* that has the same methods:

    api(h, method, parts, u, body)   stage_put(h, u, n)   clip_frame(h, rid, n)

`h` is the request handler: `reply(code, obj, ctype)`, `send_response/send_header/end_headers/wfile`, `rfile`, `headers`, `close_connection`.

Rules: the JSON body is capped at 1 MiB; the two raw-body routes (the sample upload and a clip frame) are routed *before* any JSON parse and keep their own
caps; a polled route never does slow work inline; text over 1400 bytes is gzipped.
"""
import gzip
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, config

MAX_JSON_BODY = 1 << 20
GZIP_OVER = 1400
UI_DIR = Path(__file__).resolve().parent.parent / "ui"
FONTS = {"geist.woff2", "geistmono.woff2"}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self' data: blob:; media-src blob:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


def load_token(state_dir):
    """The bearer token of this install: <state>/token (mode 0600), created on first use."""
    state_dir = Path(state_dir)
    config.make_private_dir(state_dir)
    p = state_dir / "token"
    try:
        t = p.read_text().strip()
        if TOKEN_RE.fullmatch(t):
            return t
    except OSError:
        pass
    t = secrets.token_urlsafe(24)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(t + "\n")
    return t


class App:
    """What a request needs: the backend, the token, how the page should present itself."""

    def __init__(self, backend, token, mode="live", why="", bind_host="127.0.0.1", extra=None):
        self.backend, self.token, self.mode, self.why, self.bind_host = backend, token, mode, why, bind_host
        self.extra = extra or {}

    def mode_view(self):
        return {"mode": self.mode, "why": self.why, "version": __version__, **self.extra}


class Handler(BaseHTTPRequestHandler):
    server_version = "swarmlabre"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    app = None                     # set on the subclass made by make_server

    def log_message(self, fmt, *args):
        pass                       # no access log: the paths of a run id are not secret, but a log line is one more place for a token to leak

    # ---- reply
    def reply(self, code, obj, ctype=None):
        """obj: dict/list -> JSON; str/bytes -> the text with `ctype`."""
        if isinstance(obj, (dict, list)) or obj is None:
            data, ctype = json.dumps(obj, separators=(",", ":")).encode(), "application/json"
        else:
            data = obj.encode() if isinstance(obj, str) else obj
            ctype = ctype or "text/plain; charset=utf-8"
        head = [("Content-Type", ctype), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]
        textual = ctype.startswith("text/") or "json" in ctype or "svg" in ctype or "javascript" in ctype
        if textual and len(data) > GZIP_OVER and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            data = gzip.compress(data, 5, mtime=0)
            head.append(("Content-Encoding", "gzip"))
        head += [("Vary", "Accept-Encoding"), ("Content-Length", str(len(data)))]
        self.send_response(code)
        for k, v in head:
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def fail(self, code, msg, close=False):
        self.close_connection = close or self.close_connection
        return self.reply(code, {"error": msg})

    # ---- guards
    def host_ok(self):
        """DNS-rebinding guard: on a loopback bind the Host header must name loopback."""
        if self.app.bind_host not in LOOPBACK:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        name = host[: host.rindex("]") + 1] if host.startswith("[") else host.partition(":")[0]
        return name in LOOPBACK

    def authed(self):
        got = (self.headers.get("Authorization") or "")
        got = got[7:] if got[:7].lower() == "bearer " else ""
        return bool(got) and hmac.compare_digest(got.encode(), self.app.token.encode())

    def json_body(self):
        """-> dict, or None after sending the error. Cap 1 MiB; a bad body closes the connection (the rest of it must not be read as a request)."""
        n = self.headers.get("Content-Length")
        if n is None:
            return {}
        try:
            n = int(n)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_JSON_BODY:
            self.fail(413, "The request body is too large.", close=True)
            return None
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return {}
        try:
            body = json.loads(raw)
        except ValueError:
            self.fail(400, "The request body is not JSON.")
            return None
        if not isinstance(body, dict):
            self.fail(400, "The request body must be a JSON object.")
            return None
        return body

    # ---- routes
    def do_HEAD(self):
        self.route("GET")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        try:
            self.dispatch(method)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:                                    # never leak a traceback or a path to the client
            self.close_connection = True
            try:
                print("server error: %s: %s" % (type(e).__name__, str(e)[:200]), file=sys.stderr)
                self.reply(500, {"error": "Something went wrong in swarmlabre."})
            except OSError:
                pass

    def dispatch(self, method):
        u = urlparse(self.path)
        path = u.path
        if not self.host_ok():
            return self.fail(421, "Unexpected Host header.", close=True)
        if method == "GET" and path in ("/", "/index.html"):
            return self.page()
        if method == "GET" and path.startswith("/fonts/") and path[7:] in FONTS:
            return self.font(path[7:])
        if method == "GET" and path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not path.startswith("/api/"):
            return self.fail(404, "Not found.")
        if not self.authed():
            return self.fail(401, "Bearer token needed.", close=method == "POST")
        parts = [p for p in path[5:].split("/") if p]
        if parts == ["mode"] and method == "GET":
            return self.reply(200, self.app.mode_view())
        if parts == ["replay"] and hasattr(self.app.backend, "control"):          # the replay clock: speed, pause, restart, skip to the end
            if method == "GET":
                return self.reply(200, self.app.backend.state())
            body = self.json_body()
            if body is not None:
                code, out = self.app.backend.control(body)
                return self.reply(code, out)
            return
        if not parts or parts[0] != "swarm":
            return self.fail(404, "Unknown route.")
        rest, be = parts[1:], self.app.backend
        # raw-body routes first: they read the body themselves, with their own caps, so the JSON cap and parse must not touch them
        if method == "POST" and rest == ["stage"]:
            n = self.headers.get("Content-Length")
            return be.stage_put(self, u, int(n) if n and n.isdigit() else -1)
        if method == "POST" and len(rest) == 3 and rest[1:] == ["clip", "frame"]:
            n = self.headers.get("Content-Length")
            return be.clip_frame(self, rest[0], int(n) if n and n.isdigit() else -1)
        body = self.json_body() if method == "POST" else {}
        if body is None:
            return
        return be.api(self, method, rest, u, body)

    def page(self):
        try:
            raw = (UI_DIR / "swarms.html").read_bytes()               # re-read on every request: a UI edit needs no restart
        except OSError:
            return self.fail(500, "ui/swarms.html is missing.")
        extra = [("Content-Security-Policy", CSP), ("X-Frame-Options", "DENY")]
        if len(raw) > GZIP_OVER and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            raw = gzip.compress(raw, 5, mtime=0)
            extra.append(("Content-Encoding", "gzip"))
        self.send_response(200)
        for k, v in [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                     ("Vary", "Accept-Encoding"), ("Content-Length", str(len(raw)))] + extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def font(self, name):
        try:
            raw = (UI_DIR / "fonts" / name).read_bytes()
        except OSError:
            return self.fail(404, "Not found.")
        self.send_response(200)
        for k, v in (("Content-Type", "font/woff2"), ("Cache-Control", "public, max-age=86400"), ("X-Content-Type-Options", "nosniff"), ("Content-Length", str(len(raw)))):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


def make_server(app, host="127.0.0.1", port=8810):
    handler = type("BoundHandler", (Handler,), {"app": app})
    cls = type("Srv", (Server,), {"address_family": socket.AF_INET6 if ":" in host else socket.AF_INET})
    app.bind_host = host
    return cls((host, port), handler)


def serve_forever(srv):
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    t.start()
    return t
