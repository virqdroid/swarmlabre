"""The run's model gate: a Unix-socket HTTP server between the agent container and the model client.

The container reaches the model only through this socket (mounted read-only into it); no key and no network address ever enter the container. A request
does not get a 429 when the model is busy: it passes a BLOCKING semaphore of `parallel` slots. The answer starts at once (200, text/event-stream, `: keepalive`
comments every 15 s while it waits) so pi's 300 s idle abort cannot fire however long the queue is. Only streamed chat requests are taken (pi streams).
Because the 200 is already out, a failure afterwards is an SSE `data: {"error"}` event, which pi turns into an assistant message with stopReason "error"
(the run retries that). The role comes from the URL prefix `/a/<role>/v1` of each role's models.json: advisory, used to show who is waiting and to let
the mock answer per role. `on(state, role, wait_ms, waiting, running)` reports every change (`wait`, `go`, `end`, `gone`).

Sampling is pinned here: every request is rewritten before it is forwarded so `temperature` and `seed` are what the config says, whatever the agent's client asked for.
"""
import hashlib
import json
import os
import queue
import re
import socket
import socketserver
import struct
import threading
import time
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .client import ModelError

ALLOWED = {("GET", "/v1/models"), ("POST", "/v1/chat/completions")}
MAX_BODY = 16 * 1024 * 1024
KEEPALIVE = 15          # seconds of silence before an SSE comment goes out
CONNS = 16              # 6 roles plus the orchestrator and pi's retries fit; a flood from inside the container gets 429
ROLE = re.compile(r"/a/([a-z]{1,16})(/v1/.*)")


def pump_sse(h, r, tap=None):
    """Copy a streamed reply to handler `h`, adding an SSE comment whenever the model has been silent for KEEPALIVE seconds. A model that buffers a whole tool
    call sends nothing for minutes, and Node's fetch (pi) aborts a body that is idle for 300 s. Comments are ignored by SSE parsers; one only goes out between
    events, so it never splits one. `tap(chunk)` sees every chunk when it arrives (reader thread); an error in the tap never touches the copy."""
    q = queue.Queue(maxsize=64)         # bounded: a stalled client must not make the reader buffer the whole reply
    gone = threading.Event()

    def put(item):
        while not gone.is_set():
            try:
                return q.put(item, timeout=1)
            except queue.Full:
                pass

    def read():
        try:
            while chunk := r.read1(8192):
                if tap:
                    try:
                        tap(chunk)
                    except Exception:
                        pass
                put(chunk)
        except (OSError, HTTPException, ValueError, AttributeError):
            pass
        put(None)

    threading.Thread(target=read, daemon=True).start()
    tail = b"\n\n"
    try:
        while True:
            try:
                chunk = q.get(timeout=KEEPALIVE)
            except queue.Empty:
                if tail.endswith(b"\n\n"):
                    h.wfile.write(b": keepalive\n\n")
                    h.wfile.flush()
                continue
            if chunk is None:
                return
            h.wfile.write(chunk)
            h.wfile.flush()
            tail = (tail + chunk)[-2:]
    finally:
        gone.set()
        try:
            r.close()
        except Exception:
            pass


class ReqTap:
    """Times one streamed reply from the chunks the model sends: when the first and last piece of text arrived, how many text events there were and the
    `usage` object when the server sends one. Reads only structure (never keeps text); a line that does not parse is skipped."""

    CAPTURE_MAX = 8 << 20                  # the reply kept for the trace: at most 8 MiB

    def __init__(self, capture=False):
        self.buf, self.t_first, self.t_last, self.events, self.usage, self.err = b"", None, None, 0, None, False
        self.raw, self.raw_n, self.cut = ([] if capture else None), 0, False

    def feed(self, chunk):
        now = time.time()
        if self.raw is not None:
            if self.raw_n + len(chunk) <= self.CAPTURE_MAX:
                self.raw.append(chunk)
                self.raw_n += len(chunk)
            else:
                self.cut = True
        self.buf += chunk
        *lines, self.buf = self.buf.split(b"\n")
        if len(self.buf) > (1 << 20):
            self.buf = b""
        for ln in lines:
            if not ln.startswith(b"data:"):
                continue
            p = ln[5:].strip()
            if not p or p == b"[DONE]":
                continue
            try:
                o = json.loads(p)
            except ValueError:
                continue
            if not isinstance(o, dict):
                continue
            if o.get("error"):
                self.err = True
                continue
            if isinstance(o.get("usage"), dict):
                self.usage = o["usage"]
            ch = (o.get("choices") or [{}])[0] if o.get("choices") else {}
            d = ch.get("delta") if isinstance(ch, dict) else None
            if isinstance(d, dict) and (d.get("content") or d.get("reasoning_content") or d.get("reasoning") or d.get("tool_calls")):
                if self.t_first is None:
                    self.t_first = now
                self.t_last = now
                self.events += 1

    def row(self):
        u = self.usage or {}
        num = lambda v: v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None
        det = u.get("prompt_tokens_details") if isinstance(u.get("prompt_tokens_details"), dict) else {}
        return {"t_first": self.t_first, "t_last": self.t_last, "events": self.events, "in": num(u.get("prompt_tokens")), "out": num(u.get("completion_tokens")),
                "cached": num(det.get("cached_tokens"))}


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """HTTP over a Unix socket. A connection from any other uid is dropped before a byte is read, in case the directory mode is ever wrong."""
    daemon_threads = True
    request_queue_size = 16

    def get_request(self):
        conn, _ = self.socket.accept()
        try:
            uid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        except OSError:
            uid = -1
        if uid != os.getuid():
            conn.close()
            raise OSError("peer is not this user")
        return conn, ("unix", 0)


class Gate:
    def __init__(self, client, parallel, on, sampling=None, limits=None):
        self.client = client
        self.parallel = max(1, int(parallel))
        self.sem = threading.Semaphore(self.parallel)
        self.conns = threading.BoundedSemaphore(CONNS)
        self.on, self.lk = on, threading.Lock()
        self.waiting, self.running = [], []
        self.stat = None                   # optional callback(row) with the timing of every finished request (the run's model statistics)
        self.sampling = dict(sampling or {})      # {"temperature": 0.0, "seed": 1}: overwritten into every request body
        self.limits = dict(limits or {})   # {"model": id, "max_tokens": cap}: what an agent may not change about the request (the endpoint is paid for by the operator)
        self.trace = None                  # optional callback(record) with every request and its whole reply (the run's model trace, replayable)

    # ---- pinned sampling
    def pin(self, body):
        """The request body (bytes) with the pinned fields set: temperature and seed, the run's model, one completion, and no more output tokens than the cap.
        A body that is not a JSON object is returned unchanged. A value the agent sent that is already allowed stays as it was (the body is not rewritten for nothing)."""
        if not self.sampling and not self.limits:
            return body
        try:
            o = json.loads(body or b"{}")
        except ValueError:
            return body
        if not isinstance(o, dict):
            return body
        for k, v in self.sampling.items():
            if v is not None:
                o[k] = v
        if self.limits.get("model"):
            o["model"] = self.limits["model"]
        if "n" in o and o["n"] != 1:
            o["n"] = 1
        cap = self.limits.get("max_tokens")
        if cap:
            for k in ("max_tokens", "max_completion_tokens"):
                if k in o and (not isinstance(o[k], (int, float)) or isinstance(o[k], bool) or o[k] > cap):
                    o[k] = cap
        return json.dumps(o, separators=(",", ":")).encode()

    def emit(self, rec):
        if self.trace:
            try:
                self.trace(rec)
            except Exception:
                pass

    # ---- bookkeeping
    def record(self, row):
        if self.stat:
            try:
                self.stat(row)
            except Exception:
                pass

    def note(self, state, role, wait_ms=0):
        with self.lk:
            if state == "wait":
                self.waiting.append(role)
            elif state == "go":
                self.waiting.remove(role) if role in self.waiting else None
                self.running.append(role)
            elif state == "end":
                self.running.remove(role) if role in self.running else None
            elif state == "gone":
                self.waiting.remove(role) if role in self.waiting else None
            snap = (list(self.waiting), list(self.running))
        try:
            self.on(state, role, wait_ms, snap[0], snap[1])
        except Exception:
            pass

    # ---- the orchestrator's own call takes a slot of the same gate
    def ask(self, system, user, max_tokens=2048, extra=None):
        """One non-streaming call for the planning step. Waits for a slot like an agent's request, then asks the client. -> reply text; raises RuntimeError."""
        info = self.client.info()
        if not info:
            raise RuntimeError("no model is serving")
        t0 = time.time()
        self.note("wait", "orchestrator")
        self.sem.acquire()
        t_slot = time.time()
        self.note("go", "orchestrator", int((t_slot - t0) * 1000))
        ok, text, req = False, None, {"system": system, "user": user, "max_tokens": max_tokens}
        try:
            text = self.client.chat([{"role": "system", "content": system}, {"role": "user", "content": user}], max_tokens=max_tokens, role="orchestrator",
                                    extra={**{k: v for k, v in self.sampling.items() if v is not None}, **(extra or {})})
            ok = True
        except ModelError as e:
            raise RuntimeError(str(e))
        finally:
            self.sem.release()
            t_end = time.time()
            self.record({"role": "orchestrator", "t": t0, "t_slot": t_slot, "t_end": t_end, "wait_ms": int((t_slot - t0) * 1000), "ok": ok, "stream": False,
                         "t_first": None, "t_last": None, "events": 0, "in": None, "out": None, "cached": None})
            self.emit({"kind": "ask", "role": "orchestrator", "req_sha256": hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest(), "system": system, "user": user,
                       "ok": ok, "reply": text})
            self.note("end", "orchestrator", int((t_end - t0) * 1000))
        return text

    # ---- the socket
    def handler(gate):
        class H(BaseHTTPRequestHandler):
            timeout = 30                   # the idle limit of reading the request; waiting for a slot is writing keepalives, not reading

            def log_message(self, *a):
                pass

            def _fail(self, code, msg):
                b = json.dumps({"error": {"message": msg}}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _sse_error(self, msg):
                self.wfile.write(("data: %s\n\n" % json.dumps({"error": {"message": msg, "type": "backend"}})).encode())
                self.wfile.flush()

            def _go(self, method):
                path = self.path.split("?")[0]
                m = ROLE.fullmatch(path)
                role, path = (m.group(1), m.group(2)) if m else ("-", path)
                if (method, path) not in ALLOWED:
                    return self._fail(403, "not allowed")
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return self._fail(400, "bad length")
                if not 0 <= n <= MAX_BODY:
                    return self._fail(413, "too large")
                if not gate.conns.acquire(blocking=False):
                    return self._fail(429, "too many requests in flight")
                try:
                    self._serve(method, path, role, n)
                finally:
                    gate.conns.release()

            def _serve(self, method, path, role, n):
                body = self.rfile.read(n) if n else None
                rel = path[len("/v1"):]
                if method == "GET":
                    try:
                        r = gate.client.open("GET", rel, None, None, role=role)
                    except ModelError:
                        return self._fail(502, "model server unreachable")
                    try:
                        data = r.read()
                        self.send_response(r.status)
                        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    finally:
                        r.close()
                    return
                try:
                    if json.loads(body or b"{}").get("stream") is not True:
                        return self._fail(400, "this socket takes streamed requests only")
                except (ValueError, AttributeError):
                    return self._fail(400, "bad json")
                body = gate.pin(body)
                try:
                    turn = sum(1 for m in (json.loads(body).get("messages") or []) if isinstance(m, dict) and m.get("role") == "assistant")
                except (ValueError, AttributeError):
                    turn = 0
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    self.wfile.write(b": queued\n\n")
                    self.wfile.flush()
                except OSError:
                    return
                t0 = time.time()
                gate.note("wait", role)
                got, wl, st = threading.Event(), threading.Lock(), ["wait"]

                def grab():                # polls so a client that left stops costing a thread; `st` decides who releases the slot
                    while st[0] == "wait":
                        if gate.sem.acquire(timeout=1):
                            with wl:
                                if st[0] == "cancel":
                                    gate.sem.release()
                                else:
                                    st[0] = "held"
                                    got.set()
                            return
                threading.Thread(target=grab, daemon=True).start()
                try:
                    while not got.wait(KEEPALIVE):
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except OSError:            # the client left while it waited
                    with wl:
                        if st[0] == "held":
                            gate.sem.release()
                        st[0] = "cancel"
                    gate.note("gone", role)
                    return
                t_slot = time.time()
                gate.note("go", role, int((t_slot - t0) * 1000))
                tap, ok = ReqTap(capture=gate.trace is not None), False
                try:
                    r = gate.client.open("POST", rel, body, {"Accept": "text/event-stream"}, role=role)
                    try:
                        if r.status != 200:
                            return self._sse_error("the model server answered %d" % r.status)
                        if "text/event-stream" in (r.getheader("Content-Type", "") or ""):
                            pump_sse(self, r, tap.feed)
                        else:
                            while chunk := r.read1(8192):
                                self.wfile.write(chunk)
                                self.wfile.flush()
                        ok = not tap.err
                    finally:
                        r.close()
                except (OSError, HTTPException, ModelError):
                    try:
                        self._sse_error("the model server is unreachable")
                    except OSError:
                        pass
                finally:
                    gate.sem.release()
                    t_end = time.time()
                    gate.record({"role": role, "t": t0, "t_slot": t_slot, "t_end": t_end, "wait_ms": int((t_slot - t0) * 1000), "ok": ok, "stream": True, **tap.row()})
                    if tap.raw is not None:
                        gate.emit({"kind": "chat", "role": role, "turn": turn, "req_sha256": hashlib.sha256(body).hexdigest(), "req_bytes": len(body), "ok": ok,
                                   "cut": tap.cut, "reply": b"".join(tap.raw).decode("utf-8", "replace")})
                    gate.note("end", role, int((t_end - t0) * 1000))

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")
        return H

    def start_unix(self, path):
        """Serve on a Unix socket. The directory is 0700 and the socket 0600, so only this user (and a container running as this user, with the directory
        mounted read-only) can connect. Returns the server; `srv.gate` is this gate."""
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        target, dfd = str(path), None
        if len(os.fsencode(target)) > 100:   # sun_path holds about 108 bytes: bind through the directory's descriptor instead
            dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            target = "/proc/self/fd/%d/%s" % (dfd, path.name)
        old = os.umask(0o177)
        try:
            srv = UnixServer(target, self.handler())
        except BaseException:
            if dfd is not None:
                os.close(dfd)
            raise
        finally:
            os.umask(old)
        srv.dirfd = dfd
        srv.gate = self
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
