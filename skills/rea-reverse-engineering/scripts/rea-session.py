#!/usr/bin/env python3
"""rea-session: keep one `rea --mcp` server (and its open Ghidra database) alive between shell calls.

Every plain `rea <command>` is a new process that imports and auto-analyses the sample again (minutes on a big
binary). This helper starts `rea --mcp` once in the background and sends tool calls to it over a Unix socket, so the
analysis is paid for once per sample.

  rea-session.py start                          start the server (idempotent)
  rea-session.py call TOOL ['{"json": "args"}'] run one tool; args may also be key=value pairs, @file or - (stdin)
  rea-session.py tools                          the allowed tools with their required and optional arguments
  rea-session.py status                         server state and how long the current call has run
  rea-session.py manifest [--failed] [--json]   every call so far: id, tool, arguments, status, time, evidence id
  rea-session.py triage SAMPLE [--fresh]        the fixed first pass for a sample or folder (see below)
  rea-session.py stop                           end the server and its Ghidra process

call options: --out FILE (save the full output), --full (keep every field, default keeps evidence_id and
normalized_result), --max-chars N (print at most N characters; the rest is saved, default 12000),
--timeout S (default 1700), --fresh (skip the result cache and run the tool again).

Triage: one command runs the same steps in the same order on every sample of a kind and saves each result under
<out>/triage/<sha12>/ (SUMMARY.json lists the steps). Kinds, chosen from the bytes: ELF and PE (identity, overview,
segments, procedures, imports, strings, readelf or PE resources, entropy), APK (members, package, decoded manifest and
strings, components, classes), archives (members and facts, no extraction), asar, a folder of JavaScript or one .js file
(members, package.json, rea's summary). Every step is a manifest call, so a failed or skipped step is on record; if the
Ghidra import fails, the other native steps are skipped with that reason. Nothing is executed or extracted.

Manifest and cache (in the first writable of /work/rea-out, /tmp/rea-out; REA_OUT_DIR overrides): every call, including
refused, failed and timed-out ones, gets an id (c1, c2, ...) and one line in MANIFEST.jsonl. A successful call is cached in
cache/<key>.json, keyed on the rea version, the tool, the canonical arguments, the SHA-256 of the open sample and of any
file named in the arguments, so the same question about the same sample is answered from disk without Ghidra (also in a
later session of the same run, because /work is carried over). open_binary, close_binary, binary_session, extract_artifact and the
evidence-bundle tools are never cached. The agent writes the same folder, so this is a guard against mistakes and
invented calls, not against a hostile agent.

Swarm runs: REA_SESSION_AGENT_SOCK adds a second, locked socket (no stop, no log, open_binary only
of REA_SESSION_PIN, no close/extract/export); REA_SESSION_SOCK points a client at that socket; REA_SESSION_CLIENT_ONLY=1 stops a client from
starting a server; REA_AGENT names the caller for the fair queue (round robin between agents, advisory). None of them set = unchanged.

Static analysis only: the server is limited to ALLOWED tools below. Anything that runs the target, uses a browser,
adb, a debugger or the network is refused here, whatever the model asks for. Stdlib only.
"""
import hashlib, json, os, re, signal, socket, stat, subprocess, sys, threading, time

DIR = os.environ.get("REA_SESSION_DIR", "/tmp/rea-session")
SOCK = os.environ.get("REA_SESSION_SOCK") or os.path.join(DIR, "sock")
LOG = os.environ.get("REA_SESSION_LOG") or os.path.join(DIR, "server.log")
# Swarm runs (all four optional; with none set the server behaves as a plain single-client rea session):
AGENT_SOCK = os.environ.get("REA_SESSION_AGENT_SOCK", "")   # server: a second, locked socket in a folder that agent containers mount read-only
PIN = os.environ.get("REA_SESSION_PIN", "")                 # server: the one path open_binary may bind on the locked socket
CLIENT_ONLY = os.environ.get("REA_SESSION_CLIENT_ONLY") == "1"   # client: never start a server here (the agent container has no rea)
LOCKED_REFUSED = re.compile(r"(?:close_binary|extract_artifact|export_evidence_bundle)\Z")
LOCKED_PATH = re.compile(r"(?:inspect_android_\w+|search_android_classes|decode_android_resources|trace_android_references)\Z")   # tools that take a `path`: on the locked socket only the pinned sample
OUT_DIRS = (os.environ["REA_OUT_DIR"],) if os.environ.get("REA_OUT_DIR") else ("/work/rea-out", "/tmp/rea-out")
CACHE_ENTRY_MAX = 4 << 20                 # bigger results are returned but not kept
CACHE_TOTAL_MAX = 64 << 20                # /work is a tmpfs that a later session of the same run may inherit: keep the cache small
NOCACHE = re.compile(r"(?:open_binary|close_binary|binary_session|extract_artifact|export_evidence_bundle|get_evidence_bundle)\Z")

# Allowlist (regexes, full match). Read-only analysis of files in the sandbox. Deliberately absent: capture_*, observe_*,
# *_adb_*, *_jeb_*, web page / browser / Electron / CDP tools, anything that mutates the analysis (set_*, annotate_*).
ALLOWED = [
    r"open_binary", r"close_binary", r"binary_session", r"binary_overview",
    r"list_(procedures|strings|names|segments|architectures|unknowns)", r"search_(procedures|strings)",
    r"procedure_(address|assembly|callees|callers|info|references|pseudo_code)", r"read_function_instructions",
    r"xrefs", r"find_xrefs_to_name", r"read_bytes", r"address_to_file_offset", r"address_name", r"resolve_containing_procedure",
    r"inspect_address_context", r"inspect_native_(load_image|data_type|instruction|api|dispatch_metadata)", r"resolve_native_call_targets",
    r"trace_(feature|call_path|native_values)", r"get_call_graph", r"batch_decompile", r"analyze_function",
    r"inspect_(artifact|macho|signature|plist|binary_layout|pe_resources|firmware_regions|web_network_capture)",
    r"extract_artifact", r"inspect_managed_(artifact|members|native_boundaries)", r"compare_managed_members",
    r"inspect_android_(package|class|method)", r"search_android_classes", r"trace_android_references", r"decode_android_resources",
    r"analyze_javascript_application", r"trace_(application_feature|javascript_semantics)",
    r"compare_(application_versions|javascript_export_shapes|artifacts|functions|bundles)",
    r"inspect_analysis_view", r"get_evidence_bundle", r"export_evidence_bundle", r"build_call_path",
]
ALLOWED_RE = re.compile("(?:%s)\\Z" % "|".join(ALLOWED))      # the end anchor applies to every alternative, so a name that only STARTS like an allowed one is refused


def allowed(name):
    return bool(ALLOWED_RE.match(name))


def out_base():
    for d in OUT_DIRS:
        try:
            os.makedirs(d, exist_ok=True)
            if os.access(d, os.W_OK):
                return d
        except OSError:
            pass
    return None


def unwrap(resp):
    """MCP tool result -> (python value, is_error)."""
    res = resp.get("result") or {}
    val = res.get("structuredContent")
    if val is None:
        txt = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        try:
            val = json.loads(txt)
        except ValueError:
            val = txt
    return val, bool(res.get("isError"))


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha_hex(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------- server

def die(code=0):
    """Exit and take rea and its Ghidra/JVM children with us (the daemon leads its own process group)."""
    try:
        if os.getpgrp() == os.getpid():
            os.killpg(os.getpgrp(), 9)
    finally:
        os._exit(code)


class FairLock:
    """One call at a time, served in turn per agent (round robin), first come first served inside one agent.
    `agent` is advisory (the client's env REA_AGENT): it decides fairness only, never trust."""
    def __init__(self):
        self.cond = threading.Condition()
        self.busy = False
        self.q = {}                      # agent -> [ticket, ...]
        self.order = []                  # agents in the order they first waited
        self.last = None
        self.n = 0

    def _next(self):
        if not self.order:
            return None
        i = (self.order.index(self.last) + 1) % len(self.order) if self.last in self.order else 0
        for k in range(len(self.order)):
            a = self.order[(i + k) % len(self.order)]
            if self.q.get(a):
                return self.q[a][0]
        return None

    def acquire(self, agent="-", timeout=1700):
        with self.cond:
            self.n += 1
            t = self.n
            if agent not in self.q:
                self.q[agent] = []
                self.order.append(agent)
            self.q[agent].append(t)
            end = time.time() + timeout
            while self.busy or self._next() != t:
                left = end - time.time()
                if left <= 0 or not self.cond.wait(left):
                    self.q[agent].remove(t)
                    self.cond.notify_all()
                    return None
            self.q[agent].pop(0)
            self.last = agent
            self.busy = True
            return t

    def release(self):
        with self.cond:
            self.busy = False
            self.cond.notify_all()

    def waiting(self):
        with self.cond:
            return {a: len(v) for a, v in self.q.items() if v}


class Server:
    def __init__(self):
        self.lock = FairLock()                # one call at a time: there is one Ghidra
        self.pending = {}                     # id -> [Event, response]
        self.next_id = 0
        self.running = {}                     # id -> (tool, started) until rea answers, even if the client gave up
        self.base = out_base()                # manifest and cache folder; None = neither is kept
        self.mlock = threading.Lock()
        self.fhash = {}                       # (path, size, mtime_ns) -> sha256 of a file named in a call
        self.sample = None                    # {path, sha256} of the file open_binary last bound
        self.seq = 0
        self.ver = subprocess.run(["rea", "--version"], capture_output=True, text=True, timeout=60).stdout.strip() or "?"
        if self.base:
            try:
                with open(os.path.join(self.base, "MANIFEST.jsonl"), "rb") as f:
                    self.seq = sum(1 for _ in f)
            except OSError:
                pass
        self.p = subprocess.Popen(["rea", "--mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(LOG, "ab"), text=True, bufsize=1, close_fds=True)
        threading.Thread(target=self.reader, daemon=True).start()
        r = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "rea-session", "version": "1"}}, 60)
        if not r or "result" not in r:
            raise RuntimeError("rea --mcp did not initialize: %s" % (r,))
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = self.rpc("tools/list", {}, 60)
        self.names = sorted(t["name"] for t in tools["result"]["tools"])
        self.sig = {}
        for t in tools["result"]["tools"]:
            sch = t.get("inputSchema") or {}
            req = sch.get("required") or []
            opt = [k for k in (sch.get("properties") or {}) if k not in req]
            self.sig[t["name"]] = "%s(%s%s)" % (t["name"], ", ".join(req), ("; optional: " + ", ".join(opt)) if opt else "")

    def send(self, m):
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()

    def reader(self):
        for line in self.p.stdout:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            slot = self.pending.pop(m.get("id"), None) if "id" in m and "method" not in m else None
            self.running.pop(m.get("id"), None)
            if slot:
                slot[1] = m
                slot[0].set()
        for slot in list(self.pending.values()):      # rea ended: wake everyone
            slot[0].set()
        die(1)

    def rpc(self, method, params, timeout, label=None):
        self.next_id += 1
        i = self.next_id
        slot = [threading.Event(), None]
        self.pending[i] = slot
        if label:
            self.running[i] = (label, time.time())
        self.send({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
        if not slot[0].wait(timeout):
            return {"error": {"message": "timed out after %ss; the call may still be running in the session "
                                         "(rea-session.py status)" % timeout}}
        return slot[1]

    # -- manifest and cache

    def fsha(self, path):
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode):
                return None
            k = (path, st.st_size, st.st_mtime_ns)
            if k not in self.fhash:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        h.update(b)
                self.fhash[k] = h.hexdigest()
            return self.fhash[k]
        except OSError:
            return None

    def dsig(self, path):
        """Cheap signature of a folder named in a call (paths, sizes, mtimes; no contents): a changed tree is a different key."""
        try:
            if not os.path.isdir(path):
                return None
            rows = []
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for n in sorted(files):
                    st = os.lstat(os.path.join(root, n))
                    rows.append("%s\0%d\0%d" % (os.path.relpath(os.path.join(root, n), path), st.st_size, st.st_mtime_ns))
                    if len(rows) > 50000:
                        return "big"
            return sha_hex("\n".join(rows))
        except OSError:
            return None

    def key(self, tool, args):
        parts = [self.ver, tool, canon(args), self.sample["sha256"] if self.sample else ""]
        for k in sorted(args):
            v = args[k]
            if isinstance(v, str) and v.startswith("/") and len(v) < 4096:
                parts.append(self.fsha(v) or self.dsig(v) or "")
        return sha_hex("\0".join(parts))

    def cache_get(self, key):
        try:
            with open(os.path.join(self.base, "cache", key + ".json")) as f:
                e = json.load(f)
            if e.get("key") == key and "response" in e:
                return e
        except (OSError, ValueError):
            pass
        return None

    def cache_put(self, key, entry):
        """Store one entry; returns None or the reason it was not kept."""
        text = json.dumps(entry)
        if len(text) > CACHE_ENTRY_MAX:
            return "too_big"
        d = os.path.join(self.base, "cache")
        try:
            os.makedirs(d, exist_ok=True)
            if sum(e.stat().st_size for e in os.scandir(d) if e.is_file()) + len(text) > CACHE_TOTAL_MAX:
                return "cache_full"
            tmp = os.path.join(d, ".%s.tmp" % key)
            with open(tmp, "w") as f:
                f.write(text)
            os.replace(tmp, os.path.join(d, key + ".json"))
        except OSError:
            return "write_failed"
        return None

    def log(self, tool, args, status, secs, cached=False, of=None, evidence_id=None, rsha=None, nbytes=None, error=None):
        """Append one manifest line and return the call id."""
        with self.mlock:
            self.seq += 1
            cid = "c%d" % self.seq
            if self.base:
                line = {"id": cid, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tool": tool,
                        "args": {k: (v[:200] if isinstance(v, str) else v) for k, v in args.items()},
                        "sample": self.sample["sha256"][:12] if self.sample else None, "status": status,
                        "cached": cached, "of": of, "secs": secs, "evidence_id": evidence_id,
                        "result_sha256": rsha, "bytes": nbytes, "error": (error or "")[:300] or None}
                try:
                    with open(os.path.join(self.base, "MANIFEST.jsonl"), "a") as f:
                        f.write(json.dumps(line, ensure_ascii=False) + "\n")
                except OSError:
                    pass
            return cid

    def call(self, tool, args, timeout, fresh=False, agent="-", locked=False):
        if locked and LOCKED_REFUSED.match(tool):
            msg = "tool %r is not available in a swarm run" % tool
            return {"error": msg, "cid": self.log(tool, args, "refused", 0, error=msg)}
        if locked and LOCKED_PATH.match(tool) and args.get("path") != PIN:
            msg = "%s: only the run's sample can be analysed" % tool
            return {"error": msg, "cid": self.log(tool, args, "refused", 0, error=msg)}
        if locked and tool == "open_binary" and args.get("path") != PIN:
            msg = "open_binary: only the run's sample can be opened"
            return {"error": msg, "cid": self.log(tool, args, "refused", 0, error=msg)}
        if not allowed(tool):
            msg = "tool %r is not allowed here (static analysis only); see: rea-session.py tools" % tool
            return {"error": msg, "cid": self.log(tool, args, "refused", 0, error=msg)}
        if tool not in self.names:
            msg = "unknown tool %r in this rea version" % tool
            return {"error": msg, "cid": self.log(tool, args, "error", 0, error=msg)}
        key = self.key(tool, args) if self.base and not NOCACHE.match(tool) else None

        def hit():
            e = self.cache_get(key) if key and not fresh else None
            if not e:
                return None
            r = dict(e["response"])
            r["secs"] = 0
            r["of"] = e.get("cid")
            r["cid"] = self.log(tool, args, "ok", 0, cached=True, of=e.get("cid"), evidence_id=e.get("evidence_id"),
                                rsha=e.get("result_sha256"), nbytes=e.get("bytes"))
            return r

        r = hit()
        if r:
            return r
        if self.lock.acquire(agent, timeout) is None:
            msg = "another call is still running (rea-session.py status)"
            return {"error": msg, "cid": self.log(tool, args, "error", 0, error=msg)}
        try:
            r = hit()                                  # an identical call may have finished while this one waited
            if r:
                return r
            t0 = time.time()
            r = self.rpc("tools/call", {"name": tool, "arguments": args}, timeout, label=tool)
            r = r or {"error": {"message": "rea ended"}}
            r["secs"] = round(time.time() - t0, 1)
        finally:
            self.lock.release()
        return self.record(tool, args, r, key)

    def record(self, tool, args, r, key):
        if "error" in r:
            msg = r["error"].get("message") if isinstance(r["error"], dict) else str(r["error"])
            r["cid"] = self.log(tool, args, "timeout" if str(msg).startswith("timed out") else "error", r["secs"], error=msg)
            return r
        val, is_err = unwrap(r)
        if is_err:
            r["cid"] = self.log(tool, args, "error", r["secs"], error=val if isinstance(val, str) else canon(val))
            return r
        if tool == "open_binary":
            sha = self.fsha(args.get("path")) if isinstance(args.get("path"), str) else None
            self.sample = {"path": args.get("path"), "sha256": sha} if sha else None
        elif tool == "close_binary":
            self.sample = None
        text = canon(result_of(val))                   # the result, not the evidence id: for some tools the id differs between identical runs
        ev = val.get("evidence_id") if isinstance(val, dict) else None
        rsha = sha_hex(text)
        r["cid"] = self.log(tool, args, "ok", r["secs"], evidence_id=ev, rsha=rsha, nbytes=len(text))
        if key:
            self.cache_put(key, {"key": key, "cid": r["cid"], "tool": tool, "evidence_id": ev, "result_sha256": rsha,
                                 "bytes": len(text), "response": {"result": r.get("result")}})
        return r

    def handle(self, conn, locked=False):
        try:
            f = conn.makefile("rwb")
            req = json.loads(f.readline() or b"{}")
            op = req.get("op")
            if op == "call":
                out = self.call(req["tool"], req.get("args") or {}, float(req.get("timeout") or 1700), bool(req.get("fresh")),
                                re.sub(r"[^A-Za-z0-9_.-]", "", str(req.get("agent") or "-"))[:32] or "-", locked)
            elif op == "status":
                b = min(self.running.values(), key=lambda v: v[1]) if self.running else None
                out = {"ok": True, "pid": os.getpid(), "rea_pid": self.p.pid,
                       "busy": {"tool": b[0], "secs": round(time.time() - b[1]), "calls": len(self.running)} if b else None,
                       "rea": self.ver, "sample": self.sample, "calls_logged": self.seq, "out": None if locked else self.base,
                       "queue": self.lock.waiting(), "locked": locked}
            elif op == "tools":
                out = {"tools": [self.sig[n] for n in self.names if allowed(n)]}
            elif locked and op in ("stop", "log"):          # an agent can neither end the server nor write the manifest
                out = {"error": "refused: not available in a swarm run"}
            elif op == "log" and str(req.get("tool", "")).startswith("local:"):      # a step the client ran itself (file, readelf, ...)
                out = {"cid": self.log(req["tool"], req.get("args") or {}, req.get("status", "ok"), req.get("secs", 0), error=req.get("error"))}
            elif op == "stop":
                f.write(b'{"ok": true}\n'); f.flush()
                self.p.terminate()
                time.sleep(1)
                die(0)
            else:
                out = {"error": "unknown op"}
            f.write((json.dumps(out) + "\n").encode()); f.flush()
        except Exception as e:                      # never take the server down for one bad request
            try:
                conn.sendall((json.dumps({"error": "%s: %s" % (type(e).__name__, e)}) + "\n").encode())
            except OSError:
                pass
        finally:
            conn.close()


def serve():
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    os.chmod(DIR, 0o700)
    srv = Server()
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    old = os.umask(0o177)
    ls = socket.socket(socket.AF_UNIX)
    ls.bind(SOCK)
    os.umask(old)
    ls.listen(8)
    if AGENT_SOCK:        # the locked twin: agents get the folder that holds it, never DIR (manifest, cache and the control socket stay private)
        os.makedirs(os.path.dirname(AGENT_SOCK), exist_ok=True)
        try:
            os.unlink(AGENT_SOCK)
        except FileNotFoundError:
            pass
        als = socket.socket(socket.AF_UNIX)
        als.bind(AGENT_SOCK)
        os.chmod(AGENT_SOCK, 0o666)     # each agent role runs under its own uid; the folder is mounted read-only into that one container only
        als.listen(16)

        def agent_loop():
            while True:
                c, _ = als.accept()
                threading.Thread(target=srv.handle, args=(c, True), daemon=True).start()
        threading.Thread(target=agent_loop, daemon=True).start()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=srv.handle, args=(c,), daemon=True).start()


# ---------------------------------------------------------------- client

def ask(req, timeout):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(1 << 20)
        if not d:
            break
        buf += d
    s.close()
    return json.loads(buf or b"{}")


def alive():
    try:
        return bool(ask({"op": "status"}, 5).get("ok"))
    except (OSError, ValueError):
        return False


def start():
    if alive():
        return True
    if CLIENT_ONLY:       # a swarm agent container has no rea: say so instead of starting a server that cannot work
        print("rea-session: the tool server is not reachable", file=sys.stderr)
        return False
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "serve"], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=open(LOG, "ab"), close_fds=True)
    for _ in range(120):
        time.sleep(0.5)
        if alive():
            return True
    print("rea-session: server did not start; see %s" % LOG, file=sys.stderr)
    return False


def out_path(tool):
    d = out_base()
    return os.path.join(d, "%d-%s.txt" % (time.time() * 1000 % 10**9, tool)) if d else None


def render(val, full):
    if isinstance(val, dict) and not full and "evidence_id" in val:
        keep = {k: val[k] for k in ("evidence_id", "normalized_result") if k in val}
        val = keep
    if isinstance(val, dict) and not full:
        nr = val.get("normalized_result")
        if isinstance(nr, str):                    # pseudo-code and other text: print it as text
            return "evidence_id: %s\n%s" % (val.get("evidence_id"), nr)
    return val if isinstance(val, str) else json.dumps(val, indent=1, ensure_ascii=False)


def cmd_call(argv):
    opts = {"out": None, "full": False, "max": 12000, "timeout": 1700.0, "fresh": False}
    rest = []
    it = iter(argv)
    for a in it:
        if a == "--out": opts["out"] = next(it)
        elif a == "--full": opts["full"] = True
        elif a == "--fresh": opts["fresh"] = True
        elif a == "--max-chars": opts["max"] = int(next(it))
        elif a == "--timeout": opts["timeout"] = float(next(it))
        else: rest.append(a)
    if not rest:
        sys.exit("usage: rea-session.py call TOOL [JSON|@file|-]")
    tool = rest[0]
    raw = rest[1] if len(rest) > 1 else "{}"
    if len(rest) > 1 and re.match(r"[A-Za-z_][\w.]*=", raw):          # key=value pairs: pattern=usage limit=5
        args = {}
        for kv in rest[1:]:
            k, _, v = kv.partition("=")
            try: args[k] = json.loads(v)
            except ValueError: args[k] = v
    else:
        if raw == "-": raw = sys.stdin.read()
        elif raw.startswith("@"): raw = open(raw[1:]).read()
        try:
            args = json.loads(raw)
        except ValueError as e:
            sys.exit("arguments are not valid JSON: %s" % e)
    if not start():
        sys.exit(1)
    try:
        r = ask({"op": "call", "tool": tool, "args": args, "timeout": opts["timeout"], "fresh": opts["fresh"], "agent": os.environ.get("REA_AGENT", "-")}, opts["timeout"] + 30)
    except OSError as e:
        sys.exit("rea-session: lost the server (%s). Run `rea-session.py start`; the open sample must be opened again." % e)
    if not r:
        sys.exit("rea-session: the server closed the connection without an answer (it is ending or crashed). Run `rea-session.py start`; the open sample must be opened again.")
    cid = r.get("cid", "-")
    if "error" in r and not isinstance(r["error"], dict):
        sys.exit("rea-session: %s [%s]" % (r["error"], cid))
    if "error" in r:
        sys.exit("rea-session: %s [%s]" % (r["error"].get("message") or r["error"], cid))
    val, is_err = unwrap(r)
    text = render(val, opts["full"])
    saved = opts["out"]
    if saved or len(text) > opts["max"]:
        saved = saved or out_path(tool)
        if saved:
            with open(saved, "w") as f:
                f.write(text)
    head = text[: opts["max"]]
    print(head)
    if len(text) > len(head):
        print("\n[truncated: printed %d of %d characters%s]" % (len(head), len(text),
              "; full output in %s (read it in slices with sed -n 'A,Bp')" % saved if saved else ""))
    elif opts["out"]:
        print("\n[saved to %s]" % saved)
    how = "cached, first run %s" % r["of"] if r.get("of") else "%.1fs" % r.get("secs", 0)
    print("[%s %s, %s%s]" % (cid, tool, how, ", ERROR" if is_err else ""), file=sys.stderr)
    sys.exit(1 if is_err else 0)


def cmd_manifest(argv):
    if CLIENT_ONLY:       # a swarm agent: the manifest lives in the tools container, where no agent can write it
        print("In a swarm run the manifest is kept by the tool server, not in this container. Every call prints its id after it ([c12 tool, 0.3s]): cite that id with swarm-post --call.")
        return
    base = out_base()
    path = os.path.join(base, "MANIFEST.jsonl") if base else None
    if not path or not os.path.exists(path):
        print("no calls recorded yet")
        return
    rows = []
    with open(path) as f:
        for ln in f:
            try:
                rows.append(json.loads(ln))
            except ValueError:
                pass
    if "--failed" in argv:
        rows = [r for r in rows if r.get("status") != "ok"]
    if "--json" in argv:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return
    for r in rows:
        args = " ".join("%s=%s" % (k, v if isinstance(v, str) else json.dumps(v)) for k, v in (r.get("args") or {}).items())
        args = args if len(args) <= 70 else args[:67] + "..."
        how = "cached<-%s" % r["of"] if r.get("cached") else "%.1fs" % (r.get("secs") or 0)
        print("%-5s %-26s %-72s %-8s %-14s %s" % (r["id"], r["tool"], args, r["status"], how, r.get("evidence_id") or r.get("error") or ""))
    print("[%d calls, %d not ok]" % (len(rows), sum(1 for r in rows if r.get("status") != "ok")))


# ---------------------------------------------------------------- triage

TRIAGE_FILE_MAX = 8 << 20                 # one saved list; a longer list is cut and says so
MAGIC = [(b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gzip"), (b"\xfd7zXZ\x00", "xz"),
         (b"BZh", "bzip2"), (b"Rar!", "rar"), (b"MSCF", "cab"), (b"%PDF", "pdf"), (b"dex\n", "dex"), (b"\xcf\xfa\xed\xfe", "macho"),
         (b"\xce\xfa\xed\xfe", "macho"), (b"\xfe\xed\xfa\xcf", "macho"), (b"\xfe\xed\xfa\xce", "macho"), (b"\xca\xfe\xba\xbe", "macho-or-class"),
         (b"\xff\xd8\xff", "jpeg"), (b"\x89PNG", "png"), (b"GIF8", "gif"), (b"hsqs", "squashfs"), (b"!<arch>\n", "ar"), (b"\xed\xab\xee\xdb", "rpm"), (b"070701", "cpio"), (b"(\xb5/\xfd", "zstd")]
ARCHIVES = {"zip", "7z", "gzip", "xz", "bzip2", "rar", "cab", "tar", "squashfs", "ar", "rpm", "cpio", "zstd"}
EXT = {".exe": "pe", ".dll": "pe", ".sys": "pe", ".so": "elf", ".elf": "elf", ".zip": "zip", ".jar": "zip", ".apk": "zip", ".gz": "gzip",
       ".tgz": "gzip", ".7z": "7z", ".rar": "rar", ".xz": "xz", ".bz2": "bzip2", ".pdf": "pdf", ".tar": "tar", ".asar": "asar",
       ".js": "js", ".mjs": "js", ".cjs": "js", ".zst": "zstd", ".deb": "ar", ".rpm": "rpm",
       ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".txt": "text", ".log": "text", ".json": "text", ".csv": "text", ".html": "text",
       ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".odt": "zip", ".ods": "zip"}
JS_EXT = (".js", ".mjs", ".cjs")
RUN_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".msi", ".jar",
           ".apk", ".dex", ".so", ".dylib", ".sh", ".py", ".pl", ".elf", ".bin", ".class", ".cpl", ".reg"}
NEST_EXT = {".zip", ".7z", ".rar", ".gz", ".tgz", ".xz", ".bz2", ".tar", ".cab", ".iso", ".img", ".jar", ".apk", ".aab", ".war", ".asar", ".zst", ".rpm", ".deb"}
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
MEMBER_MAX = 200000                       # members listed from one archive


def clean(t, n=200):
    return CTRL.sub("?", str(t))[:n]


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tree_info(root, hash_total=2 << 30, hash_file=256 << 20, max_files=50000):
    """Walk a folder without following links; returns (members, symlinks, notes). Members carry a SHA-256 up to the caps."""
    members, links, notes, hashed = [], 0, [], 0
    for cur, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for n in sorted(dirs):
            if os.path.islink(os.path.join(cur, n)):
                links += 1
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(cur, d))]
        for n in sorted(files):
            fp = os.path.join(cur, n)
            rel = os.path.relpath(fp, root)
            try:
                st = os.lstat(fp)
                if not stat.S_ISREG(st.st_mode):
                    links += 1 if stat.S_ISLNK(st.st_mode) else 0
                    continue
                m = {"path": clean(rel, 500), "kind": "file", "size": st.st_size, "executable": bool(st.st_mode & 0o111), "sha256": None}
                if st.st_size <= hash_file and hashed + st.st_size <= hash_total:
                    m["sha256"] = sha_file(fp)
                    hashed += st.st_size
                members.append(m)
            except OSError:
                notes.append("unreadable: " + clean(rel, 100))
            if len(members) >= max_files:
                notes.append("stopped after %d files" % max_files)
                return members, links, notes
    return members, links, notes


def identify(path):
    """Facts about the file or folder itself, from its bytes and not its name. A folder gets a tree hash."""
    ext = os.path.splitext(path.rstrip("/"))[1].lower()
    if os.path.isdir(path):
        members, links, notes = tree_info(path)
        tree = hashlib.sha256()
        for m in members:
            tree.update(("%s\0%d\0%s\n" % (m["path"], m["size"], m["sha256"])).encode("utf-8", "replace"))
        return {"path": path, "name": os.path.basename(path.rstrip("/")), "size": sum(m["size"] for m in members), "sha256": tree.hexdigest(),
                "magic": "directory", "file": "directory", "head_hex": "", "extension": "", "extension_claims": None, "extension_mismatch": False,
                "files": len(members), "symlinks_skipped": links, "notes": notes, "_members": members}
    st = os.stat(path)
    with open(path, "rb") as f:
        head = f.read(512)
        magic = next((n for m, n in MAGIC if head.startswith(m)), None)
        if head.startswith(b"MZ"):
            off = int.from_bytes(head[60:64], "little") if len(head) >= 64 else 0
            f.seek(off)
            magic = "pe" if off and f.read(4) == b"PE\0\0" else "dos-mz"
    if magic is None and head[257:262] == b"ustar":
        magic = "tar"
    if magic is None and head[:4] == b"\x04\x00\x00\x00" and head[16:24] == b'{"files"':
        magic = "asar"
    if magic is None and head and b"\0" not in head:
        try:
            head.decode("utf-8")
            magic = "text"
        except UnicodeDecodeError:
            pass
    try:
        fb = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        fb = ""
    claim = EXT.get(ext)
    return {"path": path, "name": os.path.basename(path), "size": st.st_size, "sha256": sha_file(path), "magic": magic,
            "file": clean(fb, 300), "head_hex": head[:16].hex(), "extension": ext, "extension_claims": claim,
            "extension_mismatch": bool(claim and claim != magic and not (claim == "js" and magic == "text"))}


def entropy_profile(path, block=4096, limit=64 << 20):
    import math
    from collections import Counter
    def H(b):
        n = len(b)
        return -sum(c / n * math.log2(c / n) for c in Counter(b).values()) if n else 0.0
    whole, blocks, total = Counter(), [], 0
    with open(path, "rb") as f:
        while total < limit:
            b = f.read(block)
            if not b:
                break
            total += len(b)
            whole.update(b)
            if len(b) == block:
                blocks.append(H(b))
    n = sum(whole.values())
    hw = -sum(c / n * math.log2(c / n) for c in whole.values()) if n else 0.0
    return {"bytes_read": total, "whole": round(hw, 3), "block_size": block, "blocks": len(blocks),
            "block_max": round(max(blocks), 3) if blocks else None, "block_mean": round(sum(blocks) / len(blocks), 3) if blocks else None,
            "blocks_over_7_2": sum(1 for x in blocks if x > 7.2), "fraction_over_7_2": round(sum(1 for x in blocks if x > 7.2) / len(blocks), 3) if blocks else None}


def addr_key(it):
    a = str(it.get("address", "")) if isinstance(it, dict) else ""
    try:
        if a.startswith("EXTERNAL:"):
            return (0, int(a[9:], 16), "")
        return (1, int(a, 16), str(it.get("value", "")))
    except ValueError:
        return (2, 0, a)


def tmp_write(path, text):
    with open(path + ".tmp", "w") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


def items_text(meta, items):
    """One JSON object whose items are one per line (rg and sed friendly); cut at TRIAGE_FILE_MAX."""
    lines, size, cut = [], 0, False
    for it in items:
        ln = json.dumps(it, ensure_ascii=False, sort_keys=True)
        if size + len(ln) > TRIAGE_FILE_MAX:
            cut = True
            break
        lines.append(ln)
        size += len(ln) + 2
    meta = dict(meta, total=len(items), shown=len(lines), truncated=cut)
    return json.dumps(meta, sort_keys=True, ensure_ascii=False)[:-1] + ',"items":[\n' + ",\n".join(lines) + "\n]}\n", cut


def tcall(tool, args, timeout, fresh=False):
    """One session call made by triage -> {cid, status, val, secs, cached, error}."""
    bad = lambda msg, st="error", cid=None: {"cid": cid, "status": st, "val": None, "secs": 0, "cached": False, "error": clean(msg)}
    try:
        r = ask({"op": "call", "tool": tool, "args": args, "timeout": timeout, "fresh": fresh}, timeout + 30)
    except (OSError, ValueError) as e:
        return bad("lost the server: %s" % e)
    if not r:
        return bad("the server closed the connection without an answer")
    if "error" in r:
        msg = r["error"].get("message") if isinstance(r["error"], dict) else str(r["error"])
        return bad(msg, "timeout" if str(msg).startswith("timed out") else "error", r.get("cid"))
    val, is_err = unwrap(r)
    if is_err:
        e = val.get("error") if isinstance(val, dict) else None
        return bad((e.get("message") if isinstance(e, dict) else None) or val, "error", r.get("cid"))
    return {"cid": r.get("cid"), "status": "ok", "val": val, "secs": r.get("secs", 0), "cached": bool(r.get("of")), "error": None}


def tlog(tool, args, status, secs, error=None):
    try:
        return ask({"op": "log", "tool": tool, "args": args, "status": status, "secs": secs, "error": error}, 10).get("cid")
    except (OSError, ValueError):
        return None


def result_of(val):
    if isinstance(val, dict):
        for k in ("normalized_result", "result"):
            if k in val:
                return val[k]
    return val


# -- member listings (never extract: a listing is a read of the archive's own index)

class Deadline(Exception):
    pass


def _alarm(_sig, _frm):
    raise Deadline()


def list_7z(path, timeout=120):
    """`7z l -slt` -> (members, source). Reads at most 64 MiB of listing."""
    p = subprocess.Popen(["7z", "l", "-slt", "-ba", "-sccUTF-8", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    t = threading.Timer(timeout, p.kill)
    t.start()
    try:
        out = p.stdout.read(64 << 20)
        err = p.stderr.read(4096)
        p.kill() if len(out) >= (64 << 20) else p.wait()
    finally:
        t.cancel()
    members = []
    for block in out.decode("utf-8", "replace").split("\n\n"):
        rec = {}
        for ln in block.splitlines():
            k, sep, v = ln.partition(" = ")
            if sep:
                rec[k] = v
        if "Path" not in rec:
            continue
        mode = rec.get("Attributes", "").split(" ")[-1]
        kind = "dir" if rec.get("Folder") == "+" or rec.get("Attributes", "").startswith("D") else "symlink" if mode.startswith("l") else "file"
        members.append({"path": clean(rec["Path"], 500), "kind": kind, "size": int(rec["Size"]) if rec.get("Size", "").isdigit() else None,
                        "packed": int(rec["Packed Size"]) if rec.get("Packed Size", "").isdigit() else None, "crc": rec.get("CRC") or None,
                        "encrypted": rec.get("Encrypted") == "+", "method": clean(rec.get("Method", ""), 60) or None,
                        "executable": len(mode) == 10 and "x" in mode, "modified": rec.get("Modified") or None})
        if len(members) >= MEMBER_MAX:
            break
    if not members:                                   # an empty answer is an error, not an empty archive (encrypted headers list nothing)
        msg = clean(err.decode("utf-8", "replace") + " " + " ".join(l for l in out.decode("utf-8", "replace").splitlines() if "ERROR" in l or "ssword" in l), 200)
        raise RuntimeError("7z listed no members (exit %s): %s" % (p.returncode, msg.strip() or "no message; the archive may be empty or have encrypted headers"))
    return members, "7z"


def list_tar(path, timeout=120):
    """tarfile in stream mode (tar, tgz, txz, tbz); raises tarfile.ReadError when the file is not a tar."""
    import tarfile
    members = []
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(timeout)
    try:
        with tarfile.open(path, "r|*") as tf:
            for ti in tf:
                kind = "dir" if ti.isdir() else "symlink" if ti.issym() or ti.islnk() else "file" if ti.isreg() else "other"
                members.append({"path": clean(ti.name, 500), "kind": kind, "size": ti.size if ti.isreg() else None, "packed": None, "crc": None,
                                "encrypted": False, "method": None, "executable": bool(ti.mode & 0o111) and ti.isreg(),
                                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ti.mtime))})
                if len(members) >= MEMBER_MAX:
                    break
    except Deadline:
        raise RuntimeError("listing took longer than %d s" % timeout)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    return members, "tarfile"


def list_members(path, magic):
    if magic in ("gzip", "xz", "bzip2", "tar", "zstd"):
        try:
            return list_tar(path)
        except Exception as e:                  # not a tar (one compressed file), or tarfile cannot read it: 7z names the inner file
            if isinstance(e, RuntimeError):
                raise
    return list_7z(path)


def member_facts(members, archive_size):
    files = [m for m in members if m["kind"] == "file"]
    total = sum(m["size"] or 0 for m in files)
    exts = {}
    for m in files:
        e = os.path.splitext(m["path"])[1].lower() or "(none)"
        exts[e] = exts.get(e, 0) + 1
    odd = [m["path"] for m in members if ".." in re.split(r"[\\/]", m["path"]) or m["path"].startswith(("/", "\\")) or re.match(r"[A-Za-z]:", m["path"])
           or "\\" in m["path"] or len(m["path"]) > 1024]
    return {"members": len(members), "files": len(files), "dirs": sum(1 for m in members if m["kind"] == "dir"),
            "symlinks": sum(1 for m in members if m["kind"] == "symlink"), "total_size": total,
            "expansion_ratio": round(total / archive_size, 1) if archive_size else None, "largest_member": max((m["size"] or 0 for m in files), default=0),
            "encrypted_members": sum(1 for m in members if m.get("encrypted")),
            "odd_names": len(odd), "odd_name_examples": sorted(odd)[:5],
            "nested_archives": sorted(m["path"] for m in files if os.path.splitext(m["path"])[1].lower() in NEST_EXT)[:20],
            "executable_by_extension": sum(1 for m in files if os.path.splitext(m["path"])[1].lower() in RUN_EXT),
            "executable_bit_set": sum(1 for m in files if m.get("executable")),
            "top_extensions": dict(sorted(exts.items(), key=lambda kv: (-kv[1], kv[0]))[:10])}


def parse_manifest(text):
    """Components and flags from a decoded AndroidManifest.xml (apktool output; capped, parsed with expat only)."""
    import xml.etree.ElementTree as ET
    A = "{http://schemas.android.com/apk/res/android}"
    root = ET.fromstring(text[: 2 << 20])
    app = root.find("application")
    comps = []
    if app is not None:
        for el in app:
            if el.tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                filters = el.findall("intent-filter")
                exp = el.get(A + "exported")
                comps.append({"type": el.tag, "name": clean(el.get(A + "name") or "", 300), "exported": exp, "permission": el.get(A + "permission"),
                              "exported_effective": "true" if exp == "true" or (exp is None and filters) else "false",
                              "actions": sorted({clean(a.get(A + "name") or "", 200) for f in filters for a in f.findall("action")})})
    comps.sort(key=lambda c: (c["type"], c["name"]))
    flags = {k: app.get(A + k) for k in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "name", "extractNativeLibs")
             if app is not None and app.get(A + k) is not None}
    return {"package": root.get("package"), "uses_permissions": sorted({clean(e.get(A + "name") or "", 200) for e in root.findall("uses-permission")}),
            "application": flags, "components": comps}


def parse_package_json(path):
    with open(path, "rb") as f:
        d = json.loads(f.read(1 << 20))
    pick = lambda k: clean(d.get(k), 300) if isinstance(d.get(k), (str, int, float)) else None
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    deps = {k: sorted(map(str, d[k]))[:200] if isinstance(d.get(k), dict) else [] for k in ("dependencies", "devDependencies", "optionalDependencies")}
    return {"name": pick("name"), "version": pick("version"), "main": pick("main"), "type": pick("type"), "bin": d.get("bin") if isinstance(d.get("bin"), (str, dict)) else None,
            "install_hooks": {k: clean(v, 300) for k, v in sorted(scripts.items()) if k in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack") and isinstance(v, str)},
            "script_names": sorted(map(str, scripts))[:50], "dependency_counts": {k: len(v) for k, v in deps.items()}, "dependencies": deps["dependencies"],
            "electron_dependency": any("electron" in n for n in deps["dependencies"] + deps["devDependencies"])}


class Triage:
    """Shared bookkeeping of one triage run: every step is noted, saved under <out>/ and logged in the manifest."""

    def __init__(self, ident, out, id_cid, fresh, first_t, step_t):
        self.id, self.out, self.fresh, self.first_t, self.step_t = ident, out, fresh, first_t, step_t
        self.steps, self.facts, self.ev, self.extra = [], {}, {}, {}
        self.note("identify", "local:identify", "ok", "identity.json", id_cid)

    def note(self, step, tool, status, file=None, cid=None, secs=0, cached=False, why=None, truncated=False):
        self.steps.append({"step": step, "tool": tool, "call": cid, "status": status, "secs": secs, "cached": cached, "file": file,
                           "truncated": truncated, "note": clean(why, 200) if why else None})

    def skip(self, step, tool, why, na=False):
        """na = the step does not apply to this kind of sample (not a gap); otherwise a skipped step is unresolved."""
        self.note(step, tool, "n/a" if na else "skipped", why=why)

    def put(self, file, text):
        tmp_write(os.path.join(self.out, file), text)

    def put_items(self, file, meta, items):
        text, cut = items_text(dict(meta, sample_sha256=self.id["sha256"]), items)
        self.put(file, text)
        return cut

    def save(self, step, tool, res, file):
        """Write a finished session call as <file> (no call id inside: the file must be identical on every run); returns its result."""
        nr = result_of(res["val"])
        self.ev[step] = res["val"].get("evidence_id") if isinstance(res["val"], dict) else None
        meta = {"tool": tool, "sample_sha256": self.id["sha256"]}      # the evidence id is in SUMMARY.json: for some tools it changes between runs
        cut = False
        if isinstance(nr, list):
            nr = sorted(nr, key=addr_key) if all(isinstance(x, dict) and "address" in x for x in nr) else nr
            for x in nr:
                if isinstance(x, dict) and isinstance(x.get("value"), str) and len(x["value"]) > 1000:
                    x["value"], x["value_truncated"] = x["value"][:1000], True
            text, cut = items_text(meta, nr)
        else:
            text = json.dumps(dict(meta, result=nr), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
            if len(text) > TRIAGE_FILE_MAX:
                text, cut = json.dumps(dict(meta, result=None, truncated=True, bytes=len(text))) + "\n", True
        self.put(file, text)
        self.note(step, tool, "ok", file, res["cid"], res["secs"], res["cached"], truncated=cut)
        return nr

    def call(self, step, tool, args, file, timeout=None, keep=True):
        """One session call; on success the result is saved (keep) and returned, on failure the step is noted and None comes back."""
        res = tcall(tool, args, timeout or self.step_t, self.fresh)
        if res["status"] != "ok":
            self.note(step, tool, res["status"], file, res["cid"], res["secs"], False, why=res["error"])
            return None
        if not keep:
            self.ev[step] = res["val"].get("evidence_id") if isinstance(res["val"], dict) else None
            self.note(step, tool, "ok", file, res["cid"], res["secs"], res["cached"])
            return result_of(res["val"])
        return self.save(step, tool, res, file)

    def local(self, step, tool, logargs, fn):
        """A step done by this script (file reads, 7z, readelf); fn returns (file, text, truncated, value) or raises."""
        t0 = time.time()
        try:
            file, text, cut, value = fn()
        except Exception as e:
            secs = round(time.time() - t0, 1)
            self.note(step, tool, "error", None, tlog(tool, logargs, "error", secs, clean(e)), secs, why="%s: %s" % (type(e).__name__, clean(e)))
            return None
        secs = round(time.time() - t0, 1)
        if file:
            self.put(file, text)
        self.note(step, tool, "ok", file, tlog(tool, logargs, "ok", secs), secs, truncated=cut)
        return value if value is not None else True

    def members(self, magic, source_members=None):
        """Member listing -> members.json; returns the member list or None."""
        def fn():
            ms, src = (source_members, "walk") if source_members is not None else list_members(self.id["path"], magic)
            ms = sorted(ms, key=lambda m: (m["path"], m["kind"]))
            text, cut = items_text({"source": src, "sample_sha256": self.id["sha256"]}, ms)
            return "members.json", text, cut, ms
        return self.local("members", "local:members", {"path": self.id["path"]}, fn)

    def open_target(self, path):
        """open_binary; returns what rea says about the file ({} when nothing) or None when it failed."""
        r = tcall("open_binary", {"path": path}, 120, self.fresh)
        if r["status"] != "ok":
            self.note("open", "open_binary", r["status"], None, r["cid"], r["secs"], why=r["error"])
            return None
        self.note("open", "open_binary", "ok", None, r["cid"], r["secs"])
        o = result_of(r["val"])
        return o if isinstance(o, dict) else {}

    def mark_cut(self, step, cut):
        for s in self.steps:
            if s["step"] == step:
                s["truncated"] = bool(cut)


# -- playbooks: the same fixed steps in the same order for one kind of sample

def play_native(t, play):
    ident = t.id
    native = True
    why_skip = ""
    opened = t.open_target(ident["path"])
    if opened is None:
        native, why_skip = False, "open_binary failed"
    else:
        t.facts["format"], t.facts["architecture"] = opened.get("format"), opened.get("architecture")
        if opened.get("format") and opened["format"] != play:
            t.steps[-1]["note"] = "magic says %s, rea opened it as %s" % (play, clean(opened["format"], 40))
    steps = [("overview", "binary_overview", "overview.json"), ("segments", "list_segments", "segments.json"),
             ("procedures", "list_procedures", "procedures.json"), ("strings", "list_strings", "strings.json")]
    got = {}
    for i, (step, tool, file) in enumerate(steps):
        if not native:
            t.skip(step, tool, why_skip)
            continue
        nr = t.call(step, tool, {}, file, t.first_t if i == 0 else t.step_t)
        if nr is None:
            if i == 0:                                     # the first native call pays the import: when it fails, none of the others can work
                native, why_skip = False, "native analysis unavailable: %s %s" % (tool, t.steps[-1]["status"])
            continue
        got[step] = nr
    t.native = native
    procs, segs = got.get("procedures"), got.get("segments")
    if isinstance(procs, list):
        ext = sorted({clean(str(x.get("value", "")).split("::", 1)[-1], 200) for x in procs if isinstance(x, dict) and (x.get("procedure") or {}).get("external")})
        own = [x for x in procs if isinstance(x, dict) and not (x.get("procedure") or {}).get("external")]
        t.put_items("imports.json", {"derived_from": "procedures.json"}, [{"name": n} for n in ext])
        t.note("imports", "derived", "ok", "imports.json")
        t.facts.update(imports=len(ext), functions=len(own), unnamed_functions=sum(1 for x in own if str(x.get("value", "")).startswith("FUN_")))
    else:
        t.skip("imports", "derived", "needs procedures")
    if isinstance(segs, list):
        t.facts["writable_executable_segments"] = sorted(clean(x.get("name"), 60) for x in segs if isinstance(x, dict) and x.get("writable") and x.get("executable"))
    if play == "pe":
        r = t.call("pe_resources", "inspect_pe_resources", {"path": ident["path"]}, "pe-resources.json")
    else:
        def readelf():
            p = subprocess.run(["readelf", "-W", "-h", "-l", "-S", "-d", ident["path"]], capture_output=True, text=True, timeout=60)
            if p.returncode != 0:
                raise RuntimeError(clean(p.stderr, 200) or "readelf failed")
            return "readelf.txt", p.stdout[: 1 << 20], False, None
        t.local("readelf", "local:readelf", {"path": ident["path"], "args": "-W -h -l -S -d"}, readelf)
    prof = {}
    def entropy():
        prof.update(entropy_profile(ident["path"]))
        return "entropy.json", json.dumps(dict(prof, sample_sha256=ident["sha256"]), indent=1, sort_keys=True) + "\n", False, None
    t.local("entropy", "local:entropy", {"path": ident["path"]}, entropy)
    if prof:
        t.facts.update(entropy_whole=prof["whole"], entropy_fraction_blocks_over_7_2=prof["fraction_over_7_2"])


def play_apk(t, members_ready):
    ident, path = t.id, t.id["path"]
    ms = t.members("zip", members_ready)
    if ms is not None:
        f = member_facts(ms, ident["size"])
        names = [m["path"] for m in ms if m["kind"] == "file"]
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
        emb = sorted(n for n in names if n.startswith(("assets/", "res/raw/")) and os.path.splitext(n)[1].lower() in (NEST_EXT | {".dex", ".so", ".exe", ".elf"}))[:20]
        t.facts.update(dex_files=sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n)), native_abis=abis, native_libs=sum(1 for n in names if n.startswith("lib/") and n.endswith(".so")),
                       embedded_binaries_in_assets=emb, encrypted_members=f["encrypted_members"], odd_names=f["odd_names"], meta_inf_signature_files=sorted(n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC", ".SF")))[:10])
    pkg = t.call("package", "inspect_android_package", {"path": path}, "package.json")
    if isinstance(pkg, dict):
        t.facts.update(package_name=pkg.get("package_name"), version_name=pkg.get("version_name"), version_code=pkg.get("version_code"), min_sdk=pkg.get("min_sdk"),
                       target_sdk=pkg.get("target_sdk"), permissions=sorted(pkg.get("permissions") or []), class_count=pkg.get("class_count"),
                       resource_count=pkg.get("resource_count"), signature_verification=pkg.get("signature_verification"))
    res = t.call("resources", "decode_android_resources", {"path": path}, "strings.json", keep=False)
    manifest_text = None
    if isinstance(res, dict):
        manifest_text = res.get("manifest") if isinstance(res.get("manifest"), str) else None
        strs = res.get("strings") if isinstance(res.get("strings"), list) else []
        t.mark_cut("resources", t.put_items("strings.json", {"tool": "decode_android_resources", "locales": len(res.get("locales") or []), "decoded_file_count": res.get("decoded_file_count"),
                                                              "coverage": res.get("coverage"), "metadata": res.get("metadata")}, sorted(strs, key=lambda x: json.dumps(x, sort_keys=True))))
        if manifest_text:
            t.put("manifest.xml", manifest_text[: 2 << 20])
    if manifest_text is None and isinstance(pkg, dict) and isinstance(pkg.get("manifest"), dict) and isinstance(pkg["manifest"].get("text"), str):
        manifest_text = pkg["manifest"]["text"]
        t.put("manifest.xml", manifest_text[: 2 << 20])
    if manifest_text:
        def comps():
            c = parse_manifest(manifest_text)
            return "components.json", json.dumps(dict(c, sample_sha256=ident["sha256"]), indent=1, sort_keys=True, ensure_ascii=False) + "\n", False, c
        c = t.local("components", "local:manifest", {"path": "manifest.xml"}, comps)
        if isinstance(c, dict):
            comp = c["components"]
            t.facts.update(components=len(comp), exported_components=sum(1 for x in comp if x["exported_effective"] == "true"),
                           components_by_type={k: sum(1 for x in comp if x["type"] == k) for k in sorted({x["type"] for x in comp})}, application_flags=c["application"])
    else:
        t.skip("components", "local:manifest", "no decoded manifest")
    cls = t.call("classes", "search_android_classes", {"path": path, "query": ""}, "classes.json", keep=False)
    if isinstance(cls, dict) and isinstance(cls.get("matches"), list):
        t.mark_cut("classes", t.put_items("classes.json", {"tool": "search_android_classes", "total_classes": cls.get("total_classes"), "coverage": cls.get("coverage")},
                                          [{"class": clean(c, 300)} for c in sorted(map(str, cls["matches"]))]))
    elif cls is not None:
        t.steps[-1]["status"], t.steps[-1]["note"] = "error", "no class list in the answer"


def play_archive(t, magic, members_ready):
    ident = t.id
    ms = t.members(magic, members_ready)
    if ms is not None:
        f = member_facts(ms, ident["size"])
        t.facts.update(f)
        names = [m["path"] for m in ms]
        t.facts["looks_like"] = ("java" if any(n == "META-INF/MANIFEST.MF" for n in names) and any(n.endswith(".class") for n in names)
                                 else "npm-package" if any(n.endswith("package/package.json") or n == "package.json" for n in names) else None)
        if len(ms) == 1 and ms[0]["kind"] == "file" and magic in ("gzip", "xz", "bzip2", "zstd"):
            t.facts["single_compressed_file"] = ms[0]["path"]
    if magic == "zip":                                      # rea's own artifact graph (member hashes); can exceed the 10 MiB reply budget on a big package
        if t.open_target(ident["path"]) is not None:
            t.call("artifact", "inspect_artifact", {}, "artifact.json")
    else:
        t.skip("artifact", "inspect_artifact", "rea reads zip-style packages and asar only; the member list covers this format", na=True)


def asar_members(artifact):
    """members from rea's artifact graph: logical paths joined to the node (hash, size) of their artifact."""
    sub = (artifact.get("substeps") or [{}])[0].get("evidence", {}).get("normalized_result", {})
    nodes = {n["artifact_id"]: n for n in sub.get("nodes", []) if isinstance(n, dict) and "artifact_id" in n}
    out = []
    for o in sub.get("occurrences", []):
        if not isinstance(o, dict) or o.get("logical_path") in (None, "."):
            continue
        n = nodes.get(o.get("artifact_id"), {})
        out.append({"path": clean(o["logical_path"], 500), "kind": "dir" if o.get("entry_kind") == "directory" else "symlink" if o.get("entry_kind") == "symlink" else "file",
                    "size": o.get("declared_size") if o.get("declared_size") is not None else n.get("size"), "executable": bool(o.get("executable")),
                    "encrypted": bool(o.get("encrypted")), "sha256": n.get("sha256")})
    return out


def play_js(t, play):
    ident, path = t.id, t.id["path"]
    target = path
    if play == "asar":
        ms = None
        if t.open_target(path) is not None:
            art = t.call("inventory", "inspect_artifact", {}, None, keep=False)
            if isinstance(art, dict):
                ms = t.members("asar", asar_members(art))
        else:
            t.skip("inventory", "inspect_artifact", "open_binary failed")
    else:
        ms = t.members("directory", ident["_members"] if play == "js-dir" else [{"path": ident["name"], "kind": "file", "size": ident["size"], "executable": False, "sha256": ident["sha256"]}])
    if ms is not None:
        t.facts.update(files=sum(1 for m in ms if m["kind"] == "file"), total_size=sum(m["size"] or 0 for m in ms if m["kind"] == "file"),
                       js_files=sum(1 for m in ms if os.path.splitext(m["path"])[1].lower() in JS_EXT), native_addons=sorted(m["path"] for m in ms if m["path"].endswith(".node"))[:20],
                       minified_suspects=sum(1 for m in ms if m["path"].endswith((".min.js",))))
        if play == "js-dir":
            pj = os.path.join(path, "package.json")
            if os.path.isfile(pj) and not os.path.islink(pj):
                def pack():
                    d = parse_package_json(pj)
                    return "package.json", json.dumps(dict(d, sample_sha256=ident["sha256"]), indent=1, sort_keys=True, ensure_ascii=False) + "\n", False, d
                d = t.local("package", "local:package_json", {"path": "package.json"}, pack)
                if isinstance(d, dict):
                    t.facts.update(package_name=d["name"], package_version=d["version"], install_hooks=sorted(d["install_hooks"]), electron_dependency=d["electron_dependency"])
            else:
                t.skip("package", "local:package_json", "no package.json at the top of the folder")
        else:
            t.skip("package", "local:package_json", "only read for a folder; inside an asar it is part of the analysis", na=True)
    tmpdir = None
    if play == "js-file":                                  # rea accepts only a folder or an .asar: copy the one file into an empty folder
        import shutil
        tmpdir = "/tmp/triage-js-%s" % ident["sha256"][:12]
        shutil.rmtree(tmpdir, ignore_errors=True)
        os.makedirs(tmpdir)
        shutil.copyfile(path, os.path.join(tmpdir, ident["name"]))
        target = tmpdir
        t.facts["analysed_as"] = "the file copied into an empty folder"
    try:
        nr = t.call("analysis", "analyze_javascript_application", {"input_path": target, "detail": "summary"}, "js-summary.json", t.first_t)
    finally:
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
    if isinstance(nr, dict) and isinstance(nr.get("summary"), dict):
        sm = nr["summary"]
        t.facts.update(analysis_statistics=sm.get("statistics"), electron=sm.get("electron"), analysis_coverage=(nr.get("coverage") or {}).get("status"))


def classify(path, ident):
    """-> (playbook, members already listed, why not)."""
    magic = ident["magic"]
    if magic in ("elf", "pe"):
        return magic, None, None
    if magic == "asar":
        return "asar", None, None
    if magic == "directory":
        if any(m["path"].endswith(JS_EXT) or m["path"] == "package.json" for m in ident["_members"]):
            return "js-dir", None, None
        return None, None, "a folder with no JavaScript files and no package.json"
    if magic == "zip":
        try:
            ms, _ = list_members(path, "zip")
        except Exception as e:
            return "archive", None, None
        names = {m["path"] for m in ms}
        if "AndroidManifest.xml" in names and any(re.fullmatch(r"classes\d*\.dex", n) for n in names):
            return "apk", ms, None
        return "archive", ms, None
    if magic in ARCHIVES:
        return "archive", None, None
    if magic == "text" and ident["extension"] in JS_EXT:
        return "js-file", None, None
    return None, None, "not covered (magic: %s)" % (magic or "unknown")


def cmd_triage(argv):
    fresh = "--fresh" in argv
    first_t, step_t, rest = 1700.0, 600.0, []
    it = iter(argv)
    for a in it:
        if a == "--timeout": first_t = float(next(it))
        elif a == "--step-timeout": step_t = float(next(it))
        elif a != "--fresh": rest.append(a)
    if len(rest) != 1:
        sys.exit("usage: rea-session.py triage SAMPLE [--fresh] [--timeout S] [--step-timeout S]")
    path = os.path.abspath(rest[0])
    if os.path.islink(path) or not (os.path.isfile(path) or os.path.isdir(path)):
        sys.exit("triage: %s is not a regular file or a folder" % path)
    if not start():
        sys.exit(1)
    base = out_base()
    if not base:
        sys.exit("triage: no writable output folder")
    t0 = time.time()
    ident = identify(path)
    members_dir = ident.pop("_members", None)
    id_cid = tlog("local:identify", {"path": path}, "ok", round(time.time() - t0, 1))
    out = os.path.join(base, "triage", ident["sha256"][:12])
    os.makedirs(out, exist_ok=True)
    tmp_write(os.path.join(out, "identity.json"), json.dumps(ident, indent=1, sort_keys=True) + "\n")
    if members_dir is not None:
        ident["_members"] = members_dir
    play, ready, why = classify(path, ident)
    ident.pop("_members", None)
    t = Triage(ident, out, id_cid, fresh, first_t, step_t)
    t.native = None                                      # only the native playbook decides it
    if not play:
        msg = "triage does not cover this: %s. See the skill: Unpacking / By target." % why
        tmp_write(os.path.join(out, "SUMMARY.json"), json.dumps({"triage": 2, "playbook": None, "sample": ident, "steps": t.steps, "unresolved": [msg]}, indent=1, sort_keys=True) + "\n")
        print("%s\nidentity saved to %s/identity.json" % (msg, out))
        sys.exit(2)
    if members_dir is not None:
        ident["_members"] = members_dir
    if play in ("elf", "pe"): play_native(t, play)
    elif play == "apk": play_apk(t, ready)
    elif play == "archive": play_archive(t, ident["magic"], ready)
    else: play_js(t, play)
    ident.pop("_members", None)
    t.facts["extension_mismatch"] = ident["extension_mismatch"]
    bad = [s for s in t.steps if s["status"] not in ("ok", "n/a")]
    summary = {"triage": 2, "rea": ask({"op": "status"}, 5).get("rea"), "playbook": play, "native_available": t.native, "sample": ident,
               "facts": t.facts, "evidence_ids": t.ev, "steps": t.steps,
               "unresolved": ["%s: %s%s" % (s["step"], s["status"], (": " + s["note"]) if s["note"] else "") for s in bad]}
    tmp_write(os.path.join(out, "SUMMARY.json"), json.dumps(summary, indent=1, sort_keys=True) + "\n")
    print("triage of %s (%s, sha256 %s)  ->  %s" % (ident["name"], play, ident["sha256"][:12], out))
    for s in t.steps:
        print("  %-12s %-8s %-6s %s%s" % (s["step"], s["status"], s["call"] or "-", s["file"] or "", "  [cut]" if s["truncated"] else ""))
    print("facts: " + json.dumps(t.facts, sort_keys=True))
    if bad:
        print("UNRESOLVED (report these as failed or unavailable, do not fill them from memory):")
        for u in summary["unresolved"]:
            print("  - " + u)
    print("read the saved files in slices (sed -n 'A,Bp', rg); SUMMARY.json lists every step and call id")
    sys.exit(1 if bad else 0)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return
    c = a[0]
    if c == "serve": serve()
    elif c == "start":
        if not start(): sys.exit(1)
        print("session ready (rea --mcp, pid %s)" % ask({"op": "status"}, 5).get("rea_pid"))
    elif c == "call": cmd_call(a[1:])
    elif c == "manifest": cmd_manifest(a[1:])
    elif c == "triage": cmd_triage(a[1:])
    elif c == "tools":
        if not start(): sys.exit(1)
        print("\n".join(ask({"op": "tools"}, 10)["tools"]))
    elif c == "status":
        print(json.dumps(ask({"op": "status"}, 5)) if alive() else "not running")
    elif c == "stop":
        if alive():
            try: r = ask({"op": "stop"}, 10)
            except (OSError, ValueError): r = {}
            if r.get("error"):
                sys.exit("rea-session: the server refused to stop (%s)" % r["error"])
            for _ in range(40):                       # return only when the old server is gone, so an immediate start is a new one
                if not alive():
                    break
                time.sleep(0.25)
            if alive():
                sys.exit("rea-session: the server is still running")
            print("stopped")
        else:
            print("not running")
    else:
        sys.exit("unknown command %r (start, call, tools, manifest, triage, status, stop)" % c)


if __name__ == "__main__":
    main()
