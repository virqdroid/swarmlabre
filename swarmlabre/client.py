"""Model clients: where a run gets its answers from. One interface, three implementations.

`OpenAICompat` talks to any OpenAI-compatible endpoint (llama.cpp, vLLM, Ollama, a hosted API). `Mock` answers from a script, with no GPU, key or network.
The gate (gate.py) is the only caller during a run; it opens a request through `client.open(...)` and copies the reply to the agent container, so a
client never sees the container and the container never sees a key.
"""
import hashlib
import http.client
import io
import json
import os
import re
import threading
import time
import urllib.parse

from .textutil import register_secret


class NoModel(ValueError):
    """No model is configured at all (as opposed to a configured one that is wrong or unreachable): the command line answers it with exit code 3."""


class ModelError(RuntimeError):
    pass


class Reply:
    """What `open` returns: the part of an http.client response the gate uses (status, header, read1, close)."""

    def __init__(self, status, headers, body=None, raw=None, conn=None):
        self.status, self._h, self._raw, self._conn = status, {k.lower(): v for k, v in headers.items()}, raw, conn
        self._body = io.BytesIO(body) if body is not None else None

    def getheader(self, name, default=None):
        return self._h.get(name.lower(), default)

    def read1(self, n=8192):
        if self._body is not None:
            return self._body.read(n)
        return self._raw.read1(n)

    def read(self):
        out = b""
        while chunk := self.read1(65536):
            out += chunk
        return out

    def close(self):
        for x in (self._raw, self._conn):
            try:
                if x is not None:
                    x.close()
            except Exception:
                pass


class ModelClient:
    """Base class. Subclasses implement `open` and `info`."""
    name = "client"

    def open(self, method, path, body=None, headers=None, role="-"):
        """Send one request to `<base>/<path>` ("/models", "/chat/completions"); -> Reply. Raises ModelError when the server cannot be reached."""
        raise NotImplementedError

    def info(self):
        """-> {"backend": str, "model": str} for the run record, or None when no model can be reached."""
        raise NotImplementedError

    def sampling(self):
        """What this client says about repeatability: {"pinned": [...], "seed_support": "honoured" | "unknown" | "ignored"}. Goes into the run manifest."""
        return {"seed_support": "unknown"}

    def chat(self, messages, max_tokens=2048, role="orchestrator", extra=None):
        """One non-streaming chat call -> the reply text (think blocks removed). `extra` is merged into the request body."""
        model = (self.info() or {}).get("model") or ""
        req = {"model": model, "max_tokens": max_tokens, "stream": False, "messages": messages, **(extra or {})}
        r = self.open("POST", "/chat/completions", json.dumps(req).encode(), {"Content-Type": "application/json"}, role=role)
        try:
            raw = r.read()
        finally:
            r.close()
        if r.status != 200:
            raise ModelError("the model server answered %s" % r.status)
        try:
            msg = (json.loads(raw)["choices"][0]["message"]) or {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelError("the model server sent an unreadable answer")
        return re.sub(r"(?s)<think>.*?</think>", "", msg.get("content") or "").split("</think>")[-1]


class OpenAICompat(ModelClient):
    name = "openai"

    def __init__(self, base_url, api_key="", model="", timeout=600):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("model.base_url must be an http(s) URL such as http://127.0.0.1:8080/v1")
        self.u, self.key, self.want, self.timeout = u, api_key, model, timeout
        register_secret(api_key)                  # scrub() hides it in every log string, and the container check looks for it in what a container prints
        self._info = (0.0, None)
        self._lock = threading.Lock()

    def open(self, method, path, body=None, headers=None, role="-"):
        cls = http.client.HTTPSConnection if self.u.scheme == "https" else http.client.HTTPConnection
        h = {"Content-Type": "application/json", "Accept": "*/*", **(headers or {})}
        if self.key:
            h["Authorization"] = "Bearer " + self.key
        try:
            c = cls(self.u.hostname, self.u.port, timeout=self.timeout)
            c.request(method, self.u.path.rstrip("/") + path, body, h)
            r = c.getresponse()
        except (OSError, http.client.HTTPException) as e:
            raise ModelError("the model server is unreachable (%s)" % type(e).__name__)
        return Reply(r.status, dict(r.getheaders()), raw=r, conn=c)

    def models(self):
        r = self.open("GET", "/models")
        try:
            data = json.loads(r.read()) if r.status == 200 else {}
        except ValueError:
            data = {}
        finally:
            r.close()
        return [m for m in (data.get("data") or []) if isinstance(m, dict) and m.get("id")]

    def info(self):
        with self._lock:
            at, v = self._info
            if time.time() - at < 20:
                return v
        try:
            listed = self.models()
        except ModelError:
            listed = []
        pick = next((m for m in listed if m["id"] == self.want), None) or (listed[0] if listed and not self.want else None)
        v = {"backend": self.u.hostname + (":%d" % self.u.port if self.u.port else ""), "model": pick["id"]} if pick else None
        with self._lock:
            self._info = (time.time(), v)
        return v

    def probe_seed(self, seed=1234):
        """Ask the same short question twice at a high temperature with one seed. Equal answers = the server honours `seed`; different = it ignores it.
        One cheap pair of requests, made once per run; the answer goes into the run record. Never raises."""
        model = (self.info() or {}).get("model") or ""
        req = {"model": model, "max_tokens": 24, "temperature": 1.0, "seed": seed, "stream": False,
               "messages": [{"role": "user", "content": "Write one sentence about a lighthouse."}]}
        try:
            outs = []
            for _ in range(2):
                r = self.open("POST", "/chat/completions", json.dumps(req).encode(), {"Content-Type": "application/json"})
                try:
                    m = json.loads(r.read())["choices"][0]["message"] if r.status == 200 else None
                    outs.append(None if m is None else (m.get("content") or m.get("reasoning_content") or m.get("reasoning") or ""))      # a reasoning model may answer only there
                finally:
                    r.close()
            self._seed = "unknown" if None in outs or not outs[0] else ("honoured" if outs[0] == outs[1] else "ignored")
        except (ModelError, ValueError, KeyError, IndexError, TypeError):
            self._seed = "unknown"
        return self._seed

    _seed = "unknown"

    def sampling(self):
        return {"seed_support": self._seed}


def _sse(obj):
    return ("data: %s\n\n" % json.dumps(obj, separators=(",", ":"))).encode()


class Mock(ModelClient):
    """A scripted model. The script is a dict:

        {"model": "mock-1",
         "roles": {"triage": [step, step, ...], ...},      # a step: {"text": "...", "tool": "bash", "args": {...}}; no "tool" = the final answer
         "orchestrator": ["reply text", ...]}              # answers to the planning calls, in order; after the list a plan with no tasks

    The turn of an agent is the number of assistant messages already in the conversation it sends, so a reply depends only on the request (never on
    arrival order), which is what makes a mock run, and later a replay, independent of how the six agents interleave.
    """
    name = "mock"
    EMPTY_PLAN = json.dumps({"summary": "Round 1 covered the brief.", "tasks": [], "resolutions": []})

    def __init__(self, script):
        if not isinstance(script, dict):
            raise ValueError("a mock script is a JSON object")
        self.script = script
        self.roles = script.get("roles") or {}
        self.orch = list(script.get("orchestrator") or [])
        self.model = str(script.get("model") or "mock-1")
        self.lock = threading.Lock()
        self.asked = 0
        self.seen = []                      # (role, request body) of the last 50 requests, for tests

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls(json.load(f))

    def info(self):
        return {"backend": "mock", "model": self.model}

    def sampling(self):
        return {"seed_support": "honoured", "note": "scripted replies do not depend on sampling"}

    def open(self, method, path, body=None, headers=None, role="-"):
        if method == "GET" and path == "/models":
            return Reply(200, {"Content-Type": "application/json"}, json.dumps({"object": "list", "data": [{"id": self.model, "object": "model"}]}).encode())
        if method != "POST" or path != "/chat/completions":
            return Reply(404, {"Content-Type": "application/json"}, b'{"error":{"message":"not found"}}')
        try:
            req = json.loads(body or b"{}")
        except ValueError:
            return Reply(400, {"Content-Type": "application/json"}, b'{"error":{"message":"bad json"}}')
        msgs = req.get("messages") or []
        with self.lock:
            self.seen = (self.seen + [(role, req)])[-50:]
        if role in ("orchestrator", "-") and not req.get("tools"):
            with self.lock:
                text = self.orch[self.asked] if self.asked < len(self.orch) else self.EMPTY_PLAN
                self.asked += 1
            return self._answer(req, {"content": text})
        turn = sum(1 for m in msgs if isinstance(m, dict) and m.get("role") == "assistant")
        steps = self.roles.get(role) or []
        step = steps[turn] if turn < len(steps) else {"text": "Nothing more to add."}
        msg = {"content": step.get("text") or ""}
        if step.get("tool"):
            cid = "call_" + hashlib.sha1(("%s/%d" % (role, turn)).encode()).hexdigest()[:20]
            msg["tool_calls"] = [{"index": 0, "id": cid, "type": "function", "function": {"name": step["tool"], "arguments": json.dumps(step.get("args") or {})}}]
        return self._answer(req, msg)

    def _answer(self, req, msg):
        calls = msg.get("tool_calls")
        finish = "tool_calls" if calls else "stop"
        n_in = len(json.dumps(req.get("messages") or []))
        usage = {"prompt_tokens": n_in // 4, "completion_tokens": max(1, len(msg.get("content") or "") // 4 + (8 if calls else 0)), "total_tokens": 0}
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
        base = {"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 0, "model": self.model}
        if not req.get("stream"):
            m = {"role": "assistant", "content": msg.get("content") or ""}
            if calls:
                m["tool_calls"] = [{k: v for k, v in c.items() if k != "index"} for c in calls]
            out = {**base, "object": "chat.completion", "choices": [{"index": 0, "message": m, "finish_reason": finish}], "usage": usage}
            return Reply(200, {"Content-Type": "application/json"}, json.dumps(out).encode())
        parts = []
        if msg.get("content"):
            parts.append(_sse({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": msg["content"]}, "finish_reason": None}]}))
        if calls:
            parts.append(_sse({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": calls}, "finish_reason": None}]}))
        parts.append(_sse({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}))
        parts.append(_sse({**base, "choices": [], "usage": usage}))
        parts.append(b"data: [DONE]\n\n")
        return Reply(200, {"Content-Type": "text/event-stream"}, b"".join(parts))


class Replay(ModelClient):
    """Answers from a recorded model trace (`model-trace.jsonl.gz` of a run) instead of a model. A streamed request is matched by the SHA-256 of the body the gate
    forwarded, which covers the whole conversation, so a reply is only served to the request it was recorded for; the planning calls are matched by the hash of their
    prompts, or taken in order. A request with no recording gets HTTP 409 and is counted in `self.diverged`: the run is no longer the recorded one.
    With the containers running, this re-plays the agents against the exact model replies of the recording."""
    name = "replay"

    def __init__(self, records, model=None):
        self.chats, self.asks, self.diverged = {}, [], []
        self.lock = threading.Lock()
        for r in records:
            if r.get("kind") == "chat":
                self.chats.setdefault((r["role"], r["req_sha256"]), []).append(r)
            elif r.get("kind") == "ask":
                self.asks.append(r)
        self.model = model or {"backend": "replay", "model": "recorded"}

    @classmethod
    def from_run(cls, run_dir):
        import gzip
        from pathlib import Path
        d = Path(run_dir)
        with gzip.open(d / "model-trace.jsonl.gz", "rt") as f:
            recs = [json.loads(ln) for ln in f if ln.strip()]
        try:
            model = json.loads((d / "manifest.json").read_text()).get("model")
        except (OSError, ValueError):
            model = None
        return cls(recs, model)

    def info(self):
        return dict(self.model)

    def sampling(self):
        return {"seed_support": "honoured", "note": "replayed from a recorded trace"}

    def open(self, method, path, body=None, headers=None, role="-"):
        if method == "GET" and path == "/models":
            return Reply(200, {"Content-Type": "application/json"}, json.dumps({"object": "list", "data": [{"id": self.model["model"], "object": "model"}]}).encode())
        if method != "POST" or path != "/chat/completions":
            return Reply(404, {"Content-Type": "application/json"}, b'{"error":{"message":"not found"}}')
        sha = hashlib.sha256(body or b"").hexdigest()
        with self.lock:
            q = self.chats.get((role, sha))
            rec = q.pop(0) if q else None
            if rec is None:
                self.diverged.append({"role": role, "req_sha256": sha})
        if rec is None:
            return Reply(409, {"Content-Type": "application/json"}, b'{"error":{"message":"no recorded reply for this request"}}')
        return Reply(200, {"Content-Type": "text/event-stream"}, rec["reply"].encode())

    def chat(self, messages, max_tokens=2048, role="orchestrator", extra=None):
        req = {"system": messages[0]["content"], "user": messages[1]["content"], "max_tokens": max_tokens}
        sha = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
        with self.lock:
            i = next((k for k, r in enumerate(self.asks) if r["req_sha256"] == sha), None)
            if i is None:
                self.diverged.append({"role": "orchestrator", "req_sha256": sha})
                i = 0 if self.asks else None
            rec = self.asks.pop(i) if i is not None else None
        if rec is None or not rec.get("ok"):
            raise ModelError("no recorded reply for this planning call")
        return rec["reply"] or ""


def from_config(cfg):
    """The client the config asks for. `[model] mock = "script.json"` = Mock; otherwise `base_url` is required."""
    m = cfg.get("model", {})
    if m.get("replay"):
        return Replay.from_run(os.path.expanduser(m["replay"]))
    if m.get("mock"):
        return Mock.from_file(os.path.expanduser(m["mock"]))
    if not m.get("base_url"):
        raise NoModel("no model: set [model] base_url (or mock) in swarmlabre.toml")
    return OpenAICompat(m["base_url"], os.environ.get(m.get("api_key_env") or "", ""), m.get("model", ""))
