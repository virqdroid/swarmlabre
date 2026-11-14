"""Replay mode of the web UI: a finished run, played back as if it were running.

`Replay` is a *backend* for `server.py` with the same methods as `Swarms` (`api`, `stage_put`, `clip_frame`). It owns a copy of a sealed run folder or an exported bundle
(never written to the original), a virtual clock, and a cursor into the recorded `events.jsonl`. Every route that depends on time answers *as of the cursor*:

  * the event long-poll returns the events up to the cursor (`since?cursor&wait` waits for the cursor to move);
  * the run record (`swarm/<id>`) is rebuilt from the events: status, phase, steps, tasks as they were, counts;
  * the board is folded from the `finding`/`resolution` and `reject` events, which carry the whole finding as it stood;
  * the report, its downloads and the end state appear only once the recorded `done` event is played.

Nothing here starts a model, a container or a process. What a bundle does not hold (the agents' thinking, per-task transcripts, the model's request timings) is answered
as "not recorded" instead of invented. The same fold, `View`, is the model for the in-page shim of the static demo (`tools/shim.js` implements it again in JavaScript;
`tests/test_player.py` checks that both agree).
"""
import copy
import json
import math
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

from . import replay as replaymod, swarms as swm
from .services import make_ctx

MAX_EVENTS_FILE = 64 << 20
STATUS_OF_PHASE = {"prepare": "preparing", "merge": "merging"}


class ReplayError(Exception):
    pass


def clamp_speed(v):
    """The replay clock's speed, held to 0.1 to 10000 times real time (a zero or negative value would stop or reverse the clock). NaN and infinity are refused (ValueError)."""
    v = float(v)
    if not math.isfinite(v):
        raise ValueError("bad speed")
    return max(0.1, min(v, 10000.0))


def _copy_bundle(src, dst):
    """Copy regular files and folders only (no symlinks, no devices), skipping the model trace (large, and the player never reads it)."""
    dst.mkdir(parents=True)
    for p in sorted(src.iterdir()):
        if p.is_symlink() or p.name in ("model-trace.jsonl.gz", "nonce.key", "tasks", "proxy", "cfg", "clip"):
            continue
        if p.is_dir():
            _copy_bundle(p, dst / p.name)
        elif p.is_file():
            shutil.copyfile(p, dst / p.name)


def load_events(path):
    """-> the recorded events in order. Each is kept only if it has the three fields the player relies on."""
    try:
        if Path(path).stat().st_size > MAX_EVENTS_FILE:
            raise ReplayError("events.jsonl is larger than %d MiB" % (MAX_EVENTS_FILE >> 20))
        rows = []
        with open(path) as f:
            for ln in f:
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(e, dict) and isinstance(e.get("k"), str) and isinstance(e.get("n"), int) and isinstance(e.get("t"), (int, float)):
                    rows.append(e)
    except OSError:
        raise ReplayError("events.jsonl is missing")
    rows.sort(key=lambda e: e["n"])
    if not rows:
        raise ReplayError("events.jsonl holds no events")
    return rows


class View:
    """The run as of a cursor: a fold over events, advanced one event at a time. `reset()` goes back to the start.

    The fold is deliberately simple (replace by id, append, count) so that it can be written a second time in JavaScript for the static demo."""

    def __init__(self, final, events):
        self.final, self.events = final, events
        self.reset()

    def reset(self):
        self.i = 0                           # events played
        self.status, self.reason, self.phase = "queued", None, None
        self.steps, self.step_i = [], {}
        self.tasks, self.task_i = [], {}     # task number -> position in `tasks`
        self.f, self.order, self.rejects = {}, [], []
        self.gate, self.queue = {"waiting": [], "running": []}, {}
        self.layout = False
        self.cov = {}
        self.finished = None

    @property
    def cursor(self):
        return self.events[self.i - 1]["n"] if self.i else 0

    @property
    def done(self):
        return self.finished is not None

    def advance(self, to):
        """Play events until `to` have been played (0..len)."""
        to = max(0, min(int(to), len(self.events)))
        if to < self.i:
            self.reset()
        while self.i < to:
            self.apply(self.events[self.i])
            self.i += 1

    def apply(self, e):
        k = e["k"]
        if k == "waiting":
            self.status = "waiting" if e.get("code") or e.get("why") else "preparing"
        elif k == "phase":
            self.phase = e.get("phase")
            self.status = STATUS_OF_PHASE.get(self.phase, "running")
        elif k == "step":
            row = {"step": e.get("step"), "status": e.get("status"), "msg": e.get("msg", ""), "t": e["t"]}
            j = self.step_i.get(row["step"])
            if j is None:
                self.step_i[row["step"]] = len(self.steps)
                self.steps.append(row)
            else:
                self.steps[j] = row
        elif k == "layout":
            self.layout = True
        elif k == "task_start":
            base = next((t for t in self.final.get("tasks", []) if t.get("n") == e.get("task")), {})
            t = {"n": e.get("task"), "role": e.get("role"), "uid": base.get("uid"), "state": "running", "started": e["t"], "ended": None, "tokens": {"in": 0, "out": 0},
                 "tools": 0, "findings": 0, "model_ms": 0, "tool_ms": 0, "wait_ms": 0, "retries": 0, "round": e.get("round", 1), "steers": 0, "stop": None, "notes": 0, "text": "",
                 "goal": base.get("goal"), "scope": base.get("scope")}
            self.task_i[t["n"]] = len(self.tasks)
            self.tasks.append(t)
        elif k == "tokens":
            t = self._task(e.get("task"))
            if t and t["state"] == "running":
                t["tokens"] = {"in": t["tokens"]["in"] + int(e.get("in") or 0), "out": t["tokens"]["out"] + int(e.get("out") or 0)}
                for key in ("model_ms", "tool_ms", "wait_ms"):
                    t[key] += int(e.get(key) or 0)
        elif k == "tool_start":
            t = self._task(e.get("task"))
            if t and t["state"] == "running":
                t["tools"] += 1
            if e.get("off") is not None:
                self.cov.setdefault(e.get("role"), set()).add((int(e["off"]), int(e.get("len") or 1)))
        elif k == "tool_end":
            for o, n in e.get("places") or []:
                self.cov.setdefault(e.get("role"), set()).add((int(o), int(n)))
        elif k == "task_end":
            n = e.get("task")
            j = self.task_i.get(n)
            base = next((t for t in self.final.get("tasks", []) if t.get("n") == n), None)
            if j is not None and base is not None:
                self.tasks[j] = copy.deepcopy(base)
        elif k in ("finding", "resolution") and isinstance(e.get("f"), dict) and isinstance(e["f"].get("id"), str):
            f = e["f"]
            if f["id"] not in self.f:
                self.order.append(f["id"])
            self.f[f["id"]] = f
            t = self._task(f.get("task"))
            if t and t["state"] == "running" and k == "finding" and e.get("op") == "add":
                t["findings"] += 1
        elif k == "reject" and isinstance(e.get("x"), dict):
            self.rejects.append(e["x"])
        elif k == "gate":
            self.gate = {"waiting": list(e.get("waiting") or []), "running": list(e.get("running") or [])}
        elif k == "tool_queue":
            self.queue = dict(e.get("queue") or {})
        elif k == "done":
            self.status, self.reason, self.finished = e.get("status") or "done", e.get("reason"), e["t"]

    def _task(self, n):
        j = self.task_i.get(n)
        return self.tasks[j] if j is not None else None

    def counts(self):
        c = {"total": len(self.f), "verified": 0, "unconfirmed": 0, "disputed": 0, "refuted": 0, "rejected": len(self.rejects), "byte-checked": 0, "call-cited": 0, "claimed": 0}
        for f in self.f.values():
            c[f.get("status")] = c.get(f.get("status"), 0) + 1
            c[f.get("level")] = c.get(f.get("level"), 0) + 1
        return c

    def board(self, attack):
        return {"findings": [dict(self.f[i]) for i in self.order], "rejected": list(self.rejects), "counts": self.counts(), "attack": attack}

    def coverage(self):
        return {k: sorted(v) for k, v in self.cov.items()}

    EARLY = ("id", "created", "started", "brief", "roles", "parallel", "sample", "model", "report", "limits", "native", "env", "sampling")     # in a live record from the start of the run

    def run(self, why):
        """The run record as of the cursor, in the shape of `Swarms.run_view`. Before the `done` event only what a live record holds by then: the keys a run starts with, the
        steps and tasks played so far, the rounds begun. The summary, the assessment, the model statistics and the peak memory appear with the end."""
        if self.done:
            r = copy.deepcopy(self.final)
            r.update(status=self.status, reason=self.reason, waiting=None, finished=self.finished, phase=self.phase, counts=self.counts())
        else:
            r = {k: copy.deepcopy(self.final[k]) for k in self.EARLY if k in self.final}
            began = 2 if self.phase in ("round2", "merge") else 1 if self.phase in ("round1",) else 0
            rounds = [copy.deepcopy(x) for x in self.final.get("rounds", []) if x.get("n", 0) <= began]
            for x in rounds:
                if x.get("n", 0) == began and self.phase != "merge":
                    x.pop("summary", None)
            r.update(status=self.status, reason=None, waiting=None, finished=None, phase=self.phase, steps=copy.deepcopy(self.steps), tasks=copy.deepcopy(self.tasks), counts=self.counts(),
                     peaks={"tools_mib": 0, "agents_mib": 0}, rounds=rounds)
        r.update(pausing=0, why=why if self.done else "", seq=self.cursor, waiting_why="", gate=dict(self.gate), queue=dict(self.queue),
                 has_report=self.done, has_html=self.done, has_iocs=self.done and self.final.get("_has_iocs", True), has_yara=self.done and self.final.get("_has_yara", False))
        r.pop("_has_iocs", None)
        r.pop("_has_yara", None)
        return r


class Replay:
    """A `Swarms`-shaped backend that plays one recorded run."""

    def __init__(self, source, speed=1.0, paused=False, skills_dir=None):
        src = Path(source).expanduser().resolve()
        if not src.is_dir():
            raise ReplayError("not a folder: %s" % source)
        try:
            res = replaymod.replay(src)
        except replaymod.ReplayError as e:
            raise ReplayError("cannot replay %s: %s" % (src.name, e))
        if not res["ok"]:
            raise ReplayError("%s does not replay byte for byte (see `swarmlabre replay`); refusing to show it" % src.name)
        self.level = res["level"]
        self.tmp = tempfile.TemporaryDirectory(prefix="swarmlabre-play-")
        work = Path(self.tmp.name) / "runs" / src.name
        _copy_bundle(src, work)
        cfg = {"swarm": {"enabled": True, "report_logo": False}, "model": {}}
        ctx = make_ctx(cfg, Path(self.tmp.name), skills_dir or swm.ROOT / "skills")
        ctx.state_dir = work.parent
        self.sw = swm.Swarms(ctx, cfg["swarm"])
        self.rid = src.name
        rt = self.sw.rts.get(self.rid)
        if not rt:
            raise ReplayError("the run record is not readable")
        self.rt = rt
        self.events = load_events(work / "events.jsonl")
        self.t0 = self.events[0]["t"]
        final = copy.deepcopy(rt.rec)
        out = work / "out"
        final["_has_iocs"] = (out / "iocs.csv").is_file()
        final["_has_yara"] = (out / "detection.yar").is_file()
        self.view = View(final, self.events)
        self.out = out
        self.attack = self.sw._board(rt).view()["attack"]
        self.cond = threading.Condition()
        self.speed = clamp_speed(speed)
        self.paused = bool(paused)
        self.base_v, self.base_w = 0.0, time.monotonic()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self._tick()                          # the first events (all at t0) are already played
        self.thread.start()

    # ---- the clock
    def vnow(self):
        return self.base_v + (0 if self.paused else (time.monotonic() - self.base_w) * self.speed)

    def _rebase(self):
        self.base_v, self.base_w = self.vnow(), time.monotonic()

    def _tick(self):
        with self.cond:
            v = self.vnow()
            to = self.view.i
            while to < len(self.events) and self.events[to]["t"] - self.t0 <= v:
                to += 1
            if to != self.view.i:
                self.view.advance(to)
                self.cond.notify_all()
            return v

    def _loop(self):
        while not self.stop.is_set():
            self._tick()
            with self.cond:
                if self.view.i >= len(self.events) or self.paused or self.speed <= 0:
                    self.cond.wait(0.5)
                else:
                    due = (self.events[self.view.i]["t"] - self.t0 - self.vnow()) / self.speed
                    self.cond.wait(min(max(due, 0.01), 0.5))

    def control(self, body):
        """POST /api/replay {speed?, paused?, restart?, at?, end?} -> the clock's state."""
        with self.cond:
            self._rebase()
            if "speed" in body:
                try:
                    self.speed = clamp_speed(body["speed"])
                except (TypeError, ValueError):
                    return 400, {"error": "bad speed"}
            if "paused" in body:
                self.paused = bool(body["paused"])
            if body.get("restart"):
                self.view.reset()
                self.base_v = 0.0
                self.paused = bool(body.get("paused", False))
            if "at" in body:                                  # seek: play (or rewind and play) to this many seconds from the start
                try:
                    self.base_v = max(0.0, float(body["at"]))
                except (TypeError, ValueError):
                    return 400, {"error": "bad position"}
                self.view.advance(sum(1 for e in self.events if e["t"] - self.t0 <= self.base_v))
            if body.get("end"):
                self.view.advance(len(self.events))
                self.base_v = self.events[-1]["t"] - self.t0
            self.base_w = time.monotonic()
            self.cond.notify_all()
        self._tick()
        return 200, self.state()

    def state(self):
        with self.cond:
            total = round(self.events[-1]["t"] - self.t0, 1)
            return {"speed": self.speed, "paused": self.paused, "events": len(self.events), "played": self.view.i, "finished": self.view.done, "level": self.level,
                    "seconds": total, "at": round(min(self.vnow(), total), 3), "t0": self.t0}

    def close(self):
        self.stop.set()
        with self.cond:
            self.cond.notify_all()
        self.tmp.cleanup()

    # ---- what the server calls
    def stage_put(self, h, u, n):
        h.close_connection = True
        return h.reply(409, {"error": "This is a recorded run. Nothing can be uploaded or started."})

    def clip_frame(self, h, rid, n):
        h.close_connection = True
        return h.reply(409, {"error": "A clip cannot be made from a replay."})

    def since(self, cursor, wait):
        with self.cond:
            if wait and cursor == self.view.cursor and not self.view.done:
                self.cond.wait(wait)
            first = self.events[0]["n"]
            upto = self.view.i
            played = self.events[:upto][-swm.MAX_EVENTS:]
            seq = self.view.cursor
            gap = (cursor + 1 < (played[0]["n"] if played else seq + 1) and cursor > 0) or cursor > seq
            return {"seq": seq, "gap": gap, "events": [e for e in played if e["n"] > cursor], "status": self.view.status, "reason": self.view.reason}

    def facts(self):
        """What the launch sheet reads, for a recording: nothing can be started, so no clip button, no memory check, and the model is the one the run used."""
        f = self.sw.facts()
        f.update(clip=False, model=self.view.final.get("model"), fit={"ok": True, "need_gib": f["fit"]["need_gib"], "free_gib": f["fit"]["need_gib"]})
        return f

    def listing(self):
        r = self.run_record()
        return {"enabled": True, "facts": self.facts(), "stage": None,
                "runs": [{k: r.get(k) for k in ("id", "status", "reason", "why", "created", "finished", "sample", "model", "counts")}],
                "active": None if self.view.done else self.rid}

    def run_record(self):
        with self.cond:
            return self.view.run(swm.WHY.get(self.view.reason or "", ""))

    def api(self, h, method, parts, u, body):
        if parts == [] and method == "GET":
            return h.reply(200, self.listing())
        if method == "POST":
            return h.reply(409, {"error": "This is a recorded run. Nothing can be started, stopped or changed."})
        if parts == ["model-stats"]:
            return h.reply(404, {"error": "Model statistics are not recorded in a bundle."})
        if not parts or parts[0] != self.rid:
            return h.reply(404, {"error": "unknown action"})
        rest = parts[1:]
        v = self.view
        if rest == []:
            return h.reply(200, self.run_record())
        if rest == ["events"]:
            q = parse_qs(u.query)
            try:
                cur = int(q.get("since", ["0"])[0])
                wait = min(max(float(q.get("wait", ["0"])[0]), 0), 25)
            except ValueError:
                return h.reply(400, {"error": "bad query"})
            return h.reply(200, self.since(cur, wait))
        if rest == ["layout"]:
            lay = self.sw.layout(self.rid) if v.layout else None
            return h.reply(200, lay) if lay else h.reply(404, {"error": "no layout yet"})
        if rest == ["coverage"]:
            with self.cond:
                return h.reply(200, {"ranges": v.coverage()})
        if rest == ["bytes"]:
            q = parse_qs(u.query)
            try:
                off, n = int(q.get("off", [""])[0], 0), int(q.get("len", ["64"])[0], 0)
            except ValueError:
                return h.reply(400, {"error": "bad query"})
            code, out = self.sw.peek(self.rid, off, n)
            return h.reply(code, out)
        if rest == ["thoughts"]:
            return h.reply(200, {"thoughts": []})
        if rest == ["model"]:
            return h.reply(404, {"error": "The model's request timings are not recorded in a bundle."})
        if rest == ["board"]:
            with self.cond:
                return h.reply(200, v.board(self.attack))
        if len(rest) == 2 and rest[0] == "finding":
            with self.cond:
                f = v.f.get(rest[1])
                if not f:
                    return h.reply(404, {"error": "no such finding"})
                return h.reply(200, {"finding": dict(f, manifest=[])})
        if len(rest) == 2 and rest[0] == "task" and rest[1].isdigit():
            with self.cond:
                t = next((t for t in v.tasks if t["n"] == int(rest[1])), None)
                if not t:
                    return h.reply(404, {"error": "no such task"})
                keep = ("n", "role", "state", "started", "ended", "tokens", "model_ms", "tool_ms", "wait_ms", "tools", "findings", "retries", "round", "goal", "scope", "steers", "stop", "text")
                return h.reply(200, {"task": {k: t.get(k) for k in keep}, "calls": [], "notes": "", "findings": [i for i in v.order if v.f[i].get("task") == t["n"]]})
        if rest in (["report"], ["report.md"], ["board.json"]) or (len(rest) == 1 and rest[0] in self.sw.DOWNLOADS):
            if not v.done:
                return h.reply(404, {"error": "no report yet"})
            return self._file(h, rest[0])
        return h.reply(404, {"error": "unknown action"})

    def _file(self, h, name):
        f = self.out / ("report.json" if name == "report" else name)
        try:
            raw = f.read_bytes()
        except OSError:
            return h.reply(404, {"error": "no report yet"})
        if name in self.sw.DOWNLOADS:
            h.send_response(200)
            for k, val in (("Content-Type", self.sw.DOWNLOADS[name]), ("Content-Length", str(len(raw))), ("Content-Disposition", 'attachment; filename="swarm-%s-%s"' % (self.rid, name)),
                           ("Content-Security-Policy", "sandbox"), ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-store")):
                h.send_header(k, val)
            h.end_headers()
            h.wfile.write(raw)
            return
        return h.reply(200, raw.decode("utf-8", "replace"), "text/markdown; charset=utf-8" if name.endswith(".md") else "application/json")
