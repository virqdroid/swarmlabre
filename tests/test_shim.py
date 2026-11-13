"""The static demo's in-page shim (tools/shim.js) and the replay server (player.py) are the same fold written twice. This runs the shim in node and compares what it answers with what
`player.Replay.api` answers, at many cursors: parsed JSON must be equal. It needs node (found on PATH or in the usual place) and skips without it. It always runs on the generated run and on
the committed demo bundle (demo/), and also on ~/swarmlabre-fixtures/bundles when that folder exists."""
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import fixtures
from swarmlabre import player

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path.home() / "swarmlabre-fixtures" / "bundles"
NODE = shutil.which("node") or (str(Path.home() / ".unsloth" / "node" / "bin" / "node") if (Path.home() / ".unsloth" / "node" / "bin" / "node").is_file() else None)
OFFS = [0, 1, 16, 64, 100, 300]
QUIET = {"gate", "lane", "say", "orchestrator", "role_held", "tool_queue"}


def build_demo_module():
    spec = importlib.util.spec_from_file_location("build_demo", ROOT / "tools" / "build-demo.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Handler:
    """Just enough of the server's handler for Replay.api to answer into."""
    close_connection = False

    def __init__(self):
        self.code, self.body, self.sent = None, None, False
        self.wfile = io.BytesIO()

    def reply(self, code, obj, ctype=None):
        self.code, self.body = code, obj

    def send_response(self, code):
        self.code, self.sent = code, True

    def send_header(self, k, v):
        pass

    def end_headers(self):
        pass


def ask(rep, path, query=""):
    h = Handler()
    parts = [p for p in path.split("/") if p]
    assert parts[0] == "swarm"
    rep.api(h, "GET", parts[1:], urlsplit("/api/%s?%s" % (path, query)), None)
    if h.sent:
        return [h.code, h.wfile.getvalue().decode()]
    return [h.code, json.loads(json.dumps(h.body))]


def cursors(events):
    n = len(events)
    if n <= 300:
        return list(range(n + 1))
    want = {0, n}
    want.update(i for i, e in enumerate(events, 1) if e["k"] not in QUIET)
    want.update(range(0, n + 1, 7))
    return sorted(want)


def expected(rep, rid, size, i):
    rep.view.advance(i)
    v = rep.view
    row = {}
    row["run"] = ask(rep, "swarm/" + rid)
    row["board"] = ask(rep, "swarm/%s/board" % rid)
    row["events0"] = ask(rep, "swarm/%s/events" % rid, "since=0")
    row["events_mid"] = ask(rep, "swarm/%s/events" % rid, "since=%d" % (v.cursor - 5 if v.cursor > 5 else 0))
    row["events_future"] = ask(rep, "swarm/%s/events" % rid, "since=%d" % (v.cursor + 3))
    row["coverage"] = ask(rep, "swarm/%s/coverage" % rid)
    row["layout"] = ask(rep, "swarm/%s/layout" % rid)
    row["thoughts"] = ask(rep, "swarm/%s/thoughts" % rid)
    row["list"] = ask(rep, "swarm")
    for fid in v.order[:3] + ["f9999"]:
        row["finding " + fid] = ask(rep, "swarm/%s/finding/%s" % (rid, fid))
    for n in [t["n"] for t in v.tasks[:3]] + [9999]:
        row["task %d" % n] = ask(rep, "swarm/%s/task/%d" % (rid, n))
    for o in OFFS + [size - 1, size + 5]:
        row["bytes %d" % o] = ask(rep, "swarm/%s/bytes" % rid, "off=%d&len=64" % o)
    for name in ("report", "report.md", "board.json", "report.html", "iocs.csv", "iocs.stix.json", "iocs.misp.json", "detection.yar"):
        row["file " + name] = ask(rep, "swarm/%s/%s" % (rid, name))
    row["nope"] = ask(rep, "swarm/%s/model" % rid)
    return row


@unittest.skipUnless(NODE, "node is not installed")
class ShimMatchesPlayerTest(unittest.TestCase):
    def compare(self, bundle, sample_kb=256, label="", drop_sample=False):
        bd = build_demo_module()
        data, _ = bd.collect(bundle, 8.0, True, sample_kb)
        with tempfile.TemporaryDirectory() as td:
            dp = Path(td) / "data.json"
            dp.write_text(json.dumps(data))
            rep = player.Replay(bundle, speed=1.0, paused=True)
            try:
                if drop_sample:                          # the page then has only the windows around findings; so must the player
                    (rep.rt.dir / "input" / "sample").unlink()
                rep.stop.set()
                rep.thread.join(3)                      # nothing may move the cursor but us
                curs = cursors(rep.events)
                size = rep.view.final["sample"]["size"]
                got = {}
                for chunk in [curs[i:i + 60] for i in range(0, len(curs), 60)]:
                    r = subprocess.run([NODE, str(ROOT / "tests" / "shim_probe.js"), str(dp), str(ROOT / "tools" / "shim.js")] + [str(c) for c in chunk], capture_output=True, text=True, timeout=300)
                    self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                    got.update(json.loads(r.stdout))
                self.assertEqual(sorted(int(k) for k in got), curs)
                for i in curs:
                    want, have = expected(rep, rep.rid, size, i), got[str(i)]
                    self.assertEqual(sorted(want), sorted(have), "route set at cursor %d" % i)
                    for k in want:
                        self.assertEqual(want[k], have[k], "%s %s at cursor %d (event %s)" % (label, k, i, rep.view.cursor))
                return len(curs)
            finally:
                rep.close()

    def test_on_the_generated_run(self):
        with tempfile.TemporaryDirectory() as td:
            d = fixtures.record_run(td)
            self.assertGreater(self.compare(d, label="generated"), 10)

    def test_on_the_generated_run_without_the_sample_embedded(self):
        with tempfile.TemporaryDirectory() as td:
            d = fixtures.record_run(td)
            self.assertGreater(self.compare(d, sample_kb=0, label="generated, windows", drop_sample=True), 10)

    def test_on_the_recorded_real_runs(self):
        found = [p for p in sorted((ROOT / "demo").glob("s*")) if p.is_dir()] + ([p for p in sorted(FIXTURES.glob("*")) if p.is_dir()] if FIXTURES.is_dir() else [])
        self.assertTrue(found, "the committed demo bundle (demo/) is missing")
        for p in found:
            with self.subTest(p.name):
                self.assertGreater(self.compare(p, label=p.name), 100)
            with self.subTest(p.name + ", windows only"):
                self.assertGreater(self.compare(p, sample_kb=0, label=p.name + " windows", drop_sample=True), 100)
