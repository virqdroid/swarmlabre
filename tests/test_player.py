"""Replay mode: the fold over events (`View`) and the `Replay` backend, served through the real server."""
import http.client
import json
import tempfile
import time
import unittest
from pathlib import Path

import fixtures
from swarmlabre import player, server, swarms as swm


class FoldTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = fixtures.record_run(cls.tmp.name)
        cls.final = json.loads((cls.d / "swarm.json").read_text())
        cls.events = player.load_events(cls.d / "events.jsonl")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def view_at(self, n):
        v = player.View(self.final, self.events)
        v.advance(n)
        return v

    def test_the_end_state_is_the_board_the_run_ended_with(self):
        from swarmlabre import cli, config
        sw = cli._swarms(config.defaults(), self.d.parent)
        want = sw._board(sw.rts[self.d.name]).view()
        v = self.view_at(len(self.events))
        got = v.board(want["attack"])
        self.assertEqual(got["findings"], want["findings"])
        self.assertEqual(got["rejected"], want["rejected"])
        self.assertEqual(got["counts"], want["counts"])
        self.assertTrue(v.done)

    def test_no_future_leaks_into_an_earlier_view(self):
        """At every prefix: only findings whose event was played are there, a dispute appears with its event, a resolution only with its own."""
        seen = set()
        for i, e in enumerate(self.events, 1):
            v = self.view_at(i)
            if e["k"] in ("finding", "resolution"):
                seen.add(e["f"]["id"])
            self.assertEqual(set(v.f), seen, "after event %d (%s)" % (e["n"], e["k"]))
            self.assertEqual(v.cursor, e["n"])
            self.assertEqual(len(v.rejects), sum(1 for x in self.events[:i] if x["k"] == "reject"))
        # f1 goes verified -> disputed -> resolved
        by = {e["n"]: e for e in self.events}
        stages = [self.view_at(i).f.get("f1", {}) for i in range(len(self.events) + 1)]
        self.assertEqual([s.get("status") for s in stages if s][0], "verified")
        self.assertIn("disputed", [s.get("status") for s in stages if s])
        self.assertIn("resolution", stages[-1])
        self.assertNotIn("resolution", [s for s in stages if s and s.get("status") == "disputed"][0])

    def test_rewinding_gives_the_same_view_as_playing_to_that_point(self):
        v = self.view_at(len(self.events))
        v.advance(9)
        w = self.view_at(9)
        self.assertEqual(json.dumps(v.run(""), sort_keys=True), json.dumps(w.run(""), sort_keys=True))
        self.assertEqual(v.board({}), w.board({}))

    def test_the_record_before_the_end_holds_only_what_a_live_one_would(self):
        v = self.view_at([i for i, e in enumerate(self.events, 1) if e["k"] == "reject"][0])
        r = v.run("")
        self.assertEqual((r["status"], r["phase"], r["has_report"], r["has_html"], r["finished"]), ("running", "round1", False, False, None))
        for k in ("summary", "assessment", "summary_sections", "model_stats"):
            self.assertNotIn(k, r)
        self.assertEqual(r["peaks"], {"tools_mib": 0, "agents_mib": 0})
        self.assertEqual([t["state"] for t in r["tasks"]], ["running"] * 3)
        self.assertEqual(r["counts"]["total"], 2)
        self.assertEqual(r["counts"]["rejected"], 1)
        self.assertEqual(r["tasks"][0]["tools"], 1)
        self.assertEqual(r["tasks"][0]["tokens"], {"in": 900, "out": 40})

    def test_a_finished_task_takes_its_recorded_values_and_a_running_one_has_no_text(self):
        i = [i for i, e in enumerate(self.events, 1) if e["k"] == "task_end"][0]
        r = self.view_at(i).run("")
        done = {t["n"]: t for t in r["tasks"]}
        self.assertEqual(done[1]["state"], "done")
        self.assertEqual(done[1]["text"], "Posted two findings.")
        self.assertEqual((done[2]["state"], done[2]["text"]), ("running", ""))

    def test_the_end_record_is_the_final_one(self):
        r = self.view_at(len(self.events)).run("")
        self.assertEqual((r["status"], r["has_report"], r["has_html"], r["has_iocs"]), ("done", True, True, True))
        self.assertEqual(r["summary"], self.final["summary"])
        self.assertNotIn("_has_iocs", r)

    def test_bad_event_lines_are_dropped_not_trusted(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "events.jsonl"
            p.write_text('{"k":"phase","n":2,"t":5.0}\nnot json\n{"k":1,"n":3,"t":1}\n{"k":"done","n":"x","t":1}\n[1,2]\n{"k":"done","n":1,"t":4.0,"status":"done"}\n')
            self.assertEqual([e["n"] for e in player.load_events(p)], [1, 2])
            p.write_text("")
            with self.assertRaises(player.ReplayError):
                player.load_events(p)


class ServedReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = fixtures.record_run(cls.tmp.name)
        cls.before = {p.name: p.read_bytes() for p in cls.d.iterdir() if p.is_file()}
        cls.rep = player.Replay(cls.d, speed=1.0, paused=True)
        cls.token = server.load_token(Path(cls.tmp.name) / "state")
        cls.app = server.App(cls.rep, cls.token, "replay", "recorded", "127.0.0.1", extra={"run": cls.rep.rid})
        cls.srv = server.make_server(cls.app, "127.0.0.1", 0)
        cls.port = cls.srv.server_address[1]
        server.serve_forever(cls.srv)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.rep.close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=None if body is None else json.dumps(body), headers={"Authorization": "Bearer " + self.token})
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw

    def seek(self, at):
        return self.call("POST", "/api/replay", {"at": at, "paused": True})[1]

    def test_it_refuses_a_run_that_does_not_replay_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as t:
            bad = fixtures.record_run(t)
            p = bad / "inputs.jsonl"
            p.write_text(p.read_text().replace("C2 URL", "C2 url"))
            with self.assertRaises(player.ReplayError):
                player.Replay(bad)

    def test_the_original_run_folder_is_not_touched(self):
        self.seek(30)
        self.call("GET", "/api/swarm/%s/board" % self.rep.rid)
        self.assertEqual(self.before, {p.name: p.read_bytes() for p in self.d.iterdir() if p.is_file()})

    def test_the_clock_seeks_pauses_and_reports(self):
        st = self.seek(10)
        self.assertEqual((st["paused"], st["at"], st["finished"]), (True, 10.0, False))
        time.sleep(0.4)
        self.assertEqual(self.call("GET", "/api/replay")[1]["at"], 10.0, "paused means paused")
        st = self.call("POST", "/api/replay", {"speed": 8, "paused": False})[1]
        self.assertEqual((st["speed"], st["paused"]), (8.0, False))
        time.sleep(0.5)
        self.assertGreater(self.call("GET", "/api/replay")[1]["at"], 10.0)
        self.assertEqual(self.call("POST", "/api/replay", {"speed": "fast"})[0], 400)
        st = self.call("POST", "/api/replay", {"restart": True, "paused": True})[1]
        self.assertEqual((st["at"], st["played"] > 0, st["finished"]), (0.0, True, False))

    def test_routes_answer_as_of_the_cursor(self):
        rid = self.rep.rid
        self.seek(7)                                       # f1 and f2 posted, the reject played, nobody finished
        code, run = self.call("GET", "/api/swarm/" + rid)
        self.assertEqual((code, run["status"], run["counts"]["total"], run["has_report"]), (200, "running", 2, False))
        self.assertEqual(self.call("GET", "/api/swarm/%s/report.html" % rid)[0], 404, "no report before the end")
        self.assertEqual(self.call("GET", "/api/swarm/%s/report" % rid)[0], 404)
        code, board = self.call("GET", "/api/swarm/%s/board" % rid)
        self.assertEqual([f["id"] for f in board["findings"]], ["f1", "f2"])
        self.assertEqual(self.call("GET", "/api/swarm/%s/finding/f3" % rid)[0], 404, "f3 is posted later")
        self.assertEqual(self.call("GET", "/api/swarm/%s/finding/f1" % rid)[1]["finding"]["status"], "verified")
        code, ev = self.call("GET", "/api/swarm/%s/events?since=0&wait=0" % rid)
        self.assertEqual(ev["seq"], ev["events"][-1]["n"])
        self.assertTrue(all(e["t"] - self.rep.t0 <= 7 for e in ev["events"]))
        self.assertEqual(self.call("GET", "/api/swarm")[1]["active"], rid)
        self.seek(60)
        run = self.call("GET", "/api/swarm/" + rid)[1]
        self.assertEqual((run["status"], run["has_report"]), ("done", True))
        self.assertEqual(self.call("GET", "/api/swarm")[1]["active"], None)
        code, md = self.call("GET", "/api/swarm/%s/report.md" % rid)
        self.assertEqual(code, 200)
        self.assertIn(b"tiny demo program", md if isinstance(md, bytes) else json.dumps(md).encode())
        self.assertEqual(self.call("GET", "/api/swarm/%s/board" % rid)[1]["findings"][0]["resolution"]["verdict"], "stands")

    def test_event_long_poll_waits_for_the_cursor_and_returns_when_it_moves(self):
        rid = self.rep.rid
        st = self.seek(10)
        seq = self.call("GET", "/api/swarm/%s/events?since=0" % rid)[1]["seq"]
        t0 = time.time()
        code, ev = self.call("GET", "/api/swarm/%s/events?since=%d&wait=0.6" % (rid, seq))
        self.assertGreaterEqual(time.time() - t0, 0.5, "paused: nothing new, so it waits the full time")
        self.assertEqual(ev["events"], [])

    def test_nothing_can_be_changed(self):
        rid = self.rep.rid
        for path in ("start", rid + "/stop", rid + "/pause", rid + "/steer", rid + "/delete", rid + "/clip/start", "stage/clear"):
            self.assertEqual(self.call("POST", "/api/swarm/" + path, {})[0], 409, path)
        self.assertEqual(self.call("POST", "/api/swarm/stage?name=a.elf", {})[0], 409)

    def test_what_a_bundle_does_not_hold_is_said_so(self):
        rid = self.rep.rid
        self.assertEqual(self.call("GET", "/api/swarm/%s/model" % rid)[0], 404)
        self.assertEqual(self.call("GET", "/api/swarm/%s/thoughts" % rid)[1], {"thoughts": []})


if __name__ == "__main__":
    unittest.main()
