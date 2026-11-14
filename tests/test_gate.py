"""The model client and the gate: scripted replies, pinned sampling and the socket protocol, with no Docker and no model."""
import http.client
import json
import socket
import tempfile
import unittest
from pathlib import Path

from swarmlabre import client as clientmod, gate as gatemod


SCRIPT = {"model": "m1", "roles": {"ioc": [{"text": "Looking.", "tool": "bash", "args": {"command": "echo hi"}}, {"text": "Done."}]},
          "orchestrator": ['{"summary":"x","tasks":[],"resolutions":[]}']}


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


def chat(role="ioc", messages=None, **kw):
    return {"model": "m1", "stream": True, "messages": messages or [{"role": "user", "content": "go"}], **kw}


class MockTest(unittest.TestCase):
    def setUp(self):
        self.m = clientmod.Mock(SCRIPT)

    def events(self, reply):
        out = []
        for ln in reply.read().decode().split("\n"):
            if ln.startswith("data: ") and ln != "data: [DONE]":
                out.append(json.loads(ln[6:]))
        return out

    def test_the_reply_depends_on_the_turn_not_on_arrival_order(self):
        r1 = self.m.open("POST", "/chat/completions", json.dumps(chat()).encode(), role="ioc")
        ev = self.events(r1)
        call = next(e["choices"][0]["delta"]["tool_calls"][0] for e in ev if e["choices"] and e["choices"][0]["delta"].get("tool_calls"))
        self.assertEqual(json.loads(call["function"]["arguments"]), {"command": "echo hi"})
        again = self.events(self.m.open("POST", "/chat/completions", json.dumps(chat()).encode(), role="ioc"))
        self.assertEqual(ev, again, "same request, same reply")
        self.assertEqual(call["id"], next(e["choices"][0]["delta"]["tool_calls"][0]["id"] for e in again if e["choices"] and e["choices"][0]["delta"].get("tool_calls")))
        second = chat(messages=[{"role": "user", "content": "go"}, {"role": "assistant", "content": "x", "tool_calls": []}, {"role": "tool", "content": "hi"}])
        ev2 = self.events(self.m.open("POST", "/chat/completions", json.dumps(second).encode(), role="ioc"))
        self.assertEqual(ev2[0]["choices"][0]["delta"]["content"], "Done.")
        self.assertEqual(ev2[-2]["choices"][0]["finish_reason"], "stop")

    def test_orchestrator_calls_take_the_script_in_order_then_an_empty_plan(self):
        self.assertEqual(json.loads(self.m.chat([{"role": "user", "content": "plan"}]))["summary"], "x")
        self.assertEqual(json.loads(self.m.chat([{"role": "user", "content": "plan"}]))["tasks"], [])

    def test_models_and_unknown_paths(self):
        self.assertEqual(json.loads(self.m.open("GET", "/models").read())["data"][0]["id"], "m1")
        self.assertEqual(self.m.open("GET", "/nope").status, 404)


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = clientmod.Mock(SCRIPT)
        self.calls = []
        self.gate = gatemod.Gate(self.m, 2, lambda *a: self.calls.append(a), {"temperature": 0.0, "seed": 7})
        self.rows = []
        self.gate.stat = self.rows.append
        self.sock = str(Path(self.tmp.name) / "p" / "model.sock")
        self.srv = self.gate.start_unix(self.sock)
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close()))

    def post(self, path, body):
        c = UnixConn(self.sock)
        c.request("POST", path, json.dumps(body).encode(), {"Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read().decode()

    def test_pinned_sampling_overwrites_what_the_agent_asked_for(self):
        code, text = self.post("/a/ioc/v1/chat/completions", chat(temperature=1.3, seed=99, top_p=0.5))
        self.assertEqual(code, 200)
        role, req = self.m.seen[-1]
        self.assertEqual((role, req["temperature"], req["seed"], req["top_p"]), ("ioc", 0.0, 7, 0.5))
        self.assertIn("data: [DONE]", text)

    def test_the_stream_is_timed_and_reported(self):
        self.post("/a/ioc/v1/chat/completions", chat())
        self.assertEqual([c[0] for c in self.calls], ["wait", "go", "end"])
        self.assertEqual(len(self.rows), 1)
        self.assertTrue(self.rows[0]["ok"] and self.rows[0]["stream"] and self.rows[0]["role"] == "ioc")
        self.assertGreater(self.rows[0]["events"], 0)

    def test_only_streamed_chat_and_the_model_list_are_allowed(self):
        self.assertEqual(self.post("/a/ioc/v1/chat/completions", chat(stream=False))[0], 400)
        self.assertEqual(self.post("/v1/embeddings", {})[0], 403)
        self.assertEqual(self.post("/a/ioc/v1/models", {})[0], 403, "POST /models is not on the list")
        c = UnixConn(self.sock)
        c.request("GET", "/v1/models")
        r = c.getresponse()
        self.assertEqual((r.status, json.loads(r.read())["data"][0]["id"]), (200, "m1"))

    def test_the_orchestrator_call_goes_through_the_same_gate(self):
        text = self.gate.ask("system", "user")
        self.assertEqual(json.loads(text)["summary"], "x")
        role, req = self.m.seen[-1]
        self.assertEqual((role, req["temperature"], req["seed"]), ("orchestrator", 0.0, 7))
        self.assertEqual(self.rows[-1]["role"], "orchestrator")
        self.assertFalse(self.rows[-1]["stream"])

    def test_pin_leaves_a_body_that_is_not_an_object_alone(self):
        self.assertEqual(self.gate.pin(b"[1]"), b"[1]")
        self.assertEqual(self.gate.pin(b"nope"), b"nope")


class TraceTest(unittest.TestCase):
    """What the gate records, and a Replay client that serves it back."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = clientmod.Mock(SCRIPT)
        self.recs = []
        self.gate = gatemod.Gate(self.m, 2, lambda *a: None, {"temperature": 0.0, "seed": 7})
        self.gate.trace = self.recs.append
        self.sock = str(Path(self.tmp.name) / "p" / "model.sock")
        self.srv = self.gate.start_unix(self.sock)
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close()))

    def post(self, body, gate_sock=None):
        c = UnixConn(gate_sock or self.sock)
        c.request("POST", "/a/ioc/v1/chat/completions", json.dumps(body).encode(), {"Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read().decode()

    def test_every_exchange_is_recorded_whole(self):
        _, text = self.post(chat())
        self.gate.ask("sys", "usr")
        chat_rec, ask_rec = self.recs
        self.assertEqual((chat_rec["kind"], chat_rec["role"], chat_rec["turn"], chat_rec["ok"]), ("chat", "ioc", 0, True))
        self.assertEqual(len(chat_rec["req_sha256"]), 64)
        self.assertIn("data: [DONE]", chat_rec["reply"])
        self.assertEqual((ask_rec["kind"], ask_rec["system"], ask_rec["user"], ask_rec["ok"]), ("ask", "sys", "usr", True))

    def test_replay_serves_the_recorded_reply_to_the_same_request_only(self):
        _, first = self.post(chat())
        self.gate.ask("sys", "usr")
        rep = clientmod.Replay(self.recs)
        gate2 = gatemod.Gate(rep, 2, lambda *a: None, {"temperature": 0.0, "seed": 7})
        sock2 = str(Path(self.tmp.name) / "q" / "model.sock")
        srv2 = gate2.start_unix(sock2)
        self.addCleanup(lambda: (srv2.shutdown(), srv2.server_close()))
        code, again = self.post(chat(), sock2)
        self.assertEqual((code, again.replace(": queued\n\n", "")), (200, first.replace(": queued\n\n", "")))
        self.assertIn("409", self.post(chat(messages=[{"role": "user", "content": "something else"}]), sock2)[1], "an unrecorded request is an SSE error, not a guess")
        self.assertEqual(len(rep.diverged), 1)
        self.assertEqual(gate2.ask("sys", "usr"), self.recs[1]["reply"])
        self.assertEqual(rep.info()["model"], "recorded")


class ConfigTest(unittest.TestCase):
    def test_from_config(self):
        with self.assertRaises(ValueError):
            clientmod.from_config({"model": {}})
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "s.json"
            p.write_text(json.dumps(SCRIPT))
            self.assertEqual(clientmod.from_config({"model": {"mock": str(p)}}).info()["model"], "m1")
        self.assertEqual(clientmod.from_config({"model": {"base_url": "http://127.0.0.1:9/v1"}}).name, "openai")
        with self.assertRaises(ValueError):
            clientmod.OpenAICompat("ftp://x/")


if __name__ == "__main__":
    unittest.main()


class KeyIsASecret(unittest.TestCase):
    """The endpoint key is taught to scrub() and to the container check, whatever shape it has."""

    def test_an_endpoint_key_is_registered_and_hidden(self):
        from swarmlabre import client, textutil
        key = "zq9-Plain_endpoint_key-0123456789"
        self.addCleanup(textutil.SECRETS.discard, key)
        textutil.SECRETS.discard(key)
        self.assertIn(key, textutil.scrub("prefix " + key), "the patterns alone do not recognise this shape of key")
        client.OpenAICompat("http://127.0.0.1:1/v1", key)
        self.assertEqual(textutil.scrub("a %s b" % key), "a [hidden] b")
        self.assertIn(key, list(textutil.SECRETS))


class PinnedLimits(unittest.TestCase):
    def test_an_agent_cannot_change_the_model_or_ask_for_more_output(self):
        g = gatemod.Gate(clientmod.Mock(SCRIPT), 1, lambda *a: None, {"temperature": 0.0, "seed": 7}, {"model": "the-model", "max_tokens": 1000})
        o = json.loads(g.pin(json.dumps({"model": "something-expensive", "n": 8, "max_tokens": 10 ** 6, "max_completion_tokens": "lots", "top_p": 0.5, "stream": True}).encode()))
        self.assertEqual((o["model"], o["n"], o["max_tokens"], o["max_completion_tokens"], o["top_p"], o["stream"]), ("the-model", 1, 1000, 1000, 0.5, True))
        self.assertEqual((o["temperature"], o["seed"]), (0.0, 7))

    def test_an_allowed_request_is_not_rewritten(self):
        g = gatemod.Gate(clientmod.Mock(SCRIPT), 1, lambda *a: None, {}, {"model": "m", "max_tokens": 1000})
        body = json.dumps({"model": "m", "messages": [], "max_tokens": 500, "stream": True}, separators=(",", ":")).encode()
        self.assertEqual(g.pin(body), body)
        self.assertNotIn(b"\"n\"", g.pin(body), "no n is added when the agent did not send one")

    def test_without_limits_nothing_changes(self):
        body = b'{"model":"x","max_tokens":99999999}'
        self.assertEqual(gatemod.Gate(clientmod.Mock(SCRIPT), 1, lambda *a: None).pin(body), body)
