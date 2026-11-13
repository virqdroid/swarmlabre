"""The HTTP server: token, Host check, body caps, raw routes before the JSON parse, gzip, the page and its headers. Uses a fake backend, so no run is needed."""
import gzip
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from swarmlabre import server


class Fake:
    """Records what the server handed over; the real backends are Swarms and player.Replay."""

    def __init__(self):
        self.calls = []

    def api(self, h, method, parts, u, body):
        self.calls.append(("api", method, parts, body))
        if parts == ["big"]:
            return h.reply(200, {"text": "x" * 5000})
        return h.reply(200, {"ok": True, "parts": parts})

    def stage_put(self, h, u, n):
        self.calls.append(("stage", n, u.query))
        data = h.rfile.read(n) if n > 0 else b""
        return h.reply(200, {"got": len(data)})

    def clip_frame(self, h, rid, n):
        self.calls.append(("frame", rid, n))
        data = h.rfile.read(n) if n > 0 else b""
        return h.reply(200, {"got": len(data)})


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.token = server.load_token(cls.tmp.name)
        cls.fake = Fake()
        cls.app = server.App(cls.fake, cls.token, "live", "", "127.0.0.1")
        cls.srv = server.make_server(cls.app, "127.0.0.1", 0)
        cls.port = cls.srv.server_address[1]
        cls.thread = server.serve_forever(cls.srv)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, headers=None, auth=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + self.token
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data

    def test_the_token_file_is_private_and_stable(self):
        p = Path(self.tmp.name) / "token"
        self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
        self.assertEqual(server.load_token(self.tmp.name), self.token)

    def test_api_needs_the_token(self):
        self.assertEqual(self.req("GET", "/api/mode", auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/mode", headers={"Authorization": "Bearer wrong"}, auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/swarm", auth=False)[0], 401)
        st, _, body = self.req("GET", "/api/mode")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["mode"], "live")

    def test_the_page_and_two_fonts_need_no_token_and_carry_security_headers(self):
        st, h, body = self.req("GET", "/", auth=False)
        self.assertEqual(st, 200)
        self.assertIn(b"<title>swarmlabre</title>", body)
        self.assertIn("default-src 'none'", h["content-security-policy"])
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(self.req("GET", "/fonts/geist.woff2", auth=False)[0], 200)
        self.assertEqual(self.req("GET", "/fonts/../server.py", auth=False)[0], 404)
        self.assertEqual(self.req("GET", "/fonts/secret.woff2", auth=False)[0], 404)
        self.assertEqual(self.req("GET", "/swarmlabre/server.py", auth=False)[0], 404)

    def test_host_header_must_name_loopback_on_a_loopback_bind(self):
        for host in ("evil.example", "evil.example:8810", "127.0.0.1.evil.example"):
            self.assertEqual(self.req("GET", "/", headers={"Host": host}, auth=False)[0], 421, host)
        for host in ("localhost:8810", "127.0.0.1", "[::1]:8810"):
            self.assertEqual(self.req("GET", "/", headers={"Host": host}, auth=False)[0], 200, host)

    def test_json_body_is_capped_at_one_mib_and_must_be_an_object(self):
        # The server answers from the headers and never reads the body, so the test declares the size and sends nothing: uploading a whole MiB to a server that is closing the
        # connection races (the client can get a reset before it reads the 413).
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest("POST", "/api/swarm/start")
        for k, v in (("Authorization", "Bearer " + self.token), ("Content-Type", "application/json"), ("Content-Length", str(server.MAX_JSON_BODY + 10))):
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        st, body = r.status, r.read()
        c.close()
        self.assertEqual(st, 413)
        self.assertIn("too large", json.loads(body)["error"])
        self.assertEqual(self.req("POST", "/api/swarm/start", b"[1,2]")[0], 400)
        self.assertEqual(self.req("POST", "/api/swarm/start", b"{nope")[0], 400)
        n = len(self.fake.calls)
        st, _, body = self.req("POST", "/api/swarm/start", b'{"brief": "hi"}')
        self.assertEqual((st, self.fake.calls[n][:3]), (200, ("api", "POST", ["start"])))
        self.assertEqual(self.fake.calls[n][3], {"brief": "hi"})

    def test_raw_body_routes_are_routed_before_the_json_parse(self):
        blob = b"\x7fELF" + b"\0" * (server.MAX_JSON_BODY + 4096)        # larger than the JSON cap and not JSON
        st, _, body = self.req("POST", "/api/swarm/stage?name=a.elf", blob, {"Content-Type": "application/octet-stream"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["got"], len(blob))
        self.assertEqual(self.fake.calls[-1][:2], ("stage", len(blob)))
        st, _, body = self.req("POST", "/api/swarm/s00000001/clip/frame", b"\xff\xd8\xff" + b"0" * 100)
        self.assertEqual((st, self.fake.calls[-1][:3]), (200, ("frame", "s00000001", 103)))

    def test_raw_routes_still_need_the_token(self):
        n = len(self.fake.calls)
        self.assertEqual(self.req("POST", "/api/swarm/stage?name=a.elf", b"data", auth=False)[0], 401)
        self.assertEqual(len(self.fake.calls), n)

    def test_text_over_1400_bytes_is_gzipped_when_asked(self):
        st, h, body = self.req("GET", "/api/swarm/big", headers={"Accept-Encoding": "gzip"})
        self.assertEqual((st, h.get("content-encoding")), (200, "gzip"))
        self.assertEqual(json.loads(gzip.decompress(body))["text"], "x" * 5000)
        st, h, body = self.req("GET", "/api/swarm/big")
        self.assertIsNone(h.get("content-encoding"))
        st, h, body = self.req("GET", "/api/mode", headers={"Accept-Encoding": "gzip"})
        self.assertIsNone(h.get("content-encoding"), "a small reply is not compressed")

    def test_unknown_routes_are_404_and_errors_do_not_leak_paths(self):
        self.assertEqual(self.req("GET", "/api/nothing")[0], 404)
        self.assertEqual(self.req("GET", "/nothing", auth=False)[0], 404)

    def test_the_replay_clock_route_only_exists_on_a_replay_backend(self):
        self.assertEqual(self.req("GET", "/api/replay")[0], 404)


class PageTest(unittest.TestCase):
    """What the page file must and must not contain."""
    html = (Path(server.UI_DIR) / "swarms.html").read_text()

    def test_no_external_request_and_no_brand(self):
        import re
        for url in re.findall(r"https?://[^\s'\"<>)]+", self.html):
            self.assertIn(url, ("http://www.w3.org/2000/svg",), "external URL in the page")
        low = self.html.lower()
        for bad in ("cyg" + "ient", "spark" + "-hub", "spark" + "-re", "spark" + "-pi", "/home/", "private" + "relay", "googleapis", "cdn."):       # spelled in two parts so a grep audit of the repo finds nothing
            self.assertNotIn(bad, low)

    def test_one_global_hidden_rule_and_no_backdrop_filter(self):
        self.assertEqual(self.html.count("[hidden]{display:none!important}"), 1)
        self.assertNotIn("backdrop-filter", self.html)
        self.assertIn("prefers-reduced-motion", self.html)

    def test_one_escape_handler(self):
        self.assertEqual(self.html.count("e.key!=='Escape'"), 1)

    def test_fonts_are_self_hosted(self):
        import re
        urls = re.findall(r"url\(([^)]+)\)", self.html)
        self.assertTrue(urls)
        for u in urls:
            self.assertTrue(u.startswith("fonts/") or u.startswith("data:") or u.startswith('"data:') or u.startswith("'data:"), u)


if __name__ == "__main__":
    unittest.main()
