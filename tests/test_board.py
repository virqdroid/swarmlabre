"""The findings board: every decision swarmlabre makes about a post (evidence level, reject codes, merge, dispute, replay). Ported from swarmlabre's checks."""
import tempfile
import unittest
from pathlib import Path

import fixtures
from swarmlabre import swarms
from swarmlabre.textutil import plain


class BoardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir, self.offs = fixtures.build_run(self.tmp.name)
        self.sample = self.dir / "input" / "sample"
        self.size = self.sample.stat().st_size
        self.lay = {"regions": [{"name": ".rodata", "off": 320, "len": 100}], "functions": [{"name": "entry", "va": 0x401000}], "kind": "bytes"}
        self.path = self.dir / "board.jsonl"
        self.b = swarms.Board(str(self.path), str(self.sample), self.size, plain, lambda: self.lay)

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, role="ioc", seen=(), prep=(), others=(), **kw):
        raw = {"kind": "ioc", "title": "C2 URL", "value": "http://c2.example.test/beacon", "off": self.offs["http://c2.example.test/beacon"], **kw}
        return self.b.intake(role, 1, raw, set(seen), set(prep), set(others))

    def code(self, r):
        return r["x"]["code"] if r["op"] == "reject" else r["op"]

    def test_byte_checked_when_the_bytes_match(self):
        r = self.post()
        self.assertEqual(r["op"], "add")
        self.assertEqual(r["f"]["level"], "byte-checked")
        self.assertEqual(r["f"]["status"], "verified")
        self.assertEqual(r["f"]["evidence"][-1]["section"], ".rodata")

    def test_wrong_bytes_are_rejected(self):
        self.assertEqual(self.code(self.post(value="http://other.example.test/x")), "bytes_mismatch")

    def test_offset_outside_the_file(self):
        self.assertEqual(self.code(self.post(off=self.size + 5)), "off_out_of_range")
        self.assertEqual(self.code(self.post(off=-1)), "bad_format")

    def test_claimed_without_offset_stays_unconfirmed(self):
        r = self.b.intake("ioc", 1, {"kind": "capability", "title": "Talks to a server"}, set(), set(), set())
        self.assertEqual((r["f"]["level"], r["f"]["status"]), ("claimed", "unconfirmed"))

    def test_call_citation_rules(self):
        raw = {"kind": "capability", "title": "Reads a file", "calls": ["c7"]}
        self.assertEqual(self.code(self.b.intake("static", 1, raw, set(), set(), set())), "call_unknown")
        self.assertEqual(self.code(self.b.intake("static", 1, raw, set(), set(), {"c7"})), "call_not_yours")
        r = self.b.intake("static", 1, raw, {"c7"}, set(), {"c7"})
        self.assertEqual((r["op"], r["f"]["level"]), ("add", "call-cited"))

    def test_function_must_be_in_the_list(self):
        self.assertEqual(self.code(self.b.intake("static", 1, {"kind": "function", "title": "x", "func": "nope"}, set(), set(), set())), "func_unknown")
        self.assertEqual(self.b.intake("static", 1, {"kind": "function", "title": "x", "func": "0x401000"}, set(), set(), set())["op"], "add")

    def test_same_agent_twice_is_a_duplicate_and_a_second_agent_is_credited(self):
        self.assertEqual(self.post("ioc")["op"], "add")
        self.assertEqual(self.code(self.post("ioc")), "duplicate")
        m = self.post("static")
        self.assertEqual(m["op"], "merge")
        self.assertEqual(m["f"]["agents"], ["ioc", "static"])
        self.assertEqual(len(self.b.f), 1)

    def test_malformed_posts(self):
        for raw in ({"kind": "nonsense", "title": "x"}, {"kind": "ioc"}, {"kind": "ioc", "title": "x", "off": True}, {"kind": "ioc", "title": "x", "enc": "rot13"}, "text"):
            self.assertEqual(self.code(self.b.intake("ioc", 1, raw, set(), set(), set())), "bad_format", raw)

    def test_technique_ids_come_from_the_matrix(self):
        self.assertEqual(self.code(self.b.intake("behaviour", 1, {"kind": "technique", "title": "Totally made up"}, set(), set(), set())), "technique_unknown")
        self.assertEqual(self.code(self.b.intake("behaviour", 1, {"kind": "technique", "title": "T1059 Wrong Name"}, set(), set(), set())), "technique_mismatch")

    def test_per_role_cap(self):
        self.b.PER_ROLE = 2
        self.post("ioc"), self.post("ioc")
        self.assertEqual(self.code(self.post("ioc")), "cap_exceeded")

    def test_reporter_cannot_dispute_and_others_can(self):
        self.post("ioc")
        d = {"kind": "dispute", "title": "Not C2", "of": "f1", "reason": "It is a documentation address."}
        self.assertEqual(self.code(self.b.intake("reporter", 2, d, set(), set(), set())), "role_not_allowed")
        r = self.b.intake("static", 2, d, set(), set(), set())
        self.assertEqual((r["op"], r["f"]["status"]), ("dispute", "disputed"))
        self.assertEqual(self.b.open_disputes()[0]["id"], "f1")
        self.assertEqual(self.b.resolve("f1", "wrong", "Right.")["status"], "refuted")
        self.assertIsNone(self.b.resolve("f1", "stands", "again"), "a finding with a resolution is closed")

    def test_the_log_replays_to_the_same_board(self):
        self.post("ioc"), self.post("static"), self.post(value="bad")
        again = swarms.Board(str(self.path), str(self.sample), self.size, plain, lambda: self.lay)
        again.load()
        self.assertEqual(again.view()["findings"], self.b.view()["findings"])
        self.assertEqual(again.counts(), self.b.counts())
        self.assertEqual(again.nx, self.b.nx)


if __name__ == "__main__":
    unittest.main()
