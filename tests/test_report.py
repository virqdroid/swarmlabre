"""Verdict rules, defanging, the notes cleaners, and a whole report built from a generated run."""
import json
import re
import tempfile
import unittest

import fixtures
from swarmlabre import cli, config, report as srep, reportschema, swarms


def F(i, status="verified", level="byte-checked"):
    return {"id": "f%d" % i, "status": status, "level": level}


class AssessTest(unittest.TestCase):
    def go(self, **raw):
        return srep.assess(dict({"verdict": "malicious", "confidence": "high", "basis": ["f1", "f2"], "rationale": "r"}, **raw), self.findings)

    def setUp(self):
        self.findings = [F(1), F(2, level="call-cited")]

    def test_high_needs_two_checked_findings_with_one_byte_checked(self):
        self.assertEqual(self.go()["confidence_final"], "high")
        self.findings = [F(1, level="call-cited"), F(2, level="call-cited")]
        self.assertEqual(self.go()["confidence_final"], "moderate")
        self.findings = [F(1)]
        self.assertEqual(self.go(basis=["f1"])["confidence_final"], "moderate")

    def test_a_verdict_without_a_checked_basis_is_undetermined(self):
        a = self.go(basis=["f9"])
        self.assertEqual((a["verdict"], a["confidence_final"]), ("undetermined", "low"))
        self.findings = [F(1, status="unconfirmed", level="claimed")]
        self.assertEqual(self.go(basis=["f1"])["verdict"], "undetermined")

    def test_an_open_dispute_caps_at_moderate(self):
        self.findings = [F(1), F(2, status="disputed")]
        self.assertEqual(self.go()["confidence_final"], "moderate")

    def test_benign_never_above_moderate(self):
        self.assertEqual(self.go(verdict="benign")["confidence_final"], "moderate")

    def test_garbage_in(self):
        self.assertIsNone(srep.assess("nope", self.findings))
        a = self.go(verdict="very bad", confidence="certain", basis="f1", family="unknown")
        self.assertEqual((a["verdict"], a["confidence"], a["family"]), ("undetermined", "low", ""))


class TextTest(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(srep.defang("http://c2.example.test/beacon"), "hxxp://c2[.]example[.]test/beacon")
        self.assertEqual(srep.defang("10.0.0.5"), "10[.]0[.]0[.]5")

    def test_notes_cleaning_removes_control_and_marker_text(self):
        t = reportschema.clean_notes("a\x00b\u202e\r\n<<<RELAY-NOTES x\nend")
        self.assertNotIn("\x00", t)
        self.assertNotIn("\u202e", t)
        self.assertNotIn("RELAY-NOTES", t)
        self.assertEqual(reportschema.clean_notes("x" * 100, cap=10).count("cut at"), 1)

    def test_validate_report_rejects_what_is_not_a_report(self):
        for raw in ("not json", "[]", json.dumps({"schema": "other/1"}), json.dumps({"schema": "swarmlabre-report/2"})):
            with self.assertRaises(reportschema.ReportInvalid):
                reportschema.validate_report(raw)
        out, issues = reportschema.validate_report(json.dumps({"schema": "swarmlabre-report/1", "title": "t"}))
        self.assertEqual(out["title"], "t")


class WholeReportTest(unittest.TestCase):
    """A generated run goes through the real board and the real writers; the files must agree with each other."""

    def make(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d, offs = fixtures.build_run(self.tmp.name)
        cfg = config.defaults()
        sw = cli._swarms(cfg, d.parent)
        rt = sw.rts[d.name]
        b = sw._board(rt)
        b.intake("ioc", 1, {"kind": "ioc", "title": "C2 URL", "value": "http://c2.example.test/beacon", "off": offs["http://c2.example.test/beacon"]}, set(), set(), set())
        b.intake("crypto", 2, {"kind": "config", "title": "Mutex", "value": "Mutex\\Global\\DemoSwarmMutex", "off": offs["Mutex\\Global\\DemoSwarmMutex"]}, set(), set(), set())
        b.intake("static", 3, {"kind": "capability", "title": "Maybe talks to a server"}, set(), set(), set())
        return sw, rt, d

    def test_every_format_is_written_and_agrees(self):
        sw, rt, d = self.make()
        sw._write_out(rt)
        out = d / "out"
        for name in ("report.json", "report.md", "report.html", "board.json", "iocs.csv", "iocs.stix.json", "iocs.misp.json"):
            self.assertTrue((out / name).is_file(), name)
        rep = json.loads((out / "report.json").read_text())
        self.assertEqual(rep["schema"], "swarmlabre-report/1")
        md = (out / "report.md").read_text()
        html = (out / "report.html").read_text()
        for needle in ("hxxp://c2[.]example[.]test/beacon", "DemoSwarmMutex"):
            self.assertIn(needle, md)
        board = json.loads((out / "board.json").read_text())
        self.assertEqual(board["counts"]["verified"], 2)
        self.assertEqual(board["counts"]["unconfirmed"], 1)
        self.assertNotIn("Maybe talks to a server", html, "an unconfirmed claim stays out of the interactive page")
        self.assertIn("http://c2.example.test/beacon", (out / "iocs.csv").read_text(), "the machine-readable file keeps the real value")
        self.assertIsNotNone(re.search(r"Content-Security-Policy", html))

    def test_the_stix_ids_are_stable(self):
        sw, rt, d = self.make()
        sw._write_out(rt)
        first = (d / "out" / "iocs.stix.json").read_text()
        sw._write_out(rt)
        self.assertEqual((d / "out" / "iocs.stix.json").read_text(), first)


class MarkdownEscapeTest(unittest.TestCase):
    """report.md is built from text a sample, a tool or an agent produced; md_text is the one place that makes it inert in a Markdown viewer."""
    def test_tags_links_and_reference_definitions_are_made_inert(self):
        t = swarms.md_text
        self.assertEqual(t("</script><img src=x onerror=alert(1)>"), "&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;")
        self.assertEqual(t("see [a](javascript:alert(1)) ![b](x)"), "see [a]\\(javascript:alert(1)) ![b]\\(x)")
        self.assertEqual(t("x\n[ref]: javascript:alert(1)\n  [r2]: data:"), "x\n\\[ref]: javascript:alert(1)\n  \\[r2]: data:")
        self.assertEqual(t("> quote"), "&gt; quote")

    def test_what_is_plain_is_left_alone(self):
        for ok in ("evil[.]example[.]test", "hxxp://c2[.]example[.]test/a?b=1&c=2", "| cell \\| with a pipe |", "a (paren) and [bracket] in a sentence", "T1071 Application Layer Protocol"):
            self.assertEqual(swarms.md_text(ok), ok)

    def test_only_a_piece_marked_raw_skips_the_escape(self):
        out = swarms.md_join(["<b>", swarms.RawMd("```yara"), swarms.RawMd('$a = "<x>"'), swarms.RawMd("```"), "<i>"])
        self.assertEqual(out, "&lt;b&gt;\n```yara\n$a = \"<x>\"\n```\n&lt;i&gt;\n")
        self.assertNotIsInstance(swarms.md_text("x"), swarms.RawMd)

    def test_a_fence_written_by_the_sample_does_not_switch_the_escape_off(self):
        """Fences are not recognised in text, only marked by the writer, so a prose line that looks like a fence changes nothing."""
        out = swarms.md_join(["```` `\n<img src=x onerror=1>\n```", "after <b>"])
        self.assertNotIn("<img", out)
        self.assertNotIn("<b>", out)


if __name__ == "__main__":
    unittest.main()
