"""Small fixes found by review: each test fails on the code before the fix."""
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import fixtures
from swarmlabre import cli, config, player, server, swarms

ROOT = Path(__file__).resolve().parent.parent


def mode(p):
    return Path(p).stat().st_mode & 0o777


class PrivateStateFolder(unittest.TestCase):
    def test_the_token_folder_and_its_new_parents_are_private(self):
        with tempfile.TemporaryDirectory() as t:
            state = Path(t) / "a" / "b" / "state"
            server.load_token(state)
            for p in (state, state.parent, state.parent.parent):
                self.assertEqual(mode(p), 0o700, p)

    def test_a_folder_that_exists_keeps_its_mode(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t).chmod(0o755)
            config.make_private_dir(Path(t))
            self.assertEqual(mode(t), 0o755)
            config.make_private_dir(Path(t) / "x")
            self.assertEqual((mode(t), mode(Path(t) / "x")), (0o755, 0o700))

    def test_the_runs_folder_is_private_under_a_umask_that_allows_more(self):
        old = os.umask(0)
        try:
            with tempfile.TemporaryDirectory() as t:
                cfg = config.defaults()
                cfg["paths"]["state"] = str(Path(t) / "state")
                cli._swarms(cfg, Path(t) / "state" / "runs")
                self.assertEqual((mode(Path(t) / "state"), mode(Path(t) / "state" / "runs")), (0o700, 0o700))
        finally:
            os.umask(old)


class RunStartLock(unittest.TestCase):
    def test_a_start_that_fails_releases_the_run_lock_and_the_slot(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = config.defaults()
            cfg["paths"]["state"] = str(Path(t) / "state")
            sw = cli._swarms(cfg, Path(t) / "state" / "runs")
            elf = Path(t) / "a.elf"
            fixtures.make_elf(elf)
            self.assertEqual(sw.stage_file(elf, "a.elf")[0], 200)
            with mock.patch.object(swarms.Swarms, "preflight", return_value=None), mock.patch.object(swarms.Swarms, "_save", side_effect=RuntimeError("disk full")):
                with self.assertRaises(RuntimeError):
                    sw.start({"brief": "look at it"})
            self.assertFalse(sw.busy(), "a run that nothing works on is left behind")
            self.assertTrue(sw._lock_run(), "the run lock is still held")
            sw._unlock_run()


class ReplaySpeed(unittest.TestCase):
    def test_the_clock_speed_is_held_between_0_1_and_10000(self):
        self.assertEqual(player.clamp_speed(0), 0.1)
        self.assertEqual(player.clamp_speed(-5), 0.1)
        self.assertEqual(player.clamp_speed(1e12), 10000.0)
        self.assertEqual(player.clamp_speed("8"), 8.0)
        for bad in (float("nan"), float("inf"), "x", None):
            with self.assertRaises((ValueError, TypeError)):
                player.clamp_speed(bad)

    def test_a_replay_built_with_speed_zero_does_not_stop_its_clock(self):
        with tempfile.TemporaryDirectory() as t:
            d = fixtures.record_run(t)
            for s, want in ((0, 0.1), (-3, 0.1)):
                r = player.Replay(d, speed=s, paused=True)
                try:
                    self.assertEqual(r.speed, want)
                finally:
                    r.close()

    def test_serve_refuses_a_speed_that_is_not_a_positive_number(self):
        with tempfile.TemporaryDirectory() as t:
            d = fixtures.record_run(t)
            for bad in ("0", "-1", "nan", "inf", "fast"):
                with self.subTest(speed=bad):
                    err = subprocess.run([sys.executable, "-m", "swarmlabre", "serve", "--replay", str(d), "--port", "0", "--speed", bad], cwd=ROOT, capture_output=True, text=True,
                                         timeout=60, env={**os.environ, "HOME": t, "TMPDIR": t})
                    self.assertEqual(err.returncode, cli.EXIT_USAGE, err.stderr)
                    self.assertIn("serve --replay", err.stderr)
            self.assertEqual([p.name for p in Path(t).glob("swarmlabre-play-*")], [], "a refused start left its temporary copy behind")


class ServeStopsOnSigterm(unittest.TestCase):
    def test_sigterm_ends_serve_like_ctrl_c_and_removes_the_temporary_copy(self):
        with tempfile.TemporaryDirectory() as t:
            d = fixtures.record_run(t)
            tmp = Path(t) / "tmp"
            tmp.mkdir()
            p = subprocess.Popen([sys.executable, "-m", "swarmlabre", "serve", "--replay", str(d), "--port", "0"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env={**os.environ, "HOME": t, "TMPDIR": str(tmp)})
            try:
                line = p.stdout.readline()
                self.assertIn("http://", line)
                self.assertEqual(len(list(tmp.glob("swarmlabre-play-*"))), 1)
                p.send_signal(signal.SIGTERM)
                self.assertEqual(p.wait(timeout=30), 0, p.stderr.read())
                self.assertEqual(list(tmp.glob("swarmlabre-play-*")), [])
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
                p.stdout.close()
                p.stderr.close()

    def test_a_port_that_is_taken_does_not_leave_the_copy_either(self):
        import socket
        with tempfile.TemporaryDirectory() as t, socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            d = fixtures.record_run(t)
            tmp = Path(t) / "tmp"
            tmp.mkdir()
            r = subprocess.run([sys.executable, "-m", "swarmlabre", "serve", "--replay", str(d), "--port", str(s.getsockname()[1])], cwd=ROOT, capture_output=True, text=True, timeout=60,
                               env={**os.environ, "HOME": t, "TMPDIR": str(tmp)})
            self.assertEqual(r.returncode, cli.EXIT_FAIL, r.stderr)
            self.assertEqual(list(tmp.glob("swarmlabre-play-*")), [])


class ConfigKeys(unittest.TestCase):
    """Every key the code reads is documented in the example config and has a default, and the example holds no key the code does not know."""
    def test_the_example_and_the_defaults_name_the_same_keys(self):
        ex = tomllib.loads((ROOT / "swarmlabre.example.toml").read_text())
        for sec, vals in config.DEFAULTS.items():
            with self.subTest(section=sec):
                self.assertEqual(set(ex.get(sec, {})), set(vals))
        self.assertEqual(set(ex), set(config.DEFAULTS))

    def test_the_keys_pi_and_the_gate_read_are_there(self):
        for k in ("context_window", "max_tokens", "reasoning", "thinking_toggle", "thinking_level", "extra_body", "mock", "replay"):
            self.assertIn(k, config.DEFAULTS["model"])
        self.assertNotIn("profile", config.DEFAULTS["swarm"], "[swarm] profile had no effect")


class ReporterMarkdown(unittest.TestCase):
    """The Reporter's lines reach report.md. A line that opens a code fence, a table, a heading or a setext underline must not, or one that never closes would turn the rest of the
    report into code in a viewer. Fences swarmlabre writes itself (YARA) are marked RawMd and stay."""
    F = "`" * 3

    def test_lines_that_open_a_block_are_escaped(self):
        t = swarms.md_prose
        f = self.F
        self.assertEqual(t(f + "yara\nx"), "\\`\\`\\`yara\nx")
        self.assertEqual(t("~~~~"), "\\~\\~\\~\\~")
        self.assertEqual(t("   " + f), "   \\`\\`\\`")
        self.assertEqual(t("- " + f + "py"), "- \\`\\`\\`py")
        self.assertEqual(t("1. " + f), "1. \\`\\`\\`")
        self.assertEqual(t("# Title\n## Two\n###### Six"), "\\# Title\n\\## Two\n\\###### Six")
        self.assertEqual(t("Text\n=====\n-----\n***\n- - -"), "Text\n\\=====\n\\-----\n\\***\n- - \\-")
        self.assertEqual(t("| a | b |\n|---|---|"), "\\| a \\| b \\|\n\\|---\\|---\\|")
        self.assertEqual(t("a | b\n--|--"), "a \\| b\n--\\|--")

    def test_plain_prose_lists_and_emphasis_are_left_alone(self):
        for ok in ("It writes a file.", "- item one\n- item two", "1. first\n2. second", "*emphasis* and **strong**", "use `ls` and `cat`", "text " + self.F + " not at the start",
                   "#hashtag", "a - b - c", "-- option", "######## eight"):
            self.assertEqual(swarms.md_prose(ok), ok)

    def test_report_md_holds_no_block_opener_from_the_reporter(self):
        from swarmlabre import report as srep, text as stx
        f = self.F
        prose = ("Intro\n" + f + "yara\nrule a {\n| a | b |\n|:--|--:|\n# Title\nSetext\n=====\n\n## Executive summary\nSummary\n" + f + "\n\n## Capabilities\n" + f + "\n- caps\n\n"
                 "## Recommendations\n---\n- rec\n\n## What we don't know\n~~~\n- unk\n")
        secs, _lint, canon = stx.structure(srep.split_assessment(prose + 'ASSESSMENT {"verdict": "benign", "confidence": "high", "family": "", "basis": [], "rationale": "r"}')[0])
        self.assertIn(f, secs["exec"], "the cleaned text itself keeps the line: the escape is report.md's job")
        with tempfile.TemporaryDirectory() as t:
            d = fixtures.record_run(t)
            sj = json.loads((d / "swarm.json").read_text())
            sj["summary_sections"], sj["summary"] = secs, canon
            (d / "swarm.json").write_text(json.dumps(sj))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["report", str(d)]), cli.EXIT_OK)
            md = (d / "out" / "report.md").read_text()
        hostile = {f + "yara", f, "| a | b |", "|:--|--:|", "# Title", "=====", "~~~", "---"}
        self.assertEqual([ln for ln in md.split("\n") if ln.strip() in hostile], [], "a line of the Reporter's text opens a block in report.md")
        self.assertEqual(md.count(f) % 2, 0)


class ReviewFixes(unittest.TestCase):
    """Findings of the second review (report, page, Markdown, prep script): each fails on the code before the fix."""
    F = "`" * 3

    def test_an_apk_string_pool_cannot_make_the_host_decode_the_same_megabytes_again_and_again(self):
        import struct
        from swarmlabre import report
        cnt, total, hdr = 300, 8 * 1024 * 1024 - 64, 28
        sstart = hdr + 4 * cnt
        body = bytearray(total)
        struct.pack_into("<HHIIIIII", body, 0, 1, hdr, len(body), cnt, 0, 0, sstart, 0)       # every entry has offset 0 ...
        struct.pack_into("<HH", body, sstart, 0xFFFF, 0xFFFF)                                  # ... and claims a string of 2**31 - 1 UTF-16 units
        for i in range(sstart + 4, len(body), 2):
            body[i] = 0x41
        import tracemalloc
        tracemalloc.start()
        out = report._axml_strings(bytes(body), 0, len(body))
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual(len(out), cnt)
        self.assertLessEqual(max(map(len, out)), report.AXML_STRING_CHARS)
        self.assertLessEqual(sum(map(len, out)), report.AXML_TOTAL_CHARS)
        self.assertLess(peak, 100 * 1024 * 1024, "the pool decoded far more than it holds")

    def test_a_manifest_value_that_should_be_a_number_is_made_printable_and_capped(self):
        from swarmlabre import report
        self.assertEqual(report._shown(33), "33")
        evil = "7 \u202e(Signature: validated)\n| injected | row |" + "A" * 5000
        shown = report._shown(evil)
        self.assertLessEqual(len(shown), 40)
        self.assertTrue(all(32 <= ord(ch) < 127 for ch in shown), shown)
        self.assertEqual(report._shown(True), "True")

    def test_the_title_is_set_before_the_data_so_text_in_the_data_cannot_change_the_page(self):
        import re
        from swarmlabre import report as srep, text as stx
        prose = "## Executive summary\nA %TITLE% and /*DATA*/ and \\ inside the data.\n"
        raw = 'ASSESSMENT {"verdict": "benign", "confidence": "high", "family": "Foo\\\\Bar", "basis": [], "rationale": "r"}'
        secs, _lint, canon = stx.structure(srep.split_assessment(prose + raw)[0])
        with tempfile.TemporaryDirectory() as t:
            d = fixtures.record_run(t)
            sj = json.loads((d / "swarm.json").read_text())
            sj["summary_sections"], sj["summary"], sj["assessment_raw"] = secs, canon, srep.split_assessment(prose + raw)[1]
            (d / "swarm.json").write_text(json.dumps(sj))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["report", str(d)]), cli.EXIT_OK)
            page = (d / "out" / "report.html").read_text()
        data = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', page, re.S).group(1))     # fails when the data was altered
        self.assertIn("%TITLE%", json.dumps(data))
        self.assertIn("/*DATA*/", json.dumps(data))
        self.assertNotIn("\\", re.search(r"<title>(.*?)</title>", page).group(1))

    def test_a_link_reference_definition_inside_a_list_item_is_broken_too(self):
        t = swarms.md_text
        self.assertEqual(t("- [x]: //Evil.example/a.png"), "- \\[x]: //Evil.example/a.png")
        self.assertEqual(t("1. [y]: javascript:alert(1)\n  - - [z]: u"), "1. \\[y]: javascript:alert(1)\n  - - \\[z]: u")
        self.assertEqual(t("- see [a] and [b]: not at the start"), "- see [a] and [b]: not at the start")

    def test_a_backslash_in_front_of_a_pipe_cannot_end_a_table_cell_early(self):
        self.assertEqual(swarms.md_pipe("a|b"), "a\\|b")
        self.assertEqual(swarms.md_pipe("Fake \\| 0x40"), "Fake \\\\\\| 0x40")           # \| -> \\\|  (an even run of backslashes, then an escaped pipe)
        self.assertEqual(swarms.md_pipe("C:\\Windows\\x"), "C:\\Windows\\x")           # a backslash that is not in front of a pipe is not touched
        self.assertEqual(swarms.md_prose("x \\| y"), "x \\\\\\| y")

    def test_two_class_names_that_fold_to_one_file_name_get_two_files(self):
        import ast
        src = (ROOT / "swarmlabre" / "prep_script.py").read_text()
        fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "decomp_name")
        ns = {}
        exec("import hashlib, re\n" + ast.get_source_segment(src, fn), ns)
        a, b = "com.example.A$1", "com.example.A_1"                           # both fold to com.example.A_1.java
        first = ns["decomp_name"](a, set())
        second = ns["decomp_name"](b, {first})
        self.assertNotEqual(first, second)
        self.assertRegex(second, r"[A-Za-z0-9_.$]+\.java")
        long1, long2 = "x" * 130 + "a", "x" * 130 + "b"
        self.assertNotEqual(ns["decomp_name"](long2, {ns["decomp_name"](long1, set())}), ns["decomp_name"](long1, set()))

    def test_unicode_line_separators_and_c1_controls_are_hidden_text(self):
        from swarmlabre import reportschema
        for ch in ("\u2028", "\u2029", "\x85", "\x9b", "\u00ad", "\u061c", "\U000e0041"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(reportschema.HIDDEN.sub(" ", "a%sb" % ch), "a b")
                self.assertEqual(reportschema.HIDDEN_NL.sub(" ", "a%sb" % ch), "a b")

    def test_a_pe_that_shares_one_unmappable_thunk_table_is_not_scanned_for_ever(self):
        import struct, time
        from swarmlabre import report
        size = 0x18000
        d = bytearray(size)
        d[0:2] = b"MZ"
        struct.pack_into("<I", d, 60, 0x40)
        d[0x40:0x44] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", d, 0x44, 0x14C, 96, 0, 0, 0, 0xE0, 0x102)               # 96 sections
        o = 0x40 + 24
        struct.pack_into("<H", d, o, 0x10B)
        struct.pack_into("<I", d, o + 92, 16)
        struct.pack_into("<II", d, o + 96 + 8, 0x1400, 512 * 20)                              # import directory
        sec_at = o + 0xE0
        struct.pack_into("<IIII", d, sec_at + 8, size, 0x1000, size, 0)                       # section 0 maps the whole file at RVA 0x1000
        for i in range(1, 96):
            struct.pack_into("<IIII", d, sec_at + 40 * i + 8, 0x10, 0x10000000 + 0x1000 * i, 0x10, 0)
        for k in range(511):                                                                   # 511 descriptors share one thunk table
            struct.pack_into("<IIIII", d, 0x400 + 20 * k, 0x4000, 0, 0, 0x3E00, 0x4000)
        d[0x2E00:0x2E06] = b"a.dll\0"
        for j in range(20000):
            struct.pack_into("<I", d, 0x3000 + 4 * j, 0x7FFFFFF0)                              # every thunk points nowhere
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "x.exe"
            f.write_bytes(bytes(d))
            t0 = time.monotonic()
            out = report.pe_info(f, size)
        self.assertLess(time.monotonic() - t0, 10, "the import walk is not bounded")
        self.assertIsInstance(out, dict)


if __name__ == "__main__":
    unittest.main()
