"""tools/build-demo.py: deterministic, offline, honest about what it was built from, and it refuses a recording that does not replay."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import fixtures

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "build-demo.py"


def build(bundle, out, *args):
    return subprocess.run([sys.executable, str(TOOL), str(bundle), "--out", str(out), *args], capture_output=True, text=True, timeout=120)


def data_of(index):
    m = re.search(r'<script id="demo-data" type="application/json">(.*?)</script>', index.read_text(encoding="utf-8"), re.S)
    return json.loads(m.group(1))


class BuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = fixtures.record_run(cls.tmp.name)
        cls.out = Path(cls.tmp.name) / "site-a"
        r = build(cls.run_dir, cls.out)
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_builds_are_identical_down_to_the_byte(self):
        b = Path(self.tmp.name) / "site-b"
        self.assertEqual(build(self.run_dir, b).returncode, 0)
        fa = {str(p.relative_to(self.out)): p.read_bytes() for p in self.out.rglob("*") if p.is_file()}
        fb = {str(p.relative_to(b)): p.read_bytes() for p in b.rglob("*") if p.is_file()}
        self.assertEqual(fa, fb)

    def test_it_writes_the_page_the_fonts_and_a_manifest_whose_hashes_hold(self):
        self.assertTrue((self.out / "index.html").is_file())
        self.assertEqual(sorted(p.name for p in (self.out / "fonts").iterdir()), sorted([p.name for p in (ROOT / "ui" / "fonts").glob("*.woff2")] + ["OFL.txt"]))
        bj = json.loads((self.out / "build.json").read_text())
        self.assertEqual(bj["run"], self.run_dir.name)
        self.assertEqual(sorted(bj["files"]), sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*") if p.is_file() and p.name != "build.json"))
        for name, h in bj["files"].items():
            self.assertEqual(hashlib.sha256((self.out / name).read_bytes()).hexdigest(), h, name)
        sample = json.loads((self.run_dir / "swarm.json").read_text())["sample"]["sha256"]
        self.assertEqual(bj["sample_sha256"], sample)

    def test_the_page_holds_no_address_it_could_fetch(self):
        text = (self.out / "index.html").read_text(encoding="utf-8")
        text = re.sub(r'<script id="demo-data" type="application/json">.*?</script>', "", text, flags=re.S)
        self.assertEqual([u for u in re.findall(r"https?://[^\s'\"<>)\\]+", text) if u != "http://www.w3.org/2000/svg"], [])
        for m in re.finditer(r"""(?:src|href|action)\s*=\s*["'](?!#|data:|blob:)([^"']+)""", text):
            self.assertTrue(m.group(1).startswith("fonts/"), m.group(1))

    def test_the_recorded_files_in_the_page_are_the_ones_on_disk_byte_for_byte(self):
        d = data_of(self.out / "index.html")
        out = self.run_dir / "out"
        for name, text in d["files"].items():
            self.assertEqual(text.encode("utf-8"), (out / name).read_bytes(), name)       # a CSV keeps its \r\n
        self.assertEqual(d["run"], self.run_dir.name)
        self.assertEqual(len(d["events"]), sum(1 for ln in (self.run_dir / "events.jsonl").read_text().splitlines() if ln.strip()))

    def test_speed_and_paused_land_in_the_data(self):
        o = Path(self.tmp.name) / "site-c"
        self.assertEqual(build(self.run_dir, o, "--speed", "3", "--paused").returncode, 0)
        d = data_of(o / "index.html")
        self.assertEqual((d["speed"], d["paused"]), (3.0, True))
        d0 = data_of(self.out / "index.html")
        self.assertEqual((d0["speed"], d0["paused"]), (8.0, False))

    def test_the_sample_is_embedded_only_up_to_the_limit(self):
        o = Path(self.tmp.name) / "site-d"
        self.assertEqual(build(self.run_dir, o, "--sample-kb", "0").returncode, 0)
        d = data_of(o / "index.html")
        self.assertIsNone(d["sample"])
        self.assertIsNotNone(data_of(self.out / "index.html")["sample"])

    def test_a_recording_that_does_not_replay_is_refused_and_nothing_is_written(self):
        bad = Path(self.tmp.name) / "tampered" / self.run_dir.name
        shutil.copytree(self.run_dir, bad)
        ev = bad / "events.jsonl"
        ev.write_text(ev.read_text().replace("C2 URL", "C2 URI", 1))
        o = Path(self.tmp.name) / "site-bad"
        r = build(bad, o)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("byte for byte", r.stderr)
        self.assertFalse(o.exists())

    def test_a_missing_bundle_is_refused(self):
        r = build(Path(self.tmp.name) / "nothing", Path(self.tmp.name) / "site-none")
        self.assertEqual(r.returncode, 2)

    def test_the_real_runs_build_when_they_are_there(self):
        root = Path.home() / "swarmlabre-fixtures" / "bundles"
        found = sorted(p for p in (Path(__file__).resolve().parent.parent / "demo").glob("s*") if p.is_dir()) + (sorted(p for p in root.glob("*") if p.is_dir()) if root.is_dir() else [])
        self.assertTrue(found, "the committed demo bundle (demo/) is missing")
        for p in found:
            with self.subTest(p.name):
                o = Path(self.tmp.name) / ("real-" + p.name)
                r = build(p, o)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertLess((o / "index.html").stat().st_size, 2 << 20)
