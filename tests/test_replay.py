"""Replay: a recorded run is rebuilt offline and every output is compared with the manifest."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import fixtures
from swarmlabre import replay as rp

ROOT = Path(__file__).resolve().parent.parent


class mock_budget:
    """Lower the copy size limit for a moment."""
    def __init__(self, n):
        self.n = n

    def __enter__(self):
        self.old, rp.MAX_COPY_BYTES = rp.MAX_COPY_BYTES, self.n

    def __exit__(self, *a):
        rp.MAX_COPY_BYTES = self.old


class ReplayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_recorded_run_replays_to_identical_files(self):
        d = fixtures.record_run(self.tmp.name)
        res = rp.replay(d)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["level"], "full")
        self.assertEqual(res["checks"]["board"], "identical")
        self.assertEqual(res["checks"]["summary"], "identical")
        self.assertEqual({k: v for k, v in res["checks"]["outputs"].items() if k != "detection.yar"}, {k: "identical" for k in res["checks"]["outputs"] if k != "detection.yar"})

    def test_the_sealed_run_names_its_files_by_hash(self):
        d = fixtures.record_run(self.tmp.name)
        man = json.loads((d / "manifest.json").read_text())
        self.assertEqual(man["format"], 1)
        self.assertEqual(set(man["inputs"]), {"board.jsonl", "inputs.jsonl", "layout.json", "events.jsonl", "swarm.json"})
        self.assertIn("report.html", man["outputs"])
        self.assertEqual(man["sampling"]["seed_support"], "honoured")
        self.assertEqual(len((d / "inputs.jsonl").read_text().splitlines()), 6, "five posts and one resolution")

    def test_without_the_sample_only_the_report_building_is_replayed(self):
        d = fixtures.record_run(self.tmp.name, with_sample=False)
        res = rp.replay(d)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["level"], "downstream")
        self.assertIn("no sample", res["checks"]["board"])

    def test_replay_leaves_the_run_folder_alone(self):
        d = fixtures.record_run(self.tmp.name)
        before = {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}
        before_out = {p.name: p.read_bytes() for p in (d / "out").iterdir()}
        rp.replay(d, Path(self.tmp.name) / "copy")
        self.assertEqual(before, {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()})
        self.assertEqual(before_out, {p.name: p.read_bytes() for p in (d / "out").iterdir()})
        self.assertEqual((Path(self.tmp.name) / "copy" / "report.md").read_bytes(), before_out["report.md"])

    def test_a_changed_input_file_is_caught(self):
        d = fixtures.record_run(self.tmp.name)
        p = d / "inputs.jsonl"
        p.write_text(p.read_text().replace("C2 URL", "C2 url"))
        res = rp.replay(d)
        self.assertFalse(res["ok"])
        self.assertIn("inputs.jsonl", res["checks"]["inputs_untouched"])

    def test_the_board_is_rechecked_against_the_bytes(self):
        """Someone edits a recorded post AND the manifest's hash of it: the board, re-run against the sample, no longer comes out as recorded."""
        d = fixtures.record_run(self.tmp.name)
        rows = [json.loads(ln) for ln in (d / "inputs.jsonl").read_text().splitlines()]
        rows[0]["raw"]["value"] = "http://c2.example.test/beacoN"                 # not what is in the file
        (d / "inputs.jsonl").write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows))
        man = json.loads((d / "manifest.json").read_text())
        man["inputs"]["inputs.jsonl"] = rp._sha(d / "inputs.jsonl")
        (d / "manifest.json").write_text(json.dumps(man))
        res = rp.replay(d)
        self.assertFalse(res["ok"])
        self.assertEqual(res["checks"]["board"], "differs")
        self.assertEqual(res["checks"]["outputs"]["board.json"], "differs")

    def test_a_changed_output_hash_is_caught(self):
        d = fixtures.record_run(self.tmp.name)
        man = json.loads((d / "manifest.json").read_text())
        man["outputs"]["report.md"] = "0" * 64
        (d / "manifest.json").write_text(json.dumps(man))
        res = rp.replay(d)
        self.assertFalse(res["ok"])
        self.assertEqual(res["checks"]["outputs"]["report.md"], "differs")

    def test_an_output_a_bundle_carries_must_be_the_recorded_one(self):
        """The player serves and the demo embeds `out/*` of the bundle itself. A forged copy there must fail the replay even though the rebuilt files are fine."""
        d = fixtures.record_run(self.tmp.name)
        b = rp.export(d, Path(self.tmp.name) / "bundle", True)
        self.assertTrue(rp.replay(b)["ok"])
        (b / "out" / "report.md").write_text((b / "out" / "report.md").read_text() + "\n<p>forged</p>\n")
        res = rp.replay(b)
        self.assertFalse(res["ok"])
        self.assertEqual(res["checks"]["bundle_outputs"]["report.md"], "differs")
        self.assertEqual(res["checks"]["outputs"]["report.md"], "identical", "the rebuilt file is still right: only the carried copy is wrong")
        (b / "out" / "report.md").unlink()
        self.assertEqual(rp.replay(b)["checks"]["bundle_outputs"]["report.md"], "missing")
        (b / "out" / "notes.txt").write_text("x")                                      # a file the manifest does not name is not served, so it is not a failure
        self.assertNotIn("notes.txt", rp.replay(b)["checks"]["bundle_outputs"])

    def test_the_sample_must_be_the_one_in_the_manifest(self):
        d = fixtures.record_run(self.tmp.name)
        b = rp.export(d, Path(self.tmp.name) / "bundle", True)
        s = b / "input" / "sample"
        raw = s.read_bytes()
        s.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0xFF]))
        res = rp.replay(b)
        self.assertFalse(res["ok"])
        self.assertEqual(res["checks"]["sample"], "differs from the manifest")

    def test_a_link_inside_a_bundle_is_never_followed(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("host file")
        d = fixtures.record_run(self.tmp.name)
        b = rp.export(d, Path(self.tmp.name) / "bundle", True)
        (b / "prep").mkdir(exist_ok=True)
        os.symlink(outside, b / "prep" / "evil")
        os.symlink(outside / "secret.txt", b / "prep" / "secret-link.txt")
        copy = Path(self.tmp.name) / "copy"
        rp.copy_regular(b, copy)
        self.assertTrue((copy / "manifest.json").is_file())
        self.assertFalse(any(p.name in ("evil", "secret.txt", "secret-link.txt") for p in copy.rglob("*")))
        self.assertTrue(rp.replay(b)["ok"])
        with self.assertRaises(rp.ReplayError):
            with mock_budget(0):
                rp.copy_regular(b, Path(self.tmp.name) / "copy2")

    def test_a_run_without_recording_cannot_be_replayed(self):
        d, _ = fixtures.build_run(self.tmp.name)
        with self.assertRaises(rp.ReplayError):
            rp.replay(d)

    def test_the_result_does_not_depend_on_time_zone_or_hash_seed(self):
        d = fixtures.record_run(self.tmp.name)
        for env in ({"TZ": "Pacific/Auckland", "PYTHONHASHSEED": "1"}, {"TZ": "America/Sao_Paulo", "PYTHONHASHSEED": "777"}, {"TZ": "UTC", "PYTHONHASHSEED": "random"}):
            r = subprocess.run([sys.executable, "-m", "swarmlabre", "replay", str(d)], cwd=ROOT, capture_output=True, text=True, env={**os.environ, **env})
            self.assertEqual(r.returncode, 0, (env, r.stdout[-600:], r.stderr[-300:]))

    def test_an_exported_bundle_replays_on_its_own(self):
        d = fixtures.record_run(self.tmp.name)
        for with_sample, level in ((True, "full"), (False, "downstream")):
            b = rp.export(d, Path(self.tmp.name) / ("bundle-%s" % with_sample), with_sample)
            self.assertEqual((b / "input" / "sample").is_file(), with_sample)
            self.assertFalse((b / "tasks").exists())
            res = rp.replay(b)
            self.assertTrue(res["ok"], res)
            self.assertEqual(res["level"], level)
        with self.assertRaises(rp.ReplayError):
            rp.export(d, Path(self.tmp.name) / "bundle-True", True)          # never overwrites
        plain, _ = fixtures.build_run(Path(self.tmp.name) / "other")
        with self.assertRaises(rp.ReplayError):
            rp.export(plain, Path(self.tmp.name) / "x")

    def test_replay_command_exit_codes(self):
        d = fixtures.record_run(self.tmp.name)
        run = lambda *a: subprocess.run([sys.executable, "-m", "swarmlabre", "replay", *a], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run(str(d)).returncode, 0)
        (d / "layout.json").write_text("{}")
        self.assertEqual(run(str(d)).returncode, 1)
        self.assertEqual(run(str(Path(self.tmp.name) / "nope")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
