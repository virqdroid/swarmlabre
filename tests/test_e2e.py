"""A whole run with real containers and the scripted mock model. Skipped unless SWARMLABRE_E2E=1 and the two images exist (about a minute)."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarmlabre import cli, demo, sandbox


def images_exist():
    try:
        for img in (sandbox.AGENT_IMAGE, sandbox.TOOLS_IMAGE):
            if subprocess.run(sandbox.docker(["docker", "image", "inspect", img]), capture_output=True, timeout=30).returncode:
                return False
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_cli(cfg, *args):
    return subprocess.run(["python3", "-m", "swarmlabre", "--config", str(cfg), *args], capture_output=True, text=True, timeout=900, cwd=Path(__file__).resolve().parent.parent)


@unittest.skipUnless(os.environ.get("SWARMLABRE_E2E") == "1" and images_exist(), "set SWARMLABRE_E2E=1 and build the images (docker build, see README)")
class EndToEnd(unittest.TestCase):
    def test_demo_run_with_the_mock_model(self):
        with tempfile.TemporaryDirectory() as t:
            sample, script = demo.write(Path(t) / "demo")
            cfg = Path(t) / "c.toml"
            cfg.write_text('[paths]\nstate = "%s"\n' % (Path(t) / "state"))
            r = run_cli(cfg, "run", str(sample), "--mock", str(script), "--quiet")
            self.assertEqual(r.returncode, cli.EXIT_OK, r.stderr[-800:])
            res = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertEqual(res["status"], "done")
            self.assertEqual(res["counts"]["byte-checked"], 4)
            self.assertEqual(res["counts"]["rejected"], 0)
            self.assertIn("report.html", res["files"])
            rec = json.loads((Path(res["dir"]) / "swarm.json").read_text())
            self.assertEqual((rec["sampling"]["temperature"], rec["sampling"]["seed"], rec["sampling"]["seed_support"]), (0.0, 1, "honoured"))

    def test_second_sample_is_recorded_replays_offline_and_through_the_containers(self):
        """Dispute, resolution, round 2 and a duplicate reject; then (1) the offline replay is byte-identical, (2) the containers, answered from the recorded model
        replies, ask for nothing that was not recorded and reach the same board."""
        with tempfile.TemporaryDirectory() as t:
            sample, script = demo.write(Path(t) / "demo", "two")
            cfg = Path(t) / "c.toml"
            cfg.write_text('[paths]\nstate = "%s"\n' % (Path(t) / "state"))
            r = run_cli(cfg, "run", str(sample), "--mock", str(script), "--quiet")
            self.assertEqual(r.returncode, cli.EXIT_OK, r.stderr[-800:])
            first = json.loads(r.stdout.strip().splitlines()[-1])
            d = Path(first["dir"])
            self.assertEqual(first["counts"]["rejected"], 1)
            ops = [json.loads(ln)["op"] for ln in (d / "inputs.jsonl").read_text().splitlines()]
            self.assertIn("resolve", ops)
            self.assertTrue((d / "model-trace.jsonl.gz").is_file() and (d / "manifest.json").is_file())
            self.assertTrue((d / "out" / "detection.yar").is_file(), "five distinct strings are enough for a rule")
            rp = run_cli(cfg, "replay", str(d))
            self.assertEqual(rp.returncode, 0, rp.stdout[-800:])
            self.assertEqual(json.loads(rp.stdout)["level"], "full")
            again = run_cli(cfg, "run", str(sample), "--replay", str(d), "--quiet")
            self.assertEqual(again.returncode, cli.EXIT_OK, again.stderr[-800:])
            res2 = json.loads(again.stdout.strip().splitlines()[-1])
            self.assertEqual(res2["replay_diverged"], 0)       # flaky by nature (docs/determinism.md, claim 3): which agent posts first changes the finding numbers; rerun before suspecting a bug
            self.assertEqual(res2["counts"], first["counts"])


if __name__ == "__main__":
    unittest.main()
