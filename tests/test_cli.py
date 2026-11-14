import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import fixtures
from swarmlabre import cli


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_report_builds_the_files_and_copies_them(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t).chmod(0o755)
            d, _ = fixtures.build_run(t)
            code, out, _ = run("report", str(d), "--out", str(Path(t) / "copy"))
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn("report.json", json.loads(out)["files"])
            self.assertTrue((Path(t) / "copy" / "report.md").is_file())
            self.assertEqual(Path(t).stat().st_mode & 0o777, 0o755, "a folder that already exists is not re-chmodded")

    def test_report_of_something_that_is_not_a_run(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(run("report", t)[0], cli.EXIT_USAGE)
            self.assertEqual(run("report", "s00000000")[0], cli.EXIT_USAGE)

    def test_serve_replay_refuses_what_is_not_a_run(self):
        with tempfile.TemporaryDirectory() as t:
            code, _, err = run("serve", "--replay", t, "--port", "0")
            self.assertEqual(code, cli.EXIT_USAGE)
            self.assertIn("serve --replay", err)
            code, _, err = run("serve", "--replay", str(Path(t) / "missing"), "--port", "0")
            self.assertEqual(code, cli.EXIT_USAGE)

    def test_run_needs_a_model_and_a_real_sample(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = Path(t) / "c.toml"
            cfg.write_text('[paths]\nstate = "%s"\n' % (Path(t) / "state"))
            code, _, err = run("--config", str(cfg), "run", str(Path(t) / "x"))
            self.assertEqual(code, cli.EXIT_LATER, err)      # no [model]: exit 3, as the README says
            self.assertIn("no model", err)
            code, _, err = run("--config", str(cfg), "run", str(Path(t) / "x"), "--mock", str(Path(t) / "none.json"))
            self.assertEqual(code, cli.EXIT_USAGE, err)

    def test_demo_writes_a_sample_the_parser_accepts(self):
        from swarmlabre import swarms
        with tempfile.TemporaryDirectory() as t:
            code, out, _ = run("demo", t)
            self.assertEqual(code, cli.EXIT_OK)
            sample = Path(json.loads(out)["sample"])
            kind, facts, regions = swarms.parse_sample(sample, sample.stat().st_size, [])
            self.assertEqual((kind, facts["format"]), ("elf", "ELF64 x86-64"))
            script = json.loads(Path(json.loads(out)["mock_script"]).read_text())
            self.assertEqual(set(script["roles"]), set(swarms.ROLES))

    def test_notify_runs_the_configured_command_with_fixed_text(self):
        import time
        from swarmlabre import services
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "got.txt"
            n = services.notifier({"swarm": {"notify_cmd": "sh -c 'echo \"$0|$1\" > %s' " % out}})
            n("swarm.done", "s1", run="s1", dur="3 s", verified=2, unconfirmed=1, rejected=0)
            for _ in range(50):
                if out.exists() and out.read_text():
                    break
                time.sleep(0.1)
            self.assertEqual(out.read_text().strip(), "Swarm run finished|Run s1 finished in 3 s: 2 verified, 1 unconfirmed, 0 rejected findings.")
            services.notifier({})("swarm.done", "s1")        # no command: nothing happens

    def test_missing_config_is_a_usage_error(self):
        self.assertEqual(run("--config", "/no/such/file.toml", "report", "x")[0], cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
