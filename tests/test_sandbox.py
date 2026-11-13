"""The container command line and its checks (no Docker is started)."""
import json
import tempfile
import unittest
from pathlib import Path

from swarmlabre import sandbox

PROF = {"image": "swarmlabre-agent", "network": "none", "proxy": "socket", "memory": "1g"}


class SandboxTest(unittest.TestCase):
    def test_the_command_line_is_locked_down(self):
        a = sandbox.Sandbox("swarmlabre-s1", PROF).argv(["sleep", "1"], mounts=[("/a", "/in", "ro")], proxy_dir="/p", env={"K": "v"})
        s = " ".join(a)
        for need in ("--cap-drop ALL", "no-new-privileges", "--read-only", "--network none", "--pids-limit", "--memory 1g", "/p:/run/proxy:ro", "/a:/in:ro", "K=v"):
            self.assertIn(need, s)
        self.assertNotIn("host.docker.internal", s)
        self.assertNotIn("--privileged", s)

    def test_refused_configurations(self):
        with self.assertRaises(ValueError):
            sandbox.Sandbox("x", {**PROF, "network": "bridge"}).argv(["x"], proxy_dir="/p")
        with self.assertRaises(ValueError):
            sandbox.Sandbox("x", {**PROF, "proxy": "tcp"}).argv(["x"], proxy_dir="/p")
        with self.assertRaises(ValueError):
            sandbox.Sandbox("x", PROF).argv(["x"])                    # a socket profile without its directory
        with self.assertRaises(ValueError):
            sandbox.Sandbox("bad name; rm", PROF)

    def test_posture_flags_every_weakness(self):
        good = {"HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "NetworkMode": "none", "Binds": ["/p:/run/proxy:ro"],
                               "Memory": 1, "PidsLimit": 5}, "Config": {"User": "1000:1000"}}
        self.assertEqual(sandbox.posture(good), [])
        bad = json.loads(json.dumps(good))
        bad["HostConfig"].update(ReadonlyRootfs=False, Privileged=True, NetworkMode="bridge", Binds=["/var/run/docker.sock:/s", "/p:/run/proxy"], Memory=0, PidsLimit=0)
        bad["Config"]["User"] = "root"
        self.assertEqual(len(sandbox.posture(bad)), 8)

    def test_skills_must_have_matching_front_matter(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "good"
            d.mkdir()
            (d / "SKILL.md").write_text("---\nname: good\ndescription: does a thing\n---\nbody\n")
            (Path(t) / "bad").mkdir()
            (Path(t) / "bad" / "SKILL.md").write_text("---\nname: other\ndescription: x\n---\n")
            self.assertEqual(sandbox.check_skills(t, ["good", "good"]), ["good"])
            for names in (["bad"], ["missing"], ["../x"]):
                with self.assertRaises(ValueError):
                    sandbox.check_skills(t, names)

    def test_the_shipped_skills_are_valid(self):
        root = Path(__file__).resolve().parent.parent / "skills"
        self.assertEqual(sandbox.check_skills(root, ["rea-swarm", "rea-reverse-engineering"]), ["rea-swarm", "rea-reverse-engineering"])

    def test_pi_config_is_keyless_and_points_at_the_loopback_forwarder(self):
        with tempfile.TemporaryDirectory() as t:
            served = sandbox.pi_config(t, {"system_prompt": "be careful"}, ["rea-swarm"], {"backend": "mock", "model": "m1"}, {"context_window": 8192, "reasoning": True})
            self.assertEqual(served["model"], "m1")
            m = json.loads((Path(t) / "models.json").read_text())["providers"]["swarmlabre"]
            self.assertEqual((m["baseUrl"], m["apiKey"]), ("http://127.0.0.1:8801/v1", "none"))
            self.assertEqual((m["models"][0]["contextWindow"], m["models"][0]["maxTokens"], m["models"][0]["reasoning"]), (8192, 2048, True))
            self.assertEqual(json.loads((Path(t) / "settings.json").read_text())["skills"], ["/skills/rea-swarm"])
            self.assertIsNone(sandbox.pi_config(t, {}, [], None, {}))


if __name__ == "__main__":
    unittest.main()


class NetworkCheckFailsClosed(unittest.TestCase):
    """Start is blocked unless the throwaway no-network container gave a clear 'no interface, no route out' answer."""

    def run_probe(self, **kw):
        import subprocess
        from unittest import mock
        if "exc" in kw:
            fake = mock.Mock(side_effect=kw["exc"])
        else:
            fake = mock.Mock(return_value=subprocess.CompletedProcess([], kw.get("code", 0), stdout=kw.get("out", ""), stderr=""))
        with mock.patch.object(sandbox.subprocess, "run", fake):
            return sandbox.Health("some-image").blockers()

    def test_a_clear_pass_has_no_blocker(self):
        self.assertEqual(self.run_probe(out='{"nics":[],"reach":false}\n'), [])

    def test_an_interface_or_a_route_out_is_a_blocker(self):
        self.assertTrue(self.run_probe(out='{"nics":["eth0"],"reach":false}'))
        self.assertTrue(self.run_probe(out='{"nics":[],"reach":true}'))

    def test_no_answer_is_not_a_pass(self):
        import subprocess
        for kw in (dict(out="", code=125), dict(out="", code=0), dict(out="not json"), dict(out="{}"), dict(out='{"nics":[]}'), dict(out='{"nics":[],"reach":"no"}'),
                   dict(out='{"nics":[],"reach":false}', code=1), dict(out="null"), dict(exc=OSError("no docker")), dict(exc=subprocess.TimeoutExpired("docker", 40))):
            with self.subTest(**{k: repr(v) for k, v in kw.items()}):
                self.assertTrue(self.run_probe(**kw))
