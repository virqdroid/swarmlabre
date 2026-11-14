"""The scripts the agents run inside the container: the parts that can be checked without a container."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(path, name):
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec = importlib.util.spec_from_file_location(name, str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = old


class ToolAllowlist(unittest.TestCase):
    """rea-session.py lets an agent call only the static-analysis tools of rea. The list is a regex: a name that merely starts like an allowed one must not pass."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load(ROOT / "skills" / "rea-reverse-engineering" / "scripts" / "rea-session.py", "rea_session_under_test")

    def test_the_listed_tools_pass(self):
        for name in ("open_binary", "list_strings", "procedure_callers", "trace_feature", "analyze_function", "xrefs", "find_xrefs_to_name", "extract_artifact", "inspect_managed_members", "get_evidence_bundle", "compare_functions"):
            with self.subTest(name=name):
                self.assertTrue(self.mod.allowed(name))

    def test_a_name_that_only_starts_like_an_allowed_one_is_refused(self):
        for name in ("open_binary_x", "read_bytes_and_run", "analyze_function_runtime", "trace_feature_capture", "get_evidence_bundle_and_exec", "extract_artifact2", "", " open_binary", "open_binary\n", "xrefs_to"):
            with self.subTest(name=name):
                self.assertFalse(self.mod.allowed(name))

    def test_nothing_that_runs_or_captures_is_listed(self):
        for pat in self.mod.ALLOWED:
            self.assertNotRegex(pat, r"(?i)^capture_|^observe_|runtime|execute|launch|debug|frida")           # inspect_web_network_capture reads a SAVED capture file: that one is static


if __name__ == "__main__":
    unittest.main()
