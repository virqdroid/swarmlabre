"""The benign corpus: deterministic bytes, files the host parse accepts, nothing a scanner would treat as malware."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from swarmlabre import cli, corpus, swarms


class CorpusTest(unittest.TestCase):
    def parse(self, name):
        with tempfile.TemporaryDirectory() as t:
            p, b = corpus.write(name, t)
            classes = []
            return swarms.parse_sample(p, len(b.data), classes) + (classes,)

    def test_building_twice_gives_the_same_bytes(self):
        for n in corpus.NAMES:
            self.assertEqual(corpus.build(n).data, corpus.build(n).data, n)

    def test_the_formats_are_what_they_say(self):
        self.assertEqual(self.parse("pe-benign")[:2][0], "pe")
        self.assertEqual(self.parse("pe-benign")[1]["format"], "PE32+ x86-64")
        self.assertEqual([r["name"] for r in self.parse("pe-benign")[2]], ["PE headers", ".text", ".rdata", ".data"])
        k, facts, regions, classes = self.parse("apk-benign")
        self.assertEqual((k, facts["dex_files"], [c["name"] for c in classes]), ("apk", ["classes.dex"], ["com.example.demo.MainActivity"]))
        self.assertEqual(self.parse("elf-hostile")[0], "elf")

    def test_the_offsets_point_at_the_strings(self):
        for n in corpus.NAMES:
            b = corpus.build(n)
            for s, o in b.offsets.items():
                ascii_, wide = s.encode(), s.encode("utf-16-le")                                    # a few demo strings are stored as UTF-16
                self.assertTrue(b.data[o:o + len(ascii_)] == ascii_ or b.data[o:o + len(wide)] == wide, (n, s))

    def test_a_script_is_not_a_sample(self):
        with tempfile.TemporaryDirectory() as t:
            p, b = corpus.write("script-sh", t)
            with self.assertRaises(ValueError) as cm:
                swarms.parse_sample(p, len(b.data), [])
            self.assertEqual(str(cm.exception), "Only ELF, PE and APK files are supported.")

    def test_only_reserved_names_and_addresses(self):
        import re
        for n in corpus.NAMES:
            text = corpus.build(n).data.decode("latin-1")
            for host in re.findall(r"https?://([A-Za-z0-9.\[\]-]+)", text):
                if host.startswith("schemas.android.com"):
                    continue                                                         # the Android manifest namespace, not a host anyone contacts
                self.assertRegex(host, r"(?i)\.(test|invalid|example)$|^(203\.0\.113|198\.51\.100)\.|\[\.\]example\.test$", (n, host))
        self.assertNotIn(b"EICAR", b"".join(corpus.build(n).data for n in corpus.NAMES))

    def test_cli_writes_them(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        with tempfile.TemporaryDirectory() as t, redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["corpus", t, "pe-benign"]), cli.EXIT_OK)
            self.assertEqual(hashlib.sha256((Path(t) / "demo.exe").read_bytes()).hexdigest(), corpus.sha256("pe-benign"))
            self.assertEqual(cli.main(["corpus", t, "nope"]), cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
