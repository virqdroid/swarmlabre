"""site/index.html (the one-pager on GitHub Pages): it makes no request to another site, loads no script, links only to files that exist or that pages.yml puts there, and says
nothing the README does not say. It needs no browser and no network; the browser check is tests/ui/site.py."""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "site" / "index.html"
WORKFLOW = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
REPO = "https://github.com/virqdroid/swarmlabre"
DEMO_BUNDLE = "demo/sfaef16e6"

# Files of the published site that are not in site/ but are copied there by .github/workflows/pages.yml (published path -> source in the repo).
COPIED = {
    "architecture.svg": "docs/architecture.svg",
    "img/demo-1280.png": "docs/img/demo-1280.png",
    "sample/report.html": DEMO_BUNDLE + "/out/report.html",
    "fonts/geist.woff2": "ui/fonts/geist.woff2",
    "fonts/geistmono.woff2": "ui/fonts/geistmono.woff2",
    "fonts/OFL.txt": "ui/fonts/OFL.txt",
}
BUILT = ("demo/",)                       # site/demo/ is written by tools/build-demo.py in the workflow


class Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.hrefs, self.resources, self.text, self.style, self._in = [], [], [], [], "", []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        self._in.append(tag)
        if tag == "a" and "href" in a:
            self.hrefs.append(a["href"])
        for k in ("src", "srcset", "action", "data", "poster", "formaction"):
            if k in a:
                self.resources.append(a[k])
        if tag == "link" and "href" in a:
            self.resources.append(a["href"])
        if "style" in a:
            self.style += a["style"] + "\n"
        if tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = a.get("content", "")

    def handle_endtag(self, tag):
        if self._in and self._in[-1] == tag:
            self._in.pop()

    def handle_data(self, data):
        if self._in and self._in[-1] == "style":
            self.style += data
        elif "title" not in self._in:
            self.text.append(data)


def scan():
    s = Scan()
    s.csp = ""
    s.feed(PAGE.read_text(encoding="utf-8"))
    return s


def words(text):
    """Text as one line with the Markdown and HTML marks gone, so a sentence can be compared across README and page."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"[*`]", "", text)
    return re.sub(r"\s+", " ", text).strip()


class SiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = scan()
        cls.raw = PAGE.read_text(encoding="utf-8")

    def test_no_script_form_frame_or_stylesheet_link(self):
        for tag in ("script", "form", "iframe", "frame", "object", "embed", "link", "base", "input", "button"):
            self.assertNotIn(tag, self.s.tags, "<%s> on the page" % tag)

    def test_it_fetches_nothing_from_another_site(self):
        urls = [m for m in re.findall(r"url\(\s*['\"]?([^'\")]+)", self.s.style)] + self.s.resources
        self.assertTrue(urls)
        for u in urls:
            self.assertFalse(re.match(r"^([a-z][a-z0-9+.-]*:|//)", u, re.I), "fetches %r" % u)
            self.assertNotIn("..", u)
        # the page's own policy says so too, in the browser
        self.assertIn("default-src 'none'", self.s.csp)
        self.assertNotRegex(self.s.csp, r"https?:|\*|script-src|connect-src|unsafe-eval")
        self.assertNotIn("@import", self.s.style)

    def test_every_link_goes_to_this_site_or_to_the_repository(self):
        self.assertTrue(self.s.hrefs)
        for h in self.s.hrefs:
            if h.startswith("http"):
                self.assertTrue(h == REPO or h.startswith(REPO + "/blob/main/"), "link to %r" % h)
            else:
                self.assertFalse(h.startswith("/") or ":" in h, "link %r is not relative to the page" % h)

    def test_every_relative_target_exists_or_is_put_there_by_the_workflow(self):
        targets = {h.split("#")[0] for h in self.s.hrefs + self.s.resources + re.findall(r"url\(\s*['\"]?([^'\")]+)", self.s.style) if not h.startswith("http") and not h.startswith("#")}
        for t in sorted(targets):
            if t in BUILT:
                self.assertIn("--out site/" + t.rstrip("/"), WORKFLOW)
            elif t in COPIED:
                self.assertTrue((ROOT / COPIED[t]).is_file(), "%s: its source %s is missing" % (t, COPIED[t]))
                self.assertIn("site/" + t, WORKFLOW, "pages.yml does not copy %s" % t)
            else:
                self.assertTrue((ROOT / "site" / t).is_file(), "%s is neither in site/ nor copied by pages.yml" % t)

    def test_every_copy_in_the_workflow_is_a_file_the_test_knows(self):
        for dst in re.findall(r"^\s+cp\s+\S.*?\s(site/\S+)\s*$", WORKFLOW, re.M):
            if dst.endswith("/"):
                continue
            self.assertIn(dst[len("site/"):], COPIED, dst)

    def test_repository_links_name_files_that_exist(self):
        for h in self.s.hrefs:
            if "/blob/main/" in h:
                self.assertTrue((ROOT / h.split("/blob/main/", 1)[1]).is_file(), h)

    def test_the_two_images_have_real_sizes_and_alt_text(self):
        img = re.findall(r"<img\b[^>]*>", self.raw)
        self.assertEqual(len(img), 2)
        for tag in img:
            self.assertRegex(tag, r'alt="[^"]{20,}"')
            self.assertRegex(tag, r'width="\d+" height="\d+"')
        png = (ROOT / "docs/img/demo-1280.png").read_bytes()
        w, h = int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big")
        self.assertIn('width="%d" height="%d"' % (w, h), self.raw)

    def test_the_only_address_it_names_is_the_repository(self):
        # No list of forbidden names here (a list would name them in a public repo): every address on the page, and in the workflow, must be the repository's or none.
        for name, text in (("index.html", self.raw), ("pages.yml", WORKFLOW)):
            for u in re.findall(r"https?://[^\s'\"<>)\\]+", text):
                self.assertTrue(u == REPO or u.startswith(REPO + "/") or u == "http://www.w3.org/2000/svg", "%s names %s" % (name, u))   # the XML namespace in the workflow's own check
        self.assertNotRegex(self.raw, r"swrm\.re|github\.io")          # the page works on any host: it does not know its own address

    def test_the_claims_are_the_readmes(self):
        readme = words((ROOT / "README.md").read_text(encoding="utf-8"))
        page = words("".join(self.s.text))
        sentences = [
            "Up to six AI agents analyse one binary (ELF, PE or APK) at the same time. They share one findings board, and swarmlabre checks every finding against the file's own bytes and against the tool calls the run really made. The report is built from the checked facts; the agents' prose is labelled as model text. A finished run is sealed and replays offline to byte-identical report files.",
            "Every run is sealed with a manifest.json (tool version, sample hash, model and sampling, image ids, and the SHA-256 of every input and output file), the board's inputs in order, and every model exchange. swarmlabre replay rebuilds the board and all report files offline from that record and fails if one byte differs. A live run is pinned (temperature and seed are forced on every request) and recorded, but not promised to repeat: six agents share one model.",
            "The agents run in containers with --network none and never hold the model's key; the model reaches them only through a socket swarmlabre owns.",
            "Not a sandbox for running malware: the sample is only read, never executed. Do not point it at a file you could not safely open in a disassembler.",
            "Not a claim that a verdict is right. A verdict, a family name and a confidence are a model's opinion, capped by what the board could check. A finding marked byte-checked means the bytes are there at that offset; it does not mean the agent's reading of them is correct.",
            "Not repeatable for a live model run. Replay of a recording is byte-identical; a second live run on the same file can differ",
            "Not tested on other CPU architectures or with more than one model, and no check in this repository involves real malware: the tests and the demo use generated benign files only. The tools image builds for arm64 only today.",
            "It runs no model and sends nothing anywhere. The sample is a harmless generated program that only exits; the agents were a scripted mock, so what you see is the pipeline and the checks, not the quality of any model.",
            "It was built and checked on one machine (Linux arm64, Python 3.12.3).",
        ]
        for s in sentences:
            s = words(s)
            self.assertIn(s, page, "the page does not say: %s" % s[:70])
            self.assertIn(s, readme, "the README does not say: %s" % s[:70])

    def test_the_commands_are_the_readmes_and_the_counts_are_true(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        pre = re.search(r"<pre>(.*?)</pre>", self.raw, re.S).group(1)
        for line in pre.splitlines():
            cmd = re.sub(r"\s+#.*$", "", line).strip()
            if cmd and not cmd.startswith(("git clone", "cd ", "#")):
                self.assertIn(cmd, readme, cmd)
        self.assertEqual(len(list((ROOT / "tests" / "golden").glob("*/case.json"))), 11)
        self.assertIn("11 golden cases", self.raw)
        self.assertTrue((ROOT / DEMO_BUNDLE).is_dir())
        self.assertIn("alpha 0.1.0", self.raw)
        self.assertIn('__version__ = "0.1.0"', (ROOT / "swarmlabre" / "__init__.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
