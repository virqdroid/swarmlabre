"""site/index.html (the one-pager on GitHub Pages): it makes no request to another site, runs exactly one inline script (pinned by its hash in the page's own policy), links only to
files that exist or that pages.yml puts there, says nothing the README does not say, and every number, byte, finding and line of recorded output on it is the demo bundle's.
It needs no browser and no network; the browser check is tests/ui/site.py.

The page is hand-maintained. After editing its script, put the new hash in the page's Content-Security-Policy: test_one_inline_script_pinned_by_its_hash prints the value."""
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "site" / "index.html"
FAVICON = ROOT / "site" / "favicon.svg"
WORKFLOW = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
REPO = "https://github.com/virqdroid/swarmlabre"
DEMO_BUNDLE = "demo/sfaef16e6"
BUNDLE = ROOT / DEMO_BUNDLE
SVG_NS = "http://www.w3.org/2000/svg"

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

ROLE_LABEL = {"triage": "Triage", "static": "Static", "ioc": "Strings/IOC", "crypto": "Crypto/Config", "behaviour": "Behaviour", "reporter": "Reporter"}
STEP_LABEL = {"sample": "File", "host_parse": "Host parse", "prep_functions": "Functions", "prep_edges": "Call edges"}
NUMBER = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}

# The page's copy. Plain lowercase words and phrases that do not belong on it (filler, hedges, inflated words); checked against its visible text, its alt and aria text, and the
# strings its script draws.
BANNED_WORDS = ["simply", "just", "really", "essentially", "basically", "actually", "truly", "very", "powerful", "seamless", "seamlessly", "robust", "cutting-edge",
                "game-changing", "revolutionary", "leverage", "unlock", "elevate", "streamline", "delve", "tapestry", "landscape", "realm", "journey", "here's the thing",
                "in today's", "effortless", "supercharge", "empower", "unleash", "crucial", "pivotal", "comprehensive", "amazing", "awesome", "stunning", "magic",
                "state-of-the-art", "next-generation", "best-in-class", "world-class", "plain"]
EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿⬀-⯿️]")
FORBIDDEN_API = [r"\bfetch\b", r"XMLHttpRequest", r"WebSocket", r"sendBeacon", r"\beval\s*\(", r"new\s+Function", r"\bimport\s*\(", r"localStorage", r"sessionStorage",
                 r"document\.cookie", r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"document\.write", r"\bpostMessage\b", r"\bWorker\b", r"\bopen\s*\("]
ATTR_TEXT = ("alt", "aria-label", "title", "data-idle", "placeholder", "aria-valuetext")


class Scan(HTMLParser):
    """Tags, links, resources, styles, scripts and the visible text of the page. `text` holds (text, inside_code) pieces; `attr_text` the alt/aria/title strings."""
    CODE = ("code", "pre", "kbd", "samp")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.hrefs, self.resources, self.links, self.text, self.attr_text = [], [], [], [], [], []
        self.style, self.csp, self._in, self.scripts = "", "", [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if tag not in ("meta", "link", "img", "input", "br", "source", "path", "rect", "circle", "polygon"):
            self._in.append(tag)
        if tag == "a" and "href" in a:
            self.hrefs.append(a["href"])
        if tag == "link":
            self.links.append(a)
            self.resources.append(a.get("href", ""))
        for k in ("src", "srcset", "action", "data", "poster", "formaction", "background"):
            if k in a and not (tag == "script"):
                self.resources.append(a[k])
        if tag == "script":
            self.scripts.append({"attrs": a, "body": ""})
        if "style" in a:
            self.style += (a["style"] or "") + "\n"
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "content-security-policy":
            self.csp = a.get("content", "")
        for k in ATTR_TEXT:
            if a.get(k):
                self.attr_text.append(a[k])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self._in and self._in[-1] == tag:
            self._in.pop()

    def handle_endtag(self, tag):
        if tag in self._in:
            while self._in and self._in.pop() != tag:
                pass

    def handle_data(self, data):
        cur = self._in[-1] if self._in else ""
        if cur == "style":
            self.style += data
        elif cur == "script":
            self.scripts[-1]["body"] += data
        elif "title" not in self._in and "head" not in self._in:
            self.text.append((data, any(t in self._in for t in self.CODE)))


def scan(raw):
    s = Scan()
    s.feed(raw)
    return s


def words(text):
    """Text as one line with the Markdown and HTML marks gone, so a sentence can be compared across README and page."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"[*`]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def json_block(raw, element_id):
    m = re.search(r'<script type="application/json" id="%s">(.*?)</script>' % element_id, raw, re.S)
    return json.loads(m.group(1))


def replay(bundle):
    p = subprocess.run([sys.executable, "-m", "swarmlabre", "replay", str(bundle)], cwd=ROOT, capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout.splitlines()


class SiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = PAGE.read_text(encoding="utf-8")
        cls.s = scan(cls.raw)
        cls.board = json.loads((BUNDLE / "out" / "board.json").read_text(encoding="utf-8"))
        cls.man = json.loads((BUNDLE / "manifest.json").read_text(encoding="utf-8"))
        cls.sample = (BUNDLE / "input" / "sample").read_bytes()
        cls.stage = json_block(cls.raw, "stage-data")
        cls.term = json_block(cls.raw, "term-data")

    # ---- what the page loads and runs ----

    def test_no_form_frame_object_or_stylesheet(self):
        for tag in ("form", "iframe", "frame", "object", "embed", "base", "input type=file", "audio", "video"):
            self.assertNotIn(tag, self.s.tags, "<%s> on the page" % tag)
        self.assertEqual(self.s.links, [{"rel": "icon", "href": "favicon.svg", "type": "image/svg+xml"}], "the only <link> is the icon")

    def test_it_fetches_nothing_from_another_site(self):
        urls = re.findall(r"url\(\s*['\"]?([^'\")]+)", self.s.style) + self.s.resources
        self.assertTrue(urls)
        for u in urls:
            self.assertFalse(re.match(r"^([a-z][a-z0-9+.-]*:|//)", u, re.I), "fetches %r" % u)
            self.assertNotIn("..", u)
        self.assertNotIn("@import", self.s.style)

    def test_the_policy_allows_nothing_but_the_page_itself(self):
        csp = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in self.s.csp.split(";")) if d}
        self.assertEqual(csp.get("default-src"), ["'none'"])
        self.assertNotIn("connect-src", csp)
        self.assertNotRegex(self.s.csp, r"https?:|\*|unsafe-eval|data:|blob:")
        self.assertEqual(len(csp.get("script-src", [])), 1, "script-src names exactly one hash")
        for d in ("img-src", "font-src"):
            self.assertEqual(csp.get(d), ["'self'"], d)

    def test_one_inline_script_pinned_by_its_hash(self):
        executable = [s for s in self.s.scripts if (s["attrs"].get("type") or "text/javascript") in ("text/javascript", "module")]
        self.assertEqual(len(executable), 1, "exactly one executable <script>")
        for s in self.s.scripts:
            self.assertNotIn("src", s["attrs"], "a <script> with src")
            if s not in executable:
                self.assertEqual(s["attrs"].get("type"), "application/json")
        body = executable[0]["body"]
        want = "'sha256-%s'" % base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()
        self.assertIn("script-src " + want, self.s.csp, "the page's script-src must be %s" % want)

    def test_the_script_has_no_network_storage_or_html_injection(self):
        body = [s for s in self.s.scripts if not s["attrs"].get("type")][0]["body"]
        for pat in FORBIDDEN_API:
            self.assertNotRegex(body, pat)
        self.assertNotRegex(body, r"https?://")

    def test_the_icon_is_a_plain_svg(self):
        svg = FAVICON.read_text(encoding="utf-8")
        self.assertTrue(svg.startswith("<svg "))
        self.assertEqual(re.findall(r"https?://[^\s'\"]+", svg), [SVG_NS])
        self.assertNotRegex(svg, r"(?i)<script|href|on\w+\s*=|<foreignObject|url\(")

    # ---- links ----

    def test_every_link_goes_to_this_site_or_to_the_repository(self):
        self.assertTrue(self.s.hrefs)
        for h in self.s.hrefs:
            if h.startswith("http"):
                self.assertTrue(h == REPO or h.startswith(REPO + "/blob/main/"), "link to %r" % h)
            else:
                self.assertFalse(h.startswith("/") or ":" in h, "link %r is not relative to the page" % h)

    def test_every_relative_target_exists_or_is_put_there_by_the_workflow(self):
        targets = {h.split("#")[0] for h in self.s.hrefs + self.s.resources + re.findall(r"url\(\s*['\"]?([^'\")]+)", self.s.style) if not h.startswith("http") and not h.startswith("#")}
        targets.discard("./")
        self.assertIn("favicon.svg", targets)
        for t in sorted(targets):
            if t in BUILT:
                self.assertIn("--out site/" + t.rstrip("/"), WORKFLOW)
            elif t in COPIED:
                self.assertTrue((ROOT / COPIED[t]).is_file(), "%s: its source %s is missing" % (t, COPIED[t]))
                self.assertIn("site/" + t, WORKFLOW, "pages.yml does not copy %s" % t)
            else:
                self.assertTrue((ROOT / "site" / t).is_file(), "%s is neither in site/ nor copied by pages.yml" % t)

    def test_every_in_page_anchor_exists(self):
        ids = set(re.findall(r'\bid="([^"]+)"', self.raw))
        for h in self.s.hrefs:
            if h.startswith("#"):
                self.assertIn(h[1:], ids, h)

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
        # The one exception is a finding's value from the demo run, shown as data: it must be one of the board's values and under a reserved name (RFC 2606).
        values = {f["value"] for f in self.board["findings"] if re.match(r"https?://[^/]+\.(test|example|invalid)(/|$)", f["value"])}
        for name, text in (("index.html", self.raw), ("pages.yml", WORKFLOW)):
            for u in re.findall(r"https?://[^\s'\"<>)\\]+", text):
                ok = u == REPO or u.startswith(REPO + "/") or (name == "pages.yml" and u == SVG_NS) or (name == "index.html" and (u in values or (u.endswith("…") and any(v.startswith(u[:-1]) for v in values))))
                self.assertTrue(ok, "%s names %s" % (name, u))
        self.assertNotRegex(self.raw, r"swrm\.re|github\.io")          # the page works on any host: it does not know its own address

    # ---- what it says ----

    def test_the_claims_are_the_readmes(self):
        readme = words((ROOT / "README.md").read_text(encoding="utf-8"))
        page = words("".join(t for t, _ in self.s.text))
        sentences = [
            "Up to six AI agents analyse one binary (ELF, PE or APK) and post to one board. SwarmLabRE checks every finding against the file's own bytes and the run's own tool log. The report is built from the checked facts, the agents' prose is labelled as model text, and a finished run replays offline to byte-identical report files.",
            "swarmlabre replay rebuilds the board and every report file offline and exits 1 if one byte differs.",
            "The agents run in containers with --network none and never hold the model's key; the model reaches them only through a socket SwarmLabRE owns.",
            "The tests, the demo and the golden cases use a scripted mock.",
            "Not a sandbox for running malware: the sample is only read, never executed. Do not point it at a file you could not safely open in a disassembler.",
            "Not a claim that a verdict is right. A verdict, a family name and a confidence are a model's opinion, capped by what the board could check. A finding marked byte-checked means the bytes are there at that offset; it does not mean the agent's reading of them is correct.",
            "Not repeatable for a live model run. Replay of a recording is byte-identical; a second live run on the same file can differ",
            "Not tested on other CPU architectures, and no check in this repository involves real malware: the tests and the demo use generated benign files only. The tools image builds for arm64 only today.",
            "Not tamper-proof. Nothing signs manifest.json; someone who edits a file and recomputes the hashes gets a replay that agrees.",
            "It runs no model and sends nothing anywhere.",
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
        self.assertEqual(re.findall(r"\b(\d+) golden cases", self.raw), ["11", "11"])
        self.assertIn("alpha 0.1.0", self.raw)
        self.assertIn('__version__ = "0.1.0"', (ROOT / "swarmlabre" / "__init__.py").read_text(encoding="utf-8"))

    def test_the_copy_has_no_filler_exclamation_or_emoji(self):
        body = [s for s in self.s.scripts if not s["attrs"].get("type")][0]["body"]
        drawn = [m for m in re.findall(r"'((?:[^'\\\n]|\\.){3,})'", body) if re.search(r"[A-Za-z]{3,} [a-z]", m) and not re.search(r"[;{}()=]", m)]       # the strings the script draws or sets as text
        pieces = [t for t, _ in self.s.text] + self.s.attr_text + drawn
        self.assertTrue(drawn)
        for p in pieces:
            low = p.lower()
            for w in BANNED_WORDS:
                self.assertNotRegex(low, r"(?<![a-z])%s(?![a-z])" % re.escape(w), "%r in %r" % (w, p[:80]))
            self.assertNotIn("!", p, p[:80])
            self.assertNotRegex(p, EMOJI, p[:80])
            self.assertNotRegex(p, "[–—]", "a dash in %r" % p[:80])

    def test_the_product_is_written_swarmlabre_in_prose(self):
        # Lowercase `swarmlabre` is the package, the command and the repository: it may appear in code, commands, paths and addresses, never as the product's name in prose.
        prose = [t for t, in_code in self.s.text if not in_code] + self.s.attr_text
        for p in prose:
            for m in re.finditer(r"swarmlabre", p, re.I):
                word = p[m.start():m.end()]
                if word == "SwarmLabRE":
                    continue
                self.assertEqual(word, "swarmlabre", "the product is written %r in %r" % (word, p[:80]))
                self.assertTrue(p[:m.start()].endswith("/"), "lowercase swarmlabre in prose: %r" % p[:80])      # only as a path or address (github.com/virqdroid/swarmlabre)
        title = re.search(r"<title>(.*?)</title>", self.raw).group(1)
        self.assertTrue(title.startswith("SwarmLabRE"), title)
        self.assertIn(">SwarmLabRE<", self.raw.replace('<span class="pill">', "<"))        # the wordmark
        body = [s for s in self.s.scripts if not s["attrs"].get("type")][0]["body"]
        self.assertNotRegex(body, r"'[^']*swarmlabre[^']*'", "the script draws the lowercase name")

    # ---- the demo run, as the page shows it ----

    def test_the_dump_is_the_demo_file_and_the_lit_ranges_are_the_boards(self):
        cells = []
        for hx in re.findall(r'<span class="h">(.*?)</span>', self.raw):
            cells += re.findall(r'<i(?: class="f (f\d+)")?>([0-9a-f]{2})</i>', hx)
        self.assertEqual(bytes(int(b, 16) for _, b in cells), self.sample)
        lit = {}
        for off, (fid, _) in enumerate(cells):
            if fid:
                lit.setdefault(fid, []).append(off)
        want = {f["id"]: list(range(f["off"], f["off"] + f["len"])) for f in self.board["findings"] if f["level"] == "byte-checked"}
        self.assertEqual(lit, want)
        for f in self.board["findings"]:
            if f["level"] == "byte-checked":
                self.assertEqual(self.sample[f["off"]:f["off"] + f["len"]], f["value"].encode("utf-16-le" if f["enc"] == "utf16le" else "latin-1"), f["id"])
        chips = re.findall(r'<button type="button" class="chip" data-f="(f\d+)" aria-pressed="false"><b>(f\d+)</b>([^<]+)</button>', self.raw)
        self.assertEqual([(c[0], c[2]) for c in chips], [(f["id"], f["title"]) for f in self.board["findings"] if f["level"] == "byte-checked"])

    def test_socrates_is_drawn_in_the_demo_files_characters_and_credited(self):
        # The hero's figure is decoration: the statue shaded with characters that occur in the demo file (its hex digits and its printable bytes). It is an adaptation
        # of a CC BY-SA 4.0 photo, so the page credits the photographer and the licence, and THIRD_PARTY.md lists it.
        m = re.search(r'<pre class="soc" aria-hidden="true">(.*?)</pre>', self.raw, re.S)
        self.assertTrue(m, "the hero has its figure, hidden from screen readers")
        self.assertIsNone(re.search(r"<(?!/?i\b)", m.group(1)), "only <i> runs inside the figure")
        glyphs = set(re.sub(r"<[^>]+>|\s", "", m.group(1)).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&#x27;", "'").replace("&quot;", '"'))
        allowed = set("0123456789abcdef") | {chr(c) for c in self.sample if 32 < c < 127}
        self.assertTrue(glyphs)
        self.assertLessEqual(glyphs, allowed, "glyphs not from the demo file: %r" % sorted(glyphs - allowed))
        page = words("".join(t for t, _ in self.s.text))
        self.assertIn("after a photo by C messier (CC BY-SA 4.0, credits)", page)
        third = (ROOT / "THIRD_PARTY.md").read_text(encoding="utf-8")
        self.assertIn("C messier", third)
        self.assertIn("CC BY-SA 4.0", third)

    def test_the_table_is_the_boards(self):
        rows = re.findall(r"<tr class=\"(chk|rej|)\" data-v=\"(\w+)\"([^>]*)><th scope=\"row\">(\w+)</th><td>([^<]*)</td><td>(.*?)</td><td class=\"o\">([^<]*)</td><td class=\"res\">(.*?)</td></tr>", self.raw)
        want = self.board["findings"] + self.board["rejected"]
        self.assertEqual(len(rows), len(want))
        for row, f in zip(rows, want):
            cls, verdict, attrs, fid, agent, finding, where, result = row
            self.assertEqual(fid, f["id"])
            self.assertEqual(agent, ROLE_LABEL[f["agent"]])
            self.assertTrue(finding.startswith(f["title"].replace("&", "&amp;")), finding)
            if f in self.board["rejected"]:
                self.assertEqual((cls, verdict, where), ("rej", "bad", "none"))
                self.assertIn(">rejected<", result)
                continue
            checked = f["level"] == "byte-checked"
            self.assertEqual((cls, verdict), ("chk", "ok") if checked else ("", "un"))
            self.assertIn(">%s<" % ("byte-checked" if checked else "unconfirmed"), result)
            if checked:
                self.assertEqual(where, "%d (0x%x)" % (f["off"], f["off"]))
                self.assertIn('data-off="%d" data-len="%d"' % (f["off"], f["len"]), attrs)
            else:
                self.assertEqual(where, "none")
            if f["disputes"]:
                self.assertIn("%s disputed it; the orchestrator ruled it %s." % (ROLE_LABEL[f["disputes"][0]["agent"]], f["resolution"]["verdict"]), result)
        c = self.board["counts"]
        tally = dict(re.findall(r'<b data-t="(\w+)">(\d+)</b>', self.raw))
        self.assertEqual(tally, {"ok": str(c["byte-checked"]), "un": str(c["unconfirmed"]), "bad": str(c["rejected"])})
        posts = c["total"] + c["rejected"]
        self.assertIn("<h2>%s posts, each checked by the board</h2>" % NUMBER[posts].capitalize(), self.raw)
        self.assertIn("In this run, %s posts reached the board." % NUMBER[posts], self.raw)
        self.assertIn("%s were byte-checked, %s stayed unconfirmed and %s was rejected as a duplicate." % (
            NUMBER[c["byte-checked"]].capitalize(), NUMBER[c["unconfirmed"]], NUMBER[c["rejected"]]), self.raw)
        self.assertIn("The %s lit ranges" % NUMBER[c["byte-checked"]], self.raw)

    def test_the_file_facts_are_the_manifests(self):
        sha = self.man["sample"]["sha256"]
        self.assertEqual(hashlib.sha256(self.sample).hexdigest(), sha)
        prefixes = set(re.findall(r"([0-9a-f]{12})…", self.raw))
        self.assertEqual(prefixes, {sha[:12]})
        self.assertIn("an ELF of %d bytes" % len(self.sample), self.raw)
        self.assertIn("All %d bytes of" % len(self.sample), self.raw)
        for name in self.man["outputs"]:
            self.assertIn('class="t2 mono">%s</text>' % name, self.raw)

    def test_the_run_animation_is_the_event_log(self):
        D = self.stage
        ev = [json.loads(line) for line in (BUNDLE / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        lay = json.loads((BUNDLE / "layout.json").read_text(encoding="utf-8"))
        t0 = ev[0]["t"]
        self.assertEqual(D["bytes"], self.sample.hex())
        self.assertEqual(D["size"], len(self.sample))
        self.assertEqual((D["regions"], D["entropy"], D["ebytes"], D["edges"]), (lay["regions"], lay["entropy"], lay["cell_bytes"], lay["edges"]))
        self.assertEqual(D["funcs"], [{"name": f["name"], "off": f["off"]} for f in lay["functions"]])
        self.assertEqual(D["sample"], {"name": self.man["sample"]["name"], "format": lay["format"]})
        titles = {f["title"]: f["id"] for f in self.board["findings"]}
        expect = []
        for e in ev:
            k, n = e["k"], e["n"]
            if k == "step" and e["status"] == "ok" and e["step"] in STEP_LABEL and e["msg"]:
                expect.append({"n": n, "k": "step", "label": STEP_LABEL[e["step"]], "msg": e["msg"]})
            elif k == "phase":
                expect.append({"n": n, "k": "phase", "p": e["phase"]})
            elif k in ("task_start", "task_end"):
                expect.append({"n": n, "k": "start" if k == "task_start" else "end", "role": e["role"]})
            elif k == "finding" and e["op"] == "add":
                f = e["f"]
                expect.append({"n": n, "k": "find", "role": e["role"], "id": f["id"], "title": f["title"], "off": f["off"], "len": f["len"], "ok": f["level"] == "byte-checked"})
            elif k == "finding" and e["op"] == "dispute":
                expect.append({"n": n, "k": "dispute", "role": e["role"], "id": e["f"]["id"]})
            elif k == "resolution":
                expect.append({"n": n, "k": "resolve", "id": e["f"]["id"], "verdict": e["f"]["resolution"]["verdict"]})
            elif k == "reject":
                expect.append({"n": n, "k": "reject", "role": e["role"], "id": e["x"]["id"], "code": e["x"]["code"], "target": titles[e["x"]["title"]]})
            elif k == "done":
                expect.append({"n": n, "k": "done"})
            else:
                continue
            expect[-1]["t"] = round(e["t"] - t0, 2)
        got = [{k: v for k, v in b.items() if k != "c"} for b in D["beats"]]
        self.assertEqual(got, sorted(expect, key=lambda b: b["n"]))
        cs = [b["c"] for b in D["beats"]]
        self.assertEqual(cs, sorted(cs), "the clip time runs forward")
        self.assertGreater(D["end"], cs[-1])
        self.assertEqual([[r, s] for _, r, s in D["lanes"]], [[e["role"], e["state"]] for e in ev if e["k"] == "lane"])
        self.assertEqual(len(D["tools"]), sum(1 for e in ev if e["k"] == "tool_start"))
        longest = max((e for e in ev if e["k"] == "tool_end"), key=lambda e: e["ms"])
        self.assertEqual(D["note"]["text"], "Shortened: %s waited %d s on one tool call" % (ROLE_LABEL[longest["role"]], round(longest["ms"] / 1000)))
        self.assertEqual(D["roles"], [{"id": r, "letter": {"behaviour": "B", "crypto": "C", "ioc": "I", "reporter": "R", "static": "S", "triage": "T"}[r], "label": ROLE_LABEL[r]}
                                      for r in ("triage", "static", "ioc", "crypto", "behaviour", "reporter")])

    def test_the_terminals_are_what_replay_prints(self):
        T = self.term
        code, out = replay(BUNDLE)
        self.assertEqual((code, out), (0, T["ok"]["lines"]))
        self.assertEqual((T["ok"]["cmd"], T["ok"]["exit"]), ("python3 -m swarmlabre replay " + DEMO_BUNDLE, 0))
        with tempfile.TemporaryDirectory(prefix="swarmlabre-site-") as tmp:
            copy = Path(tmp) / "edited-copy" / BUNDLE.name
            shutil.copytree(BUNDLE, copy, symlinks=True)
            md = copy / "out" / "report.md"
            text = md.read_text(encoding="utf-8")
            self.assertIn("demo", text)
            md.write_text(text.replace("demo", "Demo", 1), encoding="utf-8")         # the page says: the d of "demo" in out/report.md became D
            code, out = replay(copy)
        self.assertEqual((code, out), (1, T["bad"]["lines"]))
        self.assertEqual((T["bad"]["cmd"], T["bad"]["exit"]), ("python3 -m swarmlabre replay edited-copy/" + BUNDLE.name, 1))
        # the same text, as plain HTML for a browser without the script
        for key, pre_id in (("ok", "t-ok"), ("bad", "t-bad")):
            pre = re.search(r'<pre id="%s">(.*?)</pre>' % pre_id, self.raw, re.S).group(1)
            plain = "\n".join(["$ " + T[key]["cmd"]] + T[key]["lines"] + ["exit %d" % T[key]["exit"]])
            self.assertEqual(pre, plain.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


if __name__ == "__main__":
    unittest.main()
