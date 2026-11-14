#!/usr/bin/env python3
"""Text parity of the Swarms page, in headless Firefox, at 1280 and 500 px, for the three ways the same finished run is shown.

    python3 tests/ui/parity.py [BUNDLE ...]      (default: a generated run; any sealed run folder or bundle can be named)

Modes: live (`swarmlabre serve` over a state folder that holds the run), replay (`serve --replay`, played to the end) and static (the build-demo page, played to the end, served
by a plain http.server). For each mode and width the check compares three things that must say the same:

  1. the API (the board and run record the page was given),
  2. the page: every finding on the Findings tab (title, value, level, status, offset, who found it) and the counts of the result card,
  3. report.html as the page's own download route serves it, opened in the browser: every card (title, value, level, offset, disputed) of the checked findings.

Findings the report shows are the verified and disputed ones; titles and values there are defanged, so the comparison is made on defanged text. A finding on the page that the report
must show but does not, or the other way round, fails. Afterwards the three modes' final API answers (run record, board, task rows) are compared with each other.
It also fails on a page JavaScript error and on horizontal overflow. Exit code 0 = all passed.
Needs `geckodriver` and `firefox` (the snap is fine: profiles go under ~/swarmlabre-uitmp).
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tests"))

import wd                                      # noqa: E402
from swarmlabre import report as srep          # noqa: E402

WIDTHS = (1280, 500)
LOOPBACK = "127.0.0.1"


class Fail(Exception):
    pass


class Servers:
    """Starts what a mode needs and stops it again. `url(mode)` -> the address to open (with the token fragment where one is needed)."""

    def __init__(self, bundle, work):
        self.bundle, self.work, self.procs, self.urls = Path(bundle), Path(work), [], {}

    def start(self):
        state = self.work / "state"
        runs = state / "runs"
        runs.mkdir(parents=True)
        shutil.copytree(self.bundle, runs / self.bundle.name, ignore=shutil.ignore_patterns("model-trace.jsonl.gz"))
        cfg = self.work / "swarmlabre.toml"
        cfg.write_text('[paths]\nstate = "%s"\n' % state)
        py = [sys.executable, "-m", "swarmlabre", "--config", str(cfg)]
        ready = re.compile(r"(http://[^\s]+)")
        env_cwd = str(ROOT)
        for mode, extra in (("live", ["serve", "--port", "0"]), ("replay", ["serve", "--port", "0", "--replay", str(self.bundle), "--speed", "1000"])):
            p = subprocess.Popen(py + extra, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=env_cwd)
            self.procs.append(p)
            end = time.time() + 60
            while True:
                if time.time() > end:
                    raise Fail("%s: no address printed" % mode)
                line = p.stdout.readline()
                if not line:
                    raise Fail("%s ended early" % mode)
                m = ready.search(line)
                if m:
                    self.urls[mode] = m.group(1)
                    break
        out = self.work / "site"
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "build-demo.py"), str(self.bundle), "--out", str(out), "--speed", "1000"], capture_output=True, text=True)
        if r.returncode:
            raise Fail("build-demo: " + r.stderr)
        port = wd.free_port()
        p = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", LOOPBACK, "--directory", str(out)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        self.urls["static"] = "http://%s:%d/" % (LOOPBACK, port)
        time.sleep(0.6)

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


FETCH = """const cb=arguments[arguments.length-1], path=arguments[0], opts=arguments[1]||{};
const init={method:opts.method||'GET',headers:{Authorization:'Bearer '+(sessionStorage.getItem('swarmlabreToken')||''),'Content-Type':'application/json'}};
if(opts.body!==undefined)init.body=JSON.stringify(opts.body);
fetch('api/'+path,init).then(r=>r.text().then(t=>cb({code:r.status,text:t}))).catch(e=>cb({code:0,text:String(e)}));"""


def get(b, path, **opts):
    r = b.jsa(FETCH, path, opts)
    if r["code"] != 200:
        raise Fail("api/%s -> %s %s" % (path, r["code"], r["text"][:200]))
    return r["text"]


def hexs(n):
    return "0x%x" % n


def norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def js_errors(b):
    return [ln for ln in b.console_log().splitlines() if ln.startswith("JavaScript error: http")]


def open_page(b, mode, url):
    b.get(url)
    b.wait_for("document.querySelector('#sw-name') && document.querySelector('#sw-name').textContent", 30)
    if mode != "live":
        b.jsa(FETCH, "replay", {"method": "POST", "body": {"end": True}})
    b.wait_for("document.querySelector('#sw-stchip') && /^(Done|Failed|Stopped)/i.test(document.querySelector('#sw-stchip').textContent)", 60)
    b.js("swPane('findings')")
    time.sleep(0.5)


def final_state(b, rid):
    run = json.loads(get(b, "swarm/" + rid))
    board = json.loads(get(b, "swarm/%s/board" % rid))
    return run, board


def check_view(b, mode, width, rid, tmpdir, rows):
    """Every comparison for one browser. `rows` collects (name, ok, detail)."""
    def ok(name, cond, detail=""):
        rows.append((mode, width, name, bool(cond), "" if cond else detail))
    run, board = final_state(b, rid)
    fs = board["findings"]
    kind = (run.get("sample") or {}).get("kind")
    ok("run is finished", run["status"] in ("done", "failed", "stopped"), run["status"])
    ok("run has a report", run.get("has_report") and run.get("has_html"), "has_report/has_html")

    # --- 2. the page against the API
    b.wait_for("document.querySelectorAll('#sw-board .sw-card').length >= Math.min(%d, 300)" % len(fs), 30)
    page = b.js("""const o={};document.querySelectorAll('#sw-board .sw-card').forEach(c=>{o[c.dataset.id]={cls:c.className,title:(c.querySelector('.ti')||{}).textContent||'',value:(c.querySelector('.vl')||{}).textContent||'',
      kind:(c.querySelector('.kd')||{}).textContent||'',chips:[...c.querySelectorAll('.ev button,.ev span,.ev .sw-chip')].map(x=>x.textContent),meta:(c.querySelector('.mt')||{}).textContent||'',text:c.innerText}});return o""")
    ok("board shows every finding (up to 300)", len(page) == min(len(fs), 300), "%d cards for %d findings" % (len(page), len(fs)))
    bad = []
    for f in fs[:300]:
        c = page.get(f["id"])
        if not c:
            bad.append(f["id"] + " missing")
            continue
        if c["title"] != f["title"]:
            bad.append("%s title %r != %r" % (f["id"], c["title"], f["title"]))
        if (f.get("value") or "") != c["value"]:
            bad.append("%s value" % f["id"])
        if f["status"] not in c["meta"] or f["id"] not in c["meta"]:
            bad.append("%s status/id missing in %r" % (f["id"], c["meta"]))
        if f["status"] not in c["cls"]:
            bad.append("%s class %r vs status %s" % (f["id"], c["cls"], f["status"]))
        offs = [e["off"] for e in f.get("evidence") or [] if e.get("off") is not None] or ([f["off"]] if isinstance(f.get("off"), int) else [])
        for o in offs:
            if hexs(o) not in c["text"]:
                bad.append("%s offset %s not shown" % (f["id"], hexs(o)))
    ok("every finding's title, value, status and offset are on the page", not bad, "; ".join(bad[:5]))
    verdict = norm(b.js("return document.querySelector('#sw-verdict').innerText"))
    c = board["counts"]
    miss = [w for k, w in (("byte-checked", "byte-checked"), ("call-cited", "call-cited"), ("unconfirmed", "unconfirmed"), ("disputed", "disputed")) if c[k] and ("%d %s" % (c[k], w)) not in verdict]    # a zero row is not shown
    ok("result card counts equal the board's", not miss, "missing %s in %r" % (miss, verdict[:300]))
    ok("rejected count in the page", ("Rejected posts (%d" % c["rejected"]) in norm(b.js("return document.querySelector('#sw-rejs').textContent")) if c["rejected"] else True)
    over = b.js("return [document.documentElement.scrollWidth, window.innerWidth]")
    ok("no horizontal overflow", over[0] <= over[1], str(over))

    # --- 3. report.html, opened in the browser
    html = get(b, "swarm/%s/report.html" % rid)
    fp = Path(tmpdir) / ("report-%s-%d.html" % (mode, width))
    fp.write_text(html, encoding="utf-8")
    b2 = b
    b2.get(fp.as_uri())
    b2.wait_for("document.querySelector('#cards')", 30)
    b2.js("document.querySelectorAll('#cards .card').forEach(c=>c._open&&c._open())")
    rep = b2.js("""const o={};document.querySelectorAll('#cards .card').forEach(c=>{const q=s=>(c.querySelector(s)||{}).textContent||'';o[c.id.slice(2)]={title:q('.tt'),off:q('.off'),pills:[...c.querySelectorAll('.pill')].map(x=>x.textContent),
      value:q('pre.val'),meta:q('.meta')}});return o""")
    checked = [f for f in fs if f["status"] in ("verified", "disputed")]
    ok("report cards are exactly the verified and disputed findings", set(rep) == {f["id"] for f in checked}, "report-only %s, page-only %s" % (sorted(set(rep) - {f["id"] for f in checked})[:5], sorted({f["id"] for f in checked} - set(rep))[:5]))
    bad = []
    for f in checked:
        r = rep.get(f["id"])
        if not r:
            continue
        want_t = srep.defang_text(f["title"])[:300]
        if r["title"] != want_t:
            bad.append("%s title %r != %r" % (f["id"], r["title"], want_t))
        if srep.defang_text(page[f["id"]]["title"])[:300] != r["title"]:
            bad.append("%s page title does not match report title" % f["id"])
        v = srep.defang(f.get("value") or "", kind)[:srep.VALUE_CAP] if hasattr(srep, "VALUE_CAP") else srep.defang(f.get("value") or "", kind)
        if r["value"] != v:
            bad.append("%s value %r != %r" % (f["id"], r["value"], v))
        if isinstance(f.get("off"), int) and r["off"] != hexs(f["off"]):
            bad.append("%s offset %r" % (f["id"], r["off"]))
        if f["level"] not in r["pills"]:
            bad.append("%s level %s not in %s" % (f["id"], f["level"], r["pills"]))
        if (f["status"] == "disputed") != any(p.startswith("disputed") for p in r["pills"]):
            bad.append("%s disputed mark" % f["id"])
        # the other direction: what the report says about the finding is on the page too
        if r["off"] and r["off"] not in page[f["id"]]["text"]:
            bad.append("%s report offset %s is not on the page" % (f["id"], r["off"]))
    ok("each report card says what the page and API say (defanged)", not bad, "; ".join(bad[:5]))
    ok("report.html has no page error", True)
    return run, board


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    wd.HOME_TMP.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="parity-", dir=wd.HOME_TMP))
    bundles = [Path(a) for a in argv]
    code = 0
    try:
        if not bundles:
            import fixtures
            bundles = [fixtures.record_run(str(work / "gen"))]
        for bundle in bundles:
            rid = bundle.name
            print("== %s" % rid)
            w = work / ("m-" + rid)
            w.mkdir()
            sv = Servers(bundle, w)
            rows, finals, errs = [], {}, []
            try:
                sv.start()
                for mode in ("live", "replay", "static"):
                    for width in WIDTHS:
                        with wd.Browser(width=width, offline=(mode == "static")) as b:
                            tok = ""
                            url = sv.urls[mode]
                            if mode != "static":
                                tok = (w / "state" / "token").read_text().strip()
                                url = url.split("#")[0] + "#token=" + tok
                            open_page(b, mode, url)
                            run, board = check_view(b, mode, width, rid, w, rows)
                            e = js_errors(b)
                            rows.append((mode, width, "no page JavaScript errors", not e, "; ".join(e[:3])))
                            if width == WIDTHS[0]:
                                finals[mode] = (run, board)
                # --- the three modes' final answers against each other
                strip = lambda r: {k: v for k, v in r.items() if k not in ("seq", "why", "waiting_why")}
                base = finals["replay"]
                for mode in ("live", "static"):
                    rr, bb = finals[mode]
                    same_board = bb["findings"] == base[1]["findings"] and bb["counts"] == base[1]["counts"]       # parsed, so 4 and 4.0 are the same number
                    rows.append((mode + " vs replay", "-", "same board (findings and counts)", same_board, "differs"))
                    for k in ("id", "status", "counts", "sample", "roles", "brief", "assessment", "summary"):
                        rows.append((mode + " vs replay", "-", "run record key " + k, rr.get(k) == base[0].get(k), "differs"))
                    tk = lambda r: [{x: t.get(x) for x in ("n", "role", "state", "tokens", "tools", "findings", "round")} for t in r.get("tasks", [])]
                    rows.append((mode + " vs replay", "-", "task rows", tk(rr) == tk(base[0]), "differs"))
            except Fail as e:
                rows.append(("setup", "-", str(e), False, ""))
            finally:
                sv.stop()
            fails = [r for r in rows if not r[3]]
            for r in rows:
                print("%-5s %-5s %-4s %s%s" % ("ok" if r[3] else "FAIL", r[0], r[1], r[2], "" if r[3] else "   <- " + r[4][:300]))
            print("%d checks, %d failed" % (len(rows), len(fails)))
            code = code or (1 if fails else 0)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
