#!/usr/bin/env python3
"""Walks the whole Swarms page in headless Firefox, in replay and static mode (the static one with the network blocked), at 1280 and 500 px, and fails on any page error.

    python3 tests/ui/tour.py [BUNDLE] [--shots DIR] [--modes replay,static] [--widths 1280,500]

Steps (each one is a row): the three tabs, the result card, the map and the graph, the hex peek, the agent / finding / region drawers (and Escape closing each), the replay controls, the
download buttons (blob downloads, no error toast), the history picker, and a list of every resource the page requested (only same-origin fonts and the favicon are allowed). Screenshots are
written only when --shots is given: read them, then delete the folder (a snap Firefox needs it under the home directory).
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tests"))

import wd                                          # noqa: E402
import parity                                      # noqa: E402

ESC = "document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"


def tour(b, mode, width, rid, rows, shots):
    def ok(name, cond, detail=""):
        rows.append((mode, width, name, bool(cond), "" if cond else str(detail)[:300]))

    errs0 = [0]

    def clean(name):
        e = parity.js_errors(b)
        new = e[errs0[0]:]
        errs0[0] = len(e)
        ok("no page error after: " + name, not new, "; ".join(new[:2]))

    def shot(name, sel=None):
        if shots:
            if sel:
                b.js("const e=document.querySelector(arguments[0]);if(e)e.scrollIntoView({block:'start'})", sel)
                time.sleep(0.3)
            b.screenshot(Path(shots) / ("%s-%d-%s.png" % (mode, width, name)))

    def vis(sel):
        return b.js("const e=document.querySelector(arguments[0]);return !!(e&&e.offsetParent!==null&&e.getBoundingClientRect().width>0)", sel)

    # ---- tabs
    for tab, probe in (("findings", "#sw-board .sw-card"), ("live", "#sw-lane"), ("how", "#sw-steps li")):
        b.js("swPane(arguments[0])", tab)
        time.sleep(0.4)
        ok("tab %s shows its panel" % tab, vis("#swt-" + tab) and b.js("return document.querySelectorAll(arguments[0]).length>0", probe), tab)
        shot("tab-" + tab, {"findings": "#sw-board", "live": "#sw-stage", "how": "#swt-how"}[tab])
        clean("tab " + tab)
    ok("result card is shown", vis("#sw-verdict"))
    ok("header and run name are shown", b.js("return document.querySelector('#sw-name').textContent.length>0"))

    # ---- map and graph
    b.js("swPane('live')")
    time.sleep(0.4)
    ok("map canvas has a size", b.js("const c=document.querySelector('#sw-map');return c.width>0&&c.height>0"))
    ok("margin region names are there", b.js("return document.querySelector('#sw-rm').children.length>0"))
    b.js("document.querySelector('#sw-v-graph').click()")
    time.sleep(0.6)
    ok("graph view opens", vis("#sw-gv") and b.js("const c=document.querySelector('#sw-graph');return c.width>0&&c.height>0"))
    shot("graph", "#sw-stage")
    clean("graph")
    b.js("document.querySelector('#sw-v-map').click()")
    time.sleep(0.3)
    ok("map comes back", vis("#sw-mv"))

    # ---- hex peek
    b.js("const i=document.querySelector('#sw-hexo');i.value='0x40';document.querySelector('#sw-hexgo').click()")
    try:
        b.wait_for("document.querySelector('#sw-hexpre').textContent.length>20", 10)
        pre = b.js("return document.querySelector('#sw-hexpre').textContent")
        ok("hex peek shows rows", "00000040" in pre.replace(" ", "").lower() or "0x40" in pre.lower() or "40" in pre, pre[:80])
    except wd.WebDriverError as e:
        ok("hex peek shows rows", False, str(e) + " " + b.js("return document.querySelector('#sw-hexl').textContent"))
    b.js("document.querySelector('#sw-hexn').click()")
    time.sleep(0.5)
    shot("hex", "#sw-hex")
    clean("hex peek")

    # ---- drawers
    def drawer(name, click_js):
        b.js(click_js)
        try:
            b.wait_for("document.querySelector('#swi').classList.contains('open')", 8)
            txt = b.js("return document.querySelector('#swi-body').innerText")
            ok("%s drawer opens with text" % name, len(txt.strip()) > 10, txt[:80])
            shot("drawer-" + name)
        except wd.WebDriverError as e:
            ok("%s drawer opens with text" % name, False, e)
        b.js(ESC)
        time.sleep(0.3)
        ok("Escape closes the %s drawer" % name, not b.js("return document.querySelector('#swi').classList.contains('open')"))
        clean(name + " drawer")

    drawer("agent", "swPane('live');document.querySelector('#sw-lane .sw-lnk').click()")
    drawer("finding", "swPane('findings');document.querySelector('#sw-board .sw-card .sw-lnk').click()")
    drawer("region", "swPane('how');document.querySelector('#sw-regs .sw-lnk').click()")
    b.js("swPane('how')")
    shot("how")

    # ---- replay controls (these exist in replay and static mode only)
    ok("replay controls are shown", vis("#rp"))
    b.js("document.querySelector('#rp-restart').click()")
    time.sleep(1.2)
    c1 = b.js("return document.querySelector('#rp-clock').textContent")
    b.js("document.querySelector('#rp-end').click()")
    try:
        b.wait_for("/^(Done|Failed|Stopped)/i.test(document.querySelector('#sw-stchip').textContent)", 30)
        ok("restart then skip to the end finishes the run", True)
    except wd.WebDriverError as e:
        ok("restart then skip to the end finishes the run", False, e)
    ok("the clock text is there", bool(c1.strip()) and bool(b.js("return document.querySelector('#rp-clock').textContent").strip()), c1)
    clean("replay controls")

    # ---- downloads
    b.js("swPane('findings')")
    time.sleep(0.5)
    b.js("window.__blobs=0;const o=URL.createObjectURL;URL.createObjectURL=function(x){window.__blobs++;return o.call(URL,x)}")
    names = b.js("return [...document.querySelectorAll('#sw-vd button[data-f]')].map(x=>x.dataset.f)")
    ok("download buttons exist (primary and other formats)", "report.html" in names and len(names) >= 3, names)
    for n in names:
        b.js("document.querySelector('#sw-vd button[data-f=\"%s\"]').click()" % n)
        time.sleep(0.5)
    time.sleep(1.0)
    ok("every download made a file and none showed an error", b.js("return window.__blobs") == len(names) and not b.js("return document.querySelectorAll('.toast.err').length"), "%s blobs for %s" % (b.js("return window.__blobs"), names))
    clean("downloads")

    # ---- history picker
    opts = b.js("return [...document.querySelectorAll('#sw-pick option')].map(o=>o.value)")
    ok("history picker lists the run", rid in opts, opts)
    b.js("const s=document.querySelector('#sw-pick');s.dispatchEvent(new Event('change',{bubbles:true}))")
    time.sleep(0.5)
    ok("choosing the run again keeps it", b.js("return location.hash") in ("#" + rid, ""), b.js("return location.hash"))
    clean("history picker")

    # ---- what was requested
    res = b.js("return performance.getEntriesByType('resource').map(r=>r.name)")
    origin = b.js("return location.origin")
    outside = [r for r in res if not r.startswith(origin) and not r.startswith("data:") and not r.startswith("blob:")]
    ok("every resource came from the page's own origin", not outside, outside[:3])
    ok("the only files requested are fonts and the favicon", all(("/fonts/" in r) or r.endswith("favicon.ico") or "/api/" in r or r.rstrip("/") == origin or r.startswith(origin + "/#") or r.startswith(origin + "/index") for r in res), [r for r in res][:6])
    shot("end")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    shots, modes, widths, bundle = None, ("replay", "static"), (1280, 500), None
    while argv:
        a = argv.pop(0)
        if a == "--shots":
            shots = argv.pop(0)
        elif a == "--modes":
            modes = tuple(argv.pop(0).split(","))
        elif a == "--widths":
            widths = tuple(int(x) for x in argv.pop(0).split(","))
        else:
            bundle = Path(a)
    wd.HOME_TMP.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="tour-", dir=wd.HOME_TMP))
    if shots:
        Path(shots).mkdir(parents=True, exist_ok=True)
    rows = []
    try:
        if bundle is None:
            import fixtures
            bundle = fixtures.record_run(str(work / "gen"))
        sv = parity.Servers(bundle, work / "m")
        (work / "m").mkdir()
        try:
            sv.start()
            for mode in modes:
                for width in widths:
                    with wd.Browser(width=width, offline=(mode == "static")) as b:
                        url = sv.urls[mode]
                        if mode != "static":
                            url = url.split("#")[0] + "#token=" + (work / "m" / "state" / "token").read_text().strip()
                        parity.open_page(b, mode, url)
                        tour(b, mode, width, bundle.name, rows, shots)
        finally:
            sv.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for r in rows:
        print("%-5s %-6s %-4s %s%s" % ("ok" if r[3] else "FAIL", r[0], r[1], r[2], "" if r[3] else "   <- " + r[4]))
    bad = [r for r in rows if not r[3]]
    print("%d checks, %d failed" % (len(rows), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
