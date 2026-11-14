#!/usr/bin/env python3
"""Browser check of the one-pager (site/index.html) with the network blocked: at 1280 and 500 px, at 390 px (a phone, in a 390 px frame), and with JavaScript off.

    python3 tests/ui/site.py [SITE_DIR]      (default: site/ after the Copy step of .github/workflows/pages.yml ran; see tests/test_site.py for the file list)

Serves SITE_DIR from this machine, opens the page in headless Firefox with every other address pointed at a dead proxy, and checks: every resource the page loaded came from this
machine, no console or JavaScript error (a policy violation included), no horizontal overflow, the two images and the fonts loaded, both canvases drew something, the page's text is
the same at 1280 and 500 px and nothing is hidden at one width that shows at the other, every button-link and finding button is at least 44 px tall, the phone layout of the run
animation is portrait, and with JavaScript off the text, the table and both recorded terminals are there while the animation and the lens are not. Also opens `demo/`, `sample/report.html`
and the docs page `docs/board.html`: at 1280 and 500 px no overflow, no console error, the same text (the drawing and the menus that change with the width apart), the fonts, the
tap targets and the figure text sizes on a phone, the flowchart's final state after its one reveal and with reduced motion. Needs `geckodriver` and `firefox` (the snap is fine: profiles go under ~/swarmlabre-uitmp). Exit code 0 = all passed.
"""
import functools
import http.server
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import wd                                      # noqa: E402

PAGES = ("", "demo/", "sample/report.html")          # and every page of docs/
DOC_PAGES = "docs/"
FRAME = "__phone390.html"                      # served by this script only, never part of the site
FRAME_HTML = b'<!doctype html><meta charset="utf-8"><style>body{margin:0}iframe{border:0;width:390px;height:844px;display:block}</style><iframe src="index.html"></iframe>'

# How many distinct colours a canvas shows (sampled): a blank or failed canvas has one or two.
CANVAS_COLOURS = """var c = arguments[0] ? document.querySelector('iframe').contentDocument.getElementById(arguments[1]) : document.getElementById(arguments[1]);
var d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data, s = new Set();
for (var i = 0; i < d.length; i += 4 * 97) s.add(d[i] + ',' + d[i + 1] + ',' + d[i + 2] + ',' + d[i + 3]);
return [s.size, c.width, c.height];"""
HIDDEN = """return Array.from(document.querySelectorAll('body *')).filter(e => getComputedStyle(e).display === 'none' && !['STYLE','SCRIPT','TEMPLATE'].includes(e.tagName))
  .map(e => e.tagName + (e.id ? '#' + e.id : '') + '.' + (e.className.baseVal === undefined ? e.className : e.className.baseVal)).sort()"""


# What the docs page hides at one width and shows at the other, by design: the sidebar, "On this page" and the top bar's links fold into the Docs menu on a phone, and the
# flowchart has a wide and a tall drawing.
DOC_RESPONSIVE = {"ASIDE.side", "ASIDE.toc", "SPAN.sec", "A.", "DETAILS.menu"}           # plus the two drawings on a page that has a flowchart
# The page's text as it renders, without the two things that change with the width (the Docs menu, the flowchart drawings); each drawing's words are compared sorted.
DOC_TEXT = """var h = Array.from(document.querySelectorAll('.menu, svg.fc-wide, svg.fc-tall')), old = h.map(e => e.style.display);
h.forEach(e => e.style.setProperty('display', 'none', 'important'));       // the drawings' own rules are !important
var t = document.querySelector('main').innerText.replace(/\\s+/g, ' ').trim();
h.forEach((e, i) => { e.style.removeProperty('display'); if (old[i]) e.style.display = old[i]; });
var shown = Array.from(document.querySelectorAll('svg.fc-wide, svg.fc-tall')).filter(e => getComputedStyle(e).display !== 'none');
var words = s => Array.from(s.querySelectorAll('text')).map(x => x.textContent).join(' ').split(/\\s+/).filter(Boolean).sort().join(' ');
return {text: t, flow: shown.map(words), drawn: shown.map(e => e.getAttribute('class'))}"""
# Rendered size of every text in the visible figures: the font size times the drawing's scale.
FIGURE_TEXT = """return Array.from(document.querySelectorAll('figure svg')).filter(s => getComputedStyle(s).display !== 'none').flatMap(s => {
  var k = s.getBoundingClientRect().width / s.viewBox.baseVal.width;
  return Array.from(s.querySelectorAll('text')).map(x => parseFloat(getComputedStyle(x).fontSize) * k);
})"""
# Steps of the visible flowchart that are not fully shown (the hidden drawing never plays).
NOT_SHOWN = """return Array.from(document.querySelectorAll('.anim svg')).filter(s => getComputedStyle(s).display !== 'none').flatMap(s => Array.from(s.querySelectorAll('.st'))).filter(e => getComputedStyle(e).opacity !== '1').length"""
SMALL_TARGETS = """return Array.from(document.querySelectorAll(arguments[0])).filter(e => e.getClientRects().length && e.getBoundingClientRect().height < 44).map(e => e.textContent.trim().slice(0, 30))"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    site = Path(argv[0] if argv else ROOT / "site").resolve()
    if not (site / "index.html").is_file():
        print("site/index.html not found in %s" % site, file=sys.stderr)
        return 2

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):
            if self.path == "/" + FRAME:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(FRAME_HTML)))
                self.end_headers()
                self.wfile.write(FRAME_HTML)
                return
            super().do_GET()

    handler = functools.partial(Quiet, directory=str(site))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/" % srv.server_address[1]
    pages = PAGES + tuple(sorted(DOC_PAGES + p.name for p in (site / "docs").glob("*.html")))
    rows, texts, hidden, doc_text, doc_hidden = [], {}, {}, {}, {}

    def ok(label, cond, detail=""):
        rows.append((label, bool(cond), detail))

    def errors(b):
        return [ln for ln in b.console_log().splitlines() if ln.startswith("JavaScript error") or "Content Security Policy" in ln or "CSP" in ln]

    try:
        for width in (1280, 500):
            with wd.Browser(width=width, offline=True) as b:
                for page in pages:
                    tag = "%s %d px" % (page or "/", width)
                    b.get(base + page)
                    b.wait_for("document.readyState === 'complete'")
                    if page == "demo/":
                        b.wait_for("document.querySelector('#sw-map') || document.querySelector('.sw-card, #sw-root, main, body')")
                    res = b.js("return performance.getEntriesByType('resource').map(e => e.name)")
                    foreign = [u for u in res if not u.startswith(base)]
                    ok(tag + ": every loaded resource came from this machine", not foreign, str(foreign[:3]))
                    over = b.js("return [document.documentElement.scrollWidth, window.innerWidth]")
                    ok(tag + ": no horizontal overflow", over[0] <= over[1], str(over))
                    if page.startswith(DOC_PAGES):
                        fonts = b.jsa("var cb = arguments[arguments.length-1]; document.fonts.ready.then(() => cb(Array.from(document.fonts).map(f => f.family + ':' + f.status)))")
                        ok(tag + ": both fonts loaded from this machine", sorted(fonts) == ["Geist Mono:loaded", "Geist:loaded"], str(fonts))
                        got = b.js(DOC_TEXT)
                        doc_text[page, width] = got
                        doc_hidden[page, width] = b.js(HIDDEN)
                        flow = b.js("return !!document.querySelector('svg.fc-wide')")
                        ok(tag + ": the drawing of a flowchart is the " + ("wide" if width > 640 else "tall") + " one", got["drawn"] == ([("fc-wide" if width > 640 else "fc-tall")] if flow else []), str(got["drawn"]))
                        if b.js("return !!document.querySelector('.anim')"):
                            steps = b.js("return Math.max(...Array.from(document.querySelectorAll('.anim .st')).map(e => Number(e.style.getPropertyValue('--i'))))")
                            time.sleep(steps * 0.22 + 1.2)   # every step is delayed by .22 s per step and takes .45 s: the one reveal is over
                            dim = b.js(NOT_SHOWN)
                            ok(tag + ": the flowchart ends in its final state", dim == 0, "%s steps still not shown" % dim)
                        imgs = b.js("return Array.from(document.querySelectorAll('figure img')).map(i => [i.getAttribute('src'), i.complete && i.naturalWidth > 0, i.naturalWidth])")
                        if imgs:
                            ok(tag + ": every screenshot loaded from this machine", all(i[1] for i in imgs), str(imgs))
                        sizes = b.js(FIGURE_TEXT)
                        if width <= 640 and sizes:           # the rule is for a phone; a wide drawing is scaled down in a narrow column (see the notes)
                            ok(tag + ": no text in a figure is under 11 px as drawn", min(sizes) >= 11, str(min(sizes)))
                        if width < 700:
                            b.js("document.querySelector('.menu').open = true")
                            small = b.js(SMALL_TARGETS, ".menu summary, .menu a, .pager a, details.tv summary, .nav a")
                            ok(tag + ": every menu entry, pager link and button is at least 44 px tall", not small, str(small))
                            b.js("document.querySelector('.menu').open = false")
                    if page == "":
                        imgs = b.js("return Array.from(document.images).map(i => [i.getAttribute('src'), i.complete && i.naturalWidth > 0])")
                        ok(tag + ": both images loaded", len(imgs) == 2 and all(i[1] for i in imgs), str(imgs))
                        fonts = b.jsa("var cb = arguments[arguments.length-1]; document.fonts.ready.then(() => cb(Array.from(document.fonts).map(f => f.family + ':' + f.status)))")
                        ok(tag + ": both fonts loaded from this machine", sorted(fonts) == ["Geist Mono:loaded", "Geist:loaded"], str(fonts))
                        n = b.js(CANVAS_COLOURS, False, "bg")
                        ok(tag + ": the flock canvas drew something", n[0] > 5, str(n))
                        b.js("document.getElementById('run').scrollIntoView()")
                        time.sleep(2.5)
                        n = b.js(CANVAS_COLOURS, False, "stage")
                        ok(tag + ": the run animation drew something", n[0] > 5, str(n))
                        texts[width] = b.js("return document.body.innerText.replace(/\\s+/g, ' ').trim()")
                        hidden[width] = b.js(HIDDEN)
                        small = b.js("return Array.from(document.querySelectorAll('a.btn, .chip')).filter(e => e.getBoundingClientRect().height < 44).length")
                        ok(tag + ": every button-link and finding button is at least 44 px tall", small == 0, str(small))
                        b.js("document.querySelector('.chip[data-f=f2]').click()")
                        lens = b.js("return [document.querySelector('.lens [data-k=title]').textContent, document.querySelectorAll('#dump i.f2.on').length]")
                        ok(tag + ": a finding button shows its bytes in the lens and the dump", lens[0].startswith("Update URL") and lens[1] > 0, str(lens))
                        shot = wd.HOME_TMP / ("site-%d.png" % width)
                        b.js("window.scrollTo(0, 0)")
                        b.screenshot(shot)
                        print("screenshot: %s" % shot)
                    errs = errors(b)
                    ok(tag + ": no console or JavaScript error", not errs, "; ".join(errs[:3]))
        ok("same text at 1280 and 500 px", texts.get(1280) == texts.get(500), "%d vs %d characters" % (len(texts.get(1280, "")), len(texts.get(500, ""))))
        ok("nothing hidden at one width that shows at the other", hidden.get(1280) == hidden.get(500), str(set(hidden.get(1280, [])) ^ set(hidden.get(500, []))))

        for page in pages:
            if not page.startswith(DOC_PAGES):
                continue
            a, c = doc_text[page, 1280], doc_text[page, 500]
            ok(page + ": the same text at 1280 and 500 px", a["text"] == c["text"], "%d vs %d characters" % (len(a["text"]), len(c["text"])))
            if a["drawn"]:
                ok(page + ": the wide and the tall flowchart hold the same words", a["flow"] == c["flow"] and a["flow"], "")
            diff = set(doc_hidden[page, 1280]) ^ set(doc_hidden[page, 500])
            want = DOC_RESPONSIVE | ({"svg.fc-wide", "svg.fc-tall"} if a["drawn"] else set())
            ok(page + ": only the sidebar, the page list, the top bar's links, the Docs menu and the drawing change with the width", diff == want, str(diff ^ want))
            with wd.Browser(width=1280, offline=True, extra_prefs={"ui.prefersReducedMotion": 1}) as b:
                b.get(base + page)
                b.wait_for("document.readyState === 'complete'")
                still = [b.js("return document.getAnimations().length"), b.js(NOT_SHOWN)]
                ok(page + " with reduced motion: no animation, every step shown at once", still == [0, 0], str(still))

        # a phone: the page in a 390 px frame (Firefox does not make a window that narrow)
        with wd.Browser(width=500, height=900, offline=True) as b:
            b.get(base + FRAME)
            b.wait_for("document.querySelector('iframe').contentDocument.readyState === 'complete' && document.querySelector('iframe').contentDocument.getElementById('stage')")
            time.sleep(1)
            fr = "var w = document.querySelector('iframe').contentWindow, d = w.document;"
            over = b.js(fr + "return [d.documentElement.scrollWidth, w.innerWidth]")
            ok("390 px: no horizontal overflow", over[0] <= over[1] == 390, str(over))
            n = b.js(CANVAS_COLOURS, True, "bg")
            ok("390 px: the flock drew something", n[0] > 5, str(n))
            b.js(fr + "d.getElementById('run').scrollIntoView()")
            time.sleep(2.5)
            n = b.js(CANVAS_COLOURS, True, "stage")
            ok("390 px: the run animation drew something, in portrait", n[0] > 5 and n[2] > n[1], str(n))
            nav = b.js(fr + "return d.querySelector('.nav').getBoundingClientRect().height")
            ok("390 px: the navigation takes at most two rows", nav <= 110, str(nav))
            errs = errors(b)
            ok("390 px: no console or JavaScript error", not errs, "; ".join(errs[:3]))

        # JavaScript off: the page is text, a table and two recorded terminals
        with wd.Browser(width=1280, offline=True, extra_prefs={"javascript.enabled": False}) as b:
            b.get(base)
            time.sleep(2)
            shown = b.js("""var v = s => { var e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none'; };
              return {stage: v('.stagewrap'), lens: v('.lens'), nojs: v('.nojs'), scenes: v('.scenes'), rows: document.querySelectorAll('#gate tbody tr').length,
                      ok: document.getElementById('t-ok').textContent.trim().endsWith('exit 0'), bad: document.getElementById('t-bad').textContent.trim().endsWith('exit 1'),
                      badShown: v('#t-bad-box'), js: document.documentElement.classList.contains('js')}""")
            ok("JS off: the script did not run", not shown["js"], str(shown))
            ok("JS off: no animation box, no lens, no step scenes", not (shown["stage"] or shown["lens"] or shown["scenes"]), str(shown))
            ok("JS off: the note that the table holds the same posts shows", shown["nojs"], str(shown))
            ok("JS off: the table and both recorded terminals are there", shown["rows"] == 7 and shown["ok"] and shown["bad"] and shown["badShown"], str(shown))
            over = b.js("return [document.documentElement.scrollWidth, window.innerWidth]")
            ok("JS off: no horizontal overflow", over[0] <= over[1], str(over))
    finally:
        srv.shutdown()
    failed = 0
    for label, good, detail in rows:
        print("%s  %s%s" % ("ok  " if good else "FAIL", label, "" if good else "  [%s]" % detail))
        failed += not good
    print("%d checks, %d failed" % (len(rows), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
