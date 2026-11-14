#!/usr/bin/env python3
"""Browser check of the one-pager (site/index.html) with the network blocked: at 1280 and 500 px, at 390 px (a phone, in a 390 px frame), and with JavaScript off.

    python3 tests/ui/site.py [SITE_DIR]      (default: site/ after the Copy step of .github/workflows/pages.yml ran; see tests/test_site.py for the file list)

Serves SITE_DIR from this machine, opens the page in headless Firefox with every other address pointed at a dead proxy, and checks: every resource the page loaded came from this
machine, no console or JavaScript error (a policy violation included), no horizontal overflow, the two images and the fonts loaded, both canvases drew something, the page's text is
the same at 1280 and 500 px and nothing is hidden at one width that shows at the other, every button-link and finding button is at least 44 px tall, the phone layout of the run
animation is portrait, and with JavaScript off the text, the table and both recorded terminals are there while the animation and the lens are not. Also opens `demo/` and
`sample/report.html`. Needs `geckodriver` and `firefox` (the snap is fine: profiles go under ~/swarmlabre-uitmp). Exit code 0 = all passed.
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

PAGES = ("", "demo/", "sample/report.html")
FRAME = "__phone390.html"                      # served by this script only, never part of the site
FRAME_HTML = b'<!doctype html><meta charset="utf-8"><style>body{margin:0}iframe{border:0;width:390px;height:844px;display:block}</style><iframe src="index.html"></iframe>'

# How many distinct colours a canvas shows (sampled): a blank or failed canvas has one or two.
CANVAS_COLOURS = """var c = arguments[0] ? document.querySelector('iframe').contentDocument.getElementById(arguments[1]) : document.getElementById(arguments[1]);
var d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data, s = new Set();
for (var i = 0; i < d.length; i += 4 * 97) s.add(d[i] + ',' + d[i + 1] + ',' + d[i + 2] + ',' + d[i + 3]);
return [s.size, c.width, c.height];"""
HIDDEN = """return Array.from(document.querySelectorAll('body *')).filter(e => getComputedStyle(e).display === 'none' && !['STYLE','SCRIPT','TEMPLATE'].includes(e.tagName))
  .map(e => e.tagName + (e.id ? '#' + e.id : '') + '.' + (e.className.baseVal === undefined ? e.className : e.className.baseVal)).sort()"""


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
    rows, texts, hidden = [], {}, {}

    def ok(label, cond, detail=""):
        rows.append((label, bool(cond), detail))

    def errors(b):
        return [ln for ln in b.console_log().splitlines() if ln.startswith("JavaScript error") or "Content Security Policy" in ln or "CSP" in ln]

    try:
        for width in (1280, 500):
            with wd.Browser(width=width, offline=True) as b:
                for page in PAGES:
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
