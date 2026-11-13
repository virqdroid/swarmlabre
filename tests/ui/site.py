#!/usr/bin/env python3
"""Browser check of the one-pager (site/index.html) at 1280 and 500 px, with the network blocked.

    python3 tests/ui/site.py [SITE_DIR]      (default: site/ after the Copy step of .github/workflows/pages.yml ran; see tests/test_site.py for the file list)

Serves SITE_DIR from this machine, opens the page in headless Firefox with every other address pointed at a dead proxy, and checks: every resource the page loaded came from this
machine, no console or JavaScript error, no horizontal overflow, the two images and the fonts loaded, the page's text is the same at both widths (nothing hidden on a phone), and
that `demo/` and `sample/report.html` open too. Needs `geckodriver` and `firefox` (the snap is fine: profiles go under ~/swarmlabre-uitmp). Exit code 0 = all passed.
"""
import functools
import http.server
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import wd                                      # noqa: E402

PAGES = ("", "demo/", "sample/report.html")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    site = Path(argv[0] if argv else ROOT / "site").resolve()
    if not (site / "index.html").is_file():
        print("site/index.html not found in %s" % site, file=sys.stderr)
        return 2
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

    handler = functools.partial(Quiet, directory=str(site))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/" % srv.server_address[1]
    rows, texts = [], {}

    def ok(label, cond, detail=""):
        rows.append((label, bool(cond), detail))

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
                    errs = [ln for ln in b.console_log().splitlines() if ln.startswith("JavaScript error") or "Content Security Policy" in ln or "CSP" in ln]
                    ok(tag + ": no console or JavaScript error", not errs, "; ".join(errs[:3]))
                    over = b.js("return [document.documentElement.scrollWidth, window.innerWidth]")
                    ok(tag + ": no horizontal overflow", over[0] <= over[1], str(over))
                    if page == "":
                        imgs = b.js("return Array.from(document.images).map(i => [i.getAttribute('src'), i.complete && i.naturalWidth > 0])")
                        ok(tag + ": both images loaded", len(imgs) == 2 and all(i[1] for i in imgs), str(imgs))
                        fonts = b.jsa("var cb = arguments[arguments.length-1]; document.fonts.ready.then(() => cb(Array.from(document.fonts).map(f => f.family + ':' + f.status)))")
                        ok(tag + ": both fonts loaded from this machine", sorted(fonts) == ["Geist Mono:loaded", "Geist:loaded"], str(fonts))
                        texts[width] = b.js("return document.body.innerText.replace(/\\s+/g, ' ').trim()")
                        hidden = b.js("return Array.from(document.querySelectorAll('body *')).filter(e => getComputedStyle(e).display === 'none' && !['STYLE','HEAD','META','TITLE'].includes(e.tagName)).length")
                        ok(tag + ": nothing is hidden", hidden == 0, str(hidden))
                        small = b.js("return Array.from(document.querySelectorAll('a.btn')).filter(e => e.getBoundingClientRect().height < 44).length")
                        ok(tag + ": every button-link is at least 44 px tall", small == 0, str(small))
                        shot = wd.HOME_TMP / ("site-%d.png" % width)
                        b.screenshot(shot)
                        print("screenshot: %s" % shot)
        ok("same text at 1280 and 500 px", texts.get(1280) == texts.get(500), "%d vs %d characters" % (len(texts.get(1280, "")), len(texts.get(500, ""))))
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
