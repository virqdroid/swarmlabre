#!/usr/bin/env python3
"""Live mode in a browser: the launch sheet, a real run with the scripted mock model and the two Docker images, then the finished run checked like the other modes.

    python3 tests/ui/live.py [--keep-shots DIR]

Needs geckodriver + firefox, Docker with the `swarmlabre-agent` and `swarmlabre-tools` images, and `ffmpeg` for the clip step (skipped, said so, without it). One run takes about a minute.
Part 1: a server with no model: the sheet opens and says "No model is configured", Start stays disabled.
Part 2: a server with the mock model: stage the demo ELF through the raw `stage` route (a File set on the sheet's input), write the brief, Start; wait for `done`; the same parity checks as
the other modes on that run; every download; the clip export when ffmpeg is on PATH. Exit code 0 = all passed.
"""
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import parity                                      # noqa: E402
import wd                                          # noqa: E402
from swarmlabre import demo                        # noqa: E402


def serve(cfg, work):
    p = subprocess.Popen([sys.executable, "-m", "swarmlabre", "--config", str(cfg), "serve", "--port", "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT))
    end = time.time() + 60
    while time.time() < end:
        line = p.stdout.readline()
        if not line:
            break
        m = re.search(r"(http://\S+)", line)
        if m:
            return p, m.group(1)
    p.terminate()
    raise parity.Fail("no address from serve")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    shots = argv[argv.index("--keep-shots") + 1] if "--keep-shots" in argv else None
    wd.HOME_TMP.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="live-", dir=wd.HOME_TMP))
    rows = []
    procs = []

    def ok(mode, width, name, cond, detail=""):
        rows.append((mode, width, name, bool(cond), "" if cond else str(detail)[:300]))
    try:
        sample, script = demo.write(work / "demo")
        # ---- part 1: no model
        (work / "s1").mkdir()
        c1 = work / "nomodel.toml"
        c1.write_text('[paths]\nstate = "%s"\n' % (work / "s1"))
        p, url = serve(c1, work)
        procs.append(p)
        tok = (work / "s1" / "token").read_text().strip()
        with wd.Browser(width=1280) as b:
            b.get(url.split("#")[0] + "#token=" + tok)
            b.wait_for("document.body.dataset.mode==='live' && !document.querySelector('#sw-empty').hidden", 30)
            ok("nomodel", 1280, "empty state offers Start a run", b.js("return !document.querySelector('#sw-empty-new').hidden"))
            b.js("document.querySelector('#sw-empty-new').click()")
            b.wait_for("document.querySelector('#swl').classList.contains('open')", 10)
            why = b.js("return document.querySelector('#swl-why').textContent")
            ok("nomodel", 1280, "the sheet says no model is configured", "No model is configured" in why, why)
            ok("nomodel", 1280, "Start is disabled", b.js("return document.querySelector('#swl-go').disabled"))
            ok("nomodel", 1280, "no page JavaScript errors", not parity.js_errors(b), parity.js_errors(b)[:2])
        p.terminate()

        # ---- part 2: the mock model
        (work / "s2").mkdir()
        c2 = work / "mock.toml"
        c2.write_text('[paths]\nstate = "%s"\n[model]\nmock = "%s"\n' % (work / "s2", script))
        p, url = serve(c2, work)
        procs.append(p)
        tok = (work / "s2" / "token").read_text().strip()
        b64 = base64.b64encode(sample.read_bytes()).decode()
        for width in (1280, 500):
            if width == 500:
                # the second width views the finished run (one container run at a time): it is the same server and the same run
                pass
            with wd.Browser(width=width) as b:
                b.get(url.split("#")[0] + "#token=" + tok)
                b.wait_for("document.body.dataset.mode==='live'", 30)
                if width == 1280:
                    b.wait_for("!document.querySelector('#sw-empty').hidden", 30)
                    b.js("document.querySelector('#sw-empty-new').click()")
                    b.wait_for("document.querySelector('#swl').classList.contains('open')", 10)
                    ok("live", width, "no 'No model' text with a model", "No model" not in b.js("return document.querySelector('#swl-why').textContent"))
                    b.js("""const bytes=Uint8Array.from(atob(arguments[0]),c=>c.charCodeAt(0));const dt=new DataTransfer();dt.items.add(new File([bytes],'demo.elf'));
                      const i=document.querySelector('#swl-file');i.files=dt.files;i.dispatchEvent(new Event('change'))""", b64)
                    try:
                        b.wait_for("!document.querySelector('#swl-file-row').hidden", 20)
                        ok("live", width, "the sample was staged through the raw stage route", True)
                    except wd.WebDriverError as e:
                        ok("live", width, "the sample was staged through the raw stage route", False, e)
                    b.js("const t=document.querySelector('#swl-brief');t.value='What does this sample do?';t.dispatchEvent(new Event('input'))")
                    time.sleep(0.5)
                    ok("live", width, "Start is enabled with a sample and a brief", not b.js("return document.querySelector('#swl-go').disabled"), b.js("return document.querySelector('#swl-why').textContent"))
                    b.js("document.querySelector('#swl-go').click()")
                    try:
                        b.wait_for("document.querySelector('#sw-name').textContent && /^s[0-9a-f]{8}$/.test(location.hash.slice(1))", 30)
                        ok("live", width, "Start opens the run", True)
                    except wd.WebDriverError as e:
                        ok("live", width, "Start opens the run", False, e)
                    b.js("swPane('live')")
                    time.sleep(2)
                    if shots:
                        Path(shots).mkdir(parents=True, exist_ok=True)
                        b.screenshot(Path(shots) / "live-running.png")
                    ok("live", width, "the Live tab shows the agents while it runs", b.js("return document.querySelectorAll('#sw-lane > *').length>0"))
                    try:
                        b.wait_for("/^(Done|Failed|Stopped)/i.test(document.querySelector('#sw-stchip').textContent)", 600)
                    except wd.WebDriverError as e:
                        ok("live", width, "the run ends", False, e)
                    ok("live", width, "the run ended Done", b.js("return document.querySelector('#sw-stchip').textContent") == "Done", b.js("return document.querySelector('#sw-stchip').textContent"))
                else:
                    b.wait_for("/^(Done|Failed|Stopped)/i.test(document.querySelector('#sw-stchip').textContent)", 60)
                rid = b.js("return location.hash.slice(1)")
                parity.check_view(b, "live", width, rid, work, rows)          # leaves the browser on report.html: go back to the app
                b.get(url.split("#")[0] + "#" + rid)
                b.wait_for("document.querySelector('#sw-stchip') && document.querySelector('#sw-stchip').textContent==='Done'", 30)
                if width == 1280:
                    facts = json.loads(parity.get(b, "swarm"))["facts"]["clip"]
                    have = bool(shutil.which("ffmpeg"))
                    ok("live", width, "clip is offered exactly when ffmpeg is on PATH", bool(facts) == have, "facts.clip=%s ffmpeg=%s" % (facts, have))
                    ok("live", width, "Export clip button visible and enabled with ffmpeg", (not have) or b.js("const e=document.querySelector('#sw-clip');return !e.hidden&&!e.disabled"))
                    if have:
                        # the real flow: the button opens the clip tab, which must carry the token over (sessionStorage), then 15 s at 1280 x 720
                        main_h = b.handles()
                        b.js("document.querySelector('#sw-clip').click()")
                        time.sleep(2)
                        new = [h for h in b.handles() if h not in main_h]
                        ok("live", width, "Export clip opens its own tab", len(new) == 1, b.handles())
                        if new:
                            b.switch_to(new[0])
                            ok("live", width, "the clip tab has the token", b.js("return !!sessionStorage.getItem('swarmlabreToken')"))
                            b.js("const s=document.querySelector('#clip select');s.value='15';s.dispatchEvent(new Event('change'));[...document.querySelectorAll('#clip button')].find(x=>x.textContent==='Make clip').click()")
                            try:
                                b.wait_for("/Done\\. The clip is also kept/.test(document.querySelector('#clip').innerText)", 300)
                                ok("live", width, "a 15 s clip was rendered and encoded by ffmpeg", True)
                                b.wait_for("document.querySelector('#clip video') && document.querySelector('#clip video').videoWidth>0", 20)
                                ok("live", width, "the clip plays back as a video", True)
                                ok("live", width, "a Download MP4 link is offered", b.js("return /Download MP4/.test(document.querySelector('#clip').innerText)"))
                            except wd.WebDriverError as e:
                                ok("live", width, "a 15 s clip was rendered, encoded and plays back", False, "%s | %s" % (e, b.js("return document.querySelector('#clip').innerText.slice(-200)")))
                            if shots:
                                b.screenshot(Path(shots) / "live-clip.png")
                            e = parity.js_errors(b)
                            ok("live", width, "no page JavaScript errors in the clip tab", not e, e[:2])
                            b.switch_to(main_h[0])
                e = parity.js_errors(b)
                ok("live", width, "no page JavaScript errors", not e, e[:2])
        p.terminate()
    except (parity.Fail, wd.WebDriverError) as e:
        rows.append(("setup", "-", str(e), False, ""))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(20)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(work, ignore_errors=True)
    for r in rows:
        print("%-5s %-8s %-4s %s%s" % ("ok" if r[3] else "FAIL", r[0], r[1], r[2], "" if r[3] else "   <- " + r[4]))
    bad = [r for r in rows if not r[3]]
    print("%d checks, %d failed" % (len(rows), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
