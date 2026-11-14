#!/usr/bin/env python3
"""Build the static demo: one self-contained page that plays a recorded run with no server.

    python3 tools/build-demo.py BUNDLE [--out site/demo] [--speed 8] [--paused] [--sample-kb 256]

BUNDLE is a sealed run folder or an exported bundle (`swarmlabre export`). The output folder gets
    index.html        ui/swarms.html + the recorded run as JSON (#demo-data) + tools/shim.js, which answers the page's api/* calls from that JSON
    fonts/            the two fonts the page uses, with their licence (OFL.txt)
    build.json        what was built from what: the run id, the sample's SHA-256 and the SHA-256 of every file written
It is deterministic (the same bundle gives the same bytes) and needs nothing but the standard library. Before it writes anything it replays the bundle offline and refuses
one that does not come out byte for byte; afterwards it checks that the page holds no http(s) address except an XML namespace, so it loads with the network blocked.
"""
import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from swarmlabre import __version__, htmlreport, player, swarms           # noqa: E402

OUT_FILES = ("report.json", "report.md", "report.html", "board.json", "iocs.csv", "iocs.stix.json", "iocs.misp.json", "detection.yar")
WHY_STATIC = "This is a recorded run playing in your browser. Nothing can be started here."
ALLOWED_URLS = {"http://www.w3.org/2000/svg"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def collect(bundle, speed, paused, sample_kb):
    """Everything the shim needs, as one JSON-able dict. Uses player.Replay for the checks and the copy, then lets go of it."""
    rep = player.Replay(bundle, speed=1.0, paused=True)
    try:
        final = json.loads(json.dumps(rep.view.final))
        has_iocs, has_yara = bool(final.pop("_has_iocs", False)), bool(final.pop("_has_yara", False))
        facts = rep.facts()
        files = {}
        for n in OUT_FILES:
            p = rep.out / n
            if p.is_file():
                files[n] = p.read_bytes().decode("utf-8")      # bytes, not read_text(): a CSV keeps its \r\n
        sample = None
        sp = rep.rt.dir / "input" / "sample"
        if sp.is_file() and sp.stat().st_size <= sample_kb * 1024:
            sample = base64.b64encode(sp.read_bytes()).decode()
        windows = [] if sample else htmlreport.load_windows(rep.rt.dir / "windows.json")
        lay = rep.sw.layout(rep.rid)
        data = {"run": rep.rid, "version": __version__, "speed": speed, "paused": paused, "level": rep.level, "events": rep.events, "final": final, "attack": rep.attack, "layout": lay,
                "facts": facts, "why": swarms.WHY, "why_static": WHY_STATIC, "files": files, "has_iocs": has_iocs, "has_yara": has_yara, "sample": sample, "windows": windows}
        sample_sha = final.get("sample", {}).get("sha256", "")
        return data, sample_sha
    finally:
        rep.close()


def page(data):
    html = (ROOT / "ui" / "swarms.html").read_text(encoding="utf-8")
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    shim = (ROOT / "tools" / "shim.js").read_text(encoding="utf-8")
    if "</script" in shim.lower():
        raise SystemExit("tools/shim.js must not contain a closing script tag")
    marker = "<script>\n"
    if html.count(marker) != 1:
        raise SystemExit("ui/swarms.html: expected exactly one <script> block")
    inject = '<script id="demo-data" type="application/json">' + blob + "</script>\n<script>\n" + shim + "</script>\n"
    return html.replace(marker, inject + marker, 1)


def check_offline(text):
    """The page and the shim must hold no address they could fetch. The recorded run (#demo-data) is data: it is shown as text and only ever downloaded, so it is left out."""
    text = re.sub(r'<script id="demo-data" type="application/json">.*?</script>', "", text, flags=re.S)
    bad = sorted({u for u in re.findall(r"https?://[^\s'\"<>)\\]+", text) if u not in ALLOWED_URLS})
    if bad:
        raise SystemExit("the page holds addresses it would fetch or link: %s" % ", ".join(bad[:5]))
    for m in re.finditer(r"""(?:src|href|action)\s*=\s*["'](?!#|data:|blob:)([^"']+)""", text):
        if not m.group(1).startswith(("fonts/",)):
            raise SystemExit("the page links to %r" % m.group(1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("bundle", help="a sealed run folder or an exported bundle")
    ap.add_argument("--out", default=str(ROOT / "site" / "demo"), help="folder to write (replaced)")
    ap.add_argument("--speed", type=float, default=8.0, help="starting replay speed (default 8)")
    ap.add_argument("--paused", action="store_true", help="start paused")
    ap.add_argument("--sample-kb", type=int, default=256, help="embed the sample for the hex view when it is at most this large (default 256)")
    a = ap.parse_args(argv)
    try:
        data, sample_sha = collect(a.bundle, a.speed, a.paused, a.sample_kb)
    except player.ReplayError as e:
        print("build-demo: %s" % e, file=sys.stderr)
        return 2
    text = page(data)
    check_offline(text)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    (out / "fonts").mkdir(parents=True)
    (out / "index.html").write_text(text, encoding="utf-8")
    for f in sorted((ROOT / "ui" / "fonts").iterdir()):
        if f.suffix == ".woff2" or f.name == "OFL.txt":                  # the licence of the fonts travels with them (SIL OFL 1.1)
            shutil.copyfile(f, out / "fonts" / f.name)
    files = {str(p.relative_to(out)): sha(p.read_bytes()) for p in sorted(out.rglob("*")) if p.is_file()}
    (out / "build.json").write_text(json.dumps({"run": data["run"], "sample_sha256": sample_sha, "replay_level": data["level"], "tool_version": __version__, "files": files}, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"out": str(out), "run": data["run"], "index_bytes": len(text.encode()), "events": len(data["events"]), "sample_embedded": data["sample"] is not None}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
