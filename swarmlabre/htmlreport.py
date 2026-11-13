"""Standalone interactive HTML report of an Agent Swarms run (out/report.html).

stdlib only. `build()` gets the finished run's record, the checked board, the layout, and paths to swarmlabre's own copy of the
sample, the decompiler output and the event log. What goes in is checked content only: findings swarmlabre verified (title, value, offset, evidence level),
bytes read from swarmlabre's own copy of the sample around those findings, decompiled code of the function a finding sits in, the Reporter's summary, and a
timeline built from placed tool calls. Agent notes, `detail` text, unconfirmed claims and dispute text stay out; counts and fixed words only.
Everything the file shows is set with textContent in the page's script, and a CSP meta forbids every request.
"""
import base64, bisect, json, os, re, time
from pathlib import Path

from . import attack
from . import clock
from . import report as srep
from . import text as stx

LOGO = Path(__file__).resolve().parent / "data" / "logo.png"      # optional brand image (white lettering for the dark band); absent = no image
LOGO_MAX = 120 * 1024

WIN_CTX = 64            # bytes shown before a finding
WIN_MAX = 1280          # bytes per window
WIN_TOTAL = 256 * 1024  # bytes of sample embedded in all
SNIP_MAX = 6000         # characters per decompiled function
SNIP_COUNT = 30
EV_CAP = 3000           # placed calls in the timeline
VALUE_CAP = 2000
FILE_RE = re.compile(r"[A-Za-z0-9_.$]+\.java")


def _j(o):
    """JSON for a <script type=application/json> block: no tag or line-separator can end it."""
    return json.dumps(o, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _windows(findings, size, sample_path, cache=None):
    """Byte windows around the findings. With `cache` (a path) the windows are stored whenever the sample can be read and read back when it cannot, so a run
    whose sample was deleted keeps the bytes the report shows."""
    spans = [(0, min(512, size))] if size else []
    for f in findings:
        o = f.get("off")
        if isinstance(o, int) and 0 <= o < size:
            n = max(1, min(int(f.get("len") or 1), WIN_MAX - 2 * WIN_CTX))
            spans.append((max(0, (o - WIN_CTX) // 16 * 16), min(size, o + n + WIN_CTX)))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1] and max(b, merged[-1][1]) - merged[-1][0] <= WIN_MAX:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    out, total = [], 0
    try:
        with open(sample_path, "rb") as fh:
            for a, b in merged:
                if total + (b - a) > WIN_TOTAL:
                    break
                fh.seek(a)
                data = fh.read(b - a)
                out.append({"off": a, "b64": base64.b64encode(data).decode()})
                total += len(data)
    except OSError:
        return load_windows(cache) if cache else []
    if cache:
        try:
            tmp = "%s.tmp%d" % (cache, os.getpid())
            with open(tmp, "w") as fh:
                json.dump(out, fh, separators=(",", ":"))
            os.replace(tmp, cache)
        except OSError:
            pass
    return out


def load_windows(path):
    """[{off, b64}] stored by `_windows`; [] when the file is missing or not what it should be."""
    try:
        with open(path) as fh:
            rows = json.load(fh)
        return [{"off": r["off"], "b64": r["b64"]} for r in rows if isinstance(r, dict) and type(r.get("off")) is int and r["off"] >= 0 and isinstance(r.get("b64"), str)][:4096]
    except (OSError, ValueError, KeyError, TypeError):
        return []


def _snippets(findings, lay, decomp_dir):
    """Decompiled code of the function each finding sits in (or names). Returns (snips, finding id -> snippet index)."""
    fns = [f for f in lay.get("functions", []) if f.get("decomp")]
    offs = sorted((f["off"], i) for i, f in enumerate(fns) if isinstance(f.get("off"), int))
    keys = [o for o, _ in offs]
    snips, byid, seen = [], {}, {}
    apk = lay.get("kind") == "apk"
    d = Path(decomp_dir)
    for f in findings:
        if len(snips) >= SNIP_COUNT:
            break
        o = f.get("off")
        fn = None
        if isinstance(o, int):
            k = bisect.bisect_right(keys, o) - 1
            if k >= 0:
                cand = fns[offs[k][1]]
                end = cand["off"] + max(int(cand.get("size") or 0), 1)
                if cand["off"] <= o < end:
                    fn = cand
        if fn is None:
            continue
        if fn["id"] in seen:
            byid[f["id"]] = seen[fn["id"]]
            continue
        try:
            if apk:
                nm = str(fn.get("file") or "")
                if not FILE_RE.fullmatch(nm):
                    continue
                p = d / nm
            else:
                hexva = "%x" % fn["va"]
                p = next(iter(sorted(d.glob("*_%s.c" % hexva))), None)
                if p is None:
                    continue
            if p.is_symlink() or not p.is_file():
                continue
            with open(p, "rb") as fh:
                text = fh.read(SNIP_MAX * 4).decode("utf-8", "replace")
        except (OSError, KeyError, TypeError):
            continue
        text = "".join(c for c in text if c in "\n\t" or ord(c) >= 32)
        cut = len(text) > SNIP_MAX
        snips.append({"name": str(fn.get("name", ""))[:96], "lang": "java" if apk else "c", "off": fn.get("off"), "text": text[:SNIP_MAX], "cut": cut})
        seen[fn["id"]] = len(snips) - 1
        byid[f["id"]] = len(snips) - 1
    return snips, byid


def _timeline(rec, board, events_path, roles, t0):
    ridx = {r: i for i, r in enumerate(roles)}
    ev = []
    try:
        with open(events_path) as fh:
            for ln in fh:
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if e.get("k") == "tool_start" and isinstance(e.get("off"), int) and e.get("role") in ridx:
                    ev.append([round(max(e.get("t", t0) - t0, 0), 1), ridx[e["role"]], e["off"], int(e.get("len") or 1)])
    except OSError:
        pass
    if len(ev) > EV_CAP:
        step = len(ev) / EV_CAP
        ev = [ev[int(i * step)] for i in range(EV_CAP)]
    tasks = [[ridx[t["role"]], round(max((t.get("started") or t0) - t0, 0), 1), round(max((t.get("ended") or t.get("started") or t0) - t0, 0), 1), t.get("round") or 1,
              t.get("state", ""), int(t.get("findings") or 0), int(t.get("tools") or 0)] for t in rec.get("tasks", []) if t.get("role") in ridx and t.get("started")]
    return ev, tasks


def _attack(board, F, lint=None):
    """Checked technique findings by tactic in matrix order (a technique with several tactics sits under each). Ids, names and tactics are MITRE's, from swarmlabre's table;
    `basis` keeps only board findings that are in this page, the rest is counted (`nb`) so the page never points at a finding it does not show."""
    att = board.get("attack") or {}
    names = {a: n for a, n in att.get("tactics", [])}
    have = {f["id"] for f in F}
    by = {}
    for f in F:
        if f["kind"] != "technique":
            continue
        a = f.get("attack")
        basis = [i for i in f.get("basis", []) if i in have]
        row = {"fid": f["id"], "tid": a["id"] if a else str(f.get("value") or "")[:12], "name": (a["name"] if a else f["title"])[:200], "basis": basis, "nb": len(f.get("basis", [])) - len(basis)}
        for t in ([x["id"] for x in a["tactics"]] if a else ["other"]):
            by.setdefault(t, []).append(row)
    return {"label": att.get("label", ""), "version": att.get("version", ""), "notice": attack.notice(), "lint": list(lint or [])[:8], "tactics": [[a, n] for a, n in att.get("tactics", [])],
            "groups": [{"id": t, "name": names.get(t, "Other"), "items": by[t]} for t in [a for a, _n in att.get("tactics", [])] + ["other"] if t in by]}


def _story_data(st):
    """The fixed sections for the page, with every network value defanged (the page never shows a real address)."""
    if not st:
        return None
    d = srep.defang_text
    return {"exec": {"text": d(st["exec"]["text"]), "src": st["exec"]["src"]}, "what": {"text": d(st["what"]["text"]), "tool": st["what"]["tool"]},
            "caps": {"rows": st["caps"]["rows"], "reporter": d(st["caps"]["reporter"]), "none": st["caps"]["none"]}, "recs": {"tool": st["recs"]["tool"], "reporter": d(st["recs"]["reporter"])},
            "unknown": {"tool": st["unknown"]["tool"], "reporter": d(st["unknown"]["reporter"])}, "notes": st["notes"]}


def _logo():
    """The optional brand image (data/logo.png) as a data URI (white lettering: it is drawn on the dark brand bar), or "" when the file is missing or oversized."""
    try:
        if LOGO.is_file() and LOGO.stat().st_size <= LOGO_MAX:
            return "data:image/png;base64," + base64.b64encode(LOGO.read_bytes()).decode()
    except OSError:
        pass
    return ""


def build(rec, board, lay, sample_path, decomp_dir, events_path, roles_meta, now=None, cover=None, tlp_colors=None, verdict_words=None, logo=True, win_cache=None):
    """roles_meta: {role: {"label": str}} for the roles of this run (ROLES in swarm.py). cover: swarmlabre's front matter (Swarms._cover: title, marking, assessment, snapshot)."""
    F = [f for f in board["findings"] if f["status"] in ("verified", "disputed")]
    c = board["counts"]
    roles = [r for r in rec["roles"] if r in roles_meta]
    t0 = rec.get("started") or rec.get("created") or 0
    t1 = rec.get("finished") or max([t.get("ended") or 0 for t in rec.get("tasks", [])] + [t0])
    ev, tasks = _timeline(rec, board, events_path, roles, t0)
    snips, snip_of = _snippets(F, lay, decomp_dir)
    size = rec["sample"]["size"]
    fl = []
    for f in F:
        r = f.get("resolution")
        fl.append({"id": f["id"], "kind": f["kind"], "title": srep.defang_text(f["title"])[:300], "value": srep.defang(f.get("value") or "", rec["sample"].get("kind"))[:VALUE_CAP], "enc": f.get("enc") or "",
                   "off": f["off"] if isinstance(f.get("off"), int) else None, "len": int(f.get("len") or 0), "level": f["level"], "disputed": f["status"] == "disputed",
                   "verdict": (r or {}).get("verdict") if f["status"] == "disputed" else None, "agents": [a for a in f.get("agents", []) if a in roles],
                   "t": round(max((f.get("t") or t0) - t0, 0), 1), "snip": snip_of.get(f["id"])})
    data = {"run": rec["id"], "sample": {k: rec["sample"].get(k) for k in ("name", "format", "size", "sha256")},
            "status": rec["status"], "model": (rec.get("model") or {}).get("model", ""), "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t1 or now or clock.now())),
            "dur": round(max(t1 - t0, 0)), "roles": [{"id": r, "label": roles_meta[r]["label"]} for r in roles],
            "counts": {"verified": c["verified"] + c["disputed"], "bytes": c["byte-checked"], "cited": c["call-cited"], "unconfirmed": c["unconfirmed"], "disputed": c["disputed"],
                       "refuted": c["refuted"], "rejected": c["rejected"]},
            "summary": srep.defang_text(rec.get("summary") or "")[:6000],
            "lay": {"kind": lay.get("kind"), "cells": lay.get("cells"), "cell_bytes": lay.get("cell_bytes"), "size": lay.get("size"),
                    "regions": [{"name": r.get("name", "")[:64], "off": r.get("off"), "len": r.get("len"), "perm": r.get("perm", ""), "kind": r.get("kind", "")} for r in lay.get("regions", [])][:200],
                    "ent": lay.get("entropy", [])},
            "attack": _attack(board, F, rec.get("attack_lint")), "findings": fl, "win": _windows(F, size, sample_path, win_cache), "snips": snips, "ev": ev, "tasks": tasks}
    cv = cover or {}
    asm = cv.get("assessment")
    data["cover"] = {"title": cv.get("title") or "Analysis of " + rec["sample"]["name"], "label": cv.get("label") or rec["sample"]["name"], "tlp": cv.get("tlp") or "", "tlp_text": cv.get("tlp_text") or "",
                     "tlp_color": (tlp_colors or {}).get(cv.get("tlp"), "#ffffff"), "org": cv.get("org") or "", "contact": cv.get("contact") or "", "date": cv.get("date") or "",
                     "logo": _logo() if logo and cv.get("org") else "", "basis": cv.get("basis") or [], "snapshot": cv.get("snapshot") or [], "iocs": cv.get("iocs") or [], "ioc_note": srep.IOC_NOTE,
                     "story": _story_data(cv.get("story")), "env": cv.get("env") or [], "fmt": cv.get("format") or stx.REPORT_FORMAT, "glossary": stx.GLOSSARY, "format_log": stx.FORMAT_LOG,
                     "level_text": [["byte-checked", "Swarmlabre found exactly these bytes at that offset in its own copy of the file."], ["call-cited", "Every tool call the agent cited exists in this run's tool log and its id appeared in that agent's session output. That does not prove this agent made the call, and it does not prove a tool's output was read correctly."],
                                    ["claimed", "Neither of the above. Claims are listed apart as leads and never counted."]],
                     "det": ({"note": cv["detection"]["note"], "how": cv["detection"]["how"], "fp": cv["detection"]["fp"], "skipped": cv["detection"]["skipped"],
                              "rules": [{"name": r["name"], "n": r["n"], "need": r["need"], "text": r["shown"]} for r in cv["detection"]["rules"]]} if cv.get("detection") else None),
                     "asm": {"verdict": asm["verdict"], "word": (verdict_words or {}).get(asm["verdict"], asm["verdict"]), "conf": asm["confidence_final"], "family": asm["family"],
                             "rationale": asm["rationale"], "adjusted": asm["adjusted"]} if asm else None}
    head, tail = PAGE.split("/*DATA*/", 1)                       # the title goes in before the data is inserted: a "%TITLE%" inside the data must stay what it is
    return head.replace("%TITLE%", re.sub(r"[<>&\"'\\]", "", data["cover"]["title"])[:100]) + _j(data) + tail


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>%TITLE%</title>
<style>
:root{color-scheme:light;--bg:#eef1f0;--paper:#fff;--ink:#14232b;--mut:#5b6b72;--rule:#d5dcdd;--rule2:#e6ebeb;--pet:#0f4c5c;--gold:#b88a2a;--wash:#f4f7f7;--ok:#12794f;--cit:#1f5fa8;--warn:#a8480f;--mono:ui-monospace,"JetBrains Mono","SF Mono",Menlo,Consolas,monospace;--sans:"Hanken Grotesk","Inter","Segoe UI",system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--sans);-webkit-text-size-adjust:100%}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 64px}
header.top{background:var(--paper);border-bottom:3px solid var(--pet);margin:0 0 24px;padding:28px 16px 22px}
header.top .in{max-width:1180px;margin:0 auto}
.brand{background:#0b1b21;color:#fff;padding:10px 16px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.brand .in{max-width:1180px;margin:0 auto;display:flex;align-items:center;gap:16px;justify-content:space-between;min-height:36px}
#brandl{display:flex;align-items:center;gap:14px;min-width:0}
.brand img{height:34px;width:auto;display:block}.brand .org{font-size:14px;color:#c9d6d8;overflow-wrap:anywhere}
.tlp{font:700 13px/1 var(--mono);background:#000;padding:7px 10px;border-radius:3px;white-space:nowrap}
.verdict{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:14px 0 0}
.vchip{font-weight:700;font-size:14px;border-radius:99px;padding:4px 14px;border:1.5px solid var(--mut);color:var(--mut)}
.vchip.malicious{color:#a1201b;border-color:#a1201b;background:#fdecea}.vchip.suspicious{color:var(--warn);border-color:var(--warn);background:#fdf1e6}
.vchip.benign{color:var(--ok);border-color:var(--ok);background:#e8f5ee}
.vnote{font-size:14px;color:var(--mut)}
.prose,.prose p,.prose li,#what p,#unk li,#recs li{overflow-wrap:anywhere}.byl{font-size:12px;color:var(--mut);margin:2px 0 14px}dl.lvl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:6px 0 4px}dl.lvl dt{font-weight:600}dl.lvl dd{margin:0}
.toc{display:none}.toc ol{columns:2;margin:0;padding-left:22px;font-size:14px}.toc h2{font-size:16px;margin:0 0 6px}
@media (max-width:700px){dl.lvl{grid-template-columns:1fr}dl.lvl dd{margin-bottom:6px}}
pre.yara{margin:6px 0 14px;padding:12px 14px;border:1px solid var(--rule2);background:#fbfcfc;font:12.5px/1.6 var(--mono);overflow:auto;max-height:420px;white-space:pre}
.ioch{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0 4px}.ioch h3{font-size:16px;margin:0;flex:1}.ioch span{font-size:12px;color:var(--mut)}
.rtab td.ind{font:13px/1.5 var(--mono);overflow-wrap:anywhere;word-break:break-all;min-width:200px}.rtab td.cx{overflow-wrap:anywhere;color:var(--mut)}.rtab td.ty{white-space:nowrap}
@media (max-width:700px){#iocs .rtab,#iocs .rtab tbody{display:block}#iocs .rtab thead{display:none}#iocs .rtab tr{display:block;border-bottom:1px solid var(--rule2);padding:8px 0}#iocs .rtab td{display:block;border:0;padding:1px 0}#iocs .rtab td.ty{font-size:12px;color:var(--mut)}#iocs .rtab td.ind{min-width:0}}
.kv{width:100%;border-collapse:collapse;font-size:14px}.kv th{text-align:left;font-weight:600;color:var(--mut);width:190px;vertical-align:top;padding:8px 12px 8px 0;border-top:1px solid var(--rule2)}
.kv td{padding:8px 0;border-top:1px solid var(--rule2);overflow-wrap:anywhere}.kv td.m{font:13px/1.5 var(--mono)}
.quote{border-left:3px solid var(--gold);background:var(--wash);padding:10px 14px;margin:14px 0 0;font-size:15px}.quote small{display:block;color:var(--mut);margin-top:6px;font-size:12px}
.eyebrow{font-size:12px;letter-spacing:.04em;color:var(--mut);margin:0 0 6px}
h1{font-size:28px;line-height:1.2;margin:0 0 4px;font-weight:700;overflow-wrap:anywhere}
.sub{color:var(--mut);margin:0 0 14px;font-size:14px}
.hash{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font:12px/1.4 var(--mono);color:var(--mut)}
.hash code{overflow-wrap:anywhere;color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.kpi{border-left:3px solid var(--rule);padding:2px 0 2px 12px}
.kpi b{display:block;font-size:24px;line-height:1.1;font-variant-numeric:tabular-nums}
.kpi span{font-size:12px;color:var(--mut)}
.kpi.ok{border-color:var(--ok)}.kpi.cit{border-color:var(--cit)}.kpi.warn{border-color:var(--warn)}
nav.jump{position:sticky;top:0;z-index:5;background:var(--bg);margin:0 -16px 20px;padding:8px 16px;border-bottom:1px solid var(--rule);display:flex;gap:4px;overflow-x:auto}
nav.jump a{color:var(--ink);text-decoration:none;padding:8px 12px;border-radius:6px;font-size:14px;white-space:nowrap;min-height:44px;display:flex;align-items:center}
nav.jump a:hover,nav.jump a:focus-visible{background:var(--paper);outline:none;box-shadow:inset 0 0 0 1px var(--pet)}
section.sec{background:var(--paper);border:1px solid var(--rule);border-radius:8px;padding:22px 22px 24px;margin:0 0 20px}
section.sec>h2{font-size:20px;margin:0 0 4px}
section.sec>.lead{color:var(--mut);font-size:14px;margin:0 0 16px}
.prose p{margin:0 0 .8em}.prose h4{margin:1.1em 0 .3em;font-size:16px}.prose ul{margin:0 0 .8em;padding-left:1.2em}
code,.mono{font-family:var(--mono);font-size:.88em}
.prose code{background:var(--wash);padding:1px 5px;border-radius:3px;overflow-wrap:anywhere}
button,select,input{font:inherit;color:inherit}
button{background:var(--paper);border:1px solid var(--rule);border-radius:6px;padding:8px 14px;cursor:pointer;min-height:44px}
button:hover{border-color:var(--pet)}button:focus-visible,select:focus-visible,input:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid var(--pet);outline-offset:2px}
button.sm{min-height:32px;padding:3px 10px;font-size:14px}
button.pri{background:var(--pet);color:#fff;border-color:var(--pet)}
button[aria-pressed=true]{background:var(--pet);color:#fff;border-color:var(--pet)}
select,input[type=search]{border:1px solid var(--rule);border-radius:6px;padding:8px 10px;background:var(--paper);min-height:44px;font-size:16px}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 14px}
.bar .sp{flex:1}
.seg{display:inline-flex}.seg button{border-radius:0;margin-left:-1px}.seg button:first-child{border-radius:6px 0 0 6px;margin-left:0}.seg button:last-child{border-radius:0 6px 6px 0}
/* map */
.mapbox{position:relative;border:1px solid var(--rule);border-radius:6px;background:var(--wash);overflow:hidden}
#map{display:block;width:100%;cursor:crosshair}
#tip{position:absolute;pointer-events:none;background:var(--ink);color:#fff;font-size:12px;line-height:1.45;padding:7px 10px;border-radius:5px;max-width:300px;z-index:3;display:none;white-space:pre-line}
.legend{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin-top:10px;align-items:center}
.legend i{display:inline-block;vertical-align:middle;margin-right:6px}
.ramp{width:120px;height:10px;border-radius:2px;background:linear-gradient(90deg,#e8eff0,#6f98a3 55%,#16313b 85%,#a8480f)}
.dia{width:10px;height:10px;transform:rotate(45deg);border:2px solid var(--ink)}.dia.f{background:var(--ink)}
.rtab{width:100%;border-collapse:collapse;font-size:14px;margin-top:14px}
.rtab th{text-align:left;font-weight:600;font-size:12px;color:var(--mut);border-bottom:1px solid var(--rule);padding:6px 8px}
.rtab td{padding:7px 8px;border-bottom:1px solid var(--rule2);font-variant-numeric:tabular-nums}
.rtab tr[data-r]{cursor:pointer}.rtab tr[data-r]:hover td,.rtab tr.on td{background:var(--wash)}
.rtab .mono{white-space:nowrap}
.tscroll{overflow-x:auto}
/* timeline */
.tl{display:grid;grid-template-columns:96px 1fr;gap:6px 12px;align-items:center;margin:14px 0 6px;position:relative}
.tl .lab{font-size:12px;color:var(--mut);display:flex;align-items:center;gap:6px;min-height:20px}
.tl .lane{position:relative;height:20px;background:var(--wash);border-radius:3px}
.tl .span{position:absolute;top:3px;bottom:3px;border-radius:2px;opacity:.9}
.tl .fm{position:absolute;top:1px;width:2px;bottom:1px;background:var(--ink)}
.tl .ph{position:absolute;top:0;bottom:0;width:2px;background:var(--gold);box-shadow:0 0 0 1px #fff;pointer-events:none}
.scrub{display:flex;gap:12px;align-items:center}
.scrub input[type=range]{flex:1;min-height:44px;accent-color:var(--pet)}
.scrub .t{font:14px var(--mono);min-width:150px;text-align:right;font-variant-numeric:tabular-nums}
.sw{display:inline-block;width:12px;height:12px;border-radius:2px;flex:none}
/* hex */
.hexbox{border:1px solid var(--rule);border-radius:6px;background:#fbfcfc;overflow-x:auto}
.hex{font:13px/1.7 var(--mono);padding:10px 12px;min-width:640px}
.hr{display:grid;grid-template-columns:78px max-content max-content;gap:18px;white-space:pre}
.hr .o{color:var(--mut)}.hr .h{display:flex;flex-wrap:nowrap}.hr .h span{width:2.1ch;margin-right:.55ch;text-align:center;border-radius:2px;cursor:default}
.hr .h span:nth-child(8){margin-right:1.4ch}.hr .a span{display:inline-block;width:1ch}
.hr span.hl{background:#ffe9a8;color:#3d2a00}.hr span.sel{background:var(--pet);color:#fff}.hr span.hov{outline:1px solid var(--pet)}
.hr span.z{color:#a9b4b8}
.insp{font:13px var(--mono);color:var(--mut);margin-top:10px;min-height:20px;overflow-wrap:anywhere}
.note{font-size:14px;color:var(--mut);margin:10px 0 0}
/* findings */
.cards{display:grid;gap:8px}
.card{border:1px solid var(--rule);border-radius:6px;background:var(--paper)}
.card.on{border-color:var(--pet);box-shadow:0 0 0 1px var(--pet)}
.card>.hd{display:flex;gap:10px;align-items:center;padding:8px 12px;cursor:pointer;min-height:48px;width:100%;background:none;border:0;text-align:left;border-radius:6px}
.card .id{font:12px var(--mono);color:var(--mut);min-width:3ch}
.card .tt{flex:1;overflow-wrap:anywhere;font-weight:600}
.card .off{font:12px var(--mono);color:var(--mut);white-space:nowrap}
.pill{font-size:12px;border:1px solid var(--rule);border-radius:99px;padding:1px 9px;white-space:nowrap;color:var(--mut)}
.pill.b{border-color:var(--ok);color:var(--ok)}.pill.c{border-color:var(--cit);color:var(--cit)}.pill.d{border-color:var(--warn);color:var(--warn)}
.card .bd{padding:0 12px 12px;display:none}.card.open .bd{display:block}
.card .caret{width:10px;height:10px;border-right:2px solid var(--mut);border-bottom:2px solid var(--mut);transform:rotate(-45deg);transition:transform .15s;flex:none}
.card.open .caret{transform:rotate(45deg)}
pre.val{margin:0 0 10px;padding:10px 12px;background:var(--wash);border:1px solid var(--rule2);border-radius:5px;font:13px/1.55 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;max-height:260px;overflow:auto}
.meta{font-size:13px;color:var(--mut);margin:0 0 10px}
.acts{display:flex;gap:8px;flex-wrap:wrap}
.code{margin-top:12px;border:1px solid var(--rule);border-radius:6px;overflow:hidden}
.code .ch{display:flex;gap:10px;align-items:center;background:var(--wash);padding:4px 8px 4px 12px;font:12px var(--mono);color:var(--mut)}
.code .ch b{flex:1;color:var(--ink);font-weight:600;overflow-wrap:anywhere}
.code pre{margin:0;padding:10px 0;font:12.5px/1.6 var(--mono);overflow:auto;max-height:360px;background:#fbfcfc}
.code .ln{display:block;padding:0 12px 0 0;white-space:pre}
.code .ln:before{content:attr(data-n);display:inline-block;width:3.6ch;text-align:right;margin-right:12px;color:#9aa8ad}
.k{color:#7a2e8f;font-weight:600}.n{color:#1f5fa8}.s{color:#12794f}.c2{color:#7b878c;font-style:italic}
.att h3{font-size:16px;margin:18px 0 6px;display:flex;gap:10px;align-items:baseline}.att h3 span{font:12px var(--mono);color:var(--mut);font-weight:400}
.att .ar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-top:1px solid var(--rule2);padding:4px 0}
.att .ar>button.tb{flex:1;min-width:220px;display:flex;gap:12px;align-items:baseline;text-align:left;border:0;background:none;padding:6px 4px;min-height:44px;border-radius:6px}
.att .ar>button.tb:hover{background:var(--wash)}.att .tid{font:13px var(--mono);color:var(--pet);white-space:nowrap}.att .tn{overflow-wrap:anywhere}
.att .bs{font-size:12px;color:var(--mut);display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.ast{list-style:none;margin:8px 0 0;padding:0}
.ast li{display:grid;grid-template-columns:minmax(0,190px) minmax(0,260px) 28px minmax(0,1fr);grid-template-areas:"tn bar ct ids";gap:4px 12px;align-items:center;min-height:32px}
.ast li.z{min-height:24px}
.ast .tn{grid-area:tn;font-size:15px}.ast li.z .tn,.ast li.z .ct{color:var(--mut)}
.ast .asg{grid-area:bar;display:grid;grid-template-columns:repeat(var(--u),minmax(0,1fr));gap:2px;height:10px}
.ast li.z .asg{height:1px;background:var(--rule)}
.ast .asg i{border-radius:2px;background:var(--cit)}.ast .asg i.b{background:var(--ok)}
.ast .ct{grid-area:ct;font:600 13px var(--mono);text-align:right}
.ast .ids{grid-area:ids;display:flex;flex-wrap:wrap;gap:0 10px}
.ast .ids button{border:0;background:none;padding:0 2px;min-height:32px;font:13px var(--mono);color:var(--pet);text-decoration:underline}
@media (max-width:700px){.ast li{grid-template-columns:minmax(0,1fr) 28px;grid-template-areas:"tn ct" "bar bar" "ids ids";padding:4px 0}.ast li.z{grid-template-areas:"tn ct"}.ast li.z .asg,.ast li.z .ids{display:none}.ast .ids button{min-height:44px}}
.rlg{display:flex;flex-wrap:wrap;gap:4px 16px;margin:8px 0 0;font-size:12px;color:var(--mut)}
.rlg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}.rlg i.b{background:var(--ok)}.rlg i.c{background:var(--cit)}
.att .astn{font-size:12px;color:var(--mut);margin:4px 0 10px}
.empty{color:var(--mut);padding:18px 0;text-align:center}
.foot{font-size:13px;color:var(--mut);margin-top:28px}
.foot p{margin:0 0 8px}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
section.sec,.kpi{animation:rise .35s ease both}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
@media (max-width:700px){.kv th{width:110px}.brand .org{display:none}h1{font-size:24px}section.sec{padding:16px 14px 18px}.tl{grid-template-columns:64px 1fr}.scrub .t{min-width:0;font-size:12px}.card .off{display:none}}
@media print{.toc{display:block;margin:0 0 18px}pre.yara{max-height:none;white-space:pre-wrap;word-break:break-all}#s-det{break-inside:auto}body{background:#fff}nav.jump,.bar,.scrub,.acts,button{display:none!important}section.sec{break-inside:avoid;border-color:#bbb}.card .bd{display:block}.code pre,pre.val{max-height:none}header.top{border-bottom-width:2px}.wrap{max-width:none}}
</style></head><body>
<div class="brand" id="brand" hidden><div class="in"><span id="brandl"></span><span class="tlp" id="tlp"></span></div></div>
<header class="top"><div class="in">
<p class="eyebrow" id="eyebrow"></p><h1 id="h1"></h1><p class="sub" id="sub"></p>
<div class="hash"><span>SHA-256</span><code id="sha"></code><button class="sm" id="cpsha" type="button">Copy</button></div>
<div class="verdict" id="verdict"></div>
<div class="kpis" id="kpis"></div>
</div></header>
<div class="wrap">
<nav class="jump" aria-label="Sections"><a href="#s-asm">Assessment</a><a href="#s-exec">Summary</a><a href="#s-caps">Capabilities</a><a href="#s-recs">Actions</a><a href="#s-unk">Unknowns</a><a href="#s-snap">Snapshot</a><a href="#s-ioc">Indicators</a><a href="#s-det">Detection</a><a href="#s-map">Map</a><a href="#s-hex">Bytes</a><a href="#s-find">Findings</a><a href="#s-att">ATT&amp;CK</a><a href="#s-tl">Timeline</a><a href="#s-about">About</a><a href="#s-env">Environment</a></nav>

<section class="sec" id="s-asm"><h2>Assessment</h2><p class="lead">The Reporter's verdict, checked by swarmlabre against the findings it cites. Swarmlabre can lower the confidence; it cannot raise it.</p><div id="asm"></div></section>

<nav class="toc" id="toc" aria-label="Contents"><h2>Contents</h2><ol></ol></nav>

<section class="sec" id="s-exec"><h2>Executive summary</h2><div class="prose" id="exec"></div></section>

<section class="sec" id="s-what"><h2>What it is</h2><div class="prose" id="what"></div></section>

<section class="sec" id="s-caps"><h2>Capabilities</h2><p class="lead">What the verified findings say the file can do, grouped by MITRE ATT&amp;CK goal. The goal and technique names are MITRE's; the evidence level says how the finding was backed, not that the mapping fits.</p><div id="caps"></div></section>

<section class="sec" id="s-recs"><h2>Recommendations</h2><div id="recs"></div></section>

<section class="sec" id="s-unk"><h2>What we don't know</h2><div id="unk"></div></section>

<section class="sec" id="s-snap"><h2>Sample snapshot</h2><p class="lead">Read by swarmlabre from the file itself; no agent wrote these values.</p><div class="tscroll"><table class="kv" id="snap"></table></div></section>

<section class="sec" id="s-ioc"><h2>Indicators of compromise</h2><p class="lead" id="iocnote"></p><div id="iocs"></div></section>

<section class="sec" id="s-det"><h2>Detection engineering</h2><p class="lead" id="detnote"></p><div id="det"></div></section>

<section class="sec" id="s-map"><h2>Where things are in the file</h2>
<p class="lead">Every cell is a slice of the file coloured by entropy. Diamonds mark findings with a file offset. Click a cell to read its bytes.</p>
<div class="bar"><button type="button" id="covb" aria-pressed="true">Agent coverage</button><span class="note" id="mapnote" style="margin:0"></span></div>
<div class="mapbox"><canvas id="map" role="img" aria-label="Entropy map of the file with findings marked"></canvas><div id="tip"></div></div>
<div class="legend"><span><i class="ramp"></i>entropy, low to high (amber = 7.2 bits per byte or more: packed or encrypted data)</span>
<span><i class="dia f"></i>byte-checked finding</span><span><i class="dia"></i>call-cited finding</span><span id="rlegend"></span></div>
<div class="tscroll"><table class="rtab" id="rtab"><thead><tr><th>Region</th><th>Offset</th><th>Size</th><th>Entropy</th><th>Findings</th></tr></thead><tbody></tbody></table></div>
</section>

<section class="sec" id="s-hex"><h2>Bytes</h2>
<p class="lead">Read straight from swarmlabre's copy of the file around each finding. Highlighted bytes are the ones a finding points at.</p>
<div class="bar"><label for="winsel" class="note" style="margin:0">Window</label><select id="winsel"></select><button class="sm" type="button" id="wprev">Previous</button><button class="sm" type="button" id="wnext">Next</button><span class="sp"></span><button class="sm" type="button" id="cphex">Copy hex</button></div>
<div class="hexbox"><div class="hex" id="hex" tabindex="0" aria-label="Hex dump"></div></div>
<div class="insp" id="insp">Click a byte to inspect it.</div>
<p class="note" id="hexnote"></p></section>

<section class="sec" id="s-find"><h2>Findings</h2><p class="lead">Only findings swarmlabre checked. URLs, addresses and domains are shown defanged. Byte-checked: the exact bytes are at that offset in the file. Call-cited: the tool calls the agent cited exist in the run's tool log and their ids appeared in that agent's session output (not proof that this agent made them).</p>
<div class="bar"><input type="search" id="q" placeholder="Search findings" aria-label="Search findings">
<span class="seg" role="group" aria-label="Evidence"><button type="button" data-ev="" aria-pressed="true">All</button><button type="button" data-ev="byte-checked" aria-pressed="false">Byte-checked</button><button type="button" data-ev="call-cited" aria-pressed="false">Call-cited</button></span>
<select id="kind" aria-label="Kind"></select><select id="agent" aria-label="Agent"></select><select id="sort" aria-label="Sort"><option value="id">In order found</option><option value="off">By file offset</option></select></div>
<div class="note" id="fcount" style="margin:0 0 10px"></div><div class="cards" id="cards"></div></section>

<section class="sec att" id="s-att"><h2>MITRE ATT&amp;CK</h2><p class="lead" id="attlead"></p><div id="attbox"></div></section>

<section class="sec" id="s-tl"><h2>How the run went</h2>
<p class="lead">Replay of the run. Drag the slider or press Play: the map shows which parts of the file the agents had looked at by then and which findings existed.</p>
<div class="scrub"><button type="button" class="pri" id="play">Play</button><input type="range" id="rng" min="0" max="1000" value="1000" aria-label="Run time"><span class="t" id="tlab"></span></div>
<div class="tl" id="tl"></div>
<details style="margin-top:12px"><summary style="cursor:pointer;min-height:32px">Task table</summary><div class="tscroll"><table class="rtab" id="ttab"><thead><tr><th>Agent</th><th>Round</th><th>Started</th><th>Took</th><th>Tool calls</th><th>Findings posted</th><th>State</th></tr></thead><tbody></tbody></table></div></details>
</section>

<section class="sec" id="s-about"><h2>About this report</h2>
<div id="about"></div><div class="foot" id="foot"></div></section>

<section class="sec" id="s-env"><h2>Analysis environment</h2><p class="lead">What the analysis ran on. Facts recorded by swarmlabre when the run started.</p><div class="tscroll"><table class="kv" id="envt"></table></div></section>
</div>
<script type="application/json" id="data">/*DATA*/</script>
<script>
"use strict";
const D=JSON.parse(document.getElementById('data').textContent);
const $=s=>document.querySelector(s);
const E=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const hx=n=>'0x'+n.toString(16);
const RC=['#c2417a','#0e8aa6','#6f9a1a','#7b4bc4','#d9822b','#5b6b72'];
const rcol=i=>RC[i%RC.length];
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
const dur=n=>{n=Math.round(n);const h=Math.floor(n/3600),m=Math.floor(n%3600/60),s=n%60;return h?`${h} h ${m} min`:m?`${m} min ${s} s`:`${s} s`};
const mm=n=>{n=Math.round(n);return Math.floor(n/60)+':'+String(n%60).padStart(2,'0')};
const copy=(t,btn)=>{const done=()=>{if(!btn)return;const o=btn.textContent;btn.textContent='Copied';setTimeout(()=>btn.textContent=o,1200)};
  if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(t).then(done,()=>fb());else fb();
  function fb(){const a=E('textarea');a.value=t;a.style.cssText='position:fixed;opacity:0';document.body.append(a);a.select();try{document.execCommand('copy');done()}catch(e){}a.remove()}};

/* ---- header ---- */
const S=D.sample,C=D.counts,L=D.lay;
const CV=D.cover;
document.title=CV.title;
$('#eyebrow').textContent='Malware analysis report · '+[CV.date,'run '+D.run].filter(Boolean).join(' · ');
$('#h1').textContent=CV.label;
if(CV.tlp||CV.org){const b=$('#brand');b.hidden=false;
  if(CV.logo){const im=E('img');im.src=CV.logo;im.alt=CV.org||'logo';$('#brandl').append(im)}else $('#brandl').append(E('span','org',CV.org));
  if(CV.logo&&CV.org)$('#brandl').append(E('span','org',CV.org));
  if(CV.tlp){const t=$('#tlp');t.textContent='TLP:'+CV.tlp;t.style.color=CV.tlp_color;t.title=CV.tlp_text}}
if(CV.asm){const v=$('#verdict');v.append(E('span','vchip '+CV.asm.verdict,CV.asm.word),E('span','vnote',CV.asm.conf[0].toUpperCase()+CV.asm.conf.slice(1)+' confidence'+(CV.asm.family?' · '+CV.asm.family:'')))}
$('#sub').textContent=[S.format,S.size.toLocaleString('en')+' bytes',D.when,D.status,'ran '+dur(D.dur),D.model].filter(Boolean).join(' · ');
$('#sha').textContent=S.sha256;$('#cpsha').onclick=e=>copy(S.sha256,e.currentTarget);
[['Verified',C.verified,'ok'],['Byte-checked',C.bytes,'ok'],['Call-cited',C.cited,'cit'],['Disputed',C.disputed,'warn'],['Unconfirmed',C.unconfirmed,''],['Rejected by swarmlabre',C.rejected,'']].forEach(([l,v,k])=>{
  const d=E('div','kpi '+k);d.append(E('b','',v),E('span','',l));$('#kpis').append(d)});

/* ---- summary: paragraphs, bullets, headings, **bold**, `code`; text nodes only ---- */
function inl(p,t){t.split(/(\*\*[^*]+\*\*|`[^`]+`)/).forEach(s=>{if(!s)return;if(s.startsWith('**')&&s.endsWith('**')&&s.length>4)p.append(E('b','',s.slice(2,-2)));else if(s[0]==='`'&&s.length>2&&s.endsWith('`'))p.append(E('code','',s.slice(1,-1)));else p.append(document.createTextNode(s))})}
function prose(box,src){let ul=null,para=[];const flush=()=>{if(para.length){const p=E('p');inl(p,para.join(' '));box.append(p);para=[]}};
  for(const ln of String(src||'').split('\n')){const t=ln.trim();
    if(!t){flush();ul=null;continue}
    let m;if(m=t.match(/^#{1,6}\s+(.*)/)){flush();ul=null;const h=E('h4');inl(h,m[1]);box.append(h);continue}
    if(m=t.match(/^(?:[-*]|\d{1,2}[.)])\s+(.*)/)){flush();if(!ul){ul=E('ul');box.append(ul)}const li=E('li');inl(li,m[1]);ul.append(li);continue}
    ul=null;para.push(t)}
  flush()}
const BYL='Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.';
(function(){const S=CV.story;if(!S){['#s-exec','#s-what','#s-caps','#s-recs','#s-unk'].forEach(x=>$(x).hidden=true);return}
  const ex=$('#exec');prose(ex,S.exec.text);if(S.exec.src==='reporter')ex.append(E('p','byl',BYL));
  const wh=$('#what');if(S.what.text){prose(wh,S.what.text);wh.append(E('p','byl',BYL))}wh.append(E('p','',S.what.tool));
  const cp=$('#caps');
  if(S.caps.rows.length){const w=E('div','tscroll'),t=E('table','rtab'),th=E('thead'),hr=E('tr');['Goal (MITRE tactic)','In plain words','Techniques verified','Evidence'].forEach(x=>hr.append(E('th','',x)));th.append(hr);t.append(th);
    const tb=E('tbody');S.caps.rows.forEach(r=>{const tr=E('tr');tr.append(E('td','ty',r.tactic),E('td','',r.plain),E('td','cx',r.techs),E('td','',r.level));tb.append(tr)});t.append(tb);w.append(t);cp.append(w)}
  else cp.append(E('p','empty',S.caps.none));
  if(S.caps.reporter){cp.append(E('h3','','The Reporter\u2019s description of what the file can do'));const d=E('div','prose');prose(d,S.caps.reporter);cp.append(d,E('p','byl',BYL))}
  const lg=E('dl','lvl');CV.level_text.forEach(x=>{lg.append(E('dt','',x[0]),E('dd','',x[1]))});cp.append(E('h3','','What the evidence levels mean'),lg);
  const rc=$('#recs');rc.append(E('h3','','Standard actions'),E('p','byl','Fixed text, chosen by swarmlabre from what was verified.'));const ul=E('ul');S.recs.tool.forEach(x=>ul.append(E('li','',x)));rc.append(ul);
  if(S.recs.reporter){rc.append(E('h3','','Suggestions from the Reporter for this file'),E('p','byl','Model text, not checked by swarmlabre.'));const d=E('div','prose');prose(d,S.recs.reporter);rc.append(d)}
  const un=$('#unk'),u2=E('ul');S.unknown.tool.forEach(x=>u2.append(E('li','',x)));un.append(u2);
  if(S.unknown.reporter){un.append(E('h3','','What the Reporter says it could not establish'),E('p','byl','Model text, not checked by swarmlabre.'));const d=E('div','prose');prose(d,S.unknown.reporter);un.append(d)}})();
(function(){const box=$('#about'),S=CV.story;box.append(E('p','','This report was written by an automated agent swarm and checked by swarmlabre as described here. No person has reviewed it unless a reviewer is named on the cover.'));
  const g=E('dl','lvl');CV.glossary.forEach(x=>g.append(E('dt','',x[0]),E('dd','',x[1])));box.append(E('h3','','Terms used'),g);
  const u=E('ul');CV.format_log.forEach(x=>u.append(E('li','','Format '+x[0]+', '+x[1]+': '+x[2])));box.append(E('h3','','Report format'),u);
  if(S)S.notes.forEach(n=>box.append(E('p','note',n)));
  const t=$('#envt');CV.env.forEach(x=>{const r=E('tr');r.append(E('th','',x[0]),E('td','',x[1]));t.append(r)})})();
(function(){const ol=$('#toc ol');document.querySelectorAll('section.sec:not([hidden])>h2').forEach(h=>{const li=E('li','',h.textContent);ol.append(li)})})();

/* ---- shared state ---- */
const F=D.findings,byId={};F.forEach(f=>byId[f.id]=f);
const ST={sel:null,T:D.dur,cov:true,win:0,hit:null,regHover:-1};
const cellOf=o=>Math.min(L.cells-1,Math.floor(o/L.cell_bytes));
const cellF=new Map();F.forEach(f=>{if(f.off!=null){const c=cellOf(f.off);if(!cellF.has(c))cellF.set(c,[]);cellF.get(c).push(f.id)}});
const bits=v=>(v/255*8);

/* ---- map ---- */
const cv=$('#map'),tip=$('#tip'),ctx=cv.getContext('2d');
let G={cs:10,cols:1,rows:1,W:0,H:0,dpr:1};
const RAMP=(()=>{const a=[],lr=(p,q,t)=>Math.round(p+(q-p)*t);const lo=[232,239,240],mid=[111,152,163],hi=[22,49,59];
  for(let v=0;v<256;v++){const t=v/255;let c;if(bits(v)>=7.2)c=[168,72,15];else if(t<.55){const u=t/.55;c=[0,1,2].map(i=>lr(lo[i],mid[i],u))}else{const u=(t-.55)/.45;c=[0,1,2].map(i=>lr(mid[i],hi[i],u))}a.push(`rgb(${c})`)}return a})();
function covAt(T){const m=new Int8Array(L.cells).fill(-1);
  for(const [t,r,o,n] of D.ev){if(t>T)break;const a=cellOf(o),b=cellOf(Math.min(o+Math.max(n,1)-1,L.size-1));for(let c=a;c<=b&&c<L.cells;c++)m[c]=r}return m}
function layout(){const W=cv.parentElement.clientWidth;G.dpr=Math.min(devicePixelRatio||1,2);
  const cs=Math.max(4,Math.min(16,Math.floor(Math.sqrt(W*340/L.cells))));G.cs=cs;G.cols=Math.max(1,Math.floor(W/cs));G.rows=Math.ceil(L.cells/G.cols);
  G.W=G.cols*cs;G.H=G.rows*cs;cv.style.width=G.W+'px';cv.style.height=G.H+'px';cv.width=G.W*G.dpr;cv.height=G.H*G.dpr}
function regionOfCell(c){const o=c*L.cell_bytes;let k=-1;L.regions.forEach((r,i)=>{if(o>=r.off&&o<r.off+r.len)k=i});return k}
function draw(){const {cs,cols,dpr}=G;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,G.W,G.H);
  const cov=ST.cov&&D.ev.length?covAt(ST.T):null;
  const rr=ST.regHover>=0?L.regions[ST.regHover]:null;
  for(let c=0;c<L.cells;c++){const x=(c%cols)*cs,y=Math.floor(c/cols)*cs;
    ctx.fillStyle=RAMP[L.ent[c]||0];ctx.fillRect(x,y,cs-1,cs-1);
    if(cov&&cov[c]>=0){ctx.globalAlpha=.55;ctx.fillStyle=rcol(cov[c]);ctx.fillRect(x,y,cs-1,cs-1);ctx.globalAlpha=1}
    if(rr){const o=c*L.cell_bytes;if(!(o+L.cell_bytes>rr.off&&o<rr.off+rr.len)){ctx.fillStyle='rgba(244,247,247,.72)';ctx.fillRect(x,y,cs-1,cs-1)}}}
  for(const f of F){if(f.off==null||f.t>ST.T)continue;pin(f,f.id===ST.sel)}
  if(ST.sel&&!reduce&&ST.ring)ring()}
function pin(f,big){const c=cellOf(f.off),cs=G.cs,x=(c%G.cols)*cs+cs/2,y=Math.floor(c/G.cols)*cs+cs/2,r=Math.max(4,cs*.55)+(big?2:0);
  ctx.save();ctx.translate(x,y);ctx.rotate(Math.PI/4);ctx.beginPath();ctx.rect(-r/1.4,-r/1.4,r*1.4,r*1.4);
  ctx.fillStyle=f.level==='byte-checked'?'#14232b':'#fff';ctx.fill();ctx.lineWidth=2;ctx.strokeStyle=big?'#b88a2a':'#fff';ctx.stroke();
  if(f.level!=='byte-checked'){ctx.lineWidth=1.6;ctx.strokeStyle='#14232b';ctx.stroke()}ctx.restore()}
function ring(){const f=byId[ST.sel];if(!f||f.off==null)return;const k=Math.min((performance.now()-ST.ring)/900,1),c=cellOf(f.off),cs=G.cs,x=(c%G.cols)*cs+cs/2,y=Math.floor(c/G.cols)*cs+cs/2;
  ctx.beginPath();ctx.arc(x,y,6+k*22,0,6.283);ctx.strokeStyle=`rgba(184,138,42,${1-k})`;ctx.lineWidth=2;ctx.stroke();if(k<1)requestAnimationFrame(draw)}
function cellAt(e){const r=cv.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;const c=Math.floor(y/G.cs)*G.cols+Math.floor(x/G.cs);return c>=0&&c<L.cells?c:-1}
cv.addEventListener('mousemove',e=>{const c=cellAt(e);if(c<0){tip.style.display='none';return}
  const a=c*L.cell_bytes,b=Math.min(a+L.cell_bytes,L.size)-1,k=regionOfCell(c),fs=cellF.get(c)||[];
  tip.textContent=`${hx(a)} – ${hx(b)}\nentropy ${bits(L.ent[c]).toFixed(2)} bits per byte`+(k>=0?`\nregion ${L.regions[k].name}`:'')+(fs.length?`\nfindings ${fs.slice(0,6).join(', ')}${fs.length>6?' …':''}`:'');
  tip.style.display='block';const r=cv.parentElement.getBoundingClientRect();let x=e.clientX-r.left+14,y=e.clientY-r.top+14;if(x>r.width-300)x=e.clientX-r.left-300;tip.style.left=Math.max(4,x)+'px';tip.style.top=y+'px'});
cv.addEventListener('mouseleave',()=>tip.style.display='none');
cv.addEventListener('click',e=>{const c=cellAt(e);if(c<0)return;const fs=cellF.get(c);if(fs&&fs.length){select(fs[0],{scroll:false,hex:true});return}showOffset(c*L.cell_bytes,true)});
$('#covb').onclick=e=>{ST.cov=!ST.cov;e.currentTarget.setAttribute('aria-pressed',ST.cov);draw()};
if(!D.ev.length){$('#covb').hidden=true}
$('#mapnote').textContent=L.cells.toLocaleString('en')+' cells of '+L.cell_bytes.toLocaleString('en')+' bytes';
(function(){const tb=$('#rtab tbody');L.regions.forEach((r,i)=>{let s=0,n=0;const a=Math.floor(r.off/L.cell_bytes),b=Math.min(L.cells-1,Math.floor((r.off+Math.max(r.len,1)-1)/L.cell_bytes));for(let c=a;c<=b;c++){s+=L.ent[c]||0;n++}
  const fc=F.filter(f=>f.off!=null&&f.off>=r.off&&f.off<r.off+r.len).length,tr=E('tr');tr.dataset.r=i;tr.tabIndex=0;
  const en=n?bits(s/n):0;tr.append(E('td','',r.name+(r.perm?'  ('+r.perm+')':'')),E('td','mono',hx(r.off)),E('td','mono',r.len.toLocaleString('en')+' B'),E('td','',en.toFixed(2)+(en>=7.2?' (high)':'')),E('td','',fc||'–'));
  const on=()=>{ST.regHover=i;draw();tr.classList.add('on')},off=()=>{ST.regHover=-1;draw();tr.classList.remove('on')};
  tr.onmouseenter=on;tr.onmouseleave=off;tr.onfocus=on;tr.onblur=off;tr.onclick=()=>showOffset(r.off,true);tr.onkeydown=e=>{if(e.key==='Enter')showOffset(r.off,true)};tb.append(tr)})})();
(function(){const lg=$('#rlegend');if(!D.ev.length)return;D.roles.forEach((r,i)=>{const s=E('span');const w=E('i','sw');w.style.background=rcol(i);s.append(w,document.createTextNode(r.label+' '));s.style.marginRight='10px';lg.append(s)})})();

/* ---- hex ---- */
const W=D.win.map(w=>{const s=atob(w.b64),u=new Uint8Array(s.length);for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return {off:w.off,u}});
const wsel=$('#winsel'),hexEl=$('#hex');
W.forEach((w,i)=>{const o=E('option','',`${hx(w.off)} – ${hx(w.off+w.u.length-1)}`+(()=>{const fs=F.filter(f=>f.off!=null&&f.off>=w.off&&f.off<w.off+w.u.length).map(f=>f.id);return fs.length?'  ('+fs.slice(0,4).join(', ')+(fs.length>4?' …':'')+')':'  (file start)'})());o.value=i;wsel.append(o)});
let selByte=-1;
function winFor(o){return W.findIndex(w=>o>=w.off&&o<w.off+w.u.length)}
function drawHex(){hexEl.textContent='';if(!W.length){hexEl.append(E('div','empty','No bytes were embedded.'));return}
  const w=W[ST.win],f=ST.sel?byId[ST.sel]:null,hs=f&&f.off!=null?f.off:-1,he=hs>=0?hs+Math.max(f.len,1):-1;
  const rows=Math.ceil(w.u.length/16);
  for(let r=0;r<rows;r++){const base=w.off+r*16,row=E('div','hr'),o=E('span','o',String(base.toString(16)).padStart(8,'0')),h=E('span','h'),a=E('span','a');
    for(let i=0;i<16;i++){const k=r*16+i;if(k>=w.u.length)break;const v=w.u[k],at=base+i,hs_=E('span',v===0?'z':'',v.toString(16).padStart(2,'0')),as=E('span',v===0?'z':'',v>=32&&v<127?String.fromCharCode(v):'.');
      hs_.dataset.k=as.dataset.k=k;if(at>=hs&&at<he){hs_.classList.add('hl');as.classList.add('hl')}if(k===selByte){hs_.classList.add('sel');as.classList.add('sel')}
      h.append(hs_);a.append(as)}
    row.append(o,h,a);hexEl.append(row)}
  wsel.value=ST.win;$('#wprev').disabled=ST.win<=0;$('#wnext').disabled=ST.win>=W.length-1}
hexEl.addEventListener('mouseover',e=>{const k=e.target.dataset&&e.target.dataset.k;hexEl.querySelectorAll('.hov').forEach(x=>x.classList.remove('hov'));if(k!=null)hexEl.querySelectorAll(`[data-k="${k}"]`).forEach(x=>x.classList.add('hov'))});
hexEl.addEventListener('click',e=>{const k=e.target.dataset&&e.target.dataset.k;if(k==null)return;selByte=+k;const w=W[ST.win],i=+k,u=w.u,at=w.off+i;
  const g=(n,le)=>i+n<=u.length?(n===2?u[i]|u[i+1]<<8:(u[i]|u[i+1]<<8|u[i+2]<<16|u[i+3]*16777216)):null;
  const p=[`offset ${hx(at)} (${at})`,`u8 ${u[i]} (${hx(u[i])})`];const a=g(2),b=g(4);if(a!=null)p.push('u16 LE '+a);if(b!=null)p.push('u32 LE '+(b>>>0)+' ('+hx(b>>>0)+')');
  $('#insp').textContent=p.join('   ·   ');drawHex()});
wsel.onchange=()=>{ST.win=+wsel.value;selByte=-1;drawHex()};
$('#wprev').onclick=()=>{if(ST.win>0){ST.win--;selByte=-1;drawHex()}};$('#wnext').onclick=()=>{if(ST.win<W.length-1){ST.win++;selByte=-1;drawHex()}};
$('#cphex').onclick=e=>{if(!W.length)return;copy(Array.from(W[ST.win].u,v=>v.toString(16).padStart(2,'0')).join(' '),e.currentTarget)};
function showOffset(o,scroll){const i=winFor(o);const note=$('#hexnote');
  if(i>=0){ST.win=i;selByte=o-W[i].off;note.textContent='';drawHex();$('#insp').textContent='offset '+hx(o);}
  else{note.textContent=`Bytes at ${hx(o)} are not embedded: only the file start and the areas around findings are. Pick a window above.`;if(W.length){let b=0,bd=1e18;W.forEach((w,k)=>{const d=Math.abs(w.off-o);if(d<bd){bd=d;b=k}});ST.win=b;selByte=-1;drawHex()}}
  if(scroll)$('#s-hex').scrollIntoView({behavior:reduce?'auto':'smooth',block:'start'})}

/* ---- findings ---- */
const KINDS={ioc:'Indicator',function:'Function',crypto:'Cryptography',config:'Configuration',capability:'Capability',technique:'Technique',note:'Note'};
const kinds=[...new Set(F.map(f=>f.kind))];
$('#kind').append(new Option('All kinds',''));kinds.forEach(k=>$('#kind').append(new Option(KINDS[k]||k,k)));
$('#agent').append(new Option('All agents',''));D.roles.forEach(r=>$('#agent').append(new Option(r.label,r.id)));
const FS={q:'',ev:'',kind:'',agent:'',sort:'id'};
const KW=new Set('if else while for do return switch case break continue goto void int char long short unsigned signed struct union enum sizeof default typedef static const extern undefined undefined1 undefined2 undefined4 undefined8 bool byte uint ulong ushort uchar code class public private protected final new try catch throw throws import package extends implements this null true false string boolean float double synchronized'.split(' '));
function hl(code){const frag=document.createDocumentFragment(),lines=code.replace(/\t/g,'    ').split('\n');let inBlock=false;
  lines.forEach((ln,i)=>{const row=E('span','ln');row.dataset.n=i+1;let pos=0;
    const re=/\/\*|\*\/|\/\/.*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b0x[0-9a-fA-F]+\b|\b\d+\b|\b[A-Za-z_][A-Za-z0-9_]*\b/g;let m;
    const put=(t,c)=>{if(!t)return;if(c)row.append(E('span',c,t));else row.append(document.createTextNode(t))};
    if(inBlock){const e=ln.indexOf('*/');if(e<0){put(ln,'c2');frag.append(row);return}put(ln.slice(0,e+2),'c2');inBlock=false;pos=e+2}
    re.lastIndex=pos;
    while((m=re.exec(ln))){put(ln.slice(pos,m.index));const t=m[0];pos=m.index+t.length;
      if(t==='/*'){const e=ln.indexOf('*/',pos);if(e<0){put(ln.slice(m.index),'c2');inBlock=true;pos=ln.length;break}put(ln.slice(m.index,e+2),'c2');pos=e+2;re.lastIndex=pos}
      else if(t.startsWith('//'))put(t,'c2');else if(t[0]==='"'||t[0]==="'")put(t,'s');else if(/^(0x|\d)/.test(t))put(t,'n');else if(KW.has(t))put(t,'k');else put(t)}
    put(ln.slice(pos));frag.append(row)});return frag}
function codeBox(sn){const box=E('div','code'),h=E('div','ch'),b=E('b'),cp=E('button','sm','Copy');
  b.textContent=(sn.lang==='java'?'Decompiled class ':'Decompiled function ')+sn.name;cp.type='button';cp.onclick=()=>copy(sn.text,cp);
  h.append(b,cp);const pre=E('pre');pre.append(hl(sn.text));if(sn.cut){const n=E('div','note','Cut at '+sn.text.length.toLocaleString('en')+' characters.');n.style.padding='0 12px';pre.append(n)}box.append(h,pre);return box}
function card(f){const c=E('div','card'),hd=E('button','hd'),bd=E('div','bd');c.id='f-'+f.id;hd.type='button';hd.setAttribute('aria-expanded','false');
  hd.append(E('span','caret'),E('span','id',f.id),E('span','tt',f.title));
  hd.append(E('span','pill '+(f.level==='byte-checked'?'b':'c'),f.level));if(f.disputed)hd.append(E('span','pill d','disputed'+(f.verdict?' · '+f.verdict:'')));
  hd.append(E('span','off',f.off!=null?hx(f.off):''));
  const lazy=()=>{if(bd.dataset.done)return;bd.dataset.done=1;
    if(f.value){const pv=E('pre','val',f.value);bd.append(pv)}
    const meta=[KINDS[f.kind]||f.kind,f.off!=null?`offset ${hx(f.off)}`+(f.len?`, ${f.len} bytes`:''):'no file offset',f.enc&&f.enc!=='text'?'encoding '+f.enc:'','found by '+(f.agents.map(a=>D.roles.find(r=>r.id===a).label).join(', ')||'agent'),'at '+mm(f.t)+' into the run'].filter(Boolean).join(' · ');
    bd.append(E('p','meta',meta));
    const ac=E('div','acts');
    if(f.off!=null){const m=E('button','sm','Show on map');m.type='button';m.onclick=()=>{select(f.id,{scroll:false});$('#s-map').scrollIntoView({behavior:reduce?'auto':'smooth',block:'start'})};
      const b=E('button','sm','Show bytes');b.type='button';b.onclick=()=>{select(f.id,{scroll:false,hex:true});$('#s-hex').scrollIntoView({behavior:reduce?'auto':'smooth',block:'start'})};ac.append(m,b)}
    if(f.value){const cp=E('button','sm','Copy value');cp.type='button';cp.onclick=()=>copy(f.value,cp);ac.append(cp)}
    bd.append(ac);if(f.snip!=null)bd.append(codeBox(D.snips[f.snip]))};
  const tog=(open)=>{c.classList.toggle('open',open);hd.setAttribute('aria-expanded',open);if(open)lazy()};
  hd.onclick=()=>{const o=!c.classList.contains('open');tog(o);if(o)select(f.id,{scroll:false,keepOpen:true})};
  c._open=()=>tog(true);c.append(hd,bd);return c}
const cardEl={};F.forEach(f=>cardEl[f.id]=card(f));
function paintCards(){const q=FS.q.toLowerCase();let L2=F.filter(f=>(!FS.ev||f.level===FS.ev)&&(!FS.kind||f.kind===FS.kind)&&(!FS.agent||f.agents.includes(FS.agent))&&(!q||(f.title+' '+f.value+' '+f.id).toLowerCase().includes(q)));
  if(FS.sort==='off')L2=L2.slice().sort((a,b)=>(a.off==null)-(b.off==null)||a.off-b.off);
  const box=$('#cards');box.textContent='';L2.forEach(f=>box.append(cardEl[f.id]));
  if(!L2.length)box.append(E('div','empty','No finding matches.'));
  $('#fcount').textContent=`${L2.length} of ${F.length} findings`}
$('#q').oninput=e=>{FS.q=e.target.value;paintCards()};$('#kind').onchange=e=>{FS.kind=e.target.value;paintCards()};$('#agent').onchange=e=>{FS.agent=e.target.value;paintCards()};$('#sort').onchange=e=>{FS.sort=e.target.value;paintCards()};
document.querySelectorAll('[data-ev]').forEach(b=>b.onclick=()=>{FS.ev=b.dataset.ev;document.querySelectorAll('[data-ev]').forEach(x=>x.setAttribute('aria-pressed',x===b));paintCards()});
function select(id,o){o=o||{};ST.sel=id;ST.ring=performance.now();document.querySelectorAll('.card.on').forEach(x=>x.classList.remove('on'));const c=cardEl[id];if(c){c.classList.add('on');if(!o.keepOpen)c._open()}
  const f=byId[id];if(f&&f.t>ST.T){ST.T=f.t;syncScrub()}
  if(o.hex&&f&&f.off!=null)showOffset(f.off,false);else if(f&&f.off!=null){const i=winFor(f.off);if(i>=0){ST.win=i;selByte=-1;drawHex()}}else drawHex();
  draw();if(o.scroll!==false&&c)c.scrollIntoView({block:'center',behavior:reduce?'auto':'smooth'})}
if(!F.length)$('#cards').append(E('div','empty','No findings were verified.'));else paintCards();
$('#fcount').textContent=F.length?`${F.length} of ${F.length} findings`:'';

/* ---- ATT&CK strip: a row per tactic of the domain in matrix order (all of them, so runs compare), a block per technique, byte-checked first, then call-cited;
   names and ids are tool-set; an id opens its finding card. Same layout as swAttStrip in swarmlabre's ui/index.html ---- */
function strip(A){
  const by=new Map(A.groups.map(g=>[g.id,g.items])),lv={b:new Set(),c:new Set()},rk=it=>(byId[it.fid]||{}).level==='byte-checked'?0:1,w=E('div');
  const u=Math.max(6,...A.groups.map(g=>g.items.length)),ul=E('ul','ast');
  A.tactics.forEach(([id,name])=>{
    const its=(by.get(id)||[]).slice().sort((a,b)=>rk(a)-rk(b)||a.tid.localeCompare(b.tid)),li=E('li',its.length?'':'z'),bar=E('span','asg'),ids=E('span','ids');
    bar.style.setProperty('--u',u);bar.setAttribute('aria-hidden','true');
    its.forEach(it=>{const k=rk(it)?'c':'b',lvl=(byId[it.fid]||{}).level||'',i=E('i',k),b=E('button','',it.tid);lv[k].add(it.fid);i.title=`${it.tid} ${it.name}, ${lvl}`;bar.append(i);
      b.type='button';b.title=`${it.name}, ${lvl}`;b.onclick=()=>select(it.fid,{hex:false});ids.append(b)});
    li.append(E('span','tn',name),bar,E('span','ct',its.length?String(its.length):''),ids);ul.append(li)});
  const lg=E('div','rlg'),itm=(c,t)=>{const s=E('span');s.append(E('i',c),document.createTextNode(t));return s},ot=A.groups.find(g=>g.id==='other');
  lg.append(itm('b',`Byte-checked ${lv.b.size}`),itm('c',`Call-cited ${lv.c.size}`));
  w.append(ul,lg,E('p','astn',`A row for each of the ${A.tactics.length} tactics, in matrix order, and a block for each technique under it (a technique under two tactics shows in both). An id opens its finding.${ot?` ${ot.items.length} technique${ot.items.length===1?'':'s'} without a tactic ${ot.items.length===1?'is':'are'} only in the list below.`:''}`));
  return w;
}

/* ---- ATT&CK: techniques by tactic; a row opens its finding card, "based on" opens the board findings it rests on ---- */
(function(){const A=D.attack,box=$('#attbox'),n=new Set();A.groups.forEach(g=>g.items.forEach(i=>n.add(i.fid)));
  $('#attlead').textContent=n.size?`${A.label}${A.version?' v'+A.version:''}: ${n.size} technique${n.size===1?'':'s'} under ${A.groups.length} tactic${A.groups.length===1?'':'s'}. Ids, names and tactics are MITRE's; swarmlabre checked each id against its table for this kind of file. The agents decide which techniques apply: the evidence level shows how the finding itself was backed, and "based on" opens the board findings it rests on.`:'No technique was verified.';
  if(A.lint.length){const w=E('div','note');w.append(E('b','','Ids in the summary that swarmlabre could not confirm: '),document.createTextNode(A.lint.join(' ')));box.append(w)}
  if(!n.size){box.append(E('div','empty','No technique was verified.'));return}
  if(A.tactics&&A.tactics.length)box.append(strip(A));
  A.groups.forEach(g=>{box.append((()=>{const h=E('h3','',g.name);h.append(E('span','',g.items.length+(g.items.length===1?' technique':' techniques')));return h})());
    g.items.forEach(it=>{const f=byId[it.fid]||{},row=E('div','ar'),b=E('button','tb');b.type='button';b.append(E('span','tid',it.tid),E('span','tn',it.name));
      b.onclick=()=>select(it.fid,{hex:false});row.append(b);
      row.append(E('span','pill '+(f.level==='byte-checked'?'b':'c'),f.level||''));if(f.disputed)row.append(E('span','pill d','disputed'+(f.verdict?' · '+f.verdict:'')));
      if(it.basis.length||it.nb){const bs=E('span','bs');bs.append(document.createTextNode('based on'));
        it.basis.forEach(i=>{const x=E('button','sm',i);x.type='button';x.onclick=()=>select(i,{hex:false});bs.append(x)});
        if(it.nb)bs.append(document.createTextNode(`${it.nb} not shown`));row.append(bs)}
      box.append(row)})})})();

/* ---- timeline ---- */
const DUR=Math.max(D.dur,1);
(function(){const tl=$('#tl');
  if(!D.tasks.length&&!D.ev.length){$('#s-tl').querySelector('.scrub').hidden=true;tl.append(E('div','empty','No timeline was recorded for this run.'));return}
  D.roles.forEach((r,i)=>{const mine=D.tasks.filter(t=>t[0]===i);if(!mine.length)return;
    const lab=E('div','lab'),sw=E('i','sw');sw.style.background=rcol(i);lab.append(sw,document.createTextNode(r.label));
    const lane=E('div','lane');mine.forEach(t=>{const s=E('div','span');s.style.left=(t[1]/DUR*100)+'%';s.style.width=Math.max((t[2]-t[1])/DUR*100,.4)+'%';s.style.background=rcol(i);s.title=`${r.label}, round ${t[3]}: ${mm(t[1])} to ${mm(t[2])}`;lane.append(s)});
    tl.append(lab,lane)});
  const lab=E('div','lab','Findings'),lane=E('div','lane');F.forEach(f=>{const m=E('div','fm');m.style.left=Math.min(f.t/DUR*100,99.7)+'%';m.title=f.id+' '+f.title;lane.append(m)});tl.append(lab,lane);
  const pl=E('div','ph');pl.id='ph';tl.append(pl);
  const tb=$('#ttab tbody');D.tasks.slice().sort((a,b)=>a[1]-b[1]).forEach(t=>{const tr=E('tr');tr.append(E('td','',D.roles[t[0]].label),E('td','',t[3]),E('td','mono',mm(t[1])),E('td','',dur(t[2]-t[1])),E('td','',t[6]),E('td','',t[5]),E('td','',t[4].replace(/_/g,' ')));tb.append(tr)})})();
function syncScrub(){const r=$('#rng');r.value=Math.round(ST.T/DUR*1000);$('#tlab').textContent=`${mm(ST.T)} of ${mm(DUR)} · ${F.filter(f=>f.t<=ST.T).length} findings`;
  const ph=$('#ph'),ln=document.querySelector('#tl .lane');if(ph&&ln)ph.style.left=(ln.offsetLeft+ST.T/DUR*ln.offsetWidth)+'px'}
$('#rng').oninput=e=>{stop();ST.T=e.target.value/1000*DUR;syncScrub();draw()};
let anim=0;
function stop(){anim=0;$('#play').textContent='Play'}
$('#play').onclick=()=>{if(anim){stop();return}
  if(reduce){ST.T=ST.T>=DUR?0:DUR;syncScrub();draw();return}
  if(ST.T>=DUR)ST.T=0;$('#play').textContent='Pause';const span=14000,start=performance.now(),from=ST.T/DUR;const id=anim=Math.random();
  (function step(now){if(anim!==id)return;const k=Math.min(from+(now-start)/span,1);ST.T=k*DUR;syncScrub();draw();if(k<1)requestAnimationFrame(step);else stop()})(start)};

/* ---- assessment and snapshot ---- */
(function(){const box=$('#asm'),A=CV.asm;
  if(!A){box.append(E('p','empty','The Reporter did not record an assessment for this run, so no verdict is given.'));return}
  const t=E('table','kv');[['Verdict',A.word],['Confidence',A.conf[0].toUpperCase()+A.conf.slice(1)],['Family or software',A.family||'Not identified']].forEach(([k,v])=>{const r=E('tr');r.append(E('th','',k),E('td','',v));t.append(r)});box.append(t);
  if(A.rationale){const q=E('div','quote',A.rationale);q.append(E('small','',"Reporter's reasoning. Model judgement: swarmlabre does not check this text."));box.append(q)}
  if(CV.basis.length){box.append(E('h4','','Based on'));const ul=E('ul');CV.basis.forEach(x=>ul.append(E('li','',x)));box.append(ul)}
  if(A.adjusted.length){box.append(E('h4','','Changes swarmlabre made'));const ul=E('ul');A.adjusted.forEach(x=>ul.append(E('li','',x)));box.append(ul)}
  box.append(E('p','note','Limits: static analysis only, the sample was never run, so behaviour is inferred from code and data and not observed. A benign verdict means nothing malicious was found, not that the file is safe.'))})();
(function(){const t=$('#snap');if(!CV.snapshot.length){$('#s-snap').hidden=true;return}
  CV.snapshot.forEach(x=>{const r=E('tr'),d=E('td',/^(MD5|SHA-1|SHA-256|Imphash|Package)$/.test(x.label)?'m':'',x.value);r.append(E('th','',x.label),d);t.append(r)})})();

/* ---- indicators: grouped by the Pyramid of Pain, defanged; the real values are in the CSV, STIX and MISP downloads of swarmlabre ---- */
(function(){const box=$('#iocs');$('#iocnote').textContent=CV.ioc_note||'';
  if(!CV.iocs.length){box.append(E('p','empty','No indicator was verified.'));return}
  CV.iocs.forEach(g=>{const h=E('div','ioch');h.append(E('h3','',g.label),E('span','',g.rows.length+(g.rows.length===1?' indicator':' indicators')));
    const cb=E('button','sm','Copy defanged');cb.type='button';cb.onclick=()=>copy(g.rows.map(r=>r.ind).join('\n'),cb);h.append(cb);box.append(h);
    const w=E('div','tscroll'),t=E('table','rtab'),th=E('thead'),hr=E('tr');['Type','Indicator','Context'].forEach(x=>hr.append(E('th','',x)));th.append(hr);t.append(th);
    const tb=E('tbody');g.rows.forEach(r=>{const tr=E('tr');tr.append(E('td','ty',r.type),E('td','ind',r.ind),E('td','cx',r.ctx));tb.append(tr)});t.append(tb);w.append(t);box.append(w)})})();

/* ---- detection engineering: YARA rules swarmlabre matched against its own copy of the sample; network strings carry \\xNN escapes here, swarmlabre's detection.yar holds the plain form ---- */
(function(){const box=$('#det'),d=CV.det;if(!d){$('#s-det').hidden=true;return}
  $('#detnote').textContent=d.rules.length?d.how:d.note;
  d.rules.forEach(r=>{const h=E('div','ioch');h.append(E('h3','',r.name),E('span','',r.n+' strings, at least '+r.need+' must be present'));
    const cb=E('button','sm','Copy rule');cb.type='button';cb.onclick=()=>copy(r.text,cb);h.append(cb);box.append(h);
    const pre=E('pre','yara');pre.textContent=r.text;box.append(pre)});
  if(d.rules.length)box.append(E('p','note',d.fp+' Network strings are written with \\xNN escapes in this page so that no real address is printed; the rule is the same. Swarmlabre offers detection.yar with the plain strings.'));
  if(d.skipped.length){const u=E('ul','');d.skipped.forEach(x=>u.append(E('li','',x[1]+': '+x[0])));box.append(E('p','note','Byte-checked strings left out:'),u)}})();

/* ---- footer ---- */
(function(){const f=$('#foot');
  [CV.tlp?`Handling. TLP:${CV.tlp}: ${CV.tlp_text}`:'',CV.org?`Prepared by ${CV.org}${CV.contact?' ('+CV.contact+')':''}${CV.date?', '+CV.date:''}. Produced by an automated agent swarm (${D.model||'model not recorded'}); no human has reviewed it unless a reviewer says so.`:'',
   `Left out of this file: ${C.unconfirmed} unconfirmed claim${C.unconfirmed===1?'':'s'} (neither byte-checked nor call-cited), ${C.rejected} finding${C.rejected===1?'':'s'} swarmlabre rejected${C.refuted?`, ${C.refuted} refuted`:''}, and the agents' working notes. The Markdown and JSON reports of the run list the unconfirmed claims as leads.`,
   `Static analysis only: the sample was never run. A byte-checked finding proves the bytes are there, not that an agent read them correctly. Strings, names and code shown here come from a possibly hostile file and are displayed as plain text.`,
   `Everything is in this one file: no script, font or image is loaded from anywhere.`,D.attack&&D.attack.notice?D.attack.notice:''].filter(Boolean).forEach(t=>f.append(E('p','',t)))})();

/* ---- start ---- */
function boot(){layout();draw()}
boot();drawHex();syncScrub();
let rt=0;addEventListener('resize',()=>{clearTimeout(rt);rt=setTimeout(()=>{const w=cv.parentElement.clientWidth;if(Math.abs(w-G.W)>G.cs){layout();draw()}syncScrub()},120)});
if(location.hash.startsWith('#f-')){const id=location.hash.slice(3);if(byId[id])select(id,{hex:true})}
</script></body></html>
'''
