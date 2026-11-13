"""The report validator and the notes cleaners the swarm uses, with the `swarmlabre-report/1` schema.

Stdlib only. Everything the validator needs is in this file.
"""
import json, re, time

from . import clock



MIB = 2**20


def json_depth(o):
    m, st = 0, [(o, 1)]
    while st:
        x, d = st.pop()
        m = max(m, d)
        if m >= 64:
            return m
        if isinstance(x, dict):
            st.extend((v, d + 1) for v in x.values() if isinstance(v, (dict, list)))
        elif isinstance(x, list):
            st.extend((v, d + 1) for v in x if isinstance(v, (dict, list)))
    return m


HIDDEN = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\u00ad\u061c\u2028\u2029\U000e0000-\U000e007f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+")


HIDDEN_NL = re.compile("[\\x00-\\x09\\x0b-\\x1f\\x7f-\\x9f\u00ad\u061c\u2028\u2029\U000e0000-\U000e007f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+")


KEY_RE = re.compile(r"[a-z0-9][a-z0-9:_-]{0,63}")


URL_BAD = re.compile(r"[\s\"'<>\\]")


MAX_REPORT = 4 * MIB


TONES = ("good", "bad", "mixed", "neutral", "low", "mid", "high")


SHAPES = ("circle", "square", "diamond", "ring", "home", "metro", "rail", "rent", "dot")


TAB_BLOCKS = ("kpis", "series", "table", "list", "facts", "callout", "text")   # what a tab may hold: no map, sources or nested tabs


class Rep:
    """One validation pass: cleans values against allowlists and records what it dropped or cut."""
    def __init__(self):
        self.issues = []

    def note(self, path, why):
        if len(self.issues) < 50:
            self.issues.append({"path": path, "reason": why})

    def str(self, v, cap, path="", nl=False):
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            self.note(path, "not text")
            return None
        t = (HIDDEN_NL if nl else HIDDEN).sub(" ", str(v)).strip()
        if len(t) > cap:
            self.note(path, f"cut to {cap} characters")
            t = t[:cap]
        return t

    def num(self, v, path="", lo=None, hi=None):
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
            self.note(path, "not a finite number")
            return None
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            self.note(path, "number out of range")
            return None
        return v

    def key(self, v, path=""):
        if isinstance(v, str) and KEY_RE.fullmatch(v):
            return v
        if v is not None:
            self.note(path, "bad id")
        return None

    def url(self, v, path=""):
        if isinstance(v, str) and v.startswith("https://") and len(v) <= 400 and not URL_BAD.search(v):
            return v
        if v is not None:
            self.note(path, "link dropped (https only)")
        return None

    def cap(self, lst, n, path):
        if not isinstance(lst, list):
            return []
        if len(lst) > n:
            self.note(path, f"cut to {n} items")
        return lst[:n]

    def obj(self, v, path):
        if isinstance(v, dict):
            return v
        if v is not None:
            self.note(path, "not an object")
        return {}

    def put(self, out, k, v):
        if v is not None and v != "" and v != []:
            out[k] = v

    def links(self, lst, path, n=12):
        out = []
        for i, l in enumerate(self.cap(lst, n, path)):
            l = self.obj(l, f"{path}[{i}]")
            u = self.url(l.get("url"), f"{path}[{i}].url")
            t = self.str(l.get("text"), 200, f"{path}[{i}].text") or ""
            if u or t:
                out.append({"url": u, "text": t} if u else {"text": t})
        return out

    def chips(self, lst, path):
        out = []
        for i, c in enumerate(self.cap(lst, 12, path)):
            c = self.obj(c, f"{path}[{i}]")
            t = self.str(c.get("text"), 60, f"{path}[{i}].text")
            if t:
                o = {"text": t}
                if c.get("tone") in TONES:
                    o["tone"] = c["tone"]
                out.append(o)
        return out

    def detail(self, d, path):
        d = self.obj(d, path)
        o = {}
        n = self.num(d.get("n"), path + ".n", 1, 999)
        self.put(o, "n", int(n) if n is not None else None)
        self.put(o, "title", self.str(d.get("title"), 160, path + ".title"))
        self.put(o, "subtitle", self.str(d.get("subtitle"), 200, path + ".subtitle"))
        self.put(o, "chips", self.chips(d.get("chips"), path + ".chips"))
        self.put(o, "text", self.str(d.get("text"), 1200, path + ".text", nl=True))
        facts = []
        for i, f in enumerate(self.cap(d.get("facts"), 16, path + ".facts")):
            f = self.obj(f, f"{path}.facts[{i}]")
            lab, t = self.str(f.get("label"), 80), self.str(f.get("text"), 200, f"{path}.facts[{i}].text")
            if t:
                facts.append({"label": lab or "", "text": t})
        self.put(o, "facts", facts)
        tl = self.obj(d.get("timeline"), path + ".timeline") if d.get("timeline") else {}
        items = []
        for i, it in enumerate(self.cap(tl.get("items"), 10, path + ".timeline.items")):
            it = self.obj(it, f"{path}.timeline.items[{i}]")
            t = self.str(it.get("text"), 240)
            if t:
                items.append({"date": self.str(it.get("date"), 40) or "", "text": t})
        if items:
            o["timeline"] = {"label": self.str(tl.get("label"), 80) or "", "items": items}
        lk = self.obj(d.get("links"), path + ".links") if d.get("links") else {}
        links = self.links(lk.get("items"), path + ".links.items")
        if links or lk.get("empty"):
            o["links"] = {"label": self.str(lk.get("label"), 80) or "", "items": links, "empty": self.str(lk.get("empty"), 200) or ""}
        self.put(o, "note", self.str(d.get("note"), 400, path + ".note"))
        return o

    def fig(self, f, path):
        """{value?, text} used by deltas and extras."""
        f = self.obj(f, path)
        o = {}
        self.put(o, "text", self.str(f.get("text"), 60, path + ".text"))
        v = self.num(f.get("value"), path + ".value")
        if v is not None:
            o["value"] = v
        self.put(o, "label", self.str(f.get("label"), 80))
        if f.get("good") in ("up", "down", "none"):
            o["good"] = f["good"]
        return o

    def kpi(self, k, path):
        k = self.obj(k, path)
        o = {}
        self.put(o, "id", self.key(k.get("id"), path + ".id"))
        self.put(o, "label", self.str(k.get("label"), 80, path + ".label"))
        v = self.num(k.get("value"), path + ".value")
        if v is not None:
            o["value"] = v
        self.put(o, "text", self.str(k.get("text"), 60, path + ".text"))
        self.put(o, "sub", self.str(k.get("sub"), 200, path + ".sub"))
        if k.get("tone") in TONES:
            o["tone"] = k["tone"]
        if k.get("kind") in ("money", "number", "count", "percent", "pp"):
            o["kind"] = k["kind"]
        if k.get("delta"):
            o["delta"] = self.fig(k["delta"], path + ".delta")
        ex = [self.fig(x, f"{path}.extra[{i}]") for i, x in enumerate(self.cap(k.get("extra"), 4, path + ".extra"))]
        self.put(o, "extra", [x for x in ex if x])
        sp = [self.num(x, path + ".spark") for x in self.cap(k.get("spark"), 60, path + ".spark")]
        self.put(o, "spark", [x for x in sp if x is not None])
        return o if (o.get("text") or "value" in o) else {}

    def cell(self, c, path):
        if c is None or isinstance(c, bool):
            return None
        if isinstance(c, str):
            return self.str(c, 400, path)
        if isinstance(c, (int, float)):
            return c if self.num(c, path) is not None else None
        c = self.obj(c, path)
        o = {}
        self.put(o, "text", self.str(c.get("text"), 400, path + ".text"))
        v = self.num(c.get("value"), path + ".value")
        if v is not None:
            o["value"] = v
        if c.get("tone") in TONES:
            o["tone"] = c["tone"]
        if c.get("dir") in ("up", "down", "mixed", "neutral"):
            o["dir"] = c["dir"]
        self.put(o, "sub", self.str(c.get("sub"), 800, path + ".sub"))
        self.put(o, "links", self.links(c.get("links"), path + ".links", 8))
        return o

    def listitem(self, it, path):
        it = self.obj(it, path)
        o = {}
        self.put(o, "key", self.key(it.get("key"), path + ".key"))
        n = self.num(it.get("n"), path + ".n", 1, 999)
        self.put(o, "n", int(n) if n is not None else None)
        self.put(o, "date", self.str(it.get("date"), 40))
        mk = self.obj(it.get("marker"), path + ".marker") if it.get("marker") else {}
        if mk.get("shape") in SHAPES or mk.get("tone") in TONES:
            o["marker"] = {k: mk[k] for k, ok in (("shape", SHAPES), ("tone", TONES)) if mk.get(k) in ok}
        self.put(o, "text", self.str(it.get("text"), 400, path + ".text"))
        self.put(o, "sub", self.str(it.get("sub"), 400, path + ".sub"))
        if it.get("detail"):
            o["detail"] = self.detail(it["detail"], path + ".detail")
        t = it.get("target")
        if isinstance(t, dict) and self.key(t.get("block")) and self.key(t.get("key")):
            o["target"] = {"block": t["block"], "key": t["key"]}
        return o if (o.get("text") or o.get("detail")) else {}

    def block(self, b, path):
        b = self.obj(b, path)
        t = b.get("type")
        o = {"type": t if isinstance(t, str) and re.fullmatch(r"[a-z_]{1,24}", t) else "unknown"}
        self.put(o, "id", self.key(b.get("id"), path + ".id"))
        self.put(o, "title", self.str(b.get("title"), 160, path + ".title"))
        if t == "kpis":
            o["items"] = [x for x in (self.kpi(k, f"{path}.items[{i}]") for i, k in enumerate(self.cap(b.get("items"), 16, path + ".items"))) if x]
        elif t == "series":
            self.series(b, o, path)
        elif t == "table":
            self.table(b, o, path)
        elif t == "list":
            o["style"] = b.get("style") if b.get("style") in ("numbered", "bullets", "dated") else "bullets"
            o["items"] = [x for x in (self.listitem(i, f"{path}.items[{n}]") for n, i in enumerate(self.cap(b.get("items"), 400, path + ".items"))) if x]
        elif t == "facts":
            items = []
            for i, f in enumerate(self.cap(b.get("items"), 24, path + ".items")):
                f = self.obj(f, f"{path}.items[{i}]")
                tx = self.str(f.get("text"), 200)
                if tx:
                    v = self.num(f.get("value"))
                    items.append(dict({"label": self.str(f.get("label"), 80) or "", "text": tx}, **({"value": v} if v is not None else {})))
            o["items"] = items
        elif t == "map":
            self.map(b, o, path)
        elif t == "callout":
            o["kind"] = b.get("kind") if b.get("kind") in ("note", "warning", "opinion") else "note"
            for k, cap in (("badge", 60), ("byline", 300), ("disclaimer", 600), ("empty", 300)):
                self.put(o, k, self.str(b.get(k), cap, f"{path}.{k}"))
            self.put(o, "text", self.str(b.get("text"), 6000, path + ".text", nl=True))
        elif t == "text":
            self.put(o, "text", self.str(b.get("text"), 6000, path + ".text", nl=True))
            if b.get("muted"):
                o["muted"] = True
        elif t == "sources":
            o["ids"] = [x for x in (self.key(i) for i in self.cap(b.get("ids"), 80, path + ".ids")) if x]
        elif t == "tabs":
            self.tabs(b, o, path)
        else:   # an unknown type: a quiet box with its title and a plain text
            o["type"] = "unknown"
            o["was"] = self.str(t, 24) or "?"
            self.put(o, "text", self.str(b.get("text"), 600, path + ".text"))
            self.note(path, "unknown block type")
        self.put(o, "empty", self.str(b.get("empty"), 300) if t not in ("callout",) else None)
        return o

    def tabs(self, b, o, path):
        """Up to 6 tabs of up to 16 blocks each. Only the block types in TAB_BLOCKS are kept, so tabs never nest and a map stays top level."""
        tabs = []
        for i, tb in enumerate(self.cap(b.get("tabs"), 6, path + ".tabs")):
            tb = self.obj(tb, f"{path}.tabs[{i}]")
            blocks = []
            for j, c in enumerate(self.cap(tb.get("blocks"), 16, f"{path}.tabs[{i}].blocks")):
                if isinstance(c, dict) and c.get("type") not in TAB_BLOCKS:
                    self.note(f"{path}.tabs[{i}].blocks[{j}]", "block type not allowed inside tabs")
                    continue
                blocks.append(self.block(c, f"{path}.tabs[{i}].blocks[{j}]"))
            tabs.append({"id": self.key(tb.get("id")) or f"tab{i}", "label": self.str(tb.get("label"), 40) or f"Tab {i + 1}", "blocks": blocks})
        o["tabs"] = tabs

    def series(self, b, o, path):
        o["x"] = b.get("x") if b.get("x") in ("month", "quarter", "date") else "month"
        yf = self.obj(b.get("y_format"), path + ".y_format") if b.get("y_format") else {}
        o["y_format"] = {"compact": bool(yf.get("compact")), "unit": self.str(yf.get("unit"), 20) or ""}
        o["legend"] = [{"line": self.key(l.get("line")) if isinstance(l, dict) else None, "text": self.str(l.get("text"), 120) or ""}
                       for l in self.cap(b.get("legend"), 16, path + ".legend") if isinstance(l, dict)]
        xs = re.compile(r"\d{4}-\d{2}(?:-\d{2})?|\d{4}-Q[1-4]|\d{4}-W\d{2}")
        lines = []
        for i, l in enumerate(self.cap(b.get("lines"), 8, path + ".lines")):
            l = self.obj(l, f"{path}.lines[{i}]")
            pts = []
            for j, p in enumerate(self.cap(l.get("points"), 600, f"{path}.lines[{i}].points")):
                if isinstance(p, list) and len(p) == 2 and isinstance(p[0], str) and xs.fullmatch(p[0]) and self.num(p[1]) is not None:
                    pts.append([p[0], p[1]])
                else:
                    self.note(f"{path}.lines[{i}].points[{j}]", "bad point")
            lines.append({"id": self.key(l.get("id")) or f"line{i}", "label": self.str(l.get("label"), 80) or "",
                          "role": l.get("role") if l.get("role") in ("main", "reference", "forecast", "compare") else "main",
                          "dots": bool(l.get("dots")), "points": pts})
        o["lines"] = lines
        bands = []
        for i, bd in enumerate(self.cap(b.get("bands"), 4, path + ".bands")):
            bd = self.obj(bd, f"{path}.bands[{i}]")
            pts = []
            for p in self.cap(bd.get("points"), 600, f"{path}.bands[{i}].points"):
                if isinstance(p, list) and len(p) == 3 and isinstance(p[0], str) and xs.fullmatch(p[0]) \
                        and self.num(p[1]) is not None and self.num(p[2]) is not None:
                    pts.append(p)
            bands.append({"id": self.key(bd.get("id")) or f"band{i}", "label": self.str(bd.get("label"), 80) or "",
                          "role": "compare" if bd.get("role") == "compare" else "forecast", "points": pts})
        o["bands"] = bands
        o["marks"] = [{"x": m["x"], "label": self.str(m.get("label"), 80) or ""} for m in self.cap(b.get("marks"), 16, path + ".marks")
                      if isinstance(m, dict) and isinstance(m.get("x"), str) and xs.fullmatch(m["x"])]

    def table(self, b, o, path):
        cols = []
        for i, c in enumerate(self.cap(b.get("columns"), 16, path + ".columns")):
            c = self.obj(c, f"{path}.columns[{i}]")
            cid = self.key(c.get("id"))
            if cid:
                cols.append({"id": cid, "label": self.str(c.get("label"), 80) or "", "align": "right" if c.get("align") == "right" else "left",
                             "wrap": bool(c.get("wrap"))})
        ids = {c["id"] for c in cols}
        rows = []
        for i, r in enumerate(self.cap(b.get("rows"), 800, path + ".rows")):
            r = self.obj(r, f"{path}.rows[{i}]")
            cells = {k: self.cell(v, f"{path}.rows[{i}].{k}") for k, v in self.obj(r.get("cells"), path).items() if k in ids}
            row = {"key": self.key(r.get("key")) or f"r{i}", "cells": {k: v for k, v in cells.items() if v is not None}}
            if r.get("detail"):
                row["detail"] = self.detail(r["detail"], f"{path}.rows[{i}].detail")
            rows.append(row)
        o["columns"], o["rows"] = cols, rows
        sh = self.num(b.get("shown"), path + ".shown", 0, 800)
        if sh is not None:
            o["shown"] = int(sh)

    def map(self, b, o, path):
        c = b.get("center")
        if not (isinstance(c, list) and len(c) == 2 and self.num(c[0], path + ".center", -90, 90) is not None
                and self.num(c[1], path + ".center", -180, 180) is not None):
            raise ReportInvalid(f"{path}: map without a valid center")
        o["center"] = [c[0], c[1]]
        o["radius_km"] = self.num(b.get("radius_km"), path + ".radius_km", 0.1, 50) or 2
        o["basemap"], o["buildings"] = bool(b.get("basemap", True)), bool(b.get("buildings", True))
        o["minor_streets"] = "always" if b.get("minor_streets") == "always" else "zoomed"
        o["rings"] = [{"km": r["km"], "text": self.str(r.get("text"), 20) or ""} for r in self.cap(b.get("rings"), 8, path + ".rings")
                      if isinstance(r, dict) and self.num(r.get("km"), path + ".rings", 0.05, 50) is not None]
        layers = [{"id": self.key(l.get("id")), "label": self.str(l.get("label"), 60) or "", "on": l.get("on", True) is not False}
                  for l in self.cap(b.get("layers"), 8, path + ".layers") if isinstance(l, dict) and self.key(l.get("id"))]
        o["layers"] = layers
        lid = {l["id"] for l in layers}
        near = lambda lat, lon: abs(lat - c[0]) <= 0.46 and abs(lon - c[1]) <= 0.72   # about 50 km
        pts, seen = [], set()
        for i, p in enumerate(self.cap(b.get("points"), 800, path + ".points")):
            p = self.obj(p, f"{path}.points[{i}]")
            lat, lon = self.num(p.get("lat"), "", -90, 90), self.num(p.get("lon"), "", -180, 180)
            if lat is None or lon is None or not near(lat, lon):
                self.note(f"{path}.points[{i}]", "location missing or too far from the center")
                continue
            k = self.key(p.get("key")) or f"p{i}"
            while k in seen:
                k += "-2"
            seen.add(k)
            q = {"key": k, "lat": lat, "lon": lon, "shape": p.get("shape") if p.get("shape") in SHAPES else "circle"}
            if isinstance(p.get("layer"), str) and p["layer"] in lid:
                q["layer"] = p["layer"]
            for f, cap in (("label", 80), ("hover", 200), ("glyph", 4), ("label_pos", 10)):
                self.put(q, f, self.str(p.get(f), cap, f"{path}.points[{i}].{f}"))
            if p.get("tone") in TONES:
                q["tone"] = p["tone"]
            n = self.num(p.get("n"), "", 1, 999)
            self.put(q, "n", int(n) if n is not None else None)
            px = self.num(p.get("px"), f"{path}.points[{i}].px", 8, 28)
            self.put(q, "px", px)
            if p.get("detail"):
                q["detail"] = self.detail(p["detail"], f"{path}.points[{i}].detail")
            pts.append(q)
        o["points"] = pts
        dots = []
        for d in self.cap(b.get("dots"), 600, path + ".dots"):
            if isinstance(d, dict):
                lat, lon = self.num(d.get("lat"), "", -90, 90), self.num(d.get("lon"), "", -180, 180)
                if lat is not None and lon is not None and near(lat, lon):
                    dots.append({"lat": lat, "lon": lon, "hover": self.str(d.get("hover"), 200) or "",
                                 **({"layer": d["layer"]} if isinstance(d.get("layer"), str) and d["layer"] in lid else {})})
        o["dots"] = dots
        o["legend"] = [{"shape": l.get("shape") if l.get("shape") in SHAPES else "circle", "tone": l.get("tone") if l.get("tone") in TONES else None,
                        "glyph": self.str(l.get("glyph"), 4) or "", "text": self.str(l.get("text"), 120) or ""} for l in self.cap(b.get("legend"), 16, path + ".legend") if isinstance(l, dict)]
        self.put(o, "list", self.key(b.get("list")))
        o["captions"] = [x for x in (self.str(t, 600) for t in self.cap(b.get("captions"), 8, path + ".captions")) if x]
        self.put(o, "hint", self.str(b.get("hint"), 200))


class ReportInvalid(Exception):
    pass


def validate_report(raw, run=None, producer=None):
    """(normalised report, issues). Raises ReportInvalid when the file cannot be used at all. Spec section 7.5.
    Any other failure on agent-written input is also ReportInvalid, never an internal error."""
    try:
        return _validate_report(raw, run, producer)
    except ReportInvalid:
        raise
    except Exception as ex:
        raise ReportInvalid(f"unusable structure ({type(ex).__name__})")


def _validate_report(raw, run=None, producer=None):
    if len(raw) > MAX_REPORT:
        raise ReportInvalid("over 4 MiB")
    try:
        d = json.loads(raw)
    except (ValueError, RecursionError):
        raise ReportInvalid("not valid JSON")
    if not isinstance(d, dict) or json_depth(d) > 16:
        raise ReportInvalid("not an object, or nested too deeply")
    m = re.fullmatch(r"swarmlabre-report/(\d+)", str(d.get("schema", "")))
    if not m:
        raise ReportInvalid("no schema field")
    if int(m.group(1)) != 1:
        raise ReportInvalid("made for a newer version")
    r = Rep()
    o = {"schema": "swarmlabre-report/1"}
    r.put(o, "title", r.str(d.get("title"), 160, "title"))
    r.put(o, "subtitle", r.str(d.get("subtitle"), 200, "subtitle"))
    o["meta"] = [{"label": r.str(x.get("label"), 80) or "", "text": r.str(x.get("text"), 200) or ""} for x in r.cap(d.get("meta"), 12, "meta")
                 if isinstance(x, dict) and x.get("text")]
    r.put(o, "period", r.str(d.get("period"), 20, "period"))
    r.put(o, "generated_at", r.str(d.get("generated_at"), 40))
    r.put(o, "hero", r.key(d.get("hero")))
    o["kpis"] = [x for x in (r.kpi(k, f"kpis[{i}]") for i, k in enumerate(r.cap(d.get("kpis"), 16, "kpis"))) if x]
    nt = r.obj(d.get("notes"), "notes") if d.get("notes") else {}
    o["notes"] = {"label": r.str(nt.get("label"), 80) or "Notes", "items": [x for x in (r.str(t, 300) for t in r.cap(nt.get("items"), 40, "notes.items")) if x],
                  "empty": r.str(nt.get("empty"), 120) or ""}
    secs = []
    for i, sct in enumerate(r.cap(d.get("sections"), 32, "sections")):
        sct = r.obj(sct, f"sections[{i}]")
        sid = r.key(sct.get("id")) or f"s{i}"
        blocks = [r.block(b, f"sections[{i}].blocks[{j}]") for j, b in enumerate(r.cap(sct.get("blocks"), 24, f"sections[{i}].blocks"))]
        secs.append({"id": sid, "title": r.str(sct.get("title"), 160) or "", "intro": r.str(sct.get("intro"), 600) or "", "blocks": blocks,
                     "captions": [x for x in (r.str(t, 600) for t in r.cap(sct.get("captions"), 8, f"sections[{i}].captions")) if x]})
    o["sections"] = secs
    if sum(1 for s_ in secs for b in s_["blocks"] if b["type"] == "map") > 4:
        raise ReportInvalid("more than 4 map blocks")
    bids = {b["id"] for s_ in secs for b in s_["blocks"] if b.get("id")}
    for s_ in secs:      # a list or target that names nothing is dropped
        for b in s_["blocks"]:
            if b["type"] == "map" and b.get("list") and b["list"] not in bids:
                del b["list"]
                r.note(b.get("id", "map"), "list names no block")
            if b["type"] == "list":
                for it in b["items"]:
                    if it.get("target") and it["target"]["block"] not in bids:
                        del it["target"]
    srcs = []
    for i, x in enumerate(r.cap(d.get("sources"), 80, "sources")):
        x = r.obj(x, f"sources[{i}]")
        sid = r.key(x.get("id"))
        if sid:
            u = r.url(x.get("url"), f"sources[{i}].url")
            srcs.append({"id": sid, "title": r.str(x.get("title"), 160) or "", "text": r.str(x.get("text"), 300) or "", **({"url": u} if u else {})})
    o["sources"] = srcs
    r.put(o, "sources_text", r.str(d.get("sources_text"), 1500, "sources_text"))
    r.put(o, "disclaimer", r.str(d.get("disclaimer"), 600, "disclaimer"))
    par = ((d.get("_build") or {}).get("parity") if isinstance(d.get("_build"), dict) else None)
    if isinstance(par, dict):
        miss = [{"section": r.str(x.get("section"), 40) or "", "token": r.str(x.get("token"), 120) or ""} for x in (par.get("missing") if isinstance(par.get("missing"), list) else [])[:20]
                if isinstance(x, dict)]
        o["_build"] = {"producer": r.str((d.get("_build") or {}).get("producer"), 80) or "", "parity": {"ok": par.get("ok") is True,
                       "checked": int(par["checked"]) if isinstance(par.get("checked"), int) else 0, "missing": miss}}
    o["_issues"] = r.issues
    o["_swarmlabre"] = {"run": run, "producer": producer, "validated_at": clock.now()}
    return o, r.issues


# Markers of the wrapper format another tool used around hand-off notes. A model could imitate them to make its text look like such a wrapper, so they are cut out of the notes.
RELAY_MARK = re.compile(r"<<<RELAY-(?:NOTES|CHECK)[^\n]*|RELAY-(?:NOTES|CHECK)>>>")


MAX_NOTES_RAW, MAX_NOTES = 64 * 1024, 16 * 1024


def clean_notes(text, cap=MAX_NOTES):
    """Agent-written notes as swarmlabre keeps them: control, bidi and zero-width characters out (tab and newline stay), `\\r`
    dropped, the wrapper markers of the next leg's prompt removed, capped."""
    t = str(text).replace("\r\n", "\n").replace("\r", "")
    t = RELAY_MARK.sub("[marker removed]", HIDDEN.sub(" ", t)).strip()
    b = t.encode("utf-8")
    if len(b) > cap:
        t = b[:cap].decode("utf-8", "ignore").rstrip() + f"\n(cut at {cap // 1024} KiB)"
    return t + "\n" if t else ""


NOTES_TRIM = ("tried", "dead", "files", "state", "suspicion")      # trimmed first to last, from the end of each section


def trim_notes(text, cap=MAX_NOTES):
    """Fit cleaned notes into `cap` bytes without losing the end: a plain tail cut drops Next ideas first, because the
    agent writes it near the end. Sections are trimmed in NOTES_TRIM order (each cut to half, at least 300 bytes, a marker
    left); Plan and Next ideas are kept whole. Text that still does not fit is cut at the tail as before."""
    t = str(text)
    if len(t.encode("utf-8")) <= cap:
        return t
    parts = re.split(r"(?m)^(?=## )", t)
    def size():
        return sum(len(x.encode("utf-8")) for x in parts)
    for key in NOTES_TRIM:
        for i, x in enumerate(parts):
            if size() <= cap:
                break
            if not x.lower().startswith("## " + key):
                continue
            head, _, body = x.partition("\n")
            b = body.encode("utf-8")
            if len(b) <= 300:
                continue
            keep = max(300, len(b) // 2)
            parts[i] = head + "\n" + b[:keep].decode("utf-8", "ignore").rstrip() + "\n(trimmed by swarmlabre to fit)\n\n"
    t = "".join(parts)
    return clean_notes(t, cap) if len(t.encode("utf-8")) > cap else t
