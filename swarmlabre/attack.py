"""MITRE ATT&CK lookups for Agent Swarms (stdlib only).

The table is data/attack.json, built from MITRE's STIX bundles by tools/build-attack-table.py: every technique and sub-technique that is neither revoked
nor deprecated, for the Enterprise matrix (ELF and PE samples) and the Mobile matrix (APK samples), plus the retired ids (`replaced`: old id -> new id,
`deprecated`: no successor). The board uses it to check a technique finding: the id must exist for the kind of file, the name the agent wrote must be
MITRE's name for that id (an id written from memory with the wrong name is rejected, not silently corrected), and the name and tactics shown in the
report are MITRE's, never the agent's wording.

The match rules (`name_matches`, `search`) are mirrored in skills/rea-swarm/scripts/swarm-post and swarm-attack, which work from /prep/attack.tsv inside
the agent container: keep the three in step. Swarmlabre is the authority; the scripts only let an agent find out before it posts.
"""
import json
import os
import re
import threading

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "attack.json")
ID_RE = re.compile(r"\s*(T\d{4}(?:\.\d{3})?)(?!\w)(?!\.\d)")      # an id at the start of a title or value: "T1059.001 PowerShell"
ANY_ID_RE = re.compile(r"(?<![\w.])(T\d{4}(?:\.\d{3})?)(?!\w)(?!\.\d)")
STOP = frozenset(("a", "an", "and", "or", "of", "the", "to", "for", "via", "in", "on", "with"))
_lock = threading.Lock()
_data = None


def _load():
    global _data
    with _lock:
        if _data is None:
            try:
                with open(PATH) as f:
                    d = json.load(f)
                dom = {}
                for k in ("enterprise", "mobile"):
                    x = d["domains"][k]
                    dom[k] = {"tactics": [(a, b) for a, b in x["tactics"]], "techniques": {i: (v[0], tuple(v[1])) for i, v in x["techniques"].items()},
                              "replaced": dict(x.get("replaced", {})), "deprecated": set(x.get("deprecated", []))}
                _data = {"version": str(d.get("version", "")), "notice": str(d.get("notice", "")), "domains": dom}
            except (OSError, ValueError, KeyError, TypeError, IndexError):
                _data = {}
        return _data


def _dom(domain):
    return _load().get("domains", {}).get(domain, {})


def available():
    return bool(_load())


def version():
    return _load().get("version", "")


def notice():
    return _load().get("notice", "")


def domain_of(sample_kind):
    """The matrix that fits a sample: APKs use Mobile ATT&CK, ELF and PE use Enterprise."""
    return "mobile" if sample_kind == "apk" else "enterprise"


def label(domain):
    return "ATT&CK for Mobile" if domain == "mobile" else "ATT&CK for Enterprise"


def parse_id(text):
    """The technique id a title or value starts with, or None."""
    m = ID_RE.match(text) if isinstance(text, str) else None
    return m.group(1) if m else None


def name_after_id(text):
    """What follows a leading id in a title ("T1059.001 PowerShell" -> "PowerShell"), without separators."""
    m = ID_RE.match(text) if isinstance(text, str) else None
    return text[m.end():].strip(" \t:-–—()[]") if m else ""


def tactics(domain):
    """[(shortname, name)] in matrix order."""
    return list(_dom(domain).get("tactics", []))


def tactic_name(domain, short):
    return dict(tactics(domain)).get(short, short)


def lookup(domain, tid):
    """-> {"id", "name", "tactics": [{"id", "name"}], "domain"} for a technique of that matrix, else None."""
    t = _dom(domain).get("techniques", {}).get(tid)
    if not t:
        return None
    names = dict(tactics(domain))
    return {"id": tid, "name": t[0], "tactics": [{"id": s, "name": names.get(s, s)} for s in t[1]], "domain": domain}


def known_elsewhere(domain, tid):
    """True when the id exists in the other matrix only (an Enterprise id on an APK, or the reverse)."""
    other = "enterprise" if domain == "mobile" else "mobile"
    return tid in _dom(other).get("techniques", {}) and lookup(domain, tid) is None


def retired(domain, tid):
    """A retired id of that matrix: {"id": successor id or None, "name": successor name or ""}, else None."""
    d = _dom(domain)
    new = d.get("replaced", {}).get(tid)
    if new and new in d.get("techniques", {}):
        return {"id": new, "name": d["techniques"][new][0]}
    if tid in d.get("deprecated", ()):
        return {"id": None, "name": ""}
    return None


def _tokens(s):
    return [w for w in re.findall(r"[a-z0-9]+", str(s).lower()) if w not in STOP]


def name_matches(domain, tid, name):
    """Is `name` MITRE's name for the technique `tid`? Accepts the full name ("Process Injection: Process Hollowing"), the sub-technique part
    ("Process Hollowing") or the parent's name, with small wording differences: same words (Jaccard 0.6 or more), or at least two words that all occur
    in MITRE's name ("Run Keys")."""
    t = _dom(domain).get("techniques", {}).get(tid)
    mine = set(_tokens(name))
    if not t or not mine:
        return False
    full = t[0]
    cands = {full}
    if ": " in full:
        cands.add(full.split(": ", 1)[1])
        cands.add(full.split(": ", 1)[0])
    for c in cands:
        ct = set(_tokens(c))
        if ct and (len(mine & ct) / len(mine | ct) >= 0.6 or (len(mine) >= 2 and mine <= ct)):
            return True
    return False


def search(domain, query, limit=6, skip=(), ratio=0.0):
    """Techniques whose name or tactic shares words with `query`, best first: [{"id", "name", "tactics"}]. A query word counts when it is a prefix of a name word
    (or the other way round, from 4 letters), so "keylog" finds Keylogging. `ratio` keeps only results scoring at least that share of the best one."""
    q = _tokens(query)
    if not q:
        return []
    d = _dom(domain)
    tn = dict(d.get("tactics", []))
    out = []
    for i, (name, tac) in d.get("techniques", {}).items():
        if i in skip:
            continue
        words = _tokens(name) + _tokens(" ".join(tn.get(x, x) for x in tac))
        nw = set(_tokens(name))
        sc = sum((2 if w in nw else 1) for w in q if any(x == w or (len(w) >= 4 and (x.startswith(w) or (len(x) >= 4 and w.startswith(x)))) for x in words))
        if sc:
            out.append((-sc, "." in i, i, name, tac))
    out.sort()
    if out and ratio:
        out = [r for r in out if -r[0] >= ratio * -out[0][0]]
    return [{"id": i, "name": n, "tactics": [tn.get(x, x) for x in t]} for _s, _sub, i, n, t in out[:limit]]


def hint(domain, tid, name=""):
    """A short sentence built only from MITRE's table (never from agent text) for a rejected technique post: what the id is, or what to use instead."""
    r = retired(domain, tid) if tid else None
    t = lookup(domain, tid) if tid else None
    if t:
        near = search(domain, name, 3, skip=(tid,), ratio=0.6)
        s = "%s is MITRE's '%s'." % (tid, t["name"])
        if near:
            s += " Closest to the name you wrote: " + "; ".join("%s %s" % (x["id"], x["name"]) for x in near) + "."
        return s[:400]
    if r and r["id"]:
        return ("%s was retired in ATT&CK v%s; MITRE replaced it with %s '%s'." % (tid, version(), r["id"], r["name"]))[:400]
    if r:
        return "%s was retired in ATT&CK v%s with no replacement." % (tid, version())
    near = search(domain, name, 3, ratio=0.6)
    if tid and known_elsewhere(domain, tid):
        return ("%s is an id of the other ATT&CK matrix, not of %s." % (tid, label(domain)) + ((" Closest here: " + "; ".join("%s %s" % (x["id"], x["name"]) for x in near) + ".") if near else ""))[:400]
    return ("No such id in %s." % label(domain) + ((" Closest by name: " + "; ".join("%s %s" % (x["id"], x["name"]) for x in near) + ".") if near else ""))[:400]


FOLLOW_RE = re.compile(r"[\s:(\u2013\u2014-]{1,4}([A-Z][A-Za-z/&'-]*(?: [A-Za-z/&'-]+){0,6})")


def lint_text(domain, text, cap=8):
    """Ids named in free text (the Reporter's summary): [(id, code, sentence)] for an id that is unknown or retired, or that is followed at once by a capitalised
    phrase that is not MITRE's name for it. The sentences hold only the id and MITRE's table text, never the agent's words. At most `cap`."""
    out, seen = [], set()
    if not _load():
        return out
    text = text or ""
    for m in ANY_ID_RE.finditer(text):
        tid = m.group(1)
        if tid in seen:
            continue
        seen.add(tid)
        t = lookup(domain, tid)
        if not t:
            h = hint(domain, tid)
            out.append((tid, "unknown", h if h.startswith(tid) else "%s: %s" % (tid, h)))
        else:
            f = FOLLOW_RE.match(text, m.end())
            words = f.group(1).split() if f else []
            if words and not any(name_matches(domain, tid, " ".join(words[:n])) for n in range(1, len(words) + 1)):
                out.append((tid, "name", "The summary puts %s next to a different name than MITRE's '%s'." % (tid, t["name"])))
        if len(out) >= cap:
            break
    return out


def catalogue(domain):
    """The current top-level techniques, once each under the first tactic they belong to, as prompt text (sub-techniques are found with swarm-attack)."""
    d = _dom(domain)
    if not d:
        return ""
    names = dict(d["tactics"])
    by = {}
    for i, (name, tac) in d["techniques"].items():
        if "." not in i and tac:
            by.setdefault(tac[0], []).append("%s %s" % (i, name))
    order = [a for a, _n in d["tactics"]]
    return "\n".join("%s: %s" % (names[t], "; ".join(by[t])) for t in order if t in by)


def tsv(domain):
    """The lookup file the agents search (tool-written, MITRE text only): current techniques as `id, name, tactics`, then retired ids as `id, RETIRED: ...`."""
    d = _dom(domain)
    names = dict(d.get("tactics", []))
    head = ("# %s, v%s. Columns: id, name, tactics. A technique finding's title is the id followed by the name from this file. Lines marked RETIRED are old ids: "
            "use the id they name.\n" % (label(domain), version()))
    rows = "".join("%s\t%s\t%s\n" % (i, v[0], ", ".join(names.get(s, s) for s in v[1])) for i, v in d.get("techniques", {}).items())
    old = "".join("%s\tRETIRED: use %s %s\t\n" % (o, n, d["techniques"][n][0]) for o, n in sorted(d.get("replaced", {}).items()) if n in d.get("techniques", {}))
    old += "".join("%s\tRETIRED: no replacement\t\n" % o for o in sorted(d.get("deprecated", ())))
    return head + rows + old
