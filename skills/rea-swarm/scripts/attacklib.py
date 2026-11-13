"""ATT&CK lookups for swarm-post and swarm-attack, from /prep/attack.tsv (written by swarmlabre from MITRE's data; stdlib only).

The match rules mirror attack.py in swarmlabre (name_matches, search, hint). Swarmlabre is the authority and checks every technique again; these let an agent find
out BEFORE it posts. Keep the two in step by hand: no automated parity test compares them yet.
"""
import re

PATH = "/prep/attack.tsv"
ID_RE = re.compile(r"\s*(T\d{4}(?:\.\d{3})?)(?!\w)(?!\.\d)")
STOP = frozenset(("a", "an", "and", "or", "of", "the", "to", "for", "via", "in", "on", "with"))


def load(path=PATH):
    """-> (current {id: (name, tactics text)}, retired {id: 'use T1685 Name' | 'no replacement'}), or None when the file is not there."""
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return None
    cur, old = {}, {}
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue
        c = ln.split("\t")
        if len(c) < 2 or not re.fullmatch(r"T\d{4}(\.\d{3})?", c[0]):
            continue
        if c[1].startswith("RETIRED: "):
            old[c[0]] = c[1][9:]
        else:
            cur[c[0]] = (c[1], c[2] if len(c) > 2 else "")
    return (cur, old) if cur else None


def parse_id(text):
    m = ID_RE.match(text or "")
    return m.group(1) if m else None


def name_after_id(text):
    m = ID_RE.match(text or "")
    return text[m.end():].strip(" \t:-–—()[]") if m else ""


def tokens(s):
    return [w for w in re.findall(r"[a-z0-9]+", str(s).lower()) if w not in STOP]


def name_matches(cur, tid, name):
    t = cur.get(tid)
    mine = set(tokens(name))
    if not t or not mine:
        return False
    cands = {t[0]}
    if ": " in t[0]:
        cands.update(t[0].split(": ", 1))
    for c in cands:
        ct = set(tokens(c))
        if ct and (len(mine & ct) / len(mine | ct) >= 0.6 or (len(mine) >= 2 and mine <= ct)):
            return True
    return False


def search(cur, query, limit=6, skip=(), ratio=0.0):
    q = tokens(query)
    if not q:
        return []
    out = []
    for i, (name, tac) in cur.items():
        if i in skip:
            continue
        words = tokens(name) + tokens(tac)
        nw = set(tokens(name))
        sc = sum((2 if w in nw else 1) for w in q if any(x == w or (len(w) >= 4 and (x.startswith(w) or (len(x) >= 4 and w.startswith(x)))) for x in words))
        if sc:
            out.append((-sc, "." in i, i, name, tac))
    out.sort()
    if out and ratio:
        out = [r for r in out if -r[0] >= ratio * -out[0][0]]
    return out[:limit]


def fmt(rows):
    return "; ".join("%s %s" % (i, n) for _s, _sub, i, n, _t in rows)


def replacement(old, tid):
    """For a retired id, the (id, name) it points to, else None."""
    m = re.match(r"use (T\d{4}(?:\.\d{3})?) (.*)", old.get(tid, ""))
    return (m.group(1), m.group(2)) if m else None


def problem(table, title):
    """Why a technique title would be rejected by swarmlabre, as one sentence for the agent, or '' when it is fine."""
    cur, old = table
    tid = parse_id(title)
    name = name_after_id(title) if tid else title
    if not tid:
        near = search(cur, name, 3, ratio=0.6)
        return "the title must start with an ATT&CK id and its name, for example 'T1059 Command and Scripting Interpreter'." + (" Closest by name: " + fmt(near) + "." if near else "")
    if tid in cur:
        if name and name_matches(cur, tid, name):
            return ""
        near = search(cur, name, 3, skip=(tid,), ratio=0.6)
        return "%s is MITRE's '%s'%s." % (tid, cur[tid][0], ("; closest to the name you wrote: " + fmt(near)) if near else "") + ("" if name else " Write the title as '%s %s'." % (tid, cur[tid][0]))
    if tid in old:
        r = replacement(old, tid)
        if r and name and name_matches(cur, r[0], name):
            return ""
        return "%s was retired%s." % (tid, (" and replaced by %s '%s'" % r) if r else " with no replacement")
    near = search(cur, name, 3, ratio=0.6)
    return "%s is not an id in this ATT&CK matrix.%s" % (tid, (" Closest by name: " + fmt(near) + ".") if near else "")
