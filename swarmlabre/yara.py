"""Tool-verified YARA rules for Agent Swarms (stdlib only).

Swarmlabre holds its own copy of the sample, so it can write a rule from strings it has already byte-checked (an `ioc`, `crypto` or `config` finding with an offset: the bytes at
that offset are the value) and then prove the rule matches that sample before anyone sees it. There is no `yara` binary and no pip in the images, so the proof is made by OUR matcher
in this file, which reads back the rule text that was written (not the structures it was built from) and searches the sample for its strings. The matcher implements only the
subset of YARA that the generator emits: `ascii`/`wide` text strings, hex strings without wildcards, and a condition of `uint16(0)`/`uint32(0)` == magic, `filesize < N KB|MB` and
`K of them` / `all of them` / `any of them`. Anything else is a syntax error, on purpose. `tools/check-yara.py` is an independent, stricter check of a rule file.

Rule text is built from tool-checked values only: the string values are the bytes found in the file (printable ASCII goes out as an escaped text string, anything else as a hex
string), the metadata is fixed wording plus the configured organisation name. No agent `detail`, title, note or prose ever enters a rule.
"""
import math
import re

MIB = 1 << 20
RESERVED = frozenset("all and any ascii at base64 base64wide condition contains endswith entrypoint false filesize for fullword global import icontains iendswith iequals in include int16 int16be "
                     "int32 int32be int8 int8be istartswith matches meta nocase none not of or private private rule startswith strings them true uint16 uint16be uint32 uint32be uint8 uint8be "
                     "wide xor defined".split())
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
META_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
MAGIC = {"pe": ("uint16(0) == 0x5a4d", b"MZ"), "elf": ("uint32(0) == 0x464c457f", b"\x7fELF"), "apk": ("uint32(0) == 0x04034b50", b"PK\x03\x04")}
KIND_WORD = {"pe": "Windows PE", "elf": "Linux ELF", "apk": "Android APK"}

# ---- what is too generic to hunt with (strict profile, decided with the owner 2026-10-21)
MIN_LEN = 8                    # characters (text) or bytes (hex)
MIN_STRINGS = 4                # distinct strings per rule
MAX_STRINGS = 40               # per rule
MIN_HEX = 12                   # bytes in a hex string (8-byte constants and file magics are in every clean file that has the feature)
MAX_VALUE = 128                # a longer value is cut to its first 128 characters (a prefix of a string in the file is still in the file)
NEED_DIV = 3                   # a rule needs max(3, ceil(n / 3)) of its n strings
DOC_HOSTS = ("gnu.org", "apache.org", "w3.org", "mozilla.org", "openssl.org", "python.org", "wikipedia.org", "ietf.org", "creativecommons.org", "opensource.org", "schemas.microsoft.com",
             "schemas.android.com", "xmlsoap.org", "purl.org", "sourceforge.net", "docs.microsoft.com", "learn.microsoft.com", "msdn.microsoft.com", "developer.android.com", "www.microsoft.com",
             "microsoft.com", "unicode.org", "iana.org", "rfc-editor.org", "example.com", "example.org", "localhost")
COMMON_PREFIX = ("system.", "microsoft.", "windows.", "mscorlib", "get_", "set_", "add_", "remove_", "op_", "glibc_", "_zn", "__cxa", "__gxx", "std::", "kernel32", "user32", "ntdll", "advapi32",
                 "ws2_32", "shell32", "msvcr", "api-ms-win", "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "com.google.android", "com.android.", "org.apache.", "okhttp",
                 "__")
COMMON_SUB = ("currentversion\\run", "currentversion\\policies", "\\microsoft\\windows\\currentversion", "licen", "copyright", "warranty", "free software", "gnu general", "all rights reserved",
              "gnu lesser", "permission is hereby granted")
MAGICS = (b"\x89PNG", b"PK\x03\x04", b"MZ", b"\x7fELF", b"GIF8", b"%PDF", b"\xff\xd8\xff", b"Rar!", b"7z\xbc\xaf", b"\x1f\x8b", b"BM", b"RIFF", b"OggS", b"\xca\xfe\xba\xbe")
ALPHABETS = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
             "abcdefghijklmnopqrstuvwxyz0123456789", "0123456789abcdefghijklmnopqrstuvwxyz")
UNIX_SYS = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/", "/dev/", "/proc/", "/sys/", "/var/", "/opt/", "/run/")
SKIP_TEXT = {"short": "shorter than %d characters (hex strings: %d bytes)" % (MIN_LEN, MIN_HEX), "word": "a plain word", "prose": "ordinary prose", "path": "a system or library path", "docurl": "a documentation, licence or schema address",
             "common": "a common library, runtime or licence string", "plain": "too little variety", "format": "a format string with no fixed text", "version": "a version number or number list",
             "overlap": "overlaps a string already chosen", "dup": "the same bytes as a string already chosen", "cap": "over the %d-string limit" % MAX_STRINGS,
             "off": "the bytes at its offset did not match when swarmlabre looked again", "wide": "a wide string that needs non-ASCII characters"}


class YaraError(ValueError):
    pass


def _subseq(v, a):
    it = iter(a)
    return all(c in it for c in v)


def generic(v):
    """None when a text value is specific enough to hunt with, else a key of SKIP_TEXT."""
    if len(v) < MIN_LEN:
        return "short"
    low = v.lower()
    if len(set(v)) <= 3 or (len(set(v)) == len(v) and any(_subseq(v, a) for a in ALPHABETS)):     # "aaaa", "0123456789abcdef": a table of digits or letters, not a fingerprint
        return "plain"
    if re.fullmatch(r"[\d.,:;\s-]+", v):
        return "version"
    if any(low.startswith(p) for p in COMMON_PREFIX) and re.fullmatch(r"[\w.:<>$`-]+", v):
        return "common"
    if any(s in low for s in COMMON_SUB):
        return "common"
    if re.search(r"\.so(\.\d+)*\Z", v) and "/" not in v[:1]:
        return "common"
    m = re.match(r"(?i)[a-z][a-z0-9+.-]*://(?:[^/@]*@)?([^/:?#\s]+)", v)
    if m:
        h = m.group(1).lower()
        if any(h == d or h.endswith("." + d) for d in DOC_HOSTS):
            return "docurl"
    if v.startswith(UNIX_SYS):
        return "path"
    if re.fullmatch(r"[A-Za-z]{1,12}", v):
        return "word"
    if re.fullmatch(r"[A-Za-z][A-Za-z ,.'!?-]*", v) and " " in v.strip():
        return "prose"
    if len(re.sub(r"[^A-Za-z]+", "", re.sub(r"%[\w.]+", "", v))) < 4:
        return "format"
    return None


def _esc(v, harden=False):
    v = v.replace("\\", "\\\\").replace('"', '\\"')
    return re.sub(r"[.:@]", lambda m: "\\x%02x" % ord(m.group()), v) if harden else v


def _printable(v):
    return all(32 <= ord(c) < 127 for c in v)


def want_bytes(f):
    """The bytes a byte-checked finding stands for (the same decoding the board used)."""
    try:
        v = f["value"]
        e = f.get("enc", "text")
        return {"text": lambda: v.encode("utf-8"), "utf16le": lambda: v.encode("utf-16-le"), "hex": lambda: bytes.fromhex(re.sub(r"0x|[\s:]", "", v))}[e]()
    except (ValueError, UnicodeError, KeyError):
        return None


def candidates(findings, read_at, classify=None, kind=None):
    """(chosen, skipped): chosen = [{id, fid, group, mod, text, data, off, level}] ordered by value, skipped = {reason key: count}. `read_at(off, n)` reads swarmlabre's own copy of the sample."""
    skipped, raw = {}, []

    def skip(k):
        skipped[k] = skipped.get(k, 0) + 1
    for f in findings:
        if f.get("status") != "verified" or f.get("level") != "byte-checked" or f.get("kind") not in ("ioc", "crypto", "config") or not isinstance(f.get("off"), int):
            continue
        data = want_bytes(f)
        if not data:
            continue
        if read_at(f["off"], len(data)) != data:             # the board checked it once; swarmlabre looks again, since a rule is only as good as these bytes
            skip("off")
            continue
        enc = f.get("enc", "text")
        c = classify(f["value"], kind) if classify and enc != "hex" else None
        grp = c["group"] if c else None
        if enc == "hex":
            if len(data) < MIN_HEX:
                skip("short")
                continue
            if len(set(data)) <= 2 or data.startswith(MAGICS):
                skip("plain")
                continue
            raw.append({"fid": f["id"], "group": "crypto", "mod": "hex", "data": data, "text": None, "off": f["off"], "level": f["level"], "fkind": f["kind"]})
            continue
        v = f["value"][:MAX_VALUE]
        why = generic(v)
        if why:
            skip(why)
            continue
        if enc == "utf16le":
            if not _printable(v):
                # YARA's `wide` is ASCII with zero bytes between: other characters go out as a hex string of the UTF-16 bytes
                raw.append({"fid": f["id"], "group": grp or f["kind"], "mod": "hex", "data": v.encode("utf-16-le"), "text": None, "off": f["off"], "level": f["level"], "fkind": f["kind"]})
                continue
            raw.append({"fid": f["id"], "group": grp or f["kind"], "mod": "wide", "data": v.encode("utf-16-le"), "text": v, "off": f["off"], "level": f["level"], "fkind": f["kind"]})
        else:
            if _printable(v):
                raw.append({"fid": f["id"], "group": grp or f["kind"], "mod": "ascii", "data": v.encode("utf-8"), "text": v, "off": f["off"], "level": f["level"], "fkind": f["kind"]})
            else:
                raw.append({"fid": f["id"], "group": grp or f["kind"], "mod": "hex", "data": v.encode("utf-8"), "text": None, "off": f["off"], "level": f["level"], "fkind": f["kind"]})
    # distinct = different bytes that do not overlap in the file: "3 of them" must mean three separate places
    raw.sort(key=lambda s: (-len(s["data"]), s["off"]))
    chosen, spans, seen = [], [], set()
    for s in raw:
        key = (s["mod"] == "wide", s["data"])
        if key in seen:
            skip("dup")
            continue
        a, z = s["off"], s["off"] + len(s["data"])
        if any(a < y and x < z for x, y in spans):
            skip("overlap")
            continue
        if any(s["data"] in o["data"] for o in chosen if (o["mod"] == "wide") == (s["mod"] == "wide")):
            skip("overlap")
            continue
        seen.add(key)
        spans.append((a, z))
        chosen.append(s)
    return chosen, skipped


def need_for(n):
    return min(n, max(3, math.ceil(n / NEED_DIV)))


def _hexs(b):
    return " ".join("%02X" % x for x in b)


def _meta_s(v, cap=200):
    return re.sub(r'[^\x20-\x7e]|["\\]', "", str(v))[:cap].strip()


def rule_text(name, strs, meta, header, bound_mb, harden=None):
    """The rule as text. `strs` = chosen strings of one rule; `meta` = ordered [(key, value)] of tool-owned values; `header` = the magic comparison or None.
    `harden(text)` true = write that string's `.`, `:` and `@` as \\xNN escapes: the rule still matches the same bytes, but the report copy shows no real address (the download is not hardened)."""
    n = len(strs)
    ln = ["rule %s {" % name, "    meta:"]
    ln += ['        %s = "%s"' % (k, _meta_s(v)) for k, v in meta]
    ln.append("    strings:")
    count = {"ascii": 0, "wide": 0, "hex": 0}
    for s in sorted(strs, key=lambda s: (s["mod"], s["off"])):
        count[s["mod"]] += 1
        s["id"] = "$%s%d" % ({"ascii": "s", "wide": "w", "hex": "h"}[s["mod"]], count[s["mod"]])
        if s["mod"] == "hex":
            ln.append("        %s = { %s }" % (s["id"], _hexs(s["data"])))
        else:
            ln.append('        %s = "%s" %s' % (s["id"], _esc(s["text"], bool(harden and harden(s["text"]))), s["mod"]))
    ln.append("    condition:")
    ln.append("        %s%sfilesize < %dMB and %d of them" % (header or "", " and " if header else "", bound_mb, need_for(n)))
    ln.append("}")
    return "\n".join(ln) + "\n"


# ---- the parser and matcher for the subset above. Strict: anything else raises YaraError.
_TOK = re.compile(r'\s*(?:(//[^\n]*)|("(?:[^"\\\n]|\\.)*")|(\$[A-Za-z0-9_]*)|([A-Za-z0-9_]+)|(==|<|[{}():=]))')


def _tokens(text):
    pos, out = 0, []
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = _TOK.match(text, pos)
        if not m:
            raise YaraError("unexpected text near %r" % text[pos:pos + 20])
        pos = m.end()
        if m.group(1):
            continue
        if m.group(4) is not None:
            out.append(("num" if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", m.group(4)) else "id", m.group(4)))
            continue
        for kind, g in (("str", 2), ("var", 3), ("p", 5)):
            if m.group(g) is not None:
                out.append((kind, m.group(g)))
                break
    return out


def _unquote(s):
    body, out, i = s[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            i += 1
            e = body[i] if i < len(body) else ""
            if e in '"\\':
                out += e.encode()
            elif e == "n":
                out += b"\n"
            elif e == "t":
                out += b"\t"
            elif e == "r":
                out += b"\r"
            elif e == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", body[i + 1:i + 3]):
                out.append(int(body[i + 1:i + 3], 16))
                i += 2
            else:
                raise YaraError("bad escape in a string")
        else:
            if ord(c) > 126 or ord(c) < 32:
                raise YaraError("a string holds a character that is not printable ASCII")
            out += c.encode()
        i += 1
    return bytes(out)


def parse(text):
    try:
        return _parse(text)
    except IndexError:
        raise YaraError("the rule ends too early")


def _parse(text):
    """[{name, meta: [(k, v)], strings: [{id, mod, data, pattern}], need, magic, bound}] for a file of rules. Raises YaraError."""
    t = _tokens(text)
    i, rules = 0, []

    def expect(kind, val=None):
        nonlocal i
        if i >= len(t) or t[i][0] != kind or (val is not None and t[i][1] != val):
            raise YaraError("expected %s near token %d" % (val or kind, i))
        i += 1
        return t[i - 1][1]
    while i < len(t):
        expect("id", "rule")
        name = expect("id")
        if not NAME_RE.match(name) or name in RESERVED:
            raise YaraError("bad rule name")
        expect("p", "{")
        expect("id", "meta")
        expect("p", ":")
        meta = []
        while t[i][0] == "id" and t[i][1] not in ("strings",):
            k = expect("id")
            if not META_KEY_RE.match(k) or k in RESERVED:
                raise YaraError("bad meta key")
            expect("p", "=")
            meta.append((k, _unquote(expect("str")).decode()))
        expect("id", "strings")
        expect("p", ":")
        strs, ids = [], set()
        while t[i][0] == "var":
            sid = expect("var")
            if sid in ids or len(sid) < 2:
                raise YaraError("bad or repeated string id")
            ids.add(sid)
            expect("p", "=")
            if t[i] == ("p", "{"):
                i += 1
                hx = []
                while t[i][0] in ("id", "num"):
                    hx.append(t[i][1])
                    i += 1
                expect("p", "}")
                if not hx or not all(re.fullmatch(r"[0-9A-Fa-f]{2}", x) for x in hx):
                    raise YaraError("a hex string holds something other than whole bytes")
                strs.append({"id": sid, "mod": "hex", "data": bytes(int(x, 16) for x in hx)})
            else:
                data = _unquote(expect("str"))
                mods = []
                while t[i][0] == "id" and t[i][1] in ("ascii", "wide"):
                    mods.append(t[i][1])
                    i += 1
                if len(mods) > 1 or not data:
                    raise YaraError("a text string takes one of ascii or wide, and cannot be empty")
                mod = mods[0] if mods else "ascii"
                strs.append({"id": sid, "mod": mod, "data": data if mod == "ascii" else b"".join(bytes([c, 0]) for c in data)})
        if not strs:
            raise YaraError("a rule has no strings")
        expect("id", "condition")
        expect("p", ":")
        magic = bound = need = None
        while True:
            if t[i][0] == "id" and t[i][1] in ("uint16", "uint32"):
                w = expect("id")
                expect("p", "(")
                if expect("num") != "0":
                    raise YaraError("only offset 0 is supported")
                expect("p", ")")
                expect("p", "==")
                magic = (w, int(expect("num"), 16))
            elif t[i] == ("id", "filesize"):
                i += 1
                expect("p", "<")
                m = re.fullmatch(r"(\d+)(KB|MB)", t[i][1])
                if not m:
                    raise YaraError("filesize needs a whole number with a KB or MB unit")
                i += 1
                bound = int(m.group(1)) * (1024 if m.group(2) == "KB" else MIB)
            elif t[i][0] == "num" or t[i][1] in ("all", "any"):
                if t[i][0] == "num":
                    need = int(t[i][1])
                    i += 1
                else:
                    need = len(strs) if t[i][1] == "all" else 1
                    i += 1
                expect("id", "of")
                expect("id", "them")
                if not 1 <= need <= len(strs):
                    raise YaraError("the count in `of them` is outside 1..%d" % len(strs))
            else:
                raise YaraError("unsupported condition")
            if t[i] == ("id", "and"):
                i += 1
                continue
            break
        expect("p", "}")
        if need is None:
            raise YaraError("the condition has no `of them`")
        rules.append({"name": name, "meta": meta, "strings": strs, "need": need, "magic": magic, "bound": bound})
    if not rules:
        raise YaraError("no rule")
    if len({r["name"] for r in rules}) != len(rules):
        raise YaraError("a rule name is used twice")
    return rules


def match(rule, data):
    """(matched, hits): `hits` = ids of the strings found in `data` (bytes or mmap). The condition holds when the header, size bound and count all hold."""
    hits = [s["id"] for s in rule["strings"] if data.find(s["data"]) >= 0]
    ok = len(hits) >= rule["need"]
    if rule["bound"] is not None and not len(data) < rule["bound"]:
        ok = False
    if rule["magic"]:
        w, v = rule["magic"]
        n = 2 if w == "uint16" else 4
        ok = ok and len(data) >= n and int.from_bytes(bytes(data[:n]), "little") == v
    return ok, hits


FP_NOTE = ("The strings were picked by fixed filters (length, not a plain word, not a system path or documentation address) and the rule was checked only against the sample it came from, "
           "not against a collection of clean files. Run it over your own clean set before you block on it.")


def build(findings, read_at, data, size, kind, meta, classify=None, defang_text=None):
    """The detection section: {rules: [{name, label, text, n, need, hits, strings: [...]}], text (the whole .yar file), skipped: [(reason, count)], note (why there is none, fixed words),
    fp, how}. `data` = the sample (bytes or mmap) for the matcher; `meta` = {org, date, sha256, tlp, run} from swarmlabre; `defang_text` decides which strings the report copy (`shown`) writes with escapes. Only rules the matcher proves against `data` are returned."""
    out = {"rules": [], "text": "", "shown_text": "", "skipped": [], "note": "", "fp": FP_NOTE, "how": ""}
    chosen, skipped = candidates(findings, read_at, classify, kind)
    out["skipped"] = [(SKIP_TEXT[k], n) for k, n in sorted(skipped.items(), key=lambda kv: -kv[1])]
    magic = MAGIC.get(kind)
    header = magic[0] if magic and bytes(data[:len(magic[1])]) == magic[1] else None
    bound = max(1, math.ceil(2 * size / MIB))
    sha = meta["sha256"]
    org = _meta_s(meta.get("org") or "") or "swarmlabre"
    base = [("description", ""), ("author", org), ("date", meta["date"]), ("reference", "Agent Swarms run %s" % meta["run"]), ("hash", sha), ("tlp", meta["tlp"]),
            ("sample_type", KIND_WORD.get(kind, "file")), ("source", "strings swarmlabre byte-checked in the sample"), ("false_positives", "see the note in the report; not tested on clean files")]
    sets = [("", "all", chosen)]
    net = [s for s in chosen if s["group"] in ("ip", "domain", "url", "network") or s["fkind"] == "config"]
    cry = [s for s in chosen if s["fkind"] == "crypto"]
    for suffix, label, sub in (("_net", "network and configuration", net), ("_crypto", "cryptography", cry)):
        if len(sub) >= MIN_STRINGS and len(sub) < len(chosen):
            sets.append((suffix, label, sub))
    if len(chosen) < MIN_STRINGS:
        out["note"] = ("No rule was written: %d string%s passed the filters and a rule needs at least %d. The strings swarmlabre byte-checked in this file were too short, too common or too few to hunt with."
                       % (len(chosen), "" if len(chosen) == 1 else "s", MIN_STRINGS))
        return out
    texts, shows = [], []
    for suffix, label, sub in sets:
        sub = [dict(s) for s in sorted(sub, key=lambda s: (s["group"] not in ("ip", "domain", "url", "network"), -len(s["data"])))[:MAX_STRINGS]]
        name = "Swarmlabre_%s_%s%s" % ((kind or "file").upper(), sha[:12], suffix)
        m = list(base)
        m[0] = ("description", "%s strings from the %s sample, SHA-256 %s... (%d strings, at least %d must be present)" % (label.capitalize() if label != "all" else "Byte-checked", KIND_WORD.get(kind, "file"),
                                                                                                                 sha[:16], len(sub), need_for(len(sub))))
        txt = rule_text(name, sub, m, header, bound)
        shown = rule_text(name, sub, m, header, bound, (lambda v: defang_text(v) != v) if defang_text else None)
        try:
            parsed = parse(txt)
            ok, hits = match(parsed[0], data)
            ok2, hits2 = match(parse(shown)[0], data)                      # the report copy must be the same rule: same strings found, same verdict
            ok = ok and ok2 and hits == hits2 and [x["data"] for x in parsed[0]["strings"]] == [x["data"] for x in parse(shown)[0]["strings"]]
        except YaraError:
            ok, hits = False, []
        if not ok or len(hits) != len(sub):                       # every string must be in the sample, and the condition must hold: otherwise the rule is not shown
            out["skipped"].append(("a rule that did not match its own sample when swarmlabre checked it (not shown)", 1))
            continue
        out["rules"].append({"name": name, "label": label, "text": txt, "shown": shown, "n": len(sub), "need": need_for(len(sub)), "hits": len(hits),
                             "strings": [{"id": s["id"], "mod": s["mod"], "value": s["text"] if s["text"] is not None else _hexs(s["data"][:48]) + (" ..." if len(s["data"]) > 48 else ""),
                                          "off": s["off"], "fid": s["fid"]} for s in sorted(sub, key=lambda s: (s["mod"], s["off"]))]})
        texts.append(txt)
        shows.append(shown)
    if not out["rules"]:
        out["note"] = "No rule passed swarmlabre's own check against the sample, so none is shown."
        return out
    head = ("// Agent Swarms run %s. TLP:%s. Prepared by %s on %s.\n// Every rule was matched against the source sample by swarmlabre's own matcher (not by YARA) before it was written here.\n\n"
            % (_meta_s(meta["run"]), _meta_s(meta["tlp"]), org, _meta_s(meta["date"])))
    out["text"] = head + "\n".join(texts)
    out["shown_text"] = head + "\n".join(shows)
    out["how"] = ("Each rule was written from strings swarmlabre byte-checked in the sample, then read back and matched against the sample by swarmlabre's own matcher, which implements only the part of "
                  "YARA these rules use (this box has no YARA program). All strings were found and the condition held for every rule listed.")
    return out
