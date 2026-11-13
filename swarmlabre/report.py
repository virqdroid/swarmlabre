"""Report front matter for Agent Swarms: the facts swarmlabre reads from the sample itself (hashes, header data, APK manifest), the TLP marking, the title,
and the Reporter's assessment (verdict, family, confidence) checked against the board.

stdlib only. Two trust rules:
  - the snapshot is swarmlabre's own parse of the file (no agent text); strings that come from the file (package name, permissions) are made printable and capped;
  - the assessment is model judgement over agent text. Swarmlabre keeps only the fields it can check (cited findings must exist and be checked), caps the confidence by
    the evidence behind them, and says in fixed words when it changed something. The rationale is the Reporter's text and is always labelled as such.
"""
import collections, hashlib, json, math, re, struct, time

MIB = 1 << 20
TLP = {"CLEAR": "Disclosure is not limited.",
       "GREEN": "Limited disclosure, restricted to the community.",
       "AMBER": "Limited disclosure, restricted to the recipient's organization and its clients.",
       "AMBER+STRICT": "Limited disclosure, restricted to the recipient's organization.",
       "RED": "Not for disclosure, restricted to the named recipients only."}
TLP_COLOR = {"CLEAR": "#ffffff", "GREEN": "#33ff00", "AMBER": "#ffc000", "AMBER+STRICT": "#ffc000", "RED": "#ff2b2b"}   # FIRST's colours, drawn on black
VERDICTS = ("malicious", "suspicious", "benign", "undetermined")
VERDICT_WORD = {"malicious": "Malicious", "suspicious": "Suspicious", "benign": "No malicious behaviour found", "undetermined": "Undetermined"}
CONFIDENCE = ("low", "moderate", "high")
KIND_LABEL = {"elf": "Linux ELF", "pe": "Windows PE", "apk": "Android APK"}
HASHLIKE = re.compile(r"[0-9a-fA-F]{32,64}(\.[A-Za-z0-9]{1,5})?")
FID = re.compile(r"f\d{1,5}\Z")
IMPORT_CAP = 20000
FILE_CAP = 64 * MIB


def tlp_value(v, default="AMBER"):
    """Normalised TLP level ('amber', 'TLP:AMBER+STRICT' -> 'AMBER' / 'AMBER+STRICT'); an unknown value gives the default."""
    s = re.sub(r"^TLP:", "", str(v or "").strip().upper())
    return s if s in TLP else default


def clean(s, cap):
    """Printable ASCII only (text from a file or an agent), folded to one line, capped."""
    return re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]", "?", str(s))).strip()[:cap]


def title_label(rec, assessment=None):
    """Customer-facing name of the sample: the family when the assessment names one, the file name when it is not just a hash, else 'Android APK 9ed7b9dc'."""
    fam = (assessment or rec.get("assessment") or {}).get("family")
    if fam:
        return fam
    s = rec["sample"]
    if s.get("name") and not HASHLIKE.fullmatch(s["name"]):
        return s["name"]
    return "%s %s" % (KIND_LABEL.get(s.get("kind"), "sample"), s["sha256"][:8])


# ------------------------------------------------------------------ snapshot

def _hashes(path):
    m, s1, s2 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            m.update(b), s1.update(b), s2.update(b)
    return m.hexdigest(), s1.hexdigest(), s2.hexdigest()


def _entropy(path):
    cnt, n = collections.Counter(), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            cnt.update(b)
            n += len(b)
    return -sum(c / n * math.log2(c / n) for c in cnt.values()) if n else 0.0


def _rva(secs, rva):
    for va, vs, rsz, roff in secs:
        if va <= rva < va + max(vs, rsz):
            return roff + (rva - va)
    return None


def pe_info(path, size):
    """Compile timestamp, import counts, imphash and signature block of a PE. None where the file does not say. imphash follows pefile's rule; for ordinal imports from
    ws2_32, wsock32 and oleaut32 pefile uses name tables swarmlabre does not carry, so imphash is left out there instead of being wrong."""
    out = {"timestamp": None, "dlls": 0, "funcs": 0, "imphash": None, "imphash_why": "", "signed": False, "clr": False}
    if size > FILE_CAP:
        out["imphash_why"] = "file too large"
        return out
    with open(path, "rb") as f:
        d = f.read()
    lfa = struct.unpack_from("<I", d, 60)[0]
    if d[lfa:lfa + 4] != b"PE\0\0":
        return out
    nsec, ts, _p, _n, optsz = struct.unpack_from("<HIIIH", d, lfa + 6)
    out["timestamp"] = ts
    o = lfa + 24
    magic = struct.unpack_from("<H", d, o)[0]
    pe64 = magic == 0x20B
    dd = o + (112 if pe64 else 96)
    nrva = struct.unpack_from("<I", d, o + (108 if pe64 else 92))[0]
    sec_at = o + optsz
    secs = []
    for i in range(min(nsec, 96)):
        vs, va, rsz, roff = struct.unpack_from("<IIII", d, sec_at + 40 * i + 8)
        secs.append((va, vs, rsz, roff))
    if nrva > 14:
        out["clr"] = bool(struct.unpack_from("<II", d, dd + 14 * 8)[0])
    if nrva > 4:
        sec_off, sec_len = struct.unpack_from("<II", d, dd + 4 * 8)
        out["signed"] = bool(sec_off and sec_len)
    if nrva < 2:
        out["imphash_why"] = "no import table"
        return out
    irva, isz = struct.unpack_from("<II", d, dd + 8)
    base = _rva(secs, irva) if irva else None
    if base is None:
        out["imphash_why"] = "no import table"
        return out
    parts, ordinal_odd = [], False
    step = 8 if pe64 else 4
    scanned = 0                                         # thunks looked at, named or not: descriptors may share one table, and an entry that maps nowhere used to cost a scan of the section list for free
    for k in range(512):
        if scanned >= 4 * IMPORT_CAP:
            break
        e = base + 20 * k
        if e + 20 > len(d):
            break
        oft, _t, _f, nrv, ft = struct.unpack_from("<IIIII", d, e)
        if not (oft or nrv or ft):
            break
        no = _rva(secs, nrv)
        if no is None:
            continue
        dll = d[no:no + 260].split(b"\0")[0].decode("latin-1").lower()
        lib = dll.rsplit(".", 1)
        lib = lib[0] if len(lib) > 1 and lib[1] in ("ocx", "sys", "dll") else dll
        to = _rva(secs, oft or ft)
        if to is None:
            continue
        out["dlls"] += 1
        for j in range(IMPORT_CAP):
            scanned += 1
            p = to + j * step
            if p + step > len(d):
                break
            v = int.from_bytes(d[p:p + step], "little")
            if not v:
                break
            if v >> (step * 8 - 1):
                if dll in ("ws2_32.dll", "wsock32.dll", "oleaut32.dll"):
                    ordinal_odd = True
                parts.append("%s.ord%d" % (lib, v & 0xFFFF))
            else:
                no2 = _rva(secs, v & 0x7FFFFFFF)
                if no2 is None:
                    continue
                fn = d[no2 + 2:no2 + 2 + 260].split(b"\0")[0].decode("latin-1").lower()
                if fn:
                    parts.append("%s.%s" % (lib, fn))
            out["funcs"] += 1
            if out["funcs"] >= IMPORT_CAP:
                break
    if ordinal_odd:
        out["imphash_why"] = "ordinal imports swarmlabre cannot name"
    elif parts:
        out["imphash"] = hashlib.md5(",".join(parts).encode("latin-1"), usedforsecurity=False).hexdigest()
    else:
        out["imphash_why"] = "no named imports"
    return out


AXML_STRING_CHARS = 4096                               # one string of a manifest's pool (real names are far shorter)
AXML_TOTAL_CHARS = 1 << 20                             # all strings of one pool


def _axml_strings(d, c, end):
    hdr, cnt = struct.unpack_from("<H", d, c + 2)[0], struct.unpack_from("<I", d, c + 8)[0]
    flags, sstart = struct.unpack_from("<II", d, c + 16)[0], struct.unpack_from("<I", d, c + 20)[0]
    utf8 = bool(flags & 0x100)
    out = []
    budget = AXML_TOTAL_CHARS                          # entries may point at the same bytes: what is decoded is capped per string and in all, not by the size of the file
    for i in range(min(cnt, 20000)):
        off = struct.unpack_from("<I", d, c + hdr + 4 * i)[0]
        p = c + sstart + off
        if p >= end or budget <= 0:
            out.append("")
            continue
        if utf8:
            n = d[p]
            p += 1 if not n & 0x80 else 2
            b = d[p]
            p += 1
            if b & 0x80:
                b = ((b & 0x7F) << 8) | d[p]
                p += 1
            b = min(b, AXML_STRING_CHARS)
            out.append(d[p:p + b].decode("utf-8", "replace"))
            budget -= b
        else:
            n = struct.unpack_from("<H", d, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]
                p += 2
            n = min(n, AXML_STRING_CHARS)
            out.append(d[p:p + 2 * n].decode("utf-16-le", "replace"))
            budget -= n
    return out


def parse_axml(d):
    """[(element, {attribute: value})] from a binary AndroidManifest.xml (start tags only; strings, ints and booleans; at most 6000 elements). Raises ValueError."""
    if len(d) < 16 or struct.unpack_from("<H", d, 0)[0] != 3:
        raise ValueError("not binary XML")
    pos, strs, out = 8, [], []
    while pos + 8 <= len(d) and len(out) < 6000:
        typ, hdr, sz = struct.unpack_from("<HHI", d, pos)
        if sz < 8 or pos + sz > len(d):
            break
        if typ == 1 and not strs:
            strs = _axml_strings(d, pos, pos + sz)
        elif typ == 0x102 and strs:
            name_i, a_start, a_size, a_cnt = struct.unpack_from("<iHHH", d, pos + 20)
            attrs = {}
            for k in range(min(a_cnt, 200)):
                ap = pos + 16 + a_start + k * (a_size or 20)
                _ns, nm, raw, _sz, _r, dt, data = struct.unpack_from("<iiiHBBI", d, ap)
                if not 0 <= nm < len(strs):
                    continue
                if dt == 3 and 0 <= raw < len(strs):
                    v = strs[raw]
                elif dt in (0x10, 0x11):
                    v = data - (1 << 32) if dt == 0x10 and data >= 1 << 31 else data
                elif dt == 0x12:
                    v = bool(data)
                else:
                    continue
                attrs[strs[nm]] = v
            out.append((strs[name_i] if 0 <= name_i < len(strs) else "", attrs))
        pos += sz
    return out


def _der(d, i, end):
    """One DER element at d[i:end]: (tag, value start, value end) or None. Definite lengths only, at most 4 length bytes."""
    if i + 2 > end:
        return None
    tag, n = d[i], d[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7f
        if not 1 <= k <= 4 or j + k > end:
            return None
        n = int.from_bytes(d[j:j + k], "big")
        j += k
    return (tag, j, j + n) if j + n <= end else None


def _cert_from_pkcs7(d):
    """The first certificate of a PKCS#7 SignedData (a META-INF/*.RSA file): its DER bytes, or None. ContentInfo { oid, [0] { SignedData { version, digestAlgs, content, [0] certs ... } } }."""
    a = _der(d, 0, len(d))
    if not a or a[0] != 0x30:
        return None
    i = a[1]
    o = _der(d, i, a[2])
    if not o or o[0] != 0x06:
        return None
    x = _der(d, o[2], a[2])                                   # [0] EXPLICIT
    if not x or x[0] != 0xa0:
        return None
    sd = _der(d, x[1], x[2])
    if not sd or sd[0] != 0x30:
        return None
    i = sd[1]
    for _ in range(8):                                        # version, digestAlgorithms, contentInfo, then the optional [0] certificates
        e = _der(d, i, sd[2])
        if not e:
            return None
        if e[0] == 0xa0:
            c = _der(d, e[1], e[2])
            return d[e[1]:c[2]] if c and c[0] == 0x30 else None
        i = e[2]
    return None


def apk_signers(path):
    """[(scheme, SHA-256 of the signer certificate in DER)] read from the file's own signature data: v1 from META-INF/*.RSA|DSA|EC, v2 and v3 from the APK Signing Block. Nothing is validated
    (no signature check, no chain): it is the fingerprint `apksigner verify --print-certs` and keytool show. Never raises."""
    import zipfile
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", n, re.I) and z.getinfo(n).file_size <= 256 * 1024:
                    c = _cert_from_pkcs7(z.read(n))
                    if c:
                        out.append(("v1", hashlib.sha256(c).hexdigest()))
            cd = z.start_dir
        with open(path, "rb") as f:
            if cd >= 32:
                f.seek(cd - 24)
                size, magic = struct.unpack("<Q16s", f.read(24))
                if magic == b"APK Sig Block 42" and 24 <= size <= 16 * MIB and cd - size - 8 >= 0:
                    f.seek(cd - size - 8)
                    blk = f.read(size + 8)
                    i, end = 8, size - 16                        # pairs sit between the leading size field and the trailing size + magic
                    while i + 12 <= end:
                        ln, pid = struct.unpack_from("<QI", blk, i)
                        if ln < 4 or i + 8 + ln > end:
                            break
                        val = blk[i + 12:i + 8 + ln]
                        if pid in (0x7109871a, 0xf05368c0):    # v2, v3: signers > signer > signed data > digests, certificates
                            try:
                                p0 = 4                              # signers length
                                sl = struct.unpack_from("<I", val, p0)[0]; p1 = p0 + 4                      # first signer
                                dl = struct.unpack_from("<I", val, p1)[0]; p2 = p1 + 4                      # signed data
                                dg = struct.unpack_from("<I", val, p2)[0]; p3 = p2 + 4 + dg                 # skip digests
                                cl = struct.unpack_from("<I", val, p3)[0]; p4 = p3 + 4                      # certificates
                                c1 = struct.unpack_from("<I", val, p4)[0]
                                if sl <= len(val) and dl <= sl and p4 + 4 + c1 <= len(val) and c1 <= cl:
                                    out.append(("v2" if pid == 0x7109871a else "v3", hashlib.sha256(val[p4 + 4:p4 + 4 + c1]).hexdigest()))
                            except struct.error:
                                pass
                        i += 8 + ln
    except Exception:
        return out
    return out


def _shown(v):
    """A manifest value for the snapshot: a number as it is; anything else (a string-typed attribute is legal in the binary format) made printable and capped."""
    return str(v) if isinstance(v, int) and not isinstance(v, bool) else clean(str(v), 40)


def apk_manifest(path):
    """Package facts from the manifest, or {} when it cannot be read. Everything is the sample's text: made printable and capped."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            info = z.getinfo("AndroidManifest.xml")
            if info.file_size > 8 * MIB:
                return {}
            els = parse_axml(z.read(info))
            names = z.namelist()
            sig_v1 = any(re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", n, re.I) for n in names)
            cd = z.start_dir
        with open(path, "rb") as f:
            f.seek(max(cd - 16, 0))
            sig_v2 = f.read(16) == b"APK Sig Block 42"
    except Exception:
        return {}
    m = {"permissions": [], "components": collections.Counter(), "sig_v1": sig_v1, "sig_v2": sig_v2}
    for el, a in els:
        if el == "manifest":
            m["package"], m["versionName"], m["versionCode"] = a.get("package"), a.get("versionName"), a.get("versionCode")
        elif el == "uses-sdk":
            m["minSdk"], m["targetSdk"] = a.get("minSdkVersion"), a.get("targetSdkVersion")
        elif el in ("uses-permission", "uses-permission-sdk-23") and isinstance(a.get("name"), str):
            m["permissions"].append(clean(a["name"], 120))
        elif el in ("activity", "activity-alias", "service", "receiver", "provider"):
            m["components"]["activity" if el == "activity-alias" else el] += 1
        elif el == "application":
            m["debuggable"], m["allowBackup"] = a.get("debuggable"), a.get("allowBackup")
    return m


def snapshot(path, size, kind, facts, regions=None, ent=None):
    """Rows [{label, value}] for the report's Sample snapshot table, from swarmlabre's own parse. Never raises: a part that cannot be read is left out."""
    md5, sha1, sha256 = _hashes(path)
    rows = [("File type", clean(facts.get("format", ""), 80)), ("Size", "%s bytes" % format(size, ","))]
    rows += [("MD5", md5), ("SHA-1", sha1), ("SHA-256", sha256)]
    try:
        rows.append(("Entropy", "%.2f bits per byte over the whole file" % _entropy(path)))
        if ent:
            hi = sum(1 for v in ent if v >= 7.2 * 31.875)
            rows.append(("High-entropy data", ("%d%% of the file is at 7.2 bits per byte or more (packed or encrypted data)" % round(100 * hi / len(ent))) if hi else "None: no part of the file is at 7.2 bits per byte or more"))
    except OSError:
        pass
    try:
        if kind == "pe":
            p = pe_info(path, size)
            if p["timestamp"] is not None:
                rows.append(("Compile timestamp", (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(p["timestamp"])) if p["timestamp"] else "zero") + " (a header value the author can set to anything)"))
            if p["dlls"]:
                rows.append(("Imports", "%d functions from %d libraries" % (p["funcs"], p["dlls"])))
            rows.append(("Imphash", p["imphash"] or "not computed (%s)" % (p["imphash_why"] or "unknown")))
            if p["clr"]:
                rows.append(("Managed code", ".NET: the file has a CLR header, so the code is IL and the native import table says little"))
            rows.append(("Authenticode block", "present, signature not validated" if p["signed"] else "none"))
            ov = next((r for r in regions or [] if r.get("kind") == "overlay"), None)
            if ov:
                rows.append(("Overlay", "%s bytes after the last section" % format(ov["len"], ",")))
        elif kind == "elf":
            rows.append(("Entry point", "0x%x" % facts["entry"]) if facts.get("entry") else ("Entry point", "none"))
            rows.append(("Section headers", "none (stripped or removed)" if facts.get("stripped_sections") else "%d" % facts.get("sections", 0)))
        elif kind == "apk":
            m = apk_manifest(path)
            if m.get("package"):
                rows.append(("Package", clean(m["package"], 150)))
            v = " ".join(x for x in (clean(m.get("versionName") or "", 40), ("(code %s)" % _shown(m["versionCode"])) if m.get("versionCode") is not None else "") if x)
            if v:
                rows.append(("Version", v))
            if m.get("minSdk") is not None or m.get("targetSdk") is not None:
                rows.append(("Android API levels", "minimum %s, target %s" % (_shown(m.get("minSdk", "not set")), _shown(m.get("targetSdk", "not set")))))
            ps = m.get("permissions", [])
            if ps:
                short = [p.replace("android.permission.", "") for p in sorted(set(ps))]
                rows.append(("Permissions", "%d declared: %s%s" % (len(short), ", ".join(short[:14]), (", and %d more" % (len(short) - 14)) if len(short) > 14 else "")))
            cc = m.get("components") or {}
            if cc:
                rows.append(("Components", ", ".join("%d %s" % (cc[k], ("activities" if k == "activity" else k + "s") if cc[k] != 1 else k) for k in ("activity", "service", "receiver", "provider") if cc.get(k))))
            if m.get("debuggable"):
                rows.append(("Debuggable", "yes (the manifest sets debuggable)"))
            if "sig_v1" in m:
                sch = [x for x, on in (("v1 (JAR)", m["sig_v1"]), ("v2 or later (APK Signing Block)", m["sig_v2"])) if on]
                rows.append(("Signature", ("%s, not validated" % " and ".join(sch)) if sch else "no signature found"))
                sg = apk_signers(path)
                for fp in sorted({f for _s, f in sg}):
                    rows.append(("Signer certificate SHA-256", fp + " (" + ", ".join(sorted({sc for sc, f in sg if f == fp})) + ")"))
            if facts.get("libs"):
                rows.append(("Native libraries", "%d .so files" % facts["libs"]))
    except (OSError, ValueError, struct.error, IndexError):
        pass
    return [{"label": a, "value": b} for a, b in rows if b]


# ------------------------------------------------------------------ the Reporter's assessment

ASSESS_RE = re.compile(r"^[ \t>*`-]*ASSESSMENT[ \t:]+(\{.*\})[ \t`]*$", re.M)


def split_assessment(text):
    """(summary prose without the ASSESSMENT line, the parsed object or None). The last well-formed line wins; a bad one is dropped from the prose too."""
    raw = None
    for m in ASSESS_RE.finditer(text or ""):
        try:
            o = json.loads(m.group(1))
            raw = o if isinstance(o, dict) else raw
        except ValueError:
            pass
    prose = ASSESS_RE.sub("", text or "")
    prose = re.sub(r"^[ \t]*```\w*[ \t]*\n\s*```[ \t]*$", "", prose, flags=re.M)
    return re.sub(r"\n{3,}", "\n\n", prose).strip(), raw


def assess(raw, findings, static_only=True):
    """Validate the Reporter's ASSESSMENT object against the board. -> dict or None (nothing usable).
    Fields: verdict, confidence (what the Reporter claimed), confidence_final (what the evidence allows), family, basis (checked finding ids), rationale, adjusted (fixed sentences).
    Rules: malicious or suspicious needs at least one checked finding cited, else the verdict becomes undetermined. confidence high needs two checked findings
    including a byte-checked one and none of them disputed; moderate needs one; otherwise low. A 'benign' verdict never goes above moderate: static analysis does not prove a file safe."""
    if not isinstance(raw, dict):
        return None
    by = {f["id"]: f for f in findings}
    verdict = raw.get("verdict") if raw.get("verdict") in VERDICTS else "undetermined"
    claimed = raw.get("confidence") if raw.get("confidence") in CONFIDENCE else "low"
    basis_in = [x for x in (raw.get("basis") if isinstance(raw.get("basis"), list) else []) if isinstance(x, str) and FID.match(x)][:12]
    basis = [x for x in dict.fromkeys(basis_in) if x in by and by[x]["status"] in ("verified", "disputed")][:8]
    adjusted = []
    if len(basis) < len(set(basis_in)):
        adjusted.append("Some cited findings are not verified on the board and were dropped from the basis.")
    nb = sum(1 for x in basis if by[x]["level"] == "byte-checked")
    open_dispute = any(by[x]["status"] == "disputed" for x in basis)
    if not basis:
        cap, why = "low", "no verified finding is cited"
    elif len(basis) >= 2 and nb >= 1 and not open_dispute:
        cap, why = "high", ""
    else:
        cap, why = "moderate", "a cited finding is disputed" if open_dispute else "high confidence needs two verified findings, one of them byte-checked"
    if verdict in ("malicious", "suspicious") and not basis:
        verdict = "undetermined"
        adjusted.append("The Reporter gave a verdict without citing a checked finding, so swarmlabre shows it as undetermined.")
    if verdict == "benign" and cap == "high":
        cap, why = "moderate", "static analysis alone does not prove a file is safe"
    final = CONFIDENCE[min(CONFIDENCE.index(claimed), CONFIDENCE.index(cap))]
    if final != claimed:
        adjusted.append("Confidence was lowered from %s to %s: %s." % (claimed, final, why))
    fam = clean(raw.get("family") or "", 80)
    if re.fullmatch(r"(?i)unknown|none|n/a|not identified|unidentified|-", fam) or HASHLIKE.fullmatch(fam):
        fam = ""
    return {"verdict": verdict, "confidence": claimed, "confidence_final": final, "family": fam, "basis": basis, "rationale": clean(raw.get("rationale") or "", 400),
            "adjusted": adjusted, "static_only": bool(static_only)}


def confidence_text(a):
    return "%s confidence" % a["confidence_final"].capitalize()


# ------------------------------------------------------------------ indicators: classification, defanging, grouping (Pyramid of Pain)
# Classified from the checked VALUE with strict patterns, never from what an agent called it. A value that fits no pattern stays in "Other strings".
# Swarmlabre does not judge whether an indicator is malicious: it lists what the agents found in the file and how it was backed.
IOC_GROUPS = (("hash", "Hash values"), ("ip", "IP addresses"), ("domain", "Domain names"), ("url", "URLs"), ("network", "Network artifacts"),
              ("host", "Host artifacts"), ("other", "Other strings"))
IOC_NOTE = ("These are values the agents found in the file and swarmlabre checked. Swarmlabre does not judge whether a value is malicious: a vendor URL, a library path or a documentation "
            "link can sit in a malicious file too. Review before you block. Network values are defanged here; the exports hold the real values.")
_GTLD = ("com net org info biz edu gov mil int name pro mobi asia tel xxx app dev xyz top site online store tech cloud club live shop blog link click page space website fun icu vip work today "
         "world life news email network systems agency digital download support services solutions group company center win bid loan review stream party trade science date faith racing "
         "cricket accountant men xin ltd onion")
# two-letter country codes; left out on purpose: the ones that are also common file extensions (so py js sh rs md pl cc ml mk cs ps pm in: autotools *.in files), so libfoo.so or build.py is never a domain
_CCTLD = ("ad ae af ag al am ao ar at au aw az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cy cz de dj dk dm do dz ec ee eg er es et eu "
          "fi fj fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu "
          "lv ly ma mc me mg mh mm mn mo mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pn pr pt pw qa re ro ru rw sa sb sc sd se sg si sk sl sm sn sr ss st "
          "su sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw")
TLDS = frozenset((_GTLD + " " + _CCTLD).split())
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(r"(?i)(?:%s\.)+(%s)" % (_LABEL, "|".join(sorted(TLDS, key=len, reverse=True))))
HOSTPORT_RE = re.compile(r"(?i)([a-z0-9.-]{1,253}|\[[0-9a-f:.]+\])(?::(\d{1,5}))?")
URL_RE = re.compile(r"(?i)(https?|ftps?|wss?)://(?:[^/\s?#@]{0,200}@)?(\[[0-9a-f:.]+\]|[a-z0-9._-]{1,253})(?::(\d{1,5}))?(?:[/?#]\S*)?")
EMAIL_RE = re.compile(r"(?i)[a-z0-9._%%+-]{1,64}@((?:%s\.)+(?:%s))" % (_LABEL, "|".join(sorted(TLDS, key=len, reverse=True))))
HEX_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}")
HEX_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
UA_RE = re.compile(r"(?:Mozilla|Opera|curl|Wget|python-requests|python-urllib|Go-http-client|okhttp|Dalvik|libwww-perl|WinHttp|Microsoft-CryptoAPI)/\S.{0,380}")
HEADER_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,40}: \S.{0,300}")
REG_RE = re.compile(r"(?i)(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\x00-\x1f]{1,500}")
WINPATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\[\w.$-]+\\|%[A-Za-z_]+%[\\/])[^\x00-\x1f\"<>|*?]{1,500}")
REGREL_RE = re.compile(r"(?i)(?:SOFTWARE|SYSTEM)\\(?:[A-Za-z0-9_.{}$ -]+\\)*[A-Za-z0-9_.{}$ -]+")          # a registry path written without its hive: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
WINFRAG_RE = re.compile(r"\\?[A-Za-z0-9_.${}% -]+(?:\\[A-Za-z0-9_.${}% -]+)+|\\[A-Za-z0-9_.${}% -]+")        # Chrome\\User Data, \\Discord
FILENAME_RE = re.compile(r"(?i)[A-Za-z0-9_{}-][A-Za-z0-9_.{}-]{0,99}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|apk|dex|so|log|txt|dat|tmp|lnk|scr|msi|zip|rar|7z|db|sqlite|bin|cfg|ini|json|xml|lock|key|pem|sh)")
UNIXPATH_RE = re.compile(r"/(?:[A-Za-z0-9._@+%~-]+/)*[A-Za-z0-9._@+%~-]+/?")
PERM_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*\.permission\.[A-Za-z0-9_.]+")
ANDROID_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+){2,}")


def _ip(host):
    """(ip object) for a plain or bracketed IPv4/IPv6 text, else None."""
    import ipaddress
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def _port(p):
    return p is None or (p.isdigit() and 0 < int(p) < 65536)


def classify(value, kind=None):
    """{group, type, norm, port, private} for a checked value, or None. `kind` is the sample kind (elf, pe, apk): Android names are only recognised in an APK."""
    v = value if isinstance(value, str) else ""
    if not v or len(v) > 2000 or v != v.strip():
        return None
    if HEX_RE.fullmatch(v):
        return {"group": "hash", "type": "Hex digest, %s length" % HEX_LEN[len(v)], "norm": v.lower(), "algo": HEX_LEN[len(v)], "port": None, "private": False}
    m = URL_RE.fullmatch(v)
    if m and _port(m.group(3)):
        ip = _ip(m.group(2))
        return {"group": "url", "type": "URL", "norm": v, "port": None, "private": bool(ip and not ip.is_global)}
    m = EMAIL_RE.fullmatch(v)
    if m:
        return {"group": "network", "type": "Email address", "norm": v.lower(), "port": None, "private": False}
    m = HOSTPORT_RE.fullmatch(v)
    if m and _port(m.group(2)):
        host = m.group(1)
        ip = _ip(host)
        if ip is not None:
            return {"group": "ip", "type": "IPv%d address" % ip.version, "norm": str(ip), "port": m.group(2), "private": not ip.is_global}
        if "." in host and len(host) <= 253 and DOMAIN_RE.fullmatch(host):
            return {"group": "domain", "type": "Domain name", "norm": host.lower(), "port": m.group(2), "private": False}
    ip = _ip(v)
    if ip is not None:
        return {"group": "ip", "type": "IPv%d address" % ip.version, "norm": str(ip), "port": None, "private": not ip.is_global}
    if UA_RE.fullmatch(v):
        return {"group": "network", "type": "User agent", "norm": v, "port": None, "private": False}
    if HEADER_RE.fullmatch(v):
        return {"group": "network", "type": "HTTP header", "norm": v, "port": None, "private": False}
    if REG_RE.fullmatch(v):
        return {"group": "host", "type": "Registry key", "norm": v, "port": None, "private": False}
    if WINPATH_RE.fullmatch(v):
        return {"group": "host", "type": "Windows file path", "norm": v, "port": None, "private": False}
    if REGREL_RE.fullmatch(v):
        return {"group": "host", "type": "Registry key path (no hive)", "norm": v, "port": None, "private": False}
    if WINFRAG_RE.fullmatch(v) and "\\" in v:
        return {"group": "host", "type": "Windows path (fragment)", "norm": v, "port": None, "private": False}
    if kind == "apk" and PERM_RE.fullmatch(v):
        return {"group": "other", "type": "Android permission", "norm": v, "port": None, "private": False}      # capability evidence, not an artifact on a host
    if kind == "apk" and ANDROID_RE.fullmatch(v):
        return {"group": "host", "type": "Android name (package, component or action)", "norm": v, "port": None, "private": False}
    if UNIXPATH_RE.fullmatch(v) and v != "/" and len(v) > 2:
        return {"group": "host", "type": "File path", "norm": v, "port": None, "private": False}
    if FILENAME_RE.fullmatch(v):
        return {"group": "host", "type": "File name", "norm": v, "port": None, "private": False}
    return None


def _dots(s):
    return s.replace(".", "[.]")


_BARE_IP = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w]|\.\d)")
# a bare domain in free text: lowercase only (so System.Net, Microsoft.Win32 and other PascalCase names stay readable), a known TLD, and not followed by another dotted part
_BARE_DOM = re.compile(r"(?<![\w.@/\\%-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(sorted(TLDS, key=len, reverse=True)) + r"))(?![\w-]|\.[A-Za-z0-9])")


_BARE_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@((?:" + _LABEL + r"\.)+(?:" + "|".join(sorted(TLDS, key=len, reverse=True)) + r"))(?![\w-]|\.[A-Za-z0-9])", re.I)


def defang_text(s):
    """Defang network values inside free text (finding titles, strings, the Reporter's prose): URLs get hxxp and [.] in the host, bare IPv4 addresses and lowercase domains get [.].
    Never changes anything else; a value that is already defanged has no plain dots left to change."""
    def url(m):
        sch = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps", "ws": "wxs", "wss": "wxss"}.get(m.group(1).lower(), m.group(1))
        return "%s://%s" % (sch, _dots(m.group(2)))
    s = re.sub(r"(?i)\b(https?|ftps?|wss?)://([^/\s?#:]+)", url, str(s))
    s = _BARE_EMAIL.sub(lambda m: "%s[@]%s" % (m.group(1), _dots(m.group(2))), s)
    s = _BARE_IP.sub(lambda m: _dots(m.group(1)) if all(int(x) <= 255 for x in m.group(1).split(".")) else m.group(1), s)
    return _BARE_DOM.sub(lambda m: _dots(m.group(1)), s)


def defang(value, kind=None):
    """The defanged form of one value, safe to paste into a ticket: a URL gets hxxp and [.] in its host, an address or domain gets [.], an email also [@]."""
    c = classify(value, kind)
    if c and c["group"] == "url":
        return defang_text(value)
    if c and c["group"] in ("ip", "domain"):
        return _dots(value)
    if c and c["type"] == "Email address":
        return _dots(value).replace("@", "[@]")
    return defang_text(value)


def ioc_rows(snapshot, findings, kind=None):
    """Indicator rows for the report and the exports: the sample's own hashes first, then every verified or disputed `ioc` finding (and `config` findings whose value is an address,
    domain, URL or network artifact), merged by normalised value. A row: group, type, value (real), norm, fids, level (best of the merged findings, 'computed' for the sample's own
    hashes), off, title (first finding's), disputed (every merged finding is disputed), private, port, algo. Real values stay in the rows: callers defang for display."""
    rows, seen = [], {}
    for x in snapshot or []:
        if x["label"] in ("MD5", "SHA-1", "SHA-256") or (x["label"] == "Imphash" and re.fullmatch(r"[0-9a-f]{32}", x["value"])):
            rows.append({"group": "hash", "type": x["label"] if x["label"] != "Imphash" else "Imphash", "value": x["value"], "norm": x["value"].lower(), "fids": [], "level": "computed", "off": None,
                         "title": "Sample file" if x["label"] != "Imphash" else "Import table of the sample", "disputed": False, "private": False, "port": None, "algo": x["label"], "sample": True})
    for f in findings:
        if f["status"] not in ("verified", "disputed") or f["kind"] not in ("ioc", "config"):
            continue
        c = classify(f["value"], kind)
        if f["kind"] == "config" and not (c and c["group"] in ("ip", "domain", "url", "network")):
            continue
        g = c or {"group": "other", "type": "String", "norm": f["value"], "port": None, "private": False}
        key = (g["group"], g["type"], g["norm"])
        r = seen.get(key)
        if r:
            r["fids"].append(f["id"])
            if LEVEL_RANK.get(f["level"], 0) > LEVEL_RANK.get(r["level"], 0):
                r["level"] = f["level"]
            if r["off"] is None and isinstance(f.get("off"), int):
                r["off"] = f["off"]
            r["disputed"] = r["disputed"] and f["status"] == "disputed"
            continue
        r = {"group": g["group"], "type": g["type"], "value": f["value"], "norm": g["norm"], "fids": [f["id"]], "level": f["level"], "off": f["off"] if isinstance(f.get("off"), int) else None,
             "title": f["title"], "disputed": f["status"] == "disputed", "private": g.get("private", False), "port": g.get("port"), "algo": g.get("algo", "")}
        seen[key] = r
        rows.append(r)
    for u in [r for r in rows if r["group"] == "url"]:                      # the host of a URL is an indicator of its own (blocklists work on hosts); it carries the URL's evidence
        m = URL_RE.fullmatch(u["value"])
        if not m:
            continue
        ip = _ip(m.group(2))
        if ip is not None:
            g = {"group": "ip", "type": "IPv%d address" % ip.version, "norm": str(ip), "private": not ip.is_global}
        elif "." in m.group(2) and DOMAIN_RE.fullmatch(m.group(2)):
            g = {"group": "domain", "type": "Domain name", "norm": m.group(2).lower(), "private": False}
        else:
            continue
        key = (g["group"], g["type"], g["norm"])
        r = seen.get(key)
        if r:
            r["fids"] += [i for i in u["fids"] if i not in r["fids"]]
            if LEVEL_RANK.get(u["level"], 0) > LEVEL_RANK.get(r["level"], 0):
                r["level"] = u["level"]
            r["disputed"] = r["disputed"] and u["disputed"]
            continue
        r = {"group": g["group"], "type": g["type"], "value": g["norm"], "norm": g["norm"], "fids": list(u["fids"]), "level": u["level"], "off": u["off"], "title": "Host part of a URL found in the file",
             "disputed": u["disputed"], "private": g["private"], "port": m.group(3), "algo": "", "derived": True}
        seen[key] = r
        rows.append(r)
    order = {k: i for i, (k, _l) in enumerate(IOC_GROUPS)}
    rows.sort(key=lambda r: (order[r["group"]], 0 if r.get("sample") else 1))
    return rows


LEVEL_RANK = {"claimed": 0, "call-cited": 1, "byte-checked": 2, "computed": 3}


def ioc_context(r):
    """Tool-owned wording for the Context column: what it is, how it was backed, where it sits. The finding title is the tool-cleaned title of the first finding, defanged."""
    if r.get("sample"):
        return "%s. Computed by swarmlabre from the file itself." % r["title"]
    bits = [defang_text(r["title"]).rstrip(".")]
    bits.append(r["level"] + (", disputed" if r["disputed"] else ""))
    if r["off"] is not None:
        bits.append("offset 0x%x" % r["off"])
    if r["fids"]:
        bits.append("finding%s %s" % ("s" if len(r["fids"]) > 1 else "", ", ".join(r["fids"][:6]) + (" and %d more" % (len(r["fids"]) - 6) if len(r["fids"]) > 6 else "")))
    if r["private"]:
        bits.append("private or reserved address")
    return ". ".join(bits[:1]) + ". " + ", ".join(bits[1:]) + "."


def ioc_groups(rows, kind=None):
    """Display structure: [{id, label, rows: [{type, ind (defanged), ctx, level}]}] for the groups that have rows. Everything here is defanged and tool-worded."""
    out = []
    for gid, label in IOC_GROUPS:
        rs = [r for r in rows if r["group"] == gid]
        if rs:
            out.append({"id": gid, "label": label, "rows": [{"type": r["type"], "ind": defang(r["value"], kind), "ctx": ioc_context(r), "level": r["level"] + (", disputed" if r["disputed"] else "")} for r in rs]})
    return out


def exportable(r):
    """What the machine-readable exports carry: the sample's own hashes and checked findings that nobody disputes (byte-checked or call-cited; the level travels with each row)."""
    return not r["disputed"] and r["level"] in ("computed", "byte-checked", "call-cited")
