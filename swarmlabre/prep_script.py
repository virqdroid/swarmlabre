# swarmlabre: the preparing script, run INSIDE the tools container (swarmlabre-tools) by swarms.py: `docker exec -i <tools> python3 -I -` with this file on stdin.
# It talks to the rea-session server over the control socket, writes plain files under /work/prep and prints one JSON line per step on stdout.
# Tool-owned and never mounted into an agent container. Stdlib only. Exit codes: 0 done, 3 native analysis unavailable, 4 the tool server was lost.
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys, time

SESSION = "/skills/rea-reverse-engineering/scripts/rea-session.py"
SAMPLE = os.environ.get("PREP_SAMPLE", "/in/sample")      # an APK is staged as /in/sample.apk (jadx decides by the extension)
OUT = "/work/prep"
NFUNCS = max(1, int(os.environ.get("PREP_FUNCS", "40")))
EDGE_CAP = 2000
EDGE_SECS = int(os.environ.get("PREP_EDGE_SECS", "120"))
DECOMP_SECS = int(os.environ.get("PREP_DECOMP_SECS", "200"))
FILE_CAP = 512 * 1024


def decomp_name(n, taken):
    """The file name of a class's outline. Two class names can fold to one name (a long common prefix, or characters that became "_"): the later one gets a hash of its full name, so it never overwrites the first."""
    fn = re.sub(r"[^A-Za-z0-9_.$]", "_", n)[:120] + ".java"
    if fn in taken:
        fn = "%s_%s.java" % (fn[:-5][:110], hashlib.sha256(n.encode("utf-8", "replace")).hexdigest()[:8])
    return fn


def say(**kw):
    print(json.dumps(kw), flush=True)


spec = importlib.util.spec_from_file_location("rea_session", SESSION)
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)


class Lost(Exception):
    pass


def call(tool, args, timeout=300):
    """One tool call through the control socket; returns the result value or raises Lost (server gone) / ValueError (tool error)."""
    try:
        r = rs.ask({"op": "call", "tool": tool, "args": args, "timeout": timeout, "agent": "prep"}, timeout + 30)
    except (OSError, ValueError) as e:
        raise Lost(str(e))
    if not r:
        raise Lost("the server closed the connection")
    if "error" in r:
        msg = r["error"].get("message") if isinstance(r["error"], dict) else r["error"]
        raise ValueError(str(msg)[:200])
    val, bad = rs.unwrap(r)
    if bad:
        raise ValueError(str(val)[:200])
    return rs.result_of(val)


def write(rel, text):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text[:FILE_CAP * 4])


FRAMEWORK = ("android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "com.google.", "org.jetbrains.", "okhttp3.", "okio.", "org.apache.", "com.android.", "dalvik.")
LIFECYCLE = ("onCreate", "onStartCommand", "onReceive", "onBind", "attachBaseContext", "<clinit>", "run", "doInBackground", "onHandleIntent", "handleMessage", "onReceivedSslError",
             "onPageStarted", "onNewIntent", "onAccessibilityEvent", "onNotificationPosted", "onMessageReceived")
HOT = re.compile(r"(url|http|send|upload|download|exec|crypt|cipher|decode|encode|key|token|passw|login|sms|contact|location|install|root|dex|reflect|invoke|socket|connect|admin|accessib|overlay|inject|payload|config|decrypt)", re.I)


def top_of(name):
    return name.split("$", 1)[0]


def apk_main(base, summ):
    """The APK counterpart of the native steps: class list ranked (entry components first), outlines plus the interesting methods as /prep/decomp/*.java, class references as edges."""
    facts = summ.get("facts") or {}
    pkg = str(facts.get("package_name") or "")
    app_cls = str((facts.get("application_flags") or {}).get("name") or "")
    host = {}
    try:
        for ln in open("/in/host-classes.tsv"):
            a = ln.rstrip("\n").split("\t")
            if len(a) >= 4:
                host[a[0]] = (int(a[1]), int(a[2]), a[3])
    except (OSError, ValueError):
        pass
    names = []
    try:
        names = [str(i["class"]) for i in json.load(open(os.path.join(base, "classes.json")))["items"] if isinstance(i, dict) and i.get("class")]
        say(step="functions", status="ok", msg="%d classes from jadx" % len(names))
    except (OSError, ValueError, KeyError):
        names = list(host)
        say(step="functions", status="partial" if names else "failed", msg=("jadx has no class list; using the %d classes swarmlabre read from the DEX files" % len(names)) if names else "no class list")
    inner = {}
    for n in names:
        inner[top_of(n)] = inner.get(top_of(n), 0) + (1 if "$" in n else 0)
    comps = set()
    try:
        for c in json.load(open(os.path.join(base, "components.json"))).get("components", []):
            comps.add(top_of(str(c.get("name", ""))))
    except (OSError, ValueError):
        pass
    comps = {c if "." in c else pkg + "." + c.lstrip(".") if c.startswith(".") else c for c in comps}
    pre = ".".join(pkg.split(".")[:3]) if pkg.count(".") >= 2 else pkg

    def rank(n):
        if n in comps:
            return 0
        if n == top_of(app_cls) and app_cls:
            return 1
        if pkg and n.startswith(pre):
            return 2
        return 4 if n.startswith(FRAMEWORK) else 3
    order = sorted(inner, key=lambda n: (rank(n), -(host.get(n, (0, 0, ""))[0] + inner[n]), n))[:2000]
    pick = [n for n in order if rank(n) < 4][:NFUNCS]
    done, t0 = {}, time.time()
    for n in pick:
        if time.time() - t0 > DECOMP_SECS:
            break
        try:
            c = call("inspect_android_class", {"path": SAMPLE, "class_name": n}, 120)
        except ValueError:
            continue
        if not isinstance(c, dict):
            continue
        meths = [m for m in (c.get("methods") or []) if isinstance(m, dict) and isinstance(m.get("name"), str)]
        want = []
        for key in (lambda m: m["name"] in LIFECYCLE, lambda m: bool(HOT.search(m["name"])), lambda m: not m["name"].startswith("<")):
            for m in meths:
                if key(m) and m not in want and len(want) < 8:
                    want.append(m)
        out = ["// class %s\n// methods: %d, fields: %d, inner classes: %d\n// OUTLINE (all methods; the bodies below are only a selection)\n" % (n, len(meths), len(c.get("fields") or []), len(c.get("inner_classes") or []))]
        out += ["//   %s\n" % str(m.get("reported_signature") or m["name"])[:200] for m in meths[:400]]
        out.append("\n// DECOMPILED METHODS (jadx via rea; read the rest with: rea-session.py call inspect_android_method)\n")
        got = 0
        for m in want:
            if time.time() - t0 > DECOMP_SECS:
                break
            try:
                r = call("inspect_android_method", {"path": SAMPLE, "class_name": n, "method_name": m["name"], "overload_index": int(m.get("overload_index") or 0)}, 60)
            except ValueError:
                continue
            src = ((r or {}).get("source") or {}).get("text") if isinstance(r, dict) else None
            if isinstance(src, str) and src.strip():
                out.append("\n// ---- %s\n%s\n" % (str(m.get("reported_signature") or m["name"])[:200], src[:24000]))
                got += 1
        fn = decomp_name(n, {d["file"] for d in done.values()})
        write("decomp/" + fn, "".join(out)[:FILE_CAP])
        done[n] = {"file": fn, "methods": len(meths), "decompiled": got}
    write("decomp/INDEX.txt", "".join("%s\t%s\t%d of %d methods\n" % (n, d["file"], d["decompiled"], d["methods"]) for n, d in done.items()))
    say(step="decompile", status="ok" if done else "partial", msg="%d classes outlined, %d methods decompiled" % (len(done), sum(d["decompiled"] for d in done.values())))
    known = set(inner)
    edges, t1, cut = [], time.time(), False
    for n in sorted(order, key=lambda n: (n not in done, order.index(n))):
        if time.time() - t1 > EDGE_SECS:
            cut = True
            break
        try:
            r = call("trace_android_references", {"path": SAMPLE, "class_name": n}, 60)
        except ValueError:
            continue
        for ref in (r.get("references") if isinstance(r, dict) else None) or []:
            a = top_of(str(ref.get("top_class") or ref.get("reported_full_name") or "")) if isinstance(ref, dict) else ""
            if a in known and a != n:
                edges.append([a, n])
    edges = sorted({tuple(e) for e in edges})
    write("apk.json", json.dumps({"package": pkg, "functions": [{"name": n, "methods": host.get(n, (0, 0, ""))[0], "inner": inner[n], "rank": rank(n), "file": done.get(n, {}).get("file")} for n in order],
                                  "total": len(inner), "edges": [list(e) for e in edges[:20000]], "truncated": cut or len(order) < len(inner)}))
    say(step="edges", status="ok", msg="%d edges%s" % (len(edges), " (cut off)" if cut else ""))
    return 0


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)
    # 1. the fixed first pass (every step is a manifest call, byte-identical on a rerun)
    t0 = time.time()
    p = subprocess.run([sys.executable, "-I", SESSION, "triage", SAMPLE], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    base = os.path.join(os.environ.get("REA_OUT_DIR", "/tmp/rea-out"), "triage", hashlib.sha256(open(SAMPLE, "rb").read()).hexdigest()[:12])
    if p.returncode == 2 or not os.path.isdir(base):
        say(step="triage", status="failed", msg="triage does not cover this sample")
        return 3
    os.makedirs(os.path.join(OUT, "triage"))
    for n in sorted(os.listdir(base)):
        if os.path.isfile(os.path.join(base, n)) and not os.path.islink(os.path.join(base, n)):
            shutil.copyfile(os.path.join(base, n), os.path.join(OUT, "triage", n))
    try:
        summ = json.load(open(os.path.join(base, "SUMMARY.json")))
    except (OSError, ValueError):
        summ = {}
    bad = [s["step"] for s in summ.get("steps", []) if s.get("status") not in ("ok", "n/a")]
    say(step="triage", status="ok" if not bad else "partial", secs=round(time.time() - t0, 1), msg=("not ok: " + ", ".join(bad[:6])) if bad else "")
    if summ.get("playbook") == "apk":
        return apk_main(base, summ)
    if not summ.get("native_available"):
        say(step="native", status="unavailable", msg="Ghidra import failed or timed out")
        return 3
    # 2. the function list: sizes are estimated from the gap to the next function (procedures carry no size)
    try:
        items = json.load(open(os.path.join(base, "procedures.json")))["items"]
    except (OSError, ValueError, KeyError):
        say(step="functions", status="failed", msg="no procedure list")
        return 3
    own = []
    for it in items:
        if not isinstance(it, dict) or (it.get("procedure") or {}).get("external"):
            continue
        a = str(it.get("address", ""))
        if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", a):
            own.append({"address": a, "va": int(a, 16), "name": str(it.get("value", ""))[:80], "thunk": bool((it.get("procedure") or {}).get("thunk"))})
    own.sort(key=lambda x: x["va"])
    for i, f in enumerate(own):
        f["size_est"] = min(own[i + 1]["va"] - f["va"], 65536) if i + 1 < len(own) else 4096
    write("functions.json", json.dumps({"total": len(own), "items": [{k: f[k] for k in ("address", "name", "size_est", "thunk")} for f in own[:20000]]}))
    say(step="functions", status="ok", msg="%d functions" % len(own))
    # 3. decompile the entry points and the biggest functions with an explicit address list
    pick = [f for f in own if f["name"] in ("entry", "main", "_main", "wmain", "WinMain", "DllMain", "_start")]
    for f in sorted((f for f in own if not f["thunk"] and f not in pick), key=lambda f: -f["size_est"]):
        if len(pick) >= NFUNCS:
            break
        pick.append(f)
    done, names = [], set()
    try:
        for i in range(0, len(pick), 10):
            chunk = pick[i:i + 10]
            res = call("batch_decompile", {"addresses": [f["address"] for f in chunk]}, 600)
            for it in (res.get("items") if isinstance(res, dict) else None) or []:
                if not isinstance(it, dict) or it.get("status") != "ok" or not isinstance(it.get("pseudocode"), str):
                    continue
                f = next((x for x in chunk if x["address"] == it.get("address")), None)
                if not f:
                    continue
                safe = re.sub(r"[^A-Za-z0-9_]", "_", f["name"])[:48] or "fn"
                fn = "%s_%x.c" % (safe, f["va"])
                write("decomp/" + fn, it["pseudocode"][:FILE_CAP])
                done.append({"address": f["address"], "name": f["name"], "file": fn, "size_est": f["size_est"]})
    except ValueError as e:
        say(step="decompile", status="partial", msg=str(e))
    write("decomp/INDEX.txt", "".join("%s\t%s\t%s\n" % (d["address"], d["file"], d["name"]) for d in done))
    write("decomp.json", json.dumps(done))
    say(step="decompile", status="ok" if done else "failed", msg="%d of %d functions" % (len(done), len(pick)))
    # 4. call edges: one procedure_callees call per function (about 30 ms each), capped in number and time
    order = sorted(own, key=lambda f: (f["address"] not in {d["address"] for d in done}, -f["size_est"]))[:EDGE_CAP]
    known = {f["address"] for f in own}
    edges, t1, cut = [], time.time(), False
    for f in order:
        if time.time() - t1 > EDGE_SECS:
            cut = True
            break
        try:
            res = call("procedure_callees", {"procedure": f["address"]}, 60)
        except ValueError:
            continue
        for a in (res if isinstance(res, list) else []):
            if isinstance(a, str) and a in known and a != f["address"]:
                edges.append([f["address"], a])
    write("edges.json", json.dumps({"edges": edges[:20000], "functions_scanned": len(order), "truncated": cut or len(own) > EDGE_CAP}))
    say(step="edges", status="ok", msg="%d edges%s" % (len(edges), " (cut off)" if cut else ""))
    return 0


try:
    code = main()
except Lost as e:
    say(step="tools", status="lost", msg=str(e)[:200])
    code = 4
except ValueError as e:
    say(step="prep", status="failed", msg=str(e)[:200])
    code = 3
say(step="end", status="ok" if code == 0 else "failed", code=code)
sys.exit(code)
