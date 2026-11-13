#!/usr/bin/env python3
"""Golden cases: record, replay, compare, and the reviewed update flow. Standard library only; replaying needs no Docker, no model and no network.

    python3 tests/goldenrun.py --check [CASE ...] [--twice]        replay each case and compare every output with tests/golden/<case>/expected, byte for byte;
                                                                   prints one "case/file sha256" line per output (the CI job compares these lines across hash seeds)
    python3 tests/goldenrun.py --update-golden [CASE ...]          NEVER writes an expected file. Re-records (scripted cases) or reseals (recorded ones) into
                                                                   tests/golden/.proposed, prints the diff and a review token, exits 1 if anything would change
    python3 tests/goldenrun.py --update-golden --accept TOKEN      applies the proposal that was shown, only if its token matches (refused when CI is set)
    python3 tests/goldenrun.py --record-real CASE                  re-records a recorded case with the real pipeline and the mock model (Docker and the two images),
                                                                   as a proposal for the same review
    python3 tests/goldenrun.py --proposal-dir DIR ...              also copy the proposal there, to read it with `diff -ru`

A case is a folder tests/golden/<case>/: case.json (what it proves), <run id>/ (the sealed, replayable trace, with the generated sample) and expected/ (the outputs).
Scripted cases are written from tests/golden_cases.py; recorded cases come from a real run with the mock model (a case may point at a trace elsewhere in the repo).
"""
import argparse
import difflib
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import fixtures                                                    # noqa: E402
import golden_cases as gc                                          # noqa: E402
import swarmlabre                                                  # noqa: E402
from swarmlabre import cli, clock, config, corpus, demo, replay as rp, report as srep, swarms, text as stx     # noqa: E402

GOLDEN = ROOT / "tests" / "golden"
PROPOSED = GOLDEN / ".proposed"
OUT_FILES = swarms.Swarms.OUT_FILES
T0 = 1_790_000_000.0


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tree(base, skip=()):
    """{relative path: bytes} of every file under base."""
    base = Path(base)
    return {str(p.relative_to(base)): p.read_bytes() for p in sorted(base.rglob("*")) if p.is_file() and p.parts[len(base.parts)] not in skip} if base.is_dir() else {}


# ---------------------------------------------------------------- cases on disk
def case_names():
    return sorted(p.parent.name for p in GOLDEN.glob("*/case.json"))


def load_case(name):
    meta = json.loads((GOLDEN / name / "case.json").read_text())
    meta["dir"] = GOLDEN / name
    meta["trace_dir"] = (ROOT / meta["trace"]) if meta.get("trace") else GOLDEN / name / meta["run"]
    return meta


# ---------------------------------------------------------------- replay and compare
def replay_outputs(trace):
    """-> (replay result, {output name: bytes}); the trace folder is left alone."""
    with tempfile.TemporaryDirectory(prefix="golden-") as t:
        res = rp.replay(trace, out_dir=Path(t) / "out")
        return res, {p.name: p.read_bytes() for p in sorted((Path(t) / "out").glob("*")) if p.is_file()}


def check_case(name, twice=False):
    """-> (problems [str], {file: sha256 of the replayed output})."""
    c = load_case(name)
    problems = []
    try:
        res, outs = replay_outputs(c["trace_dir"])
    except rp.ReplayError as e:
        return ["%s: cannot replay: %s" % (name, e)], {}
    if not res["ok"]:
        problems.append("%s: the replay does not match its own manifest: %s" % (name, json.dumps(res["checks"], sort_keys=True)))
    if res["level"] != "full":
        problems.append("%s: replayed at the %s level, not full (the trace needs its sample)" % (name, res["level"]))
    exp = tree(c["dir"] / "expected")
    for n in sorted(set(exp) | set(outs)):
        if n not in outs:
            problems.append("%s: expected/%s exists but the replay did not produce it" % (name, n))
        elif n not in exp:
            problems.append("%s: the replay produced %s but expected/ does not have it" % (name, n))
        elif outs[n] != exp[n]:
            problems.append("%s: %s differs from expected/ (%d bytes vs %d)" % (name, n, len(outs[n]), len(exp[n])))
    if twice:
        _, again = replay_outputs(c["trace_dir"])
        if again != outs:
            problems.append("%s: two replays of the same trace gave different bytes" % name)
    return problems, {n: sha(b) for n, b in outs.items()}


# ---------------------------------------------------------------- recording a scripted case (no containers, no model)
def record_scripted(name, root):
    """Board inputs from golden_cases.SCRIPTED -> a sealed run folder under root (through the same recording hooks a live run uses). -> the run folder."""
    spec = gc.SCRIPTED[name]
    built = corpus.build(spec["sample"])
    r = gc.rid(name)
    d, _ = fixtures.build_run(root, r, clock=T0, data=built.data, name=built.filename, functions=gc.FUNCTIONS, brief="What does this sample do?")
    sw = cli._swarms(config.defaults(), d.parent)
    sw._image_ids = lambda: {"swarmlabre-agent": None, "swarmlabre-tools": None}              # no container ran: the manifest must not name this box's images
    rt = sw.rts[r]
    ticks = itertools.count(1)
    real = clock.real
    clock.real = lambda: round(T0 + 2 + next(ticks) * 0.5, 1)
    results = []
    try:
        for op in spec["ops"]:
            if op[0] == "post":
                _, role, n, raw, seen, prep, others = op
                res = sw._record_intake(rt, role, n, raw, set(seen), set(prep), set(others))
                results.append((role, n, json.loads(json.dumps(res))))
            elif op[0] == "spot":
                _, fid, rows = op
                sw._record_spot(rt, sw._board(rt), fid, rows)
                results.append(("orchestrator", 0, {"op": "spot", "fid": fid, "rows": rows}))
            else:
                _, fid, verdict, text = op
                g = sw._record_resolve(rt, sw._board(rt), fid, verdict, text)
                results.append(("orchestrator", 0, {"op": "resolve", "f": json.loads(json.dumps(g))} if g else None))
    finally:
        clock.real = real
    tasks = _tasks(spec, results)
    _events(d, results, tasks)
    prose, raw = srep.split_assessment(spec["report"])
    secs, lint_st, canon = stx.structure(prose)
    rec = rt.rec
    rec["tasks"] = tasks
    rec.update(summary=canon, summary_sections=secs, summary_lint=lint_st, assessment_raw=raw, status="done", counts=sw._board(rt).counts(),
               sampling={"temperature": 0.0, "seed": 1, "seed_support": "unknown", "note": "scripted board inputs; no model was asked"}, finished=T0 + 60.0, peaks={"tools_mib": 0, "agents_mib": 0})
    sw._save(rt)
    sw._write_out(rt)
    sw._seal(rt)
    return d


def _tasks(spec, results):
    """One task row per (task number, role) that posted, and the Reporter's row carrying the report text."""
    rows, seen = [], {}
    for role, n, res in results:
        if n and n not in seen:
            seen[n] = len(rows)
            rows.append(role)
    posted = {}
    for role, n, res in results:
        if res and res["op"] in ("add", "merge", "dispute"):
            posted[n] = posted.get(n, 0) + 1
    out = []
    for n, i in sorted(seen.items()):
        role = rows[i]
        out.append({"n": n, "role": role, "uid": swarms.ROLES[role]["uid"], "state": "done", "started": T0 + 2.0, "ended": T0 + 20.0 + n, "tokens": {"in": 100 * n, "out": 10 * n}, "tools": n,
                    "findings": posted.get(n, 0), "retries": 0, "round": 1, "model_ms": 10 * n, "tool_ms": n, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0, "text": "Posted what it could prove."})
    rep = next((t for t in out if t["role"] == "reporter"), None)
    if not rep:
        rep = {"n": max([t["n"] for t in out] + [0]) + 1, "role": "reporter", "uid": swarms.ROLES["reporter"]["uid"], "state": "done", "started": T0 + 32.0, "ended": T0 + 55.0,
               "tokens": {"in": 1200, "out": 300}, "tools": 0, "findings": 0, "retries": 0, "round": 1, "model_ms": 200, "tool_ms": 0, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0}
        out.append(rep)
    rep["text"] = spec["report"]
    return out


def _events(d, results, tasks):
    """events.jsonl in the order a live run writes it: phases, task starts, one event per board decision, task ends, done."""
    ev = []

    def add(k, dt, **kw):
        ev.append(dict(kw, k=k, t=round(T0 + dt, 2), n=len(ev) + 1))
    add("waiting", 0, code=None, why="")
    add("phase", 0, phase="prepare")
    add("step", 0, step="sample", status="ok", msg="generated sample")
    add("layout", 1)
    add("phase", 2, phase="round1")
    work = [t for t in tasks if t["role"] != "reporter"]
    for t in work:
        add("task_start", 2, task=t["n"], role=t["role"], letter=swarms.ROLES[t["role"]]["letter"], label=swarms.ROLES[t["role"]]["label"], limit=600, round=1)
    for i, (role, n, res) in enumerate(results):
        if not res:
            continue
        dt = 3 + i * 0.01
        if res["op"] == "reject":
            add("reject", dt, task=n, role=role, x=res["x"])
        elif res["op"] == "spot":
            add("spot_check", dt, f=res["fid"], rows=res["rows"])
        elif res["op"] == "resolve":
            add("finding", dt, task=0, role="orchestrator", op="resolve", f=res["f"])
        else:
            add("finding", dt, task=n, role=role, op=res["op"], f=res["f"])
    for t in work:
        add("task_end", 25 + t["n"], task=t["n"], role=t["role"], state="done")
    add("phase", 32, phase="merge")
    rep = next(t for t in tasks if t["role"] == "reporter")
    add("task_start", 32, task=rep["n"], role="reporter", letter="R", label="Reporter", limit=600, round=1)
    add("task_end", 55, task=rep["n"], role="reporter", state="done")
    add("done", 60, status="done", reason=None)
    (Path(d) / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in ev))


# ---------------------------------------------------------------- making a trace folder out of a sealed run
def trim_trace(bundle):
    """What a golden trace does not need: the outputs (expected/ holds them), the sample-derived cache and the ATT&CK table copy (the package has it)."""
    shutil.rmtree(bundle / "out", ignore_errors=True)
    (bundle / "windows.json").unlink(missing_ok=True)
    (bundle / "prep" / "attack.tsv").unlink(missing_ok=True)
    if (bundle / "prep").is_dir() and not any((bundle / "prep").iterdir()):
        (bundle / "prep").rmdir()


def make_trace(run_dir, dest):
    b = rp.export(run_dir, dest, with_sample=True)
    trim_trace(b)
    return b


def proposal_scripted(name, work):
    run = record_scripted(name, work / "runs")
    b = make_trace(run, work / "trace")
    return b


def record_real(name, work):
    """A real run (containers) answered by the scripted mock model -> the trace folder. Needs Docker and the two images."""
    spec = gc.RECORDED[name]
    d = work / "sample"
    if name == "elf-benign":
        sample, script = demo.write(d, "one")
    elif spec["sample"] in corpus.SAMPLES:
        sample = corpus.write(spec["sample"], d)[0]
        script = d / "mock.json"
        script.write_text(json.dumps(corpus.mock_script(spec["sample"], spec.get("func")), indent=1) + "\n")
    else:
        raise SystemExit("%s cannot be re-recorded here" % name)
    cfg = work / "c.toml"
    cfg.write_text('[paths]\nstate = "%s"\n' % (work / "state"))
    r = subprocess.run([sys.executable, "-m", "swarmlabre", "--config", str(cfg), "run", str(sample), "--mock", str(script), "--quiet"], capture_output=True, text=True, cwd=ROOT, timeout=900)
    if r.returncode:
        raise SystemExit("the recording failed (exit %d): %s" % (r.returncode, r.stderr[-600:]))
    res = json.loads(r.stdout.strip().splitlines()[-1])
    return make_trace(Path(res["dir"]), work / "trace")


SET_TOOL = None          # --set-tool: the revision string a reseal writes into a recorded trace (swarm.json env.tool and the manifest), see set_tool()


def set_tool(dst, tool):
    """Replace the tool revision a recording names (a commit of the development history, with or without "with local changes") by `tool`, in swarm.json and the manifest,
    and re-hash swarm.json. Nothing else in the record changes; the reseal that follows rebuilds every output from it."""
    sj = json.loads((dst / "swarm.json").read_text())
    (sj.get("env") or {})["tool"] = tool
    (dst / "swarm.json").write_text(json.dumps(sj, indent=1))
    man = json.loads((dst / "manifest.json").read_text())
    man["env"]["tool"] = tool
    man["tool"] = {"name": "swarmlabre", "version": swarmlabre.__version__, "revision": tool}
    man["inputs"]["swarm.json"] = sha((dst / "swarm.json").read_bytes())
    (dst / "manifest.json").write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")


def reseal(src, dst):
    """Copy a recorded trace and rewrite what a changed report or board changes: swarm.json, board.jsonl and the manifest hashes. The inputs (posts, sample, layout, events) are untouched."""
    shutil.copytree(src, dst)
    if SET_TOOL:
        set_tool(dst, SET_TOOL)
    with tempfile.TemporaryDirectory(prefix="reseal-") as t:
        rp.replay(dst, rebuilt_dir=t)
        for n in ("swarm.json", "board.jsonl"):
            if (Path(t) / n).is_file():
                shutil.copyfile(Path(t) / n, dst / n)
        man = json.loads((dst / "manifest.json").read_text())
        for n in ("swarm.json", "board.jsonl"):
            if n in man["inputs"]:
                man["inputs"][n] = sha((dst / n).read_bytes())
        man["outputs"] = {n: sha((Path(t) / "out" / n).read_bytes()) for n in OUT_FILES if (Path(t) / "out" / n).is_file()}
        (dst / "manifest.json").write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
        if (dst / "out").is_dir():                                  # a bundle that carries its outputs (the demo) keeps them current
            for n in OUT_FILES:
                if (Path(t) / "out" / n).is_file():
                    shutil.copyfile(Path(t) / "out" / n, dst / "out" / n)
                else:
                    (dst / "out" / n).unlink(missing_ok=True)


def case_meta(name, run_id, trace=None):
    spec = gc.SCRIPTED.get(name) or gc.RECORDED[name]
    built = corpus.build(spec["sample"])
    m = {"name": name, "kind": "scripted" if name in gc.SCRIPTED else "recorded", "proves": spec["proves"], "sample": spec["sample"], "sample_sha256": sha(built.data)}
    if trace:
        m["trace"] = trace
    else:
        m["run"] = run_id
    return m


# ---------------------------------------------------------------- the reviewed update
def build_proposal(name, real=False):
    """-> a folder tests/golden/.proposed/<name>/ holding case.json, the new trace (under trace/) and expected/. Nothing under tests/golden/<name> is touched."""
    out = PROPOSED / name
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="golden-rec-") as t:
        work = Path(t)
        old = (GOLDEN / name / "case.json").is_file() and load_case(name)
        if name in gc.SCRIPTED:
            trace = proposal_scripted(name, work)
            meta = case_meta(name, trace.name)
        elif (real or not old) and not gc.RECORDED[name].get("trace"):
            trace = record_real(name, work)
            meta = case_meta(name, trace.name)
        else:
            if real:
                raise SystemExit("%s uses the committed trace %s (the static demo's bundle); it is not re-recorded by a script" % (name, gc.RECORDED[name]["trace"]))
            src = old["trace_dir"] if old else ROOT / gc.RECORDED[name]["trace"]
            trace = work / "trace" / src.name
            trace.parent.mkdir()
            reseal(src, trace)
            meta = {k: v for k, v in old.items() if k not in ("dir", "trace_dir")} if old else case_meta(name, None, gc.RECORDED[name]["trace"])
        res, outs = replay_outputs(trace)
        if not res["ok"] or res["level"] != "full":
            raise SystemExit("%s: the proposed trace does not replay cleanly: %s" % (name, json.dumps(res["checks"], sort_keys=True)))
        shutil.copytree(trace, out / "trace" / trace.name)
        (out / "expected").mkdir()
        for n, b in outs.items():
            (out / "expected" / n).write_bytes(b)
    (out / "case.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
    return out


def current_tree(name):
    """The committed state of a case in the same shape as a proposal: trace/<run id>/..., expected/..., case.json."""
    if not (GOLDEN / name / "case.json").is_file():
        return {}
    c = load_case(name)
    t = {"case.json": (GOLDEN / name / "case.json").read_bytes()}
    t.update({"trace/%s/%s" % (c["trace_dir"].name, k): v for k, v in tree(c["trace_dir"]).items()})
    t.update({"expected/" + k: v for k, v in tree(c["dir"] / "expected").items()})
    return t


def diff_text(old, new, limit=40):
    """The review text for one case: every added, removed and changed file, with a unified diff of text files (long lines and long diffs cut for the screen)."""
    lines = []
    for rel in sorted(set(old) | set(new)):
        a, b = old.get(rel), new.get(rel)
        if a == b:
            continue
        if a is None:
            lines.append("+ added    %s (%d bytes, sha256 %s)" % (rel, len(b), sha(b)[:12]))
        elif b is None:
            lines.append("- removed  %s (%d bytes)" % (rel, len(a)))
        else:
            lines.append("~ changed  %s (%d -> %d bytes)" % (rel, len(a), len(b)))
        if a is None or b is None:                                     # a new or deleted file: its name and size are the review (the content is the new case itself)
            continue
        try:
            ta, tb = a.decode(), b.decode()
        except UnicodeDecodeError:
            continue
        if rel.endswith(".gz") or rel.endswith("/sample"):
            continue
        d = [ln.rstrip("\n") for ln in difflib.unified_diff(ta.splitlines(), tb.splitlines(), "old/" + rel, "new/" + rel, lineterm="", n=0)]
        for ln in d[:limit]:
            lines.append("    " + (ln if len(ln) <= 200 else ln[:197] + "..."))
        if len(d) > limit:
            lines.append("    ... %d more diff lines (use --proposal-dir and diff -ru for all of it)" % (len(d) - limit))
    return "\n".join(lines)


def token_of(name, new):
    h = hashlib.sha256()
    for rel in sorted(new):
        h.update(rel.encode() + b"\0" + sha(new[rel]).encode() + b"\n")
    return h.hexdigest()


def proposed_tree(name):
    return tree(PROPOSED / name)


def update_golden(names, accept=None, real=False, proposal_dir=None):
    names = names or ([n for n, v in gc.RECORDED.items() if not v.get("trace")] if real else sorted(set(case_names()) | set(gc.SCRIPTED) | set(gc.RECORDED)))
    if accept is None:
        shutil.rmtree(PROPOSED, ignore_errors=True)
        changed = {}
        for n in names:
            if n in gc.RECORDED and not real and not (GOLDEN / n / "case.json").is_file() and not gc.RECORDED[n].get("trace"):
                print("%s: no recording yet; use --record-real %s (needs Docker)" % (n, n))
                continue
            build_proposal(n, real=real)
            old, new = current_tree(n), proposed_tree(n)
            d = diff_text(old, new)
            if d:
                changed[n] = (new, d)
            else:
                shutil.rmtree(PROPOSED / n)
        if not changed:
            print("golden: nothing would change")
            return 0
        tok = hashlib.sha256("".join(token_of(n, v[0]) for n, v in sorted(changed.items())).encode()).hexdigest()[:12]
        for n, (new, d) in sorted(changed.items()):
            print("== %s\n%s\n" % (n, d))
        if proposal_dir:
            shutil.copytree(PROPOSED, proposal_dir, dirs_exist_ok=True)
        print("Review the diff above. Nothing was written to tests/golden/<case>. Proposal: %s\nTo apply exactly this: python3 tests/goldenrun.py --update-golden --accept %s" % (PROPOSED, tok))
        return 1
    if os.environ.get("CI"):
        print("golden: refusing to accept a proposal when CI is set", file=sys.stderr)
        return 2
    props = sorted(p.name for p in PROPOSED.iterdir() if p.is_dir()) if PROPOSED.is_dir() else []
    if not props:
        print("golden: no proposal; run --update-golden first", file=sys.stderr)
        return 2
    tok = hashlib.sha256("".join(token_of(n, proposed_tree(n)) for n in props).encode()).hexdigest()[:12]
    if tok != accept:
        print("golden: token %s does not match the proposal on disk (%s). Run --update-golden again and read its diff." % (accept, tok), file=sys.stderr)
        return 2
    for n in props:
        apply_proposal(n)
        print("golden: updated %s" % n)
    shutil.rmtree(PROPOSED, ignore_errors=True)
    return 0


def apply_proposal(name):
    p = PROPOSED / name
    meta = json.loads((p / "case.json").read_text())
    dest = GOLDEN / name
    dest.mkdir(parents=True, exist_ok=True)
    if meta.get("trace"):
        target = ROOT / meta["trace"]
        src = next((p / "trace").iterdir())
    else:
        target = dest / meta["run"]
        src = p / "trace" / meta["run"]
        for old in dest.iterdir():                                     # a re-recording may have another run id: only one trace per case
            if old.is_dir() and old.name not in ("expected", meta["run"]):
                shutil.rmtree(old)
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(src, target)
    shutil.rmtree(dest / "expected", ignore_errors=True)
    shutil.copytree(p / "expected", dest / "expected")
    shutil.copyfile(p / "case.json", dest / "case.json")


# ---------------------------------------------------------------- command line
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cases", nargs="*")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--twice", action="store_true", help="with --check: replay every case twice and require the same bytes")
    ap.add_argument("--update-golden", action="store_true")
    ap.add_argument("--accept", metavar="TOKEN")
    ap.add_argument("--record-real", action="store_true", help="re-record the named recorded cases with the real pipeline (Docker), as a proposal")
    ap.add_argument("--proposal-dir")
    ap.add_argument("--set-tool", metavar="STRING", help="with --update-golden: write STRING as the tool revision of every recorded (real-pipeline) trace; the proposal is reviewed like any other")
    a = ap.parse_args(argv)
    global SET_TOOL
    SET_TOOL = a.set_tool
    if a.check:
        bad, names = 0, a.cases or case_names()
        if not names:
            print("no golden cases found under %s" % GOLDEN, file=sys.stderr)
            return 2
        for n in names:
            problems, hashes = check_case(n, a.twice)
            for f, h in sorted(hashes.items()):
                print("%s/%s %s" % (n, f, h))
            for p in problems:
                print("FAIL " + p, file=sys.stderr)
            bad += bool(problems)
        print("%d cases, %d failed" % (len(names), bad), file=sys.stderr)
        return 1 if bad else 0
    if a.update_golden or a.record_real:
        return update_golden(a.cases, a.accept, real=a.record_real, proposal_dir=a.proposal_dir)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
