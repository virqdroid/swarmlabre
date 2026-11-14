"""Offline replay of a recorded run: no model, no Docker, no network.

A finished run folder holds what the report depends on: the sample, the layout and prepared files, the board's inputs in the order the board received them
(`inputs.jsonl`), the Reporter's text and the run record. `replay` rebuilds the board from those inputs under the recorded clock, re-derives the Reporter's
summary and assessment, writes every output file again, and compares each one with the SHA-256 in `manifest.json`.

Two levels. **full**: the sample is there, so the board's evidence checks (the bytes at an offset, the YARA matching) run again. **downstream**: the sample is
not kept, so the board is taken from the record and only the report building is re-run; the result says so and never claims more.
"""
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

from . import clock, report as srep, text as stx
from .services import make_ctx

SKIP_DIRS = {"out", "tasks", "proxy", "cfg", "tools-sock", "clip"}
MAX_COPY_BYTES = 4 << 30           # a bundle or run folder is copied into a temp folder: stop at this size (a link to a big folder must not fill the disk)
MAX_COPY_DEPTH = 8


class ReplayError(Exception):
    pass


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _same(a, b):
    return "identical" if a == b else "differs"


def copy_regular(src, dst, budget=None, depth=0, ignore=()):
    """Copy folders and regular files only. A symlink, a device or a fifo in a recorded folder is skipped (the folder may have been written by a container, or be a downloaded bundle):
    `shutil.copytree` would follow a link and copy what it points at. `budget` is a one-item list of the bytes still allowed."""
    if budget is None:
        budget = [MAX_COPY_BYTES]
    if depth > MAX_COPY_DEPTH:
        raise ReplayError("%s is nested deeper than %d levels" % (src, MAX_COPY_DEPTH))
    dst.mkdir(parents=True, exist_ok=True)
    for p in sorted(Path(src).iterdir()):
        if p.is_symlink() or any(p.match(g) for g in ignore):
            continue
        if p.is_dir():
            copy_regular(p, dst / p.name, budget, depth + 1, ignore)
        elif p.is_file():
            budget[0] -= p.stat().st_size
            if budget[0] < 0:
                raise ReplayError("the folder is larger than %d GiB" % (MAX_COPY_BYTES >> 30))
            shutil.copy2(p, dst / p.name)


def _copy_inputs(src, dst, with_sample):
    dst.mkdir(parents=True)
    for p in src.iterdir():
        if p.name in SKIP_DIRS or p.name in ("board.jsonl", "manifest.json", "model-trace.jsonl.gz", "nonce.key"):
            continue
        if with_sample and p.name in ("windows.json", "detection.json"):      # caches derived from the sample: re-derive them
            continue
        if p.is_symlink():
            continue
        if p.is_dir():
            if p.name == "input" and not with_sample:
                (dst / "input").mkdir()
                continue
            copy_regular(p, dst / p.name)
        elif p.is_file():
            shutil.copy2(p, dst / p.name)


BUNDLE_FILES = ("swarm.json", "manifest.json", "inputs.jsonl", "board.jsonl", "layout.json", "events.jsonl", "detection.json", "windows.json", "model-trace.jsonl.gz", "nonce.key")


def export(run_dir, dest, with_sample=False):
    """Copy what a replay needs into <dest>/<run id>/: the record, the board's inputs, the model trace, the prepared files and the outputs (so the bundle can be
    compared as well as rebuilt). The sample goes along only with `with_sample` (full-level replay); without it the bundle replays at the downstream level.
    Never copied: the agents' transcripts, thoughts, container folders and the clip. -> the bundle folder."""
    src = Path(run_dir).resolve()
    if not (src / "manifest.json").is_file():
        raise ReplayError("not a sealed run (no manifest.json)")
    out = Path(dest).expanduser().resolve() / src.name
    if out.exists():
        raise ReplayError("%s already exists" % out)
    out.mkdir(parents=True)
    for n in BUNDLE_FILES:
        if (src / n).is_file():
            shutil.copy2(src / n, out / n)
    for sub in ("prep", "out"):
        if (src / sub).is_dir():
            copy_regular(src / sub, out / sub, ignore=("*.tmp*",))
    if with_sample and (src / "input" / "sample").is_file():
        (out / "input").mkdir()
        shutil.copy2(src / "input" / "sample", out / "input" / "sample")
    return out


def replay(run_dir, out_dir=None, use_sample=True, rebuilt_dir=None):
    """-> a dict: {"run", "level", "checks": {...}, "ok": bool}. Raises ReplayError when the folder cannot be replayed at all.
    `rebuilt_dir` (used by the golden tests to reseal a recording) receives what the rebuild wrote that a manifest names: swarm.json, board.jsonl and out/*."""
    from . import swarms
    src = Path(run_dir).resolve()
    try:
        man = json.loads((src / "manifest.json").read_text())
        inputs = [json.loads(ln) for ln in (src / "inputs.jsonl").read_text().splitlines() if ln.strip()] if (src / "inputs.jsonl").is_file() else []     # no post at all = no file
        rec0 = json.loads((src / "swarm.json").read_text())
    except (OSError, ValueError):
        raise ReplayError("not a recorded run: manifest.json and swarm.json are needed (runs from before recording cannot be replayed)")
    if man.get("format") != 1:
        raise ReplayError("manifest format %r is not supported" % man.get("format"))
    checks = {}
    # the recorded files are what they were when the run ended
    changed = [n for n, h in sorted((man.get("inputs") or {}).items()) if not (src / n).is_file() or _sha(src / n) != h]
    checks["inputs_untouched"] = "identical" if not changed else "changed: " + ", ".join(changed)
    has_sample = use_sample and (src / "input" / "sample").is_file() and not (src / "input" / "sample").is_symlink()
    level = "full" if has_sample else "downstream"
    if has_sample:        # the sample the board is checked against must be the one the run was about
        want = (man.get("sample") or {}).get("sha256")
        checks["sample"] = "identical" if want and _sha(src / "input" / "sample") == want else ("differs from the manifest" if want else "no hash in the manifest")
    else:
        checks["sample"] = "not kept"
    # the outputs a bundle carries are what the player serves and the demo embeds: they must be the recorded ones, not only the rebuilt ones
    bo = src / "out"
    if bo.is_dir() and not bo.is_symlink():
        carried = {}
        for n in swarms.Swarms.OUT_FILES:
            f, want = bo / n, (man.get("outputs") or {}).get(n)
            if f.is_symlink() or (f.exists() and not f.is_file()):
                carried[n] = "not a regular file"
            elif f.is_file():
                carried[n] = "identical" if want and _sha(f) == want else ("extra" if not want else "differs")
            else:
                carried[n] = "missing" if want else "absent"
        checks["bundle_outputs"] = carried
    else:
        checks["bundle_outputs"] = "not kept"
    with tempfile.TemporaryDirectory(prefix="swarmlabre-replay-") as tmp:
        work = Path(tmp) / "runs" / src.name
        _copy_inputs(src, work, has_sample)
        cfg = {"swarm": {"enabled": True, "report_logo": bool((man.get("config") or {}).get("report_logo")), "detection_rules": bool((man.get("config") or {}).get("detection_rules", True)),
                         "max_rounds": (man.get("config") or {}).get("max_rounds", 2)}, "model": {}}
        ctx = make_ctx(cfg, work.parent.parent, swarms.ROOT / "skills")
        ctx.state_dir = work.parent
        sw = swarms.Swarms(ctx, cfg["swarm"])
        rt = sw.rts.get(src.name)
        if not rt:
            raise ReplayError("the run record is not readable")
        # 1. the board
        if has_sample:
            b = sw._board(rt)
            for row in inputs:
                with clock.pinned(row["t"]):
                    if row["op"] == "intake":
                        b.intake(row["role"], row["task"], row["raw"], set(row["seen"]), set(row["prep"]), set(row["others"]))
                    elif row["op"] == "resolve":
                        b.resolve(row["fid"], row["verdict"], row["text"])
                    elif row["op"] == "spot":
                        b.spot(row["fid"], row["rows"])
                    else:
                        raise ReplayError("unknown input %r" % row["op"])
            checks["board"] = _same((src / "board.jsonl").read_bytes() if (src / "board.jsonl").exists() else b"", (work / "board.jsonl").read_bytes() if (work / "board.jsonl").exists() else b"")
        else:
            if (src / "board.jsonl").is_file():
                shutil.copy2(src / "board.jsonl", work / "board.jsonl")
            checks["board"] = "taken from the record (no sample to re-check it against)"
        # 2. the Reporter's summary and assessment
        rec = rt.rec
        rep = next((t for t in rec["tasks"] if t["role"] == "reporter" and t["state"] in ("done", "timed_out")), None)
        if rep:
            prose, raw = srep.split_assessment(rep["text"][:6000])
            secs, lint_st, canon = stx.structure(prose)
            mine = {"summary": canon, "summary_sections": secs, "summary_lint": lint_st, "assessment_raw": raw}
            checks["summary"] = _same({k: rec0.get(k) for k in mine}, mine)
            rec.update(mine)
        else:
            checks["summary"] = "no Reporter text recorded"
        # 3. every output file
        sw._write_out(rt)
        outs = {}
        for n in swarms.Swarms.OUT_FILES:
            want, p = (man.get("outputs") or {}).get(n), work / "out" / n
            got = _sha(p) if p.is_file() else None
            outs[n] = "identical" if want == got and want else ("not produced, none recorded" if want is None and got is None else ("missing" if got is None else ("extra" if want is None else "differs")))
        checks["outputs"] = outs
        checks["record"] = _same(man["inputs"].get("swarm.json"), _sha(work / "swarm.json"))
        if rebuilt_dir:
            rb = Path(rebuilt_dir)
            (rb / "out").mkdir(parents=True, exist_ok=True)
            for n in ("swarm.json", "board.jsonl"):
                if (work / n).is_file():
                    shutil.copyfile(work / n, rb / n)
            for n in outs:
                if (work / "out" / n).is_file():
                    shutil.copyfile(work / "out" / n, rb / "out" / n)
        if out_dir:
            dest = Path(out_dir).expanduser()
            dest.mkdir(parents=True, exist_ok=True)
            for n in outs:
                if (work / "out" / n).is_file():
                    shutil.copyfile(work / "out" / n, dest / n)
    ok = (checks["inputs_untouched"] == "identical" and checks["sample"] in ("identical", "not kept") and checks["board"] in ("identical", "taken from the record (no sample to re-check it against)")
          and checks["summary"] in ("identical", "no Reporter text recorded") and checks["record"] == "identical"
          and all(v in ("identical", "not produced, none recorded") for v in outs.values())
          and (checks["bundle_outputs"] == "not kept" or all(v in ("identical", "absent") for v in checks["bundle_outputs"].values())))
    return {"run": src.name, "level": level, "ok": ok, "checks": checks}
