"""A benign, generated sample and a complete stored run folder built from it, so the report code can be tested with no model, no Docker and no real malware.

The sample is a tiny ELF written by `make_elf`: a header, two sections and a handful of harmless strings (example domains from RFC 2606, a made-up
mutex name). Findings go through the real `Board.intake`, so the evidence checks run exactly as in a live run.
"""
import hashlib
import json
import struct
import time
from pathlib import Path

from swarmlabre import swarms

SECRETS_AT = {}      # filled by make_elf: string -> file offset


def make_elf(path):
    """A 64-bit little-endian ELF with .text (x86-64 `ret` padding) and .rodata (the demo strings). Returns {string: offset}."""
    strings = [b"http://c2.example.test/beacon", b"Mutex\\Global\\DemoSwarmMutex", b"cmd.exe /c echo demo", b"example.invalid"]
    ro = b"\0".join(strings) + b"\0"
    text = b"\xc3" * 256
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    off_text, off_ro = 64, 64 + len(text)
    off_str = off_ro + len(ro)
    off_sh = (off_str + len(shstr) + 7) & ~7
    offs = {}
    pos = off_ro
    for s in strings:
        offs[s.decode()] = pos
        pos += len(s) + 1

    def sh(name, typ, flags, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, 0, 0, 1, 0)
    shdrs = sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, 0x401000, off_text, len(text)) + sh(7, 1, 2, 0x402000, off_ro, len(ro)) + sh(15, 3, 0, 0, off_str, len(shstr))
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 0, off_sh, 0, 64, 56, 0, 64, 4, 3)
    blob = ehdr + text + ro + shstr
    blob += b"\0" * (off_sh - len(blob)) + shdrs
    Path(path).write_bytes(blob)
    return offs


def build_run(root, rid="s0000abcd", clock=None, data=None, name="demo.elf", functions=None, brief="What does this sample do?"):
    """Create <root>/<rid>/ as a finished run and return (Path of the run, {string: offset}). `clock` makes every timestamp a fixed number.
    `data` (bytes) replaces the built-in ELF as the sample (then the returned offsets are {}); `functions` replaces the one-entry function list."""
    d = Path(root) / rid
    (d / "input").mkdir(parents=True)
    (d / "prep").mkdir()
    sample = d / "input" / "sample"
    if data is None:
        offs = make_elf(sample)
    else:
        sample.write_bytes(data)
        offs = {}
    size = sample.stat().st_size
    sha = hashlib.sha256(sample.read_bytes()).hexdigest()
    kind, facts, regions = swarms.parse_sample(sample, size, [])
    cell = swarms.cell_size(size)
    ent = swarms.entropy_cells(sample, size, cell)
    lay = {"kind": "bytes", "format": facts["format"], "size": size, "sha256": sha, "cells": len(ent), "cell_bytes": cell, "regions": regions, "entropy": ent,
           "functions": functions or [{"id": 0, "name": "entry", "va": 0x401000, "off": 64, "size": 256, "decomp": False, "callees": 0, "callers": 0}], "edges": [],
           "functions_total": len(functions or [0]), "entry": facts.get("entry"), "image_base": 0x400000}
    (d / "layout.json").write_text(json.dumps(lay))
    now = clock or time.time()
    rec = {"id": rid, "status": "done", "waiting": None, "reason": None, "created": now, "started": now, "finished": now + 60,
           "brief": brief, "roles": list(swarms.ROLES), "parallel": {"n": 2, "trait": 2, "override": False},
           "sample": {"name": name, "size": size, "sha256": sha, "kind": kind, "format": facts["format"], "snapshot": []},
           "model": {"backend": "mock", "model": "mock"}, "report": {"tlp": "CLEAR", "org": "", "contact": ""}, "steps": [], "tasks": [], "env": {}, "rounds": [],
           "counts": {}, "phase": "merge"}
    (d / "swarm.json").write_text(json.dumps(rec))
    (d / "events.jsonl").write_text("")
    return d, offs


def write_events(d, view, t0=1_790_000_000.0):
    """events.jsonl of a small run, in the order a live one writes it: the findings carry their whole state as it stood (add, dispute, resolution), a reject carries its row."""
    ev = []

    def add(k, dt, **kw):
        ev.append(dict(kw, k=k, t=round(t0 + dt, 2), n=len(ev) + 1))
    f = {x["id"]: x for x in view["findings"]}
    f1 = f["f1"]
    first = {k: v for k, v in f1.items() if k not in ("resolution",)}
    first.update(disputes=[], status="verified")
    disputed = {k: v for k, v in f1.items() if k != "resolution"}
    disputed["status"] = "disputed"
    add("waiting", 0, code=None, why="")
    add("phase", 0, phase="prepare")
    add("step", 0, step="sample", status="ok", msg="ELF64 x86-64")
    add("layout", 1)
    add("step", 1, step="host_parse", status="ok", msg="2 regions")
    add("phase", 2, phase="round1")
    for i, role in ((1, "ioc"), (2, "crypto"), (3, "static")):
        add("task_start", 2, task=i, role=role, letter=role[0].upper(), label=role, limit=600, round=1)
    add("gate", 3, state="wait", role="ioc", wait_ms=0, waiting=["ioc"], running=["crypto"])
    add("tool_start", 4, task=1, role="ioc", id="c1", tool="bash", text="strings", off=None)
    add("tokens", 5, task=1, role="ioc", model_ms=100, tool_ms=10, wait_ms=0, **{"in": 900, "out": 40})
    add("finding", 6, task=1, role="ioc", op="add", f=first)
    add("finding", 7, task=2, role="crypto", op="add", f=f["f2"])
    add("reject", 8, task=1, role="ioc", x=view["rejected"][0])
    add("task_end", 20, task=1, role="ioc", state="done")
    add("finding", 21, task=3, role="static", op="add", f=f["f3"])
    add("finding", 22, task=3, role="static", op="dispute", f=disputed)
    add("task_end", 25, task=2, role="crypto", state="done")
    add("task_end", 30, task=3, role="static", state="done")
    add("finding", 31, task=0, role="orchestrator", op="resolve", f=f1)
    add("phase", 32, phase="merge")
    add("task_start", 32, task=4, role="reporter", letter="R", label="Reporter", limit=600, round=1)
    add("task_end", 55, task=4, role="reporter", state="done")
    add("done", 60, status="done", reason=None)
    (Path(d) / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in ev))


def record_run(root, rid="s0000beef", with_sample=True):
    """A finished, SEALED run built the way a live one is: posts go through the recording hooks, then the outputs and the manifest are written. No containers."""
    from swarmlabre import cli, config, report as srep, text as stx, clock
    d, offs = build_run(root, rid, clock=1_790_000_000.0)
    sw = cli._swarms(config.defaults(), d.parent)
    rt = sw.rts[rid]
    url, mutex = "http://c2.example.test/beacon", "Mutex\\Global\\DemoSwarmMutex"
    post = lambda role, n, raw, seen=(), others=(): sw._record_intake(rt, role, n, raw, set(seen), {"c1"}, set(others))
    post("ioc", 1, {"kind": "ioc", "title": "C2 URL", "value": url, "off": offs[url]})
    post("crypto", 2, {"kind": "config", "title": "Mutex", "value": mutex, "off": offs[mutex]})
    post("static", 3, {"kind": "capability", "title": "Maybe talks to a server"})
    post("static", 3, {"kind": "dispute", "title": "Not C2", "of": "f1", "reason": "It is a documentation address."})
    post("ioc", 1, {"kind": "ioc", "title": "bad", "value": "nope", "off": offs[url]})          # a reject is an input too
    sw._record_resolve(rt, sw._board(rt), "f1", "stands", "It is an indicator even if it is an example domain.")
    text = ("## Executive summary\nA tiny demo program.\n\n## What it is\nA small static program.\n\n## Capabilities\n- Names a web address.\n\n"
            "## Recommendations\n- Treat it as a test file.\n\n## What we don't know\n- Whether anything loads it.\n"
            'ASSESSMENT {"verdict": "benign", "confidence": "high", "family": "", "basis": ["f1", "f2"], "rationale": "Made-up strings; the code only exits."}')
    prose, raw = srep.split_assessment(text)
    secs, lint_st, canon = stx.structure(prose)
    rec = rt.rec
    rec["tasks"] = [{"n": 1, "role": "ioc", "uid": 20001, "state": "done", "started": 1_790_000_002.0, "ended": 1_790_000_020.0, "tokens": {"in": 900, "out": 40}, "tools": 3, "findings": 2, "retries": 0,
                     "round": 1, "model_ms": 100, "tool_ms": 10, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0, "text": "Posted two findings."},
                    {"n": 2, "role": "crypto", "uid": 20002, "state": "done", "started": 1_790_000_002.0, "ended": 1_790_000_025.0, "tokens": {"in": 800, "out": 30}, "tools": 2, "findings": 1, "retries": 0,
                     "round": 1, "model_ms": 90, "tool_ms": 8, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0, "text": "Posted one finding."},
                    {"n": 3, "role": "static", "uid": 20003, "state": "done", "started": 1_790_000_002.0, "ended": 1_790_000_030.0, "tokens": {"in": 700, "out": 20}, "tools": 1, "findings": 1, "retries": 0,
                     "round": 1, "model_ms": 80, "tool_ms": 5, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0, "text": "Disputed the C2 claim."},
                    {"n": 4, "role": "reporter", "uid": 20004, "state": "done", "started": 1_790_000_032.0, "ended": 1_790_000_055.0, "tokens": {"in": 1200, "out": 300}, "tools": 0, "findings": 0, "retries": 0,
                     "round": 1, "model_ms": 200, "tool_ms": 0, "wait_ms": 0, "steers": 0, "stop": None, "notes": 0, "text": text}]
    write_events(d, sw._board(rt).view())
    rec.update(summary=canon, summary_sections=secs, summary_lint=lint_st, assessment_raw=raw, status="done", counts=sw._board(rt).counts(),
               sampling={"temperature": 0.0, "seed": 1, "seed_support": "honoured"}, finished=1_790_000_060.0,
               peaks={"tools_mib": 900, "agents_mib": 120})
    sw._save(rt)
    sw._write_out(rt)
    sw._seal(rt)
    if not with_sample:
        (d / "input" / "sample").unlink()
    return d
