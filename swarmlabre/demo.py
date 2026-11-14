"""A harmless demo: a tiny ELF made of example data, and the script of a mock model that analyses it. `swarmlabre demo DIR` writes both.

The sample is a valid static x86-64 executable that only calls exit(0). Its strings use reserved example domains (RFC 2606), a made-up mutex name and a
made-up command line. Nothing in it is malicious and nothing in it is copied from a real sample.
"""
import json
import struct
from pathlib import Path

from . import attack

STRINGS = ["http://c2.example.test/beacon", "Mutex\\Global\\DemoSwarmMutex", "cmd.exe /c echo demo", "example.invalid"]
STRINGS_TWO = ["https://updates.example.test/check", "Global\\Demo2Lock", "/tmp/.demo-cache", "203.0.113.9", "w:C:\\Demo\\agent.dll"]     # "w:" = stored as UTF-16LE; 203.0.113.0/24 is reserved for documentation (RFC 5737)
BASE = 0x400000
# _start: call f; mov eax,60; xor edi,edi; syscall.   f: push rbp; mov rbp,rsp; pop rbp; ret.
CODE = bytes.fromhex("e809000000" "b83c000000" "31ff" "0f05" "55" "4889e5" "5d" "c3") + b"\x90" * 9


def make_elf(path, strings=None):
    """Write the demo ELF to `path`. Returns {string: file offset} for the strings in .rodata (UTF-16 ones are keyed by their text, without the "w:" mark)."""
    blob, offs = elf_bytes(strings)
    Path(path).write_bytes(blob)
    return offs


def elf_bytes(strings=None):
    """The demo ELF as bytes -> (bytes, {string: file offset}); see make_elf."""
    strings = strings or STRINGS
    ro, offs = b"", {}
    off_text = 64 + 56
    off_ro = off_text + len(CODE)
    for s in strings:
        wide = s.startswith("w:")
        if wide and (off_ro + len(ro)) % 2:
            ro += b"\0"                                         # UTF-16 strings start on an even offset
        offs[s[2:] if wide else s] = off_ro + len(ro)
        ro += (s[2:].encode("utf-16-le") + b"\0\0") if wide else (s.encode() + b"\0")
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    off_str = off_ro + len(ro)
    off_sh = (off_str + len(shstr) + 7) & ~7

    def sh(name, typ, flags, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, 0, 0, 1, 0)
    shdrs = sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, BASE + off_text, off_text, len(CODE)) + sh(7, 1, 2, BASE + off_ro, off_ro, len(ro)) + sh(15, 3, 0, 0, off_str, len(shstr))
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, off_ro + len(ro), off_ro + len(ro), 0x1000)       # one PT_LOAD, read + execute, from the file start
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, BASE + off_text, 64, off_sh, 0, 64, 56, 1, 64, 4, 3)
    blob = ehdr + phdr + CODE + ro + shstr
    blob += b"\0" * (off_sh - len(blob)) + shdrs
    return blob, offs


def _post(**kw):
    cmd = ["python3", "/skills/rea-swarm/scripts/swarm-post"]
    for k, v in kw.items():
        cmd += ["--" + k, str(v)]
    return " ".join(("'%s'" % c.replace("'", "'\\''")) if (" " in c or not c.isascii() or "\\" in c) else c for c in cmd)


def _say(text):
    return {"tool": "bash", "args": {"command": "python3 /skills/rea-swarm/scripts/swarm-say '%s'" % text}}


def mock_script(offs):
    """The mock model's script for the demo sample: each role reads its prepared files, posts what it can prove from the bytes, and says it is done."""
    url, mutex, cmd = STRINGS[0], STRINGS[1], STRINGS[2]
    t1071 = attack.lookup("enterprise", "T1071")
    roles = {
        "triage": [_say("Reading the prepared overview and triage files"),
                   {"text": "Reading the overview.", "tool": "read", "args": {"path": "/prep/overview.md"}},
                   {"tool": "bash", "args": {"command": _post(kind="note", title="Small static x86-64 ELF", detail="A tiny executable with one load segment; no packing seen.", off=0, confidence="high")}},
                   {"text": "Triage done: a tiny static ELF, nothing packed, strings worth reading."}],
        "static": [_say("Reading the function index"),
                   {"tool": "bash", "args": {"command": "cat /prep/decomp/INDEX.txt 2>/dev/null | head -20"}},
                   {"text": "Static done: the entry point calls one small helper and exits."}],
        "ioc": [_say("Reading the strings file for hosts and names"),
                {"tool": "bash", "args": {"command": "head -40 /prep/strings.txt"}},
                {"tool": "bash", "args": {"command": _post(kind="ioc", title="C2 URL", value=url, off=hex(offs[url]), confidence="high", detail="A URL on a reserved example domain.")}},
                {"tool": "bash", "args": {"command": _post(kind="ioc", title="Mutex name", value=mutex, off=hex(offs[mutex]), confidence="high", detail="A made-up mutex name.")}},
                {"tool": "bash", "args": {"command": _post(kind="ioc", title="Command line", value=cmd, off=hex(offs[cmd]), confidence="medium", detail="A made-up command line.")}},
                {"text": "Strings done: three indicators posted."}],
        "crypto": [_say("Looking for constants and configuration"),
                   {"tool": "bash", "args": {"command": "grep -i -c example /prep/strings.txt"}},
                   {"tool": "bash", "args": {"command": _post(kind="config", title="Mutex name", value=mutex, off=hex(offs[mutex]), confidence="medium", detail="The mutex looks like configuration.")}},
                   {"text": "Crypto and config done: no cryptography, one configuration string."}],
        "behaviour": [_say("Mapping the findings to techniques"),
                      {"tool": "bash", "args": {"command": _post(kind="technique", title="%s %s" % (t1071["id"], t1071["name"]), detail="Rests on f1 and f2: a URL string and a mutex name.", confidence="low")}},
                      {"text": "Behaviour done: one technique, resting on the strings."}],
        "reporter": [{"text": ("## Executive summary\nThis is a tiny demo program. It contains a made-up web address and a made-up mutex name, and it only exits when run.\n\n"
                               "## What it is\nA small static 64-bit Linux program built for demonstration.\n\n"
                               "## Capabilities\n- It names a web address, but nothing in the file uses it.\n\n"
                               "## Recommendations\n- Treat it as a test file.\n\n"
                               "## What we don't know\n- Whether anything else loads it.\n\n"
                               'ASSESSMENT {"verdict": "benign", "confidence": "moderate", "family": "", "basis": ["f1", "f2"], "rationale": "The strings are made-up examples and the code only exits."}')}],
    }
    plan = {"summary": "Round 1 covered the brief.", "tasks": [], "resolutions": []}
    return {"model": "mock-1", "roles": roles, "orchestrator": [json.dumps(plan)]}


def mock_script_two(offs):
    """The script for the second demo sample: a UTF-16 string, a dispute raised by Static (after a pause, so there is a finding to dispute), a round-2 plan from the
    planning model that settles the dispute and sends Crypto back out (its second pass posts the same finding again, which the board rejects as a duplicate)."""
    url, lock, path, ip, dll = STRINGS_TWO[0], STRINGS_TWO[1], STRINGS_TWO[2], STRINGS_TWO[3], STRINGS_TWO[4][2:]
    post_ioc = lambda title, v, **kw: {"tool": "bash", "args": {"command": _post(kind="ioc", title=title, value=v, off=hex(offs[v]), confidence="high", **kw)}}
    roles = {
        "triage": [_say("Reading the overview"), {"tool": "read", "args": {"path": "/prep/overview.md"}}, {"text": "Triage done: a tiny static ELF."}],
        "static": [_say("Waiting for the first findings, then checking them"), {"tool": "bash", "args": {"command": "sleep 20; cat /prep/board.json | head -c 300"}},
                   {"tool": "bash", "args": {"command": _post(kind="dispute", title="Not an indicator", of="f1", reason="A documentation address or example domain is not an indicator of anything on its own.")}},
                   {"text": "Static done: disputed the first finding."}],
        "ioc": [_say("Reading the strings file"), {"tool": "bash", "args": {"command": "head -40 /prep/strings.txt"}},
                post_ioc("Update URL", url, detail="A URL on a reserved example domain."), post_ioc("Documentation IP", ip, detail="An address from the documentation range."),
                post_ioc("Temp path", path, detail="A hidden cache path."),
                {"tool": "bash", "args": {"command": _post(kind="ioc", title="Wide library name", value=dll, enc="utf16le", off=hex(offs[dll]), confidence="medium", detail="A UTF-16 path.")}},
                {"text": "Strings done: four indicators posted."}],
        "crypto": [_say("Looking for configuration"), {"tool": "bash", "args": {"command": _post(kind="config", title="Lock name", value=lock, off=hex(offs[lock]), confidence="medium", detail="A lock name.")}},
                   {"text": "Crypto and config done: one configuration string."}],
        "behaviour": [_say("Nothing to map beyond the strings"), {"tool": "bash", "args": {"command": _post(kind="note", title="No code reads the strings", detail="Only an exit call is present.", off=0)}},
                      {"text": "Behaviour done."}],
        "reporter": [{"text": ("## Executive summary\nA tiny demo program with made-up network names. It only exits when run.\n\n"
                               "## What it is\nA small static 64-bit Linux program built for demonstration.\n\n"
                               "## Capabilities\n- It names web and file locations, but nothing in the file uses them.\n\n"
                               "## Recommendations\n- Treat it as a test file.\n\n## What we don't know\n- Whether anything else loads it.\n\n"
                               'ASSESSMENT {"verdict": "suspicious", "confidence": "moderate", "family": "", "basis": ["f1", "f2", "f3"], "rationale": "Made-up network strings; the code only exits."}')}],
    }
    plan = {"summary": "Settle the dispute and let Crypto look again.", "tasks": [{"role": "crypto", "goal": "Look again for configuration values.", "scope": "the read-only data section", "minutes": 2}],
            "resolutions": [{"of": "f1", "verdict": "stands", "text": "The URL is still an indicator even though its domain is reserved for examples."}]}
    return {"model": "mock-1", "roles": roles, "orchestrator": [json.dumps(plan)]}


def write(dest, variant="one"):
    """Write the demo sample and the mock model's script for it into `dest`: demo.elf + mock-script.json, or (variant "two") demo2.elf + mock-script2.json.
    -> (sample path, script path)."""
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    if variant == "two":
        offs = make_elf(d / "demo2.elf", STRINGS_TWO)
        (d / "mock-script2.json").write_text(json.dumps(mock_script_two(offs), indent=1) + "\n")
        return d / "demo2.elf", d / "mock-script2.json"
    offs = make_elf(d / "demo.elf")
    (d / "mock-script.json").write_text(json.dumps(mock_script(offs), indent=1) + "\n")
    return d / "demo.elf", d / "mock-script.json"
