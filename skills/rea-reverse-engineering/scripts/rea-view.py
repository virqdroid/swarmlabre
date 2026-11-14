#!/usr/bin/env python3
"""Read one part of a saved rea result without running the analysis again.

  rea-view.py EVIDENCE.json summary
  rea-view.py EVIDENCE.json page collection=modules offset=0 limit=16
  rea-view.py EVIDENCE.json item collection=modules selector.node_id=<id>
  rea-view.py EVIDENCE.json native facet=pseudocode offset=0 limit=4000

EVIDENCE.json is the output of `rea <command> --format json > EVIDENCE.json` (analyze-javascript-application, or
function/decompile for the native facets). The view is `{"kind": <kind>, ...}` built from the key=value pairs; a dotted key
makes a nested object, numbers become numbers. Extra rea flags can follow `--`. Stdlib only; nothing is written outside /tmp.
"""
import json, os, subprocess, sys, tempfile

def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, kind, rest = argv[1], argv[2], argv[3:]
    extra = []
    if "--" in rest:
        i = rest.index("--")
        rest, extra = rest[:i], rest[i + 1:]
    view = {"kind": kind}
    for kv in rest:
        if "=" not in kv:
            print(f"expected key=value, got {kv!r}", file=sys.stderr)
            return 2
        k, v = kv.split("=", 1)
        v = int(v) if v.lstrip("-").isdigit() else v
        node = view
        parts = k.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = v
    try:
        with open(path, encoding="utf-8") as f:
            evidence = json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return 1
    if isinstance(evidence, dict) and isinstance(evidence.get("data"), dict) and "evidence_id" in evidence["data"]:
        evidence = evidence["data"]  # --full-output wraps the record
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="rea-view-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"source": {"kind": "inline", "evidence": evidence}, "view": view}, f)
        base = ["rea", "inspect-analysis-view", tmp] + extra
        r = subprocess.run(base + ["--filter-output", "evidence_id,normalized_result"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() not in ("", "{}"):
            sys.stdout.write(r.stdout)
            return 0
        # --filter-output turns an error into empty output: show the real message
        r = subprocess.run(base, capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode or 1
    finally:
        os.unlink(tmp)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
