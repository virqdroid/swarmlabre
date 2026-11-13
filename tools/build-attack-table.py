#!/usr/bin/env python3
"""Build swarmlabre/data/attack.json, the MITRE ATT&CK table the Agent Swarms board validates technique findings against.

Host-side maintenance script (not part of any run). Input: the STIX bundles from github.com/mitre-attack/attack-stix-data,
  curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.0/enterprise-attack/enterprise-attack.json
  curl -o mobile-attack.json     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.0/mobile-attack/mobile-attack.json
Run:  python3 -I tools/build-attack-table.py enterprise-attack.json mobile-attack.json
Keeps every technique and sub-technique that is neither revoked nor deprecated: id -> [name, [tactic shortnames]]; a sub-technique is named
"Parent: Sub" and carries its parent's tactics. Tactic order comes from the matrix. Retired ids are kept too, so an old id can be answered with its
successor: `replaced` = {old id: new id} (from MITRE's revoked-by links, only when the new id is a current technique), `deprecated` = ids retired
with no successor. Stdlib only.
"""
import json
import os
import re
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "swarmlabre", "data", "attack.json")
NOTICE = ("ATT&CK is a registered trademark of The MITRE Corporation. (c) 2015-%s The MITRE Corporation. This work is reproduced and distributed with the "
          "permission of The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).")


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and re.fullmatch(r"T\d{4}(\.\d{3})?", r.get("external_id", "")):
            return r["external_id"]
    return None


def one(path):
    objs = json.load(open(path))["objects"]
    by = {o["id"]: o for o in objs}
    coll = next(o for o in objs if o["type"] == "x-mitre-collection")
    tactics = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    matrix = max((o for o in objs if o["type"] == "x-mitre-matrix"), key=lambda m: len(m["tactic_refs"]))      # Mobile also has a small network-effects matrix
    order = [by[r]["x_mitre_shortname"] for r in matrix["tactic_refs"] if r in by and by[r]["x_mitre_shortname"] in tactics]
    tech, parent = {}, {}
    for o in objs:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        i = ext_id(o)
        if i:
            tech[i] = o
    rel = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of" and not o.get("revoked"):
            s, t = by.get(o["source_ref"]), by.get(o["target_ref"])
            if s and t and ext_id(s) and ext_id(t):
                rel[ext_id(s)] = ext_id(t)
    replaced, deprecated = {}, []
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            s, t = by.get(o["source_ref"]), by.get(o["target_ref"])
            if s and t and s["type"] == "attack-pattern" and t["type"] == "attack-pattern" and ext_id(s) and ext_id(t) and ext_id(t) in tech:
                replaced[ext_id(s)] = ext_id(t)
    for o in objs:
        if o["type"] == "attack-pattern" and (o.get("revoked") or o.get("x_mitre_deprecated")) and ext_id(o) and ext_id(o) not in tech and ext_id(o) not in replaced:
            deprecated.append(ext_id(o))
    out = {}
    for i, o in tech.items():
        tac = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name", "").startswith("mitre-") and p["phase_name"] in tactics]
        if "." in i:
            p = tech.get(rel.get(i) or i.split(".")[0])
            if not p:
                continue
            name = "%s: %s" % (p["name"], o["name"])
            tac = tac or [x["phase_name"] for x in p.get("kill_chain_phases", []) if x["phase_name"] in tactics]
        else:
            name = o["name"]
        if tac:
            out[i] = [name, sorted(set(tac), key=order.index)]
    return {"version": coll.get("x_mitre_version", ""), "modified": coll.get("modified", "")[:10], "tactics": [[k, tactics[k]] for k in order], "techniques": dict(sorted(out.items())),
            "replaced": dict(sorted(replaced.items())), "deprecated": sorted(deprecated)}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    ent, mob = one(sys.argv[1]), one(sys.argv[2])
    year = (ent["modified"] or "2026")[:4]
    data = {"notice": NOTICE % year, "source": "https://github.com/mitre-attack/attack-stix-data", "version": ent["version"], "modified": ent["modified"],
            "domains": {"enterprise": ent, "mobile": mob}}
    for d in data["domains"].values():
        d.pop("version", None)
        d.pop("modified", None)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    print("wrote %s: ATT&CK v%s, enterprise %d (+%d retired with a successor), mobile %d (+%d)" % (os.path.normpath(OUT), data["version"], len(ent["techniques"]), len(ent["replaced"]), len(mob["techniques"]), len(mob["replaced"])))


main()
