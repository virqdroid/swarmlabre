"""Machine-readable indicator exports of an Agent Swarms run: CSV, a STIX 2.1 bundle and a MISP event (iocs.csv, iocs.stix.json, iocs.misp.json).

stdlib only. Input is what `report.ioc_rows` returns (checked values, real, not defanged) plus the run's cover and record.
Rules: the sample's own hashes and checked findings nobody disputes go in (`report.exportable`); every row carries its evidence level (byte-checked,
call-cited, computed) and the exports never claim more than that: STIX confidence 85 / 50 / 100, MISP `to_ids` only for byte-checked values of a kind
that is matchable; unconfirmed, refuted and disputed findings never appear. Swarmlabre does not judge maliciousness: STIX indicator_types is ["unknown"].
Real values are in these files on purpose (a blocklist needs them); the report formats defang.
"""
import csv, io, json, re, time, uuid

from . import clock
from .report import defang as _defang

NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/virqdroid/swarmlabre/export")      # ids below are uuid5 over run + content: re-exporting a run gives the same ids
SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")                              # the STIX 2.1 namespace for deterministic SCO ids
CONFIDENCE = {"byte-checked": 85, "call-cited": 50, "computed": 100}              # STIX 2.1 spec's suggested Low 15 / Med 50 / High 85 bands, 100 for what swarmlabre computed
# TLP 2.0 marking definitions and their extension definition, exactly as OASIS publishes them
# (github.com/oasis-open/cti-stix-common-objects, extension-definition-specifications/tlp-2.0; ids and values checked there 2026-10-21)
TLP_EXT = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP_IDS = {"CLEAR": ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "clear"), "GREEN": ("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "green"),
           "AMBER": ("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "amber"), "AMBER+STRICT": ("marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003", "amber+strict"),
           "RED": ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "red")}
TLP_EXT_OBJ = {"id": TLP_EXT, "type": "extension-definition", "spec_version": "2.1", "name": "TLP 2.0", "description": "This defines TLP 2.0 as a STIX extension", "created": "2022-10-01T00:00:00.000Z",
               "modified": "2022-10-01T00:00:00.000Z", "created_by_ref": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
               "schema": "https://github.com/oasis-open/cti-stix-common-objects/tree/master/extension-definition-specifications/tlp-2.0", "version": "1.0.0", "extension_types": ["property-extension"]}
STIX_HASH = {"MD5": "MD5", "SHA-1": "SHA-1", "SHA-256": "SHA-256"}


def _ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".000Z"


def _u(kind, *parts):
    return "%s--%s" % (kind, uuid.uuid5(NS, "\0".join(str(p) for p in parts)))


def lit(s):
    """A STIX pattern string literal: backslash and single quote escaped, nothing else."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern(r):
    """The STIX pattern for a row, or None when STIX has no honest way to say it (paths, Android names, other strings, finding-derived hex strings, private addresses)."""
    g, t, n = r["group"], r["type"], r["norm"]
    if g == "hash" and r.get("sample") and t in STIX_HASH:
        return "[file:hashes.%s = %s]" % (lit(STIX_HASH[t]), lit(n))
    if g == "ip" and not r["private"]:
        return "[%s:value = %s]" % ("ipv6-addr" if ":" in n else "ipv4-addr", lit(n))
    if g == "domain":
        return "[domain-name:value = %s]" % lit(n)
    if g == "url":
        return "[url:value = %s]" % lit(r["value"])
    if t == "Email address":
        return "[email-addr:value = %s]" % lit(n)
    if t == "User agent":
        return "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = %s]" % lit(r["value"])
    if t == "Registry key":
        return "[windows-registry-key:key = %s]" % lit(r["value"])
    return None


def _desc(r, run):
    how = {"byte-checked": "Swarmlabre found these exact bytes in the file at offset 0x%x." % r["off"] if r.get("off") is not None else "Swarmlabre found these exact bytes in the file.",
           "call-cited": "An analysis agent cited a tool call for this value; the call exists in the run's tool log and its id appeared in that agent's session output (not proof that this agent made it). The value was not located as raw bytes in the file.",
           "computed": "Computed by swarmlabre from the file."}[r["level"]]
    return "Found in the analysed sample (swarm run %s). %s Swarmlabre does not judge whether this value is malicious." % (run, how)


def stix_bundle(rows, cover, rec, sample, org=""):
    """STIX 2.1 bundle: identity, TLP marking (+ its extension definition), a file observable for the sample, one indicator per row STIX can express, and a report object."""
    rid = rec["id"]
    t1 = rec.get("finished") or rec.get("created") or clock.now()
    ts = _ts(t1)
    ident_name = (cover.get("org") or "swarmlabre")[:200]
    ident = {"type": "identity", "spec_version": "2.1", "id": _u("identity", "org", ident_name), "created": ts, "modified": ts, "name": ident_name, "identity_class": "organization"}
    if cover.get("contact"):
        ident["contact_information"] = cover["contact"][:200]
    objs = [ident]
    mark = TLP_IDS.get(cover.get("tlp"))
    if mark:
        objs += [dict(TLP_EXT_OBJ), {"type": "marking-definition", "spec_version": "2.1", "id": mark[0], "created": "2022-10-01T00:00:00.000Z", "name": "TLP:" + cover["tlp"],
                                      "extensions": {TLP_EXT: {"extension_type": "property-extension", "tlp_2_0": mark[1]}}}]
    hashes = {STIX_HASH[x["label"]]: x["value"] for x in sample.get("snapshot", []) if x["label"] in STIX_HASH}
    refs = []
    if hashes:
        fid = "file--%s" % uuid.uuid5(SCO_NS, json.dumps({"hashes": hashes}, sort_keys=True, separators=(",", ":")))
        f = {"type": "file", "spec_version": "2.1", "id": fid, "hashes": hashes, "size": sample["size"]}
        if sample.get("name") and not re.fullmatch(r"[0-9a-fA-F]{32,64}(\.\w+)?", sample["name"]):
            f["name"] = sample["name"][:200]
        objs.append(f)
        refs.append(fid)
    n = 0
    for r in rows:
        p = pattern(r)
        if not p:
            continue
        i = {"type": "indicator", "spec_version": "2.1", "id": _u("indicator", rid, p), "created": ts, "modified": ts, "created_by_ref": ident["id"],
             "name": ("%s: %s" % (r["type"], _defang(r["value"])))[:250], "description": _desc(r, rid), "indicator_types": ["unknown"], "pattern": p, "pattern_type": "stix", "valid_from": ts,
             "confidence": CONFIDENCE[r["level"]], "x_swarmlabre_evidence": r["level"]}
        if r.get("off") is not None:
            i["x_swarmlabre_offset"] = r["off"]
        if mark:
            i["object_marking_refs"] = [mark[0]]
        objs.append(i)
        refs.append(i["id"])
        n += 1
    rep = {"type": "report", "spec_version": "2.1", "id": _u("report", rid), "created": ts, "modified": ts, "created_by_ref": ident["id"], "name": (cover.get("title") or "Malware analysis report")[:250],
           "description": "Indicators from an automated static analysis (run %s, %s). Evidence levels: byte-checked 85, call-cited 50, computed 100 (STIX confidence). Static analysis only: the sample was never run." % (rid, cover.get("date", "")),
           "report_types": ["malware"], "published": ts, "object_refs": refs or [ident["id"]]}
    if mark:
        rep["object_marking_refs"] = [mark[0]]
    objs.append(rep)
    return {"type": "bundle", "id": _u("bundle", rid, len(objs)), "objects": objs}


MISP_TYPE = {"ip": ("ip-dst", "Network activity"), "domain": ("domain", "Network activity"), "url": ("url", "Network activity")}


def misp_attr(r):
    """(type, category, to_ids) of a row for MISP. to_ids is true only for byte-checked or computed values of a kind that detection can match."""
    g, t = r["group"], r["type"]
    ok = r["level"] in ("byte-checked", "computed")
    if g == "hash":
        if r.get("sample"):
            return ("imphash" if t == "Imphash" else {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}[t]), "Payload delivery", True
        return {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}[r["algo"]], "Payload delivery", False      # a hex string of that length found in the file: may be a key or an id
    if g in MISP_TYPE:
        typ, cat = MISP_TYPE[g]
        if g == "ip":
            typ = "ip-dst|port" if r.get("port") else typ
        return typ, cat, ok and not (g == "ip" and r["private"])
    if t == "Email address":
        return "email-src", "Network activity", ok
    if t == "User agent":
        return "user-agent", "Network activity", ok
    if t == "Registry key":
        return "regkey", "Artifacts dropped", ok
    if t in ("File path", "Windows file path", "Windows path (fragment)", "File name"):
        return "filename", "Artifacts dropped", False
    if t == "Registry key path (no hive)":
        return "regkey", "Artifacts dropped", False
    return "other", "Other", False


def misp_event(rows, cover, rec):
    rid = rec["id"]
    t1 = rec.get("finished") or rec.get("created") or clock.now()
    attrs = []
    for r in rows:
        typ, cat, ids = misp_attr(r)
        v = r["value"]
        if typ == "ip-dst|port":
            v = "%s|%s" % (r["norm"], r["port"])
        elif typ == "ip-dst":
            v = r["norm"]
        elif typ in ("md5", "sha1", "sha256", "sha512", "imphash"):
            v = r["norm"]
        comment = "%s%s. %s" % ("Sample " if r.get("sample") else "", r["level"], "Finding %s." % ", ".join(r["fids"][:6]) if r["fids"] else "Computed by swarmlabre from the file.")
        if r.get("off") is not None:
            comment = comment[:-1] + ", offset 0x%x." % r["off"]
        attrs.append({"uuid": str(uuid.uuid5(NS, "\0".join(("misp", rid, typ, v)))), "type": typ, "category": cat, "value": v[:2000], "to_ids": ids, "comment": comment[:300], "distribution": "5",
                      "timestamp": str(int(t1))})
    tags = [{"name": "tlp:%s" % cover["tlp"].lower(), "colour": "#000000"}] if cover.get("tlp") else []
    return {"Event": {"uuid": str(uuid.uuid5(NS, "misp-event\0" + rid)), "info": (cover.get("title") or "Malware analysis report")[:250] + " (static analysis, run %s)" % rid, "date": cover.get("date") or time.strftime("%Y-%m-%d", time.gmtime(t1)),
                      "threat_level_id": "4", "analysis": "2", "distribution": "0", "published": False, "timestamp": str(int(t1)), "Tag": tags, "Attribute": attrs}}


CSV_COLS = ("tlp", "group", "type", "indicator", "defanged", "evidence", "offset", "findings", "context", "run")


def _cell(v):
    """A spreadsheet reads a cell that starts with = + - @ tab or CR as a formula: a leading single quote makes it text. Indicators that start that way are rare; this one rule covers every column."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def csv_text(rows, cover, rec, labels, defang, context):
    """All exportable rows, including 'Other strings' (type String), with the real value and the defanged one side by side."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CSV_COLS)
    for r in rows:
        w.writerow([_cell(x) for x in (cover.get("tlp", ""), labels.get(r["group"], r["group"]), r["type"], r["value"], defang(r["value"]), r["level"], ("0x%x" % r["off"]) if r.get("off") is not None else "",
                                       " ".join(r["fids"]), context(r), rec["id"])])
    return out.getvalue()


def build_all(rows, cover, rec, sample, labels, defang, context):
    """{file name: text} for the three exports; `rows` are already filtered to what may be exported."""
    return {"iocs.csv": csv_text(rows, cover, rec, labels, defang, context),
            "iocs.stix.json": json.dumps(stix_bundle(rows, cover, rec, sample), indent=1),
            "iocs.misp.json": json.dumps(misp_event(rows, cover, rec), indent=1)}
