"""Report prose for Agent Swarms (stdlib only): the fixed sections of the Reporter's answer, the lint that removes internal talk and identifiers from it, and the
wording swarmlabre owns (what a verified technique means in plain words, the standard recommendations, what is not known).

Trust: the Reporter's text is model text about a hostile sample. It is split on heading lines, cut sentence by sentence by `lint`, and always shown labelled as the Reporter's. The tool-owned
sentences below are fixed text keyed on checked facts (ATT&CK tactic slugs from MITRE's table, the verdict word, counts); nothing from the sample or an agent is put into them.
"""
import re

SECTIONS = (("exec", "Executive summary"), ("what", "What it is"), ("caps", "Capabilities"), ("recs", "Recommendations"), ("unknown", "What we don't know"))
TITLE = dict(SECTIONS)
HEAD = {"exec": r"executive summary|summary|overview|in short",
        "what": r"what (?:it|the sample|the file) is|about the (?:sample|file)|the sample",
        "caps": r"capabilit(?:y|ies)|what it (?:appears to )?do(?:es)?|behaviou?r",
        "recs": r"recommendations?|what to do|advice|next steps",
        "unknown": r"what we (?:do not|don'?t|dont) know|unknowns?|gaps(?: and \w+)?|limits(?: of this analysis)?|open questions"}
HEAD_RE = {k: re.compile(r"(?i)(?:%s)\Z" % v) for k, v in HEAD.items()}
HEADLINE = re.compile(r"^[ \t]{0,3}(?:#{1,4}[ \t]*)?[*_]{0,2}([^\n*_#]{2,48}?)[*_]{0,2}[ \t]*:?[ \t]*$")

ID_PAREN = re.compile(r"\s*[(\[]\s*(?:findings?\s+)?f\d{1,5}(?:\s*(?:,|;|and|&|/|to)\s*f\d{1,5})*\s*[)\]]", re.I)
ID_BARE = re.compile(r"\bf\d{1,5}\b")
PROCESS = re.compile(r"\b(?:board|hub|swarmlabre|swarm|orchestrator|steer(?:ed|ing)?|hints?|planning model|round (?:1|2|one|two)|task limit|swarm-(?:post|say|attack)|rea-session|ASSESSMENT|disputed_by|resolution (?:field|verdict)s?|stands/wrong/unresolved|claimed findings?)\b"
                     r"|\bas (?:instructed|requested|told|asked)\b|\bI (?:was|am|have been) (?:asked|told|instructed)\b", re.I)
ACTORS = re.compile(r"\b(?:agents?|reporter|triage|the static agent)\b", re.I)                    # strict only: "the agents did not read the native code" is a fair unknown, but not in an executive summary
NAMES = re.compile(r"\b(?:FUN|DAT|LAB|PTR|thunk_FUN|switchD|caseD|SUB)_[0-9A-Za-z_]+|\bsub_[0-9a-fA-F]{3,}\b|\b0x[0-9a-fA-F]{4,}\b|\boffsets?\s+\d{4,}\b")
SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")
BULLET = re.compile(r"^(\s*(?:[-*•]|\d{1,2}[.)])\s+)(.*)$")


def lint(text, strict=False):
    """(clean text, {ids, process, names}) = the Reporter's text with `(f12, f14)` citations stripped and every sentence removed that still names a finding id, talks about the
    swarmlabre's own workings (board, hub, steering, hints, rounds, the tools' names) and, in `strict` mode (executive summary, recommendations), that names the agents or holds a function name,
    an address or an offset. Counts are of removed or stripped parts; nothing of the text itself is kept."""
    st = {"ids": 0, "process": 0, "names": 0}
    out = []
    for ln in (text or "").replace("\r", "").split("\n"):
        ln, n = ID_PAREN.subn("", ln)
        st["ids"] += n
        m = BULLET.match(ln)
        pre, body = (m.group(1), m.group(2)) if m else ("", ln)
        keep = []
        for s in (SENT.split(body) if body.strip() else [body]):
            if ID_BARE.search(s):
                st["ids"] += 1
            elif PROCESS.search(s) or (strict and ACTORS.search(s)):
                st["process"] += 1
            elif strict and NAMES.search(s):
                st["names"] += 1
            else:
                keep.append(s)
        body = " ".join(keep).strip()
        if not body and ln.strip():
            continue                                                  # the whole line went
        out.append((pre + body) if body else "")
    t = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
    t = re.sub(r"[ \t]+([,.;:!?])(?=\s|$)", r"\1", re.sub(r"[ \t]{2,}", " ", t))
    return t, st


def split_sections(prose):
    """({key: text}, preface) for the fixed headings (a heading is a line of its own that matches HEAD; any other short line stays in the text). Text before the first heading is
    the preface (it becomes the executive summary when the Reporter wrote none). The old headings (What the sample is, What it appears to do, Gaps) map to the same keys."""
    secs, cur, buf, pre = {}, None, [], []
    for ln in (prose or "").split("\n"):
        m = HEADLINE.match(ln)
        k = next((k for k, r in HEAD_RE.items() if m and r.match(m.group(1).strip())), None) if m else None
        if k and k not in secs and k != cur:
            if cur is not None:
                secs[cur] = "\n".join(buf).strip()
            cur, buf = k, []
            continue
        (buf if cur is not None else pre).append(ln)
    if cur is not None:
        secs[cur] = "\n".join(buf).strip()
    return {k: v for k, v in secs.items() if v}, "\n".join(pre).strip()


def structure(prose):
    """The Reporter's answer cleaned and cut into the five sections: ({key: clean text}, one stats dict summed over all sections, canonical prose for the result card)."""
    secs, pre = split_sections(prose)
    if pre and "exec" not in secs:
        secs["exec"] = pre
    elif pre:
        secs["exec"] = pre + "\n\n" + secs["exec"]
    clean, tot = {}, {"ids": 0, "process": 0, "names": 0}
    for k, _t in SECTIONS:
        if k in secs:
            c, st = lint(secs[k], strict=k in ("exec", "recs"))
            for x in tot:
                tot[x] += st[x]
            if c:
                clean[k] = c
    canon = "\n\n".join("%s\n%s" % (TITLE[k], clean[k]) for k, _t in SECTIONS if k in clean)
    return clean, tot, canon


def lint_note(st):
    """Fixed sentence for About this report when the lint removed something (None when it did not)."""
    n = st["ids"] + st["process"] + st["names"]
    if not n:
        return None
    return ("Swarmlabre removed %d sentence%s or citation%s from the Reporter's text because %s referred to internal finding numbers, to swarmlabre's own workings or to function names."
            % (n, "" if n == 1 else "s", "" if n == 1 else "s", "it" if n == 1 else "they"))


# ---- what a verified technique means, in plain words (keyed on ATT&CK tactic slugs: Enterprise v20 has stealth and defense-impairment, Mobile keeps defense-evasion)
PLAIN = {
    "other": "Not tied to a MITRE tactic (the run predates the table swarmlabre checks techniques against).",
    "reconnaissance": "Gathers information about a target before an attack.",
    "resource-development": "Sets up infrastructure or tools for later use.",
    "initial-access": "Contains a way to get onto a system.",
    "execution": "Runs code or commands on the system it is on.",
    "persistence": "Keeps itself on the system so that it survives a restart or a logout.",
    "privilege-escalation": "Tries to gain more rights than it started with.",
    "stealth": "Hides itself or its activity from people and security tools.",
    "defense-impairment": "Weakens or switches off security controls.",
    "defense-evasion": "Hides itself or its activity from people and security tools.",
    "credential-access": "Looks for or takes stored passwords, tokens or keys.",
    "discovery": "Collects information about the system, the user or the network it runs on.",
    "lateral-movement": "Can move from one system to others.",
    "collection": "Gathers data of interest before sending it on.",
    "command-and-control": "Communicates with a server that can control it or receive its data.",
    "exfiltration": "Sends data out of the environment.",
    "impact": "Can disrupt, damage or lock data or systems.",
}
# ---- standard recommendations per tactic slug: what to do if the file ran, never a claim that it did
REC = {
    "persistence": "Check the places the sample uses to start itself (startup folders, scheduled tasks, services, registry run keys, launch agents, boot receivers) on any system where the file ran, and remove what it added.",
    "credential-access": "Treat passwords, session tokens, browser data, wallets and keys stored on any system where the file ran as exposed: reset the passwords, revoke the sessions and tokens, move funds from wallets, and require multi-factor authentication.",
    "command-and-control": "Block and watch the network indicators in this report at your DNS, proxy and firewall, and search past logs for connections to them. Check each against a reputation source before you rely on it.",
    "exfiltration": "Look in network logs for large or unusual uploads from systems where the file ran, and treat the data it could reach as disclosed until shown otherwise.",
    "collection": "List what data the sample can reach (documents, screen, keystrokes, contacts, messages) and tell the owners of that data.",
    "stealth": "Do not trust the tools on a system where the file ran to show it: use an offline scan or rebuild the system from known-good media.",
    "defense-evasion": "Do not trust the tools on a system where the file ran to show it: use an offline scan or rebuild the system from known-good media.",
    "defense-impairment": "Check that antivirus, logging and firewall settings on any system where the file ran are still on and unchanged, and restore them.",
    "execution": "Search endpoint and process logs for the commands and child processes named in this report.",
    "privilege-escalation": "Review the accounts and permissions on any system where the file ran, and reset any that changed.",
    "lateral-movement": "Check the other systems the affected one can reach for the same file hashes and the indicators in this report.",
    "discovery": "Review what the sample could learn about the system and network, and use that to scope who and what else to check.",
    "impact": "Check backups and the availability of the affected data and systems before you restore anything, and keep an offline copy.",
    "initial-access": "Find out how the file arrived (mail, download, update, removable media) and close that route.",
}
REC_FIRST = {
    "malicious": ["Do not run the file. Keep the original and its SHA-256 for your records and store it where it cannot be started by accident.",
                  "If the file ran on any system, treat that system as compromised: isolate it, keep evidence, and follow your incident response process. This report comes from static analysis and cannot say whether the file ran."],
    "suspicious": ["Do not run the file outside an isolated test system. Keep the original and its SHA-256 for your records.",
                   "If the file ran on any system, treat that system as at risk until you have looked at it. This report comes from static analysis and cannot say whether the file ran."],
    "undetermined": ["Treat the file as unverified. Do not run it outside an isolated test system.",
                     "The analysis did not find enough to decide. Consider analysing the file while it runs, or ask another reviewer."],
    "benign": ["No action is needed because of this analysis.",
               "A benign verdict means no malicious behaviour was found by reading the file; it does not prove the file is safe."],
}


def recommendations(verdict, tactics, has_net, has_yara, has_hashes=True):
    """Standard recommendations (fixed text): the opening ones for the verdict, one per verified tactic slug, then the use of the exports. Order is stable."""
    out = list(REC_FIRST.get(verdict, REC_FIRST["undetermined"]))
    if verdict in ("malicious", "suspicious"):
        seen = set()
        for t in tactics:
            r = REC.get(t)
            if r and r not in seen:
                seen.add(r)
                out.append(r)
        if has_hashes:
            out.append("Search your endpoint and mail tools for the file hashes in this report.")
        if has_yara:
            out.append("Test the YARA rules on a set of clean files first, then use them to hunt for the same file and close variants.")
        if has_net and "command-and-control" not in tactics:
            out.append("Check network logs for the addresses and domains in the indicators section before deciding they are harmless or harmful: this report does not judge them.")
    return out


def unknowns(kind, verdict, has_net, n_unconfirmed, n_disputed_open, gaps, native_ok=True):
    """What is not known, as fixed sentences from facts swarmlabre holds. `gaps` = swarmlabre's own gap sentences (tasks that did not finish)."""
    out = ["The file was analysed by reading it, never by running it. What it does while it runs, what it downloads or drops, and whether its servers answer today are not known."]
    if has_net:
        out.append("The network addresses and domains in this report were not contacted. Whether they are live, and who runs them, is not known.")
    out.append("Who wrote or uses this file is not known: the report does not attribute it.")
    if kind == "apk":
        out.append("Native libraries inside the package were listed and scanned for strings only, not analysed in depth.")
    if not native_ok:
        out.append("The native analysis tool was not available for this run, so what the machine code does is less well covered.")
    if n_unconfirmed:
        out.append("%d further claim%s could not be checked against the file and %s not relied on. %s listed at the end of the technical sections as leads." % (
            n_unconfirmed, "" if n_unconfirmed == 1 else "s", "is" if n_unconfirmed == 1 else "are", "It is" if n_unconfirmed == 1 else "They are"))
    if n_disputed_open:
        out.append("%d finding%s %s disputed and %s not settled." % (n_disputed_open, "" if n_disputed_open == 1 else "s", "is" if n_disputed_open == 1 else "are", "is" if n_disputed_open == 1 else "are"))
    out += gaps
    if verdict == "benign":
        out.append("A benign verdict is not a safety claim: behaviour that only shows at run time, or that the analysis did not reach, would not be found this way.")
    return out


def exec_fallback(verdict_word, conf, label, size, family, n_checked, n_unconfirmed):
    """Executive summary when the Reporter wrote none (or all of it was removed): facts swarmlabre holds, in plain words."""
    s = "Verdict: %s%s. The file is %s (%s)%s." % (verdict_word, (", %s confidence" % conf) if conf else "", label, size, (", identified as %s" % family) if family else "")
    s += " %d statement%s about it %s checked against the file itself." % (n_checked, "" if n_checked == 1 else "s", "was" if n_checked == 1 else "were")
    if n_unconfirmed:
        s += " %d further claim%s could not be checked and %s not relied on." % (n_unconfirmed, "" if n_unconfirmed == 1 else "s", "is" if n_unconfirmed == 1 else "are")
    return s + " No narrative summary was written for this run."


REPORT_FORMAT = 4
FORMAT_LOG = (
    (4, "2026-10-21", "Fixed sections (executive summary, what it is, capabilities, recommendations, what we don't know), YARA rules, contents, this appendix and the analysis environment."),
    (3, "2026-10-21", "Indicators grouped by the Pyramid of Pain and defanged; CSV, STIX 2.1 and MISP exports."),
    (2, "2026-10-21", "Cover with TLP marking, assessment with a verdict and a confidence the evidence caps, sample snapshot with hashes."),
    (1, "2026-10-19", "Interactive HTML report with the map, byte windows, findings and a replay."),
)
GLOSSARY = (
    ("Finding", "A statement about the file that an agent posted and swarmlabre checked."),
    ("Byte-checked", "Swarmlabre found exactly these bytes at that offset in its own copy of the file."),
    ("Call-cited", "Every tool call the agent cited exists in this run's tool log and its id appeared in that agent's session output. That does not prove this agent made the call, and it does not prove a tool's output was read correctly."),
    ("Claimed", "Neither of the above. Claims are listed apart as leads and never counted."),
    ("Indicator", "A value found in the file (a hash, address, name or string). The report does not judge whether an indicator is malicious."),
    ("Verdict and confidence", "The Reporter's judgement. Swarmlabre checks it against the findings it cites and can lower the confidence, never raise it."),
)
