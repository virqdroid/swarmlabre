TLP:AMBER. Limited disclosure, restricted to the recipient's organization and its clients.

# Malware analysis report: demo2.elf


Contents: 1 Assessment; 2 Executive summary; 3 What it is; 4 Capabilities; 5 Recommendations; 6 What we don't know; 7 Sample snapshot; 8 Indicators of compromise; 9 Functions; 10 Cryptography and configuration; 11 Capability findings; 12 Notes on the file; 13 Unconfirmed claims; 14 MITRE ATT&CK; 15 Detection engineering; 16 Disputes; 17 About this report; 18 Analysis environment

- ELF64 x86-64, 552 bytes
- SHA-256 4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564
- run sfaef16e6, status done, model mock-1
- 5 verified (5 byte-checked), 1 unconfirmed, 0 disputed, 0 refuted, 1 rejected

## Assessment

| item | assessment |
|---|---|
| Verdict | Suspicious |
| Confidence | Moderate |
| Family or software | Not identified |

Reporter's reasoning (model judgement, not checked by swarmlabre): Made-up network strings; the code only exits.

Based on:

- f1: Lock name (byte-checked)
- f2: Update URL (byte-checked)
- f3: Documentation IP (byte-checked)

Limits: static analysis only, the sample was never run. A benign verdict means nothing malicious was found, not that the file is safe.

## Executive summary

A tiny demo program with made-up network names. It only exits when run.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

## What it is

A small static 64-bit Linux program built for demonstration.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

ELF64 x86-64, 1 KB, SHA-256 4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564. Its properties are listed under Sample snapshot.

## Capabilities

No ATT&CK technique was verified for this file.

The Reporter's description of what the file can do.

- It names web and file locations, but nothing in the file uses them.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

Evidence levels. byte-checked: swarmlabre found these exact bytes at that offset in the file. call-cited: every tool call the agent cited exists in this run's tool log and its id appeared in that agent's session output; that does not prove this agent made the call, or that a tool's output was read correctly. claimed: neither, so it is listed apart and never counted in the summary.

## Recommendations

Standard actions (fixed text, chosen from what was verified):

- Do not run the file outside an isolated test system. Keep the original and its SHA-256 for your records.
- If the file ran on any system, treat that system as at risk until you have looked at it. This report comes from static analysis and cannot say whether the file ran.
- Search your endpoint and mail tools for the file hashes in this report.
- Test the YARA rules on a set of clean files first, then use them to hunt for the same file and close variants.
- Check network logs for the addresses and domains in the indicators section before deciding they are harmless or harmful: this report does not judge them.

Suggestions from the Reporter for this file (model text, not checked by swarmlabre):

- Treat it as a test file.

## What we don't know

- The file was analysed by reading it, never by running it. What it does while it runs, what it downloads or drops, and whether its servers answer today are not known.
- The network addresses and domains in this report were not contacted. Whether they are live, and who runs them, is not known.
- Who wrote or uses this file is not known: the report does not attribute it.
- 1 further claim could not be checked against the file and is not relied on. It is listed at the end of the technical sections as leads.
- 1 posted findings were rejected by swarmlabre: duplicate 1.

What the Reporter says it could not establish (model text, not checked by swarmlabre):

- Whether anything else loads it.

## Sample snapshot

Read by swarmlabre from the file itself; no agent wrote these values.

| property | value |
|---|---|
| File type | ELF64 x86-64 |
| Size | 552 bytes |
| MD5 | d0e6226b2c5e01d1f8bc9c46c32591be |
| SHA-1 | e7d9e12462cea4c74018b33cd19b685143b0595e |
| SHA-256 | 4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564 |
| Entropy | 2.81 bits per byte over the whole file |
| High-entropy data | None: no part of the file is at 7.2 bits per byte or more |
| Entry point | 0x400078 |
| Section headers | 4 |

## Indicators of compromise

These are values the agents found in the file and swarmlabre checked. Swarmlabre does not judge whether a value is malicious: a vendor URL, a library path or a documentation link can sit in a malicious file too. Review before you block. Network values are defanged here; the exports hold the real values.

### Hash values

| type | indicator | context |
|---|---|---|
| MD5 | d0e6226b2c5e01d1f8bc9c46c32591be | Sample file. Computed by swarmlabre from the file itself. |
| SHA-1 | e7d9e12462cea4c74018b33cd19b685143b0595e | Sample file. Computed by swarmlabre from the file itself. |
| SHA-256 | 4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564 | Sample file. Computed by swarmlabre from the file itself. |

### IP addresses

| type | indicator | context |
|---|---|---|
| IPv4 address | 203[.]0[.]113[.]9 | Documentation IP. byte-checked, offset 0xda, finding f3, private or reserved address. |

### URLs

| type | indicator | context |
|---|---|---|
| URL | hxxps://updates[.]example[.]test/check | Update URL. byte-checked, offset 0x95, finding f2. |

### Host artifacts

| type | indicator | context |
|---|---|---|
| File path | /tmp/.demo-cache | Temp path. byte-checked, offset 0xc9, finding f4. |
| Windows file path | C:\Demo\agent.dll | Wide library name. byte-checked, offset 0xe6, finding f5. |

## Functions

None.

## Cryptography and configuration

| id | finding | value | offset | evidence | agents |
|---|---|---|---|---|---|
| f1 | Lock name | Global\Demo2Lock | 0xb8 | byte-checked | crypto |

## Capability findings

None.

## Notes on the file

None.

## Unconfirmed claims

| id | finding | value | offset | evidence | agents |
|---|---|---|---|---|---|
| f6 | No code reads the strings |  | 0x0 | claimed | behaviour |

## MITRE ATT&CK

No technique was verified. ATT&CK is a registered trademark of The MITRE Corporation. (c) 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Detection engineering

Each rule was written from strings swarmlabre byte-checked in the sample, then read back and matched against the sample by swarmlabre's own matcher, which implements only the part of YARA these rules use (this box has no YARA program). All strings were found and the condition held for every rule listed.

### Swarmlabre_ELF_4f514261553c

4 strings, at least 3 must be present.

```yara
rule Swarmlabre_ELF_4f514261553c {
    meta:
        description = "Byte-checked strings from the Linux ELF sample, SHA-256 4f514261553c3026... (4 strings, at least 3 must be present)"
        author = "swarmlabre"
        date = "2026-11-13"
        reference = "Agent Swarms run sfaef16e6"
        hash = "4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564"
        tlp = "AMBER"
        sample_type = "Linux ELF"
        source = "strings swarmlabre byte-checked in the sample"
        false_positives = "see the note in the report; not tested on clean files"
    strings:
        $s1 = "https\x3a//updates\x2eexample\x2etest/check" ascii
        $s2 = "Global\\Demo2Lock" ascii
        $s3 = "/tmp/.demo-cache" ascii
        $w1 = "C:\\Demo\\agent.dll" wide
    condition:
        uint32(0) == 0x464c457f and filesize < 1MB and 3 of them
}
```

Before you use these rules: The strings were picked by fixed filters (length, not a plain word, not a system path or documentation address) and the rule was checked only against the sample it came from, not against a collection of clean files. Run it over your own clean set before you block on it. Network strings are written with \xNN escapes here so that no real address is printed; the rule is the same. The download detection.yar holds the same rules with the plain strings.

Byte-checked strings left out:

- 1: a version number or number list

## Disputes

- f1 Lock name: static: A documentation address or example domain is not an indicator of anything on its own.. Resolution: stands, The URL is still an indicator even though its domain is reserved for examples.

## Rounds

- Round 1: One task per role, started at once (built in). 5 of 5 tasks finished; 6 findings, 4 verified, 1 disputed.
- Round 2: Settle the dispute and let Crypto look again. 1 of 1 tasks finished; the board now holds 6 findings, 5 verified, 0 disputed, 0 refuted.

## About this report

This report was written by an automated agent swarm and checked by swarmlabre as described here. No person has reviewed it unless a reviewer is named on the cover.

| term | meaning |
|---|---|
| Finding | A statement about the file that an agent posted and swarmlabre checked. |
| Byte-checked | Swarmlabre found exactly these bytes at that offset in its own copy of the file. |
| Call-cited | Every tool call the agent cited exists in this run's tool log and its id appeared in that agent's session output. That does not prove this agent made the call, and it does not prove a tool's output was read correctly. |
| Claimed | Neither of the above. Claims are listed apart as leads and never counted. |
| Indicator | A value found in the file (a hash, address, name or string). The report does not judge whether an indicator is malicious. |
| Verdict and confidence | The Reporter's judgement. Swarmlabre checks it against the findings it cites and can lower the confidence, never raise it. |

Report format:

- Format 4, 2026-10-21: Fixed sections (executive summary, what it is, capabilities, recommendations, what we don't know), YARA rules, contents, this appendix and the analysis environment.
- Format 3, 2026-10-21: Indicators grouped by the Pyramid of Pain and defanged; CSV, STIX 2.1 and MISP exports.
- Format 2, 2026-10-21: Cover with TLP marking, assessment with a verdict and a confidence the evidence caps, sample snapshot with hashes.
- Format 1, 2026-10-19: Interactive HTML report with the map, byte windows, findings and a replay.

## Analysis environment

| item | value |
|---|---|
| Report format | 4, 2026-10-21 |
| swarmlabre revision | 0.1.0 |
| Model | mock-1 (served by mock) |
| Parallel model requests | 4 (set by the operator) |
| rea (reverse-engineering toolbox) | 6.4.0 |
| Ghidra | 12.1.4 |
| Java | not recorded for this run |
| Apktool | 3.0.3 |
| JADX | jadx-headless-mcp 0.7.1 |
| MITRE ATT&CK table | version 20.0 |
| Isolation | Two containers, both without any network: one holds the analysis tools and the sample (read-only), one holds the agents. The model is reached only through a socket swarmlabre opens for this run. Read-only root file systems, all capabilities dropped, memory, CPU and process limits, and a private working folder for each agent. |
| Limits | tools 6.0 GiB and 4 CPUs, agents 1.4 GiB |
| Agents | Triage, Static, Strings/IOC, Crypto/Config, Behaviour, Reporter |
| Rounds | 2 |
| Duration | 1 min |

