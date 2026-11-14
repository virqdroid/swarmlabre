TLP:CLEAR. Disclosure is not limited.

# Malware analysis report: demo.elf


Contents: 1 Assessment; 2 Executive summary; 3 What it is; 4 Capabilities; 5 Recommendations; 6 What we don't know; 7 Sample snapshot; 8 Indicators of compromise; 9 Functions; 10 Cryptography and configuration; 11 Capability findings; 12 Notes on the file; 13 Unconfirmed claims; 14 MITRE ATT&CK; 15 Detection engineering; 16 Disputes; 17 About this report; 18 Analysis environment

- ELF64 x86-64, 528 bytes
- SHA-256 c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e
- run s598de684, status done, model mock
- 1 verified (1 byte-checked), 1 unconfirmed, 0 disputed, 0 refuted, 0 rejected

## Assessment

| item | assessment |
|---|---|
| Verdict | Undetermined |
| Confidence | Low |
| Family or software | Not identified |

Reporter's reasoning (model judgement, not checked by swarmlabre): It looks bad.

Changes swarmlabre made:

- Some cited findings are not verified on the board and were dropped from the basis.
- The Reporter gave a verdict without citing a checked finding, so swarmlabre shows it as undetermined.
- Confidence was lowered from high to low: no verified finding is cited.

Limits: static analysis only, the sample was never run. A benign verdict means nothing malicious was found, not that the file is safe.

## Executive summary

A tiny generated test file with made-up network names. It only exits when run.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

## What it is

A small generated program.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

ELF64 x86-64, 1 KB, SHA-256 c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e. Its properties are listed under Sample snapshot.

## Capabilities

No ATT&CK technique was verified for this file.

The Reporter's description of what the file can do.

- It names a web address, but nothing in the file uses it.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

Evidence levels. byte-checked: swarmlabre found these exact bytes at that offset in the file. call-cited: every tool call the agent cited exists in this run's tool log and its id appeared in that agent's session output; that does not prove this agent made the call, or that a tool's output was read correctly. claimed: neither, so it is listed apart and never counted in the summary.

## Recommendations

Standard actions (fixed text, chosen from what was verified):

- Treat the file as unverified. Do not run it outside an isolated test system.
- The analysis did not find enough to decide. Consider analysing the file while it runs, or ask another reviewer.

Suggestions from the Reporter for this file (model text, not checked by swarmlabre):

- Treat it as a test file.

## What we don't know

- The file was analysed by reading it, never by running it. What it does while it runs, what it downloads or drops, and whether its servers answer today are not known.
- The network addresses and domains in this report were not contacted. Whether they are live, and who runs them, is not known.
- Who wrote or uses this file is not known: the report does not attribute it.
- 1 further claim could not be checked against the file and is not relied on. It is listed at the end of the technical sections as leads.
- Static: did not run.
- Crypto/Config: did not run.
- Behaviour: did not run.

What the Reporter says it could not establish (model text, not checked by swarmlabre):

- Whether anything else loads it.

## Indicators of compromise

These are values the agents found in the file and swarmlabre checked. Swarmlabre does not judge whether a value is malicious: a vendor URL, a library path or a documentation link can sit in a malicious file too. Review before you block. Network values are defanged here; the exports hold the real values.

### URLs

| type | indicator | context |
|---|---|---|
| URL | hxxp://c2[.]example[.]test/beacon | C2 URL. byte-checked, offset 0x95, finding f2. |

## Functions

None.

## Cryptography and configuration

None.

## Capability findings

None.

## Notes on the file

None.

## Unconfirmed claims

| id | finding | value | offset | evidence | agents |
|---|---|---|---|---|---|
| f1 | Looks bad |  |  | claimed | triage |

## MITRE ATT&CK

No technique was verified. ATT&CK is a registered trademark of The MITRE Corporation. (c) 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Detection engineering

No rule was written: 1 string passed the filters and a rule needs at least 4. The strings swarmlabre byte-checked in this file were too short, too common or too few to hunt with.

## Disputes

None.

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
| swarmlabre revision | not recorded for this run |
| Model | mock (served by mock) |
| Parallel model requests | 2 (what the model server offers) |
| rea (reverse-engineering toolbox) | not recorded for this run |
| Ghidra | not recorded for this run |
| Java | not recorded for this run |
| Apktool | not recorded for this run |
| JADX | not recorded for this run |
| MITRE ATT&CK table | version 20.0 |
| Isolation | Two containers, both without any network: one holds the analysis tools and the sample (read-only), one holds the agents. The model is reached only through a socket swarmlabre opens for this run. Read-only root file systems, all capabilities dropped, memory, CPU and process limits, and a private working folder for each agent. |
| Limits | not recorded for this run |
| Agents | Triage, Static, Strings/IOC, Crypto/Config, Behaviour, Reporter |
| Rounds | 1 |
| Duration | 1 min |

