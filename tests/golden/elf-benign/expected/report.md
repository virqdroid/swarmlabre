TLP:AMBER. Limited disclosure, restricted to the recipient's organization and its clients.

# Malware analysis report: demo.elf


Contents: 1 Assessment; 2 Executive summary; 3 What it is; 4 Capabilities; 5 Recommendations; 6 What we don't know; 7 Sample snapshot; 8 Indicators of compromise; 9 Functions; 10 Cryptography and configuration; 11 Capability findings; 12 Notes on the file; 13 Unconfirmed claims; 14 MITRE ATT&CK; 15 Detection engineering; 16 Disputes; 17 About this report; 18 Analysis environment

- ELF64 x86-64, 528 bytes
- SHA-256 c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e
- run sf549b7df, status done, model mock-1
- 4 verified (4 byte-checked), 2 unconfirmed, 0 disputed, 0 refuted, 0 rejected

## Assessment

| item | assessment |
|---|---|
| Verdict | No malicious behaviour found |
| Confidence | Moderate |
| Family or software | Not identified |

Reporter's reasoning (model judgement, not checked by swarmlabre): The strings are made-up examples and the code only exits.

Based on:

- f2: C2 URL (byte-checked)

Changes swarmlabre made:

- Some cited findings are not verified on the board and were dropped from the basis.

Limits: static analysis only, the sample was never run. A benign verdict means nothing malicious was found, not that the file is safe.

## Executive summary

This is a tiny demo program. It contains a made-up web address and a made-up mutex name, and it only exits when run.

*Written by the Reporter agent. Model text: swarmlabre removed internal references from it but does not check it.*

## What it is

A small static 64-bit Linux program built for demonstration.

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

- No action is needed because of this analysis.
- A benign verdict means no malicious behaviour was found by reading the file; it does not prove the file is safe.

Suggestions from the Reporter for this file (model text, not checked by swarmlabre):

- Treat it as a test file.

## What we don't know

- The file was analysed by reading it, never by running it. What it does while it runs, what it downloads or drops, and whether its servers answer today are not known.
- The network addresses and domains in this report were not contacted. Whether they are live, and who runs them, is not known.
- Who wrote or uses this file is not known: the report does not attribute it.
- 2 further claims could not be checked against the file and are not relied on. They are listed at the end of the technical sections as leads.
- A benign verdict is not a safety claim: behaviour that only shows at run time, or that the analysis did not reach, would not be found this way.

What the Reporter says it could not establish (model text, not checked by swarmlabre):

- Whether anything else loads it.

## Sample snapshot

Read by swarmlabre from the file itself; no agent wrote these values.

| property | value |
|---|---|
| File type | ELF64 x86-64 |
| Size | 528 bytes |
| MD5 | cda5b751da9f89c6c757462ce25ced0a |
| SHA-1 | 6ffc8f0743822f27e102ac07b83b1aadda0f5d7f |
| SHA-256 | c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e |
| Entropy | 2.82 bits per byte over the whole file |
| High-entropy data | None: no part of the file is at 7.2 bits per byte or more |
| Entry point | 0x400078 |
| Section headers | 4 |

## Indicators of compromise

These are values the agents found in the file and swarmlabre checked. Swarmlabre does not judge whether a value is malicious: a vendor URL, a library path or a documentation link can sit in a malicious file too. Review before you block. Network values are defanged here; the exports hold the real values.

### Hash values

| type | indicator | context |
|---|---|---|
| MD5 | cda5b751da9f89c6c757462ce25ced0a | Sample file. Computed by swarmlabre from the file itself. |
| SHA-1 | 6ffc8f0743822f27e102ac07b83b1aadda0f5d7f | Sample file. Computed by swarmlabre from the file itself. |
| SHA-256 | c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e | Sample file. Computed by swarmlabre from the file itself. |

### URLs

| type | indicator | context |
|---|---|---|
| URL | hxxp://c2[.]example[.]test/beacon | C2 URL. byte-checked, offset 0x95, finding f2. |

### Host artifacts

| type | indicator | context |
|---|---|---|
| Windows path (fragment) | Mutex\Global\DemoSwarmMutex | Mutex name. byte-checked, offset 0xb3, finding f4. |

### Other strings

| type | indicator | context |
|---|---|---|
| String | cmd.exe /c echo demo | Command line. byte-checked, offset 0xcf, finding f5. |

## Functions

None.

## Cryptography and configuration

| id | finding | value | offset | evidence | agents |
|---|---|---|---|---|---|
| f3 | Mutex name | Mutex\Global\DemoSwarmMutex | 0xb3 | byte-checked | crypto |

## Capability findings

None.

## Notes on the file

None.

## Unconfirmed claims

| id | finding | value | offset | evidence | agents |
|---|---|---|---|---|---|
| f1 | Small static x86-64 ELF |  | 0x0 | claimed | triage |
| f6 | T1071 Application Layer Protocol | T1071 |  | claimed | behaviour |

## MITRE ATT&CK

No technique was verified. ATT&CK is a registered trademark of The MITRE Corporation. (c) 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Detection engineering

No rule was written: the assessment found nothing malicious, and a rule for a benign file would only flag clean software.

## Disputes

None.

## Rounds

- Round 1: One task per role, started at once (built in). 5 of 5 tasks finished; 6 findings, 4 verified, 0 disputed.
- Round 2: Round 1 covered the brief. the model planned no further work

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
| Duration | 0 min |

