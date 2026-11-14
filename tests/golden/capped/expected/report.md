TLP:CLEAR. Disclosure is not limited.

# Malware analysis report: demo.elf


Contents: 1 Assessment; 2 Executive summary; 3 What it is; 4 Capabilities; 5 Recommendations; 6 What we don't know; 7 Sample snapshot; 8 Indicators of compromise; 9 Functions; 10 Cryptography and configuration; 11 Capability findings; 12 Notes on the file; 13 Unconfirmed claims; 14 MITRE ATT&CK; 15 Detection engineering; 16 Disputes; 17 About this report; 18 Analysis environment

- ELF64 x86-64, 528 bytes
- SHA-256 c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e
- run s5a194219, status done, model mock
- 0 verified (0 byte-checked), 200 unconfirmed, 0 disputed, 0 refuted, 5 rejected

## Assessment

| item | assessment |
|---|---|
| Verdict | Undetermined |
| Confidence | Low |
| Family or software | Not identified |

Reporter's reasoning (model judgement, not checked by swarmlabre): Made-up strings; the code only exits.

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
- Who wrote or uses this file is not known: the report does not attribute it.
- 200 further claims could not be checked against the file and are not relied on. They are listed at the end of the technical sections as leads.
- Triage: did not run.
- Static: did not run.
- Crypto/Config: did not run.
- Behaviour: did not run.
- 5 posted findings were rejected by swarmlabre: cap_exceeded 5.

What the Reporter says it could not establish (model text, not checked by swarmlabre):

- Whether anything else loads it.

## Indicators of compromise

These are values the agents found in the file and swarmlabre checked. Swarmlabre does not judge whether a value is malicious: a vendor URL, a library path or a documentation link can sit in a malicious file too. Review before you block. Network values are defanged here; the exports hold the real values.

No indicator was verified.

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
| f1 | Note 1 |  |  | claimed | ioc |
| f2 | Note 2 |  |  | claimed | ioc |
| f3 | Note 3 |  |  | claimed | ioc |
| f4 | Note 4 |  |  | claimed | ioc |
| f5 | Note 5 |  |  | claimed | ioc |
| f6 | Note 6 |  |  | claimed | ioc |
| f7 | Note 7 |  |  | claimed | ioc |
| f8 | Note 8 |  |  | claimed | ioc |
| f9 | Note 9 |  |  | claimed | ioc |
| f10 | Note 10 |  |  | claimed | ioc |
| f11 | Note 11 |  |  | claimed | ioc |
| f12 | Note 12 |  |  | claimed | ioc |
| f13 | Note 13 |  |  | claimed | ioc |
| f14 | Note 14 |  |  | claimed | ioc |
| f15 | Note 15 |  |  | claimed | ioc |
| f16 | Note 16 |  |  | claimed | ioc |
| f17 | Note 17 |  |  | claimed | ioc |
| f18 | Note 18 |  |  | claimed | ioc |
| f19 | Note 19 |  |  | claimed | ioc |
| f20 | Note 20 |  |  | claimed | ioc |
| f21 | Note 21 |  |  | claimed | ioc |
| f22 | Note 22 |  |  | claimed | ioc |
| f23 | Note 23 |  |  | claimed | ioc |
| f24 | Note 24 |  |  | claimed | ioc |
| f25 | Note 25 |  |  | claimed | ioc |
| f26 | Note 26 |  |  | claimed | ioc |
| f27 | Note 27 |  |  | claimed | ioc |
| f28 | Note 28 |  |  | claimed | ioc |
| f29 | Note 29 |  |  | claimed | ioc |
| f30 | Note 30 |  |  | claimed | ioc |
| f31 | Note 31 |  |  | claimed | ioc |
| f32 | Note 32 |  |  | claimed | ioc |
| f33 | Note 33 |  |  | claimed | ioc |
| f34 | Note 34 |  |  | claimed | ioc |
| f35 | Note 35 |  |  | claimed | ioc |
| f36 | Note 36 |  |  | claimed | ioc |
| f37 | Note 37 |  |  | claimed | ioc |
| f38 | Note 38 |  |  | claimed | ioc |
| f39 | Note 39 |  |  | claimed | ioc |
| f40 | Note 40 |  |  | claimed | ioc |
| f41 | Note 41 |  |  | claimed | ioc |
| f42 | Note 42 |  |  | claimed | ioc |
| f43 | Note 43 |  |  | claimed | ioc |
| f44 | Note 44 |  |  | claimed | ioc |
| f45 | Note 45 |  |  | claimed | ioc |
| f46 | Note 46 |  |  | claimed | ioc |
| f47 | Note 47 |  |  | claimed | ioc |
| f48 | Note 48 |  |  | claimed | ioc |
| f49 | Note 49 |  |  | claimed | ioc |
| f50 | Note 50 |  |  | claimed | ioc |
| f51 | Note 51 |  |  | claimed | ioc |
| f52 | Note 52 |  |  | claimed | ioc |
| f53 | Note 53 |  |  | claimed | ioc |
| f54 | Note 54 |  |  | claimed | ioc |
| f55 | Note 55 |  |  | claimed | ioc |
| f56 | Note 56 |  |  | claimed | ioc |
| f57 | Note 57 |  |  | claimed | ioc |
| f58 | Note 58 |  |  | claimed | ioc |
| f59 | Note 59 |  |  | claimed | ioc |
| f60 | Note 60 |  |  | claimed | ioc |
| f61 | Note 61 |  |  | claimed | ioc |
| f62 | Note 62 |  |  | claimed | ioc |
| f63 | Note 63 |  |  | claimed | ioc |
| f64 | Note 64 |  |  | claimed | ioc |
| f65 | Note 65 |  |  | claimed | ioc |
| f66 | Note 66 |  |  | claimed | ioc |
| f67 | Note 67 |  |  | claimed | ioc |
| f68 | Note 68 |  |  | claimed | ioc |
| f69 | Note 69 |  |  | claimed | ioc |
| f70 | Note 70 |  |  | claimed | ioc |
| f71 | Note 71 |  |  | claimed | ioc |
| f72 | Note 72 |  |  | claimed | ioc |
| f73 | Note 73 |  |  | claimed | ioc |
| f74 | Note 74 |  |  | claimed | ioc |
| f75 | Note 75 |  |  | claimed | ioc |
| f76 | Note 76 |  |  | claimed | ioc |
| f77 | Note 77 |  |  | claimed | ioc |
| f78 | Note 78 |  |  | claimed | ioc |
| f79 | Note 79 |  |  | claimed | ioc |
| f80 | Note 80 |  |  | claimed | ioc |
| f81 | Note 81 |  |  | claimed | ioc |
| f82 | Note 82 |  |  | claimed | ioc |
| f83 | Note 83 |  |  | claimed | ioc |
| f84 | Note 84 |  |  | claimed | ioc |
| f85 | Note 85 |  |  | claimed | ioc |
| f86 | Note 86 |  |  | claimed | ioc |
| f87 | Note 87 |  |  | claimed | ioc |
| f88 | Note 88 |  |  | claimed | ioc |
| f89 | Note 89 |  |  | claimed | ioc |
| f90 | Note 90 |  |  | claimed | ioc |
| f91 | Note 91 |  |  | claimed | ioc |
| f92 | Note 92 |  |  | claimed | ioc |
| f93 | Note 93 |  |  | claimed | ioc |
| f94 | Note 94 |  |  | claimed | ioc |
| f95 | Note 95 |  |  | claimed | ioc |
| f96 | Note 96 |  |  | claimed | ioc |
| f97 | Note 97 |  |  | claimed | ioc |
| f98 | Note 98 |  |  | claimed | ioc |
| f99 | Note 99 |  |  | claimed | ioc |
| f100 | Note 100 |  |  | claimed | ioc |
| f101 | Note 101 |  |  | claimed | ioc |
| f102 | Note 102 |  |  | claimed | ioc |
| f103 | Note 103 |  |  | claimed | ioc |
| f104 | Note 104 |  |  | claimed | ioc |
| f105 | Note 105 |  |  | claimed | ioc |
| f106 | Note 106 |  |  | claimed | ioc |
| f107 | Note 107 |  |  | claimed | ioc |
| f108 | Note 108 |  |  | claimed | ioc |
| f109 | Note 109 |  |  | claimed | ioc |
| f110 | Note 110 |  |  | claimed | ioc |
| f111 | Note 111 |  |  | claimed | ioc |
| f112 | Note 112 |  |  | claimed | ioc |
| f113 | Note 113 |  |  | claimed | ioc |
| f114 | Note 114 |  |  | claimed | ioc |
| f115 | Note 115 |  |  | claimed | ioc |
| f116 | Note 116 |  |  | claimed | ioc |
| f117 | Note 117 |  |  | claimed | ioc |
| f118 | Note 118 |  |  | claimed | ioc |
| f119 | Note 119 |  |  | claimed | ioc |
| f120 | Note 120 |  |  | claimed | ioc |
| f121 | Note 121 |  |  | claimed | ioc |
| f122 | Note 122 |  |  | claimed | ioc |
| f123 | Note 123 |  |  | claimed | ioc |
| f124 | Note 124 |  |  | claimed | ioc |
| f125 | Note 125 |  |  | claimed | ioc |
| f126 | Note 126 |  |  | claimed | ioc |
| f127 | Note 127 |  |  | claimed | ioc |
| f128 | Note 128 |  |  | claimed | ioc |
| f129 | Note 129 |  |  | claimed | ioc |
| f130 | Note 130 |  |  | claimed | ioc |
| f131 | Note 131 |  |  | claimed | ioc |
| f132 | Note 132 |  |  | claimed | ioc |
| f133 | Note 133 |  |  | claimed | ioc |
| f134 | Note 134 |  |  | claimed | ioc |
| f135 | Note 135 |  |  | claimed | ioc |
| f136 | Note 136 |  |  | claimed | ioc |
| f137 | Note 137 |  |  | claimed | ioc |
| f138 | Note 138 |  |  | claimed | ioc |
| f139 | Note 139 |  |  | claimed | ioc |
| f140 | Note 140 |  |  | claimed | ioc |
| f141 | Note 141 |  |  | claimed | ioc |
| f142 | Note 142 |  |  | claimed | ioc |
| f143 | Note 143 |  |  | claimed | ioc |
| f144 | Note 144 |  |  | claimed | ioc |
| f145 | Note 145 |  |  | claimed | ioc |
| f146 | Note 146 |  |  | claimed | ioc |
| f147 | Note 147 |  |  | claimed | ioc |
| f148 | Note 148 |  |  | claimed | ioc |
| f149 | Note 149 |  |  | claimed | ioc |
| f150 | Note 150 |  |  | claimed | ioc |
| f151 | Note 151 |  |  | claimed | ioc |
| f152 | Note 152 |  |  | claimed | ioc |
| f153 | Note 153 |  |  | claimed | ioc |
| f154 | Note 154 |  |  | claimed | ioc |
| f155 | Note 155 |  |  | claimed | ioc |
| f156 | Note 156 |  |  | claimed | ioc |
| f157 | Note 157 |  |  | claimed | ioc |
| f158 | Note 158 |  |  | claimed | ioc |
| f159 | Note 159 |  |  | claimed | ioc |
| f160 | Note 160 |  |  | claimed | ioc |
| f161 | Note 161 |  |  | claimed | ioc |
| f162 | Note 162 |  |  | claimed | ioc |
| f163 | Note 163 |  |  | claimed | ioc |
| f164 | Note 164 |  |  | claimed | ioc |
| f165 | Note 165 |  |  | claimed | ioc |
| f166 | Note 166 |  |  | claimed | ioc |
| f167 | Note 167 |  |  | claimed | ioc |
| f168 | Note 168 |  |  | claimed | ioc |
| f169 | Note 169 |  |  | claimed | ioc |
| f170 | Note 170 |  |  | claimed | ioc |
| f171 | Note 171 |  |  | claimed | ioc |
| f172 | Note 172 |  |  | claimed | ioc |
| f173 | Note 173 |  |  | claimed | ioc |
| f174 | Note 174 |  |  | claimed | ioc |
| f175 | Note 175 |  |  | claimed | ioc |
| f176 | Note 176 |  |  | claimed | ioc |
| f177 | Note 177 |  |  | claimed | ioc |
| f178 | Note 178 |  |  | claimed | ioc |
| f179 | Note 179 |  |  | claimed | ioc |
| f180 | Note 180 |  |  | claimed | ioc |
| f181 | Note 181 |  |  | claimed | ioc |
| f182 | Note 182 |  |  | claimed | ioc |
| f183 | Note 183 |  |  | claimed | ioc |
| f184 | Note 184 |  |  | claimed | ioc |
| f185 | Note 185 |  |  | claimed | ioc |
| f186 | Note 186 |  |  | claimed | ioc |
| f187 | Note 187 |  |  | claimed | ioc |
| f188 | Note 188 |  |  | claimed | ioc |
| f189 | Note 189 |  |  | claimed | ioc |
| f190 | Note 190 |  |  | claimed | ioc |
| f191 | Note 191 |  |  | claimed | ioc |
| f192 | Note 192 |  |  | claimed | ioc |
| f193 | Note 193 |  |  | claimed | ioc |
| f194 | Note 194 |  |  | claimed | ioc |
| f195 | Note 195 |  |  | claimed | ioc |
| f196 | Note 196 |  |  | claimed | ioc |
| f197 | Note 197 |  |  | claimed | ioc |
| f198 | Note 198 |  |  | claimed | ioc |
| f199 | Note 199 |  |  | claimed | ioc |
| f200 | Note 200 |  |  | claimed | ioc |

## MITRE ATT&CK

No technique was verified. ATT&CK is a registered trademark of The MITRE Corporation. (c) 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Detection engineering

No rule was written: 0 strings passed the filters and a rule needs at least 4. The strings swarmlabre byte-checked in this file were too short, too common or too few to hunt with.

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

