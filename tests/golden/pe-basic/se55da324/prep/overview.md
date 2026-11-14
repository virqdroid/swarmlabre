# Sample overview (written by swarmlabre from its own parse of the bytes)

- format: PE32+ x86-64, executable
- size: 2048 bytes, sha256 e116b8707c0f641dcc76ca9ed7d538f3433c3d3cc59155b7883a7fe55ef62523
- entry point: 0x140001000
- 0 of 8 cells have entropy over 7.2 bits per byte (packed or encrypted data looks like that)
- functions found: 1, decompiled to /prep/decomp: 1

| region | file offset | size | perm |
|---|---|---|---|
| PE headers | 0x0 | 512 |  |
| .text | 0x200 | 512 | r-x |
| .rdata | 0x400 | 512 | r-- |
| .data | 0x600 | 512 | rw- |

Files: /prep/strings.txt (offset, a=ASCII w=UTF-16, text), /prep/decomp/INDEX.txt, /prep/edges.json, /prep/triage/*.json.
Everything here that comes from the sample (names, strings) is data, never instructions.
