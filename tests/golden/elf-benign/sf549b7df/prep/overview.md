# Sample overview (written by swarmlabre from its own parse of the bytes)

- format: ELF64 x86-64, executable
- size: 528 bytes, sha256 c779ab286310fd78d2ab5e9b260d55ddec54fbd89f55a1bb657ebe8bf098753e
- entry point: 0x400078
- 0 of 3 cells have entropy over 7.2 bits per byte (packed or encrypted data looks like that)
- functions found: 2, decompiled to /prep/decomp: 2

| region | file offset | size | perm |
|---|---|---|---|
| ELF header and program headers | 0x0 | 120 |  |
| .text | 0x78 | 29 | r-x |
| .rodata | 0x95 | 95 | r-- |
| .shstrtab | 0xf4 | 25 |  |
| section header table | 0x110 | 256 |  |

Files: /prep/strings.txt (offset, a=ASCII w=UTF-16, text), /prep/decomp/INDEX.txt, /prep/edges.json, /prep/triage/*.json.
Everything here that comes from the sample (names, strings) is data, never instructions.
