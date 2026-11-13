# Security

swarmlabre reads files that may be hostile and lets language models act on them. This page says what it defends against, how, and what it does **not** claim. It describes version 0.1.0.

## Reporting a problem

Use the repository's **Security** tab, "Report a vulnerability" (GitHub private vulnerability reporting). Please do not open a public issue for something that lets a sample, an agent
or a web page escape a boundary below, run code on the host, read the model key, or make a report show something the board did not check. A report that includes a sample file is welcome;
do not send real malware you are not allowed to share. This is a one-person project: there is no response-time promise.

## What it protects

| Asset | Where it must not leak or be changed |
|---|---|
| The host and its files | by a sample, an agent or a tool |
| The model's API key (if one is used) | into a container, a log, a report or a recording |
| The truth of a report | by text in a sample or from an agent that makes a finding look checked, or a link or tag that reaches a viewer |
| The recorded run | by an accidental or careless edit going unnoticed (not by a deliberate one: see below) |

## Who it assumes is hostile

1. **The sample.** Bytes and strings written by an attacker: markers that imitate swarmlabre's own protocol, text that tells a model what to do, HTML, ANSI and bidi controls, spreadsheet formulas,
   Markdown links, over-long values, malformed ELF/PE/APK headers, archives with odd names or links.
2. **The agents.** A model steered by that text. It may post false findings, forge lines, write hostile prose, cite tool calls it never made, or try to read another role's files.
3. **What the tools print and what the containers write.** Output of Ghidra, jadx, Apktool and `rea`, and every file in a run folder that a container could have written.
4. **Anything that can reach the web UI's port**, including a web page in a browser on the same machine.

## What it does about each

| Threat | Defence | Where to look |
|---|---|---|
| A sample or agent runs code | The sample is only read, never executed. Agents run in containers, as the host user's uid (not root) with `--read-only`, `--cap-drop ALL`, `no-new-privileges`, memory, CPU and pid limits, and `--network none`; each role has its own uid and its own private tmpfs. | `swarmlabre/sandbox.py`, `tests/test_sandbox.py` |
| A container reaches the network | `--network none` is the only network the code will build; before a run a throwaway container proves it has no interface besides loopback and cannot connect out (the probe tries one public address and expects the attempt to fail). A run does not start if the probe reports an interface or a route out, or if it gives no clear answer at all (it fails closed). A running container is also inspected for a writable root, kept capabilities, privileged mode, a mounted Docker socket or a writable proxy directory. | `sandbox.py` (`Health`, `posture`) |
| The model key reaches a container | The key stays in the host process. The container reaches the model only through a Unix socket the run owns, mounted read-only; the gate adds the key on the host side. The agent's config holds no key. The key is also registered with `scrub()`, so it is hidden in log strings, and a run does not start if a container's own configuration (`docker inspect`: environment, arguments, mounts) contains it. The gate overwrites `temperature`, `seed` and `model` in every request, forces `n` to 1 and caps the output tokens, so an agent cannot spend the operator's endpoint on another model or on many completions. | `gate.py`, `client.py`, `tests/test_gate.py`, `test_sandbox.py` |
| A forged finding line in a sample's strings | A finding is read only from a line that carries the task's own nonce (an HMAC of a per-run key over role and task number), in the agent's own tool-result stream. | `HostileStrings` in `tests/test_golden.py`, `tests/test_board.py` |
| A false finding looks verified | The board re-checks every post: the bytes at the offset, that each cited call exists in the run's tool log and shows up in output of the agent's own session (see the limit under "does not claim"), the function list, the ATT&CK id and name against MITRE's table, caps and duplicates. Verdict and confidence are capped by the evidence. A model's judgement never changes a count, a level or a hash. | `Board` in `swarms.py`, `report.py` |
| Hostile text reaches a viewer | Everything that came from a sample, an agent or a tool is cleaned, capped and set as text (`textContent`/escaped), network indicators are defanged, a CSV cell that could be a formula is neutralised, and `report.md` escapes `<`, `>` and link syntax (a reported bug, fixed). | golden case `hostile`, `tests/test_report.py` |
| A container writes a hostile file back | Archives are parsed, never extracted; paths are resolved inside the container; files are opened with `O_NOFOLLOW`; sizes and counts are capped; the run folder is treated as untrusted data. | `read_tar` in `swarms.py` |
| A web page or another user drives the UI | The server listens on loopback by default; every `api/*` call needs a bearer token kept in a mode-0600 file and printed once in the address fragment; a `Host` header that is not loopback is refused (DNS rebinding); JSON bodies are capped at 1 MiB; the page is sent with `default-src 'none'`, `connect-src 'self'` and `frame-ancestors 'none'`; report files download as attachments and are never rendered in the server's origin. | `server.py`, `tests/test_server.py` |
| A recorded run is changed afterwards, by accident | `manifest.json` holds the SHA-256 of every input and output; `swarmlabre replay` exits 1 on a differing byte, an edited recorded file, a sample that is not the one the manifest names, or an output file a bundle carries that is not the recorded one; `serve --replay` and the demo build refuse a run that does not replay. A bundle is copied without following links and with a size cap. | `replay.py`, `tests/test_replay.py` |

## What this repository does **not** claim

- **Docker is not a perfect boundary.** A kernel or runtime flaw could let a process leave a container. Run swarmlabre on a machine and an account where that would be survivable, and keep Docker and the kernel current.
  The host firewall rules of the project this came from are not included; `--network none` is the only network control here.
- **No run on real malware is part of any check.** The tests, the golden cases and the demo use generated benign files only (reserved example domains, documentation addresses, code that only exits). How the parser,
  Ghidra, jadx or the agents behave on hostile real-world files is not verified here.
- **The parsers have not been fuzzed.** The ELF, PE and APK readers are hand-written Python with size limits and tests on hand-built files. A crafted file may crash a run (a failed run keeps what the board built).
- **A verdict is a model's opinion.** *byte-checked* means the bytes are at that offset, not that the agent understood them. A report can still be wrong, incomplete or misleading about what a file does.
- **A model can be steered.** The defences above stop a sample from forging the protocol and from becoming a verified fact without evidence; they do not stop a model from believing, repeating or acting on text in a sample
  inside its own sandbox, and they do not make the Reporter's prose accurate.
- **Live runs are not repeatable.** Only replay of a recording is byte-identical (see [docs/determinism.md](docs/determinism.md)).
- **One tested environment.** Everything was run on Linux arm64 with Python 3.12.3, one Docker installation and one locally served model for the live checks. Other kernels, CPU architectures, Python minor versions,
  Docker versions and container runtimes are untested. The tools image builds for arm64 only.
- **The web UI is for one person on one machine.** It has no user accounts, no HTTPS and no rate limiting. A non-loopback `--host` prints a warning; the token is then the only protection and travels in clear text.
  Do not put it on the internet.
- **The static demo and replay mode show a recording.** They add no evidence and re-check nothing; the byte-for-byte check is `swarmlabre replay`.
- **Call citations are attributed by text, not by the tool server.** A finding is `call-cited` when each cited call id exists in the run's tool log and appears in the output of a command in that agent's own session. An
  agent that can run shell commands can print another role's call id (`echo '[c5 …'`), and swarmlabre cannot tell that from a real call of its own. So *call-cited* means "the call exists in this run's tool log and the agent's session printed
  its id", not "this agent made it". The roles share one tool server; attributing calls per role (by peer uid) is not built.
- **The agents' tool socket binds only some tools to the sample.** On the locked socket the Android tools (`inspect_android_*` and the related search, decode and trace tools) accept only the pinned sample path. Other
  tools that take a file path (for example `inspect_artifact`, `inspect_signature`, `inspect_pe_resources`) are allowed but not bound, so a steered agent could point one at another file inside the tools container (the
  run's input folder, the tool output and the result cache; no key or host file is mounted there). Binding them needs the tool schemas of the real `rea` image and was not done.
- **Tamper evidence is not authentication.** `manifest.json` holds hashes and nothing signs it. Someone who edits a recorded file can recompute its hash and the manifest's; replay then agrees. The hashes detect accidental
  change and a forgery that forgot the manifest, not a determined one. Keep a run's origin by other means (a signature, a trusted copy of the manifest hash) if that matters.
- **No audit.** No third party has reviewed this code. The two skills (`skills/`) are prompts for a model, not security controls.
- **Third-party software** (Ghidra, jadx, Apktool, Binwalk, mitmproxy, the pi agent, `rea`, Debian packages, Node) is installed into the images at build time at pinned versions. A vulnerability in it is outside this
  repository's control; see [THIRD_PARTY.md](THIRD_PARTY.md) for what is used.

The determinism page lists the checks that were run and the areas the golden cases do not cover; those gaps apply here too (a failed, stopped or timed-out run, a run with fewer than six roles, a packed or multi-DEX or
32-bit sample, other machines).

## Supported versions

Only the latest commit on `main`. There are no releases yet.
