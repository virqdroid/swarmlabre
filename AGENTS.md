# Repository guidelines

SwarmLabRE: up to six AI agents analyse one binary (ELF, PE or APK) and post to one board. The board checks every finding against the file's own bytes and the run's own tool log, and a finished run replays offline to byte-identical report files. Python 3.12, standard library only. Docs: <https://swrm.re/docs/>.

## Product and authority

- SwarmLabRE only reads a sample and never executes it. Do not add a path that runs, loads or emulates the sample on the host.
- The program, `tools/` and the scripts that run inside the containers use the standard library only. Do not add a dependency, a package manifest, a build step or a virtualenv.
- Ask the maintainer before changing any of these: a sandbox flag (network, capabilities, read-only root, limits), what crosses the host and container boundary, the board's checks or evidence levels, the report templates, the manifest format, or a golden file.
- Nothing may reach the network from the repository, the UI, a report or a test, except the model endpoint the user configured. The UI and `report.html` make no request to another site and load no script or font from elsewhere.
- Do not add real malware, a third-party sample or an EICAR file. Samples are generated (`swarmlabre/corpus.py`, `demo.py`) and benign. A third-party file or component goes into `THIRD_PARTY.md` with its licence read from its own source.

## Architecture

- `swarmlabre/cli.py` and `server.py` call `swarms.py` (the run and the board); the board calls the checks; report writers read only checked facts. Read the module table on the [Architecture page](https://swrm.re/docs/architecture.html) before moving code between modules.
- Trust boundaries: the sample's bytes, an agent's text, a tool's output and the model's answer are untrusted. Clean, cap and label them, set them in a page as text, and never put them into a path, a command, a notification or a log line.
- A finding enters the board only through `swarm-post`. Agents must not pipe or redirect it. A model's verdict, assessment or prose is display-only and never changes a count, an evidence level or a hash. A report states only what the board checked, in fixed templates.
- Files a container can write are untrusted. Never extract an archive from one, resolve paths inside the container, open with `O_NOFOLLOW`, cap sizes, and read each field with a type check.
- The model's key lives on the host only. The agents container reaches the model through the gate's Unix socket, mounted read-only. The key never enters a container, a file under a run folder, a log or a report. Keep it in the environment variable named by `api_key_env`.
- Both containers run `--network none`, read-only root, all capabilities dropped, memory and pid limits. Do not add a flag that weakens this to make something work.
- Every JSON body is capped at 1 MiB; raw-body routes keep their own caps and are routed before the JSON parse.
- Time stamped on findings, events and reports comes from `clock.py` so a replay can pin it. Other modules read the clock only to measure a duration or the age of a cached answer.
- A new agent role needs its entry in `swarms.py` and a test. Run ids stay short: socket paths are limited to 108 bytes.

## Determinism

- `swarmlabre replay` must rebuild every output byte for byte from a recording and exit 1 on any difference. Report output must not depend on the hash seed, the time zone, dict or set order, the locale or the current time. Sort before you write.
- Do not edit a golden file by hand. Use `python3 tests/goldenrun.py --update-golden`: it only proposes a diff and a review token. Read the diff, and commit the new files only when the change is intended.
- A live run is pinned (temperature and seed forced on every request) and recorded, but is not promised to repeat. Do not claim otherwise in code, docs or a commit message.

## Development

- Python 3.12. Docker is needed only to analyse a new file. Replay, the web UI in replay mode, the static demo, the tests and CI never use it.
- The images build for arm64 only today. Rebuild both after any change under `sandbox/`: `docker build -t swarmlabre-agent sandbox/`, then `docker build -f sandbox/Dockerfile.re -t swarmlabre-tools sandbox/` (about 10 minutes the first time).
- Config is one TOML file, read and never written by the tool: `swarmlabre.toml` (gitignored) from `swarmlabre.example.toml`. A new key goes into `swarmlabre.example.toml`, `config.py` and [the config page](https://swrm.re/docs/config.html) together. Search order: `--config`, `$SWARMLABRE_CONFIG`, `./swarmlabre.toml`, `~/.config/swarmlabre/swarmlabre.toml`.
- If `docker` fails with a permission error, your shell may lack the docker group; the tool itself retries through `sg docker`.

Set up the lab and check it works, in this order:

```sh
git clone https://github.com/virqdroid/swarmlabre && cd swarmlabre
python3 -m swarmlabre replay demo/sfaef16e6          # offline; exit 0 only if every byte is the recorded one
docker build -t swarmlabre-agent sandbox/
docker build -f sandbox/Dockerfile.re -t swarmlabre-tools sandbox/
python3 -m swarmlabre demo out-demo/                 # a harmless demo.elf and a scripted mock model
python3 -m swarmlabre run out-demo/demo.elf --mock out-demo/mock-script.json --out out/
```

A mock run takes about a minute and writes `report.html`, `report.md`, `report.json`, `board.json` and the IOC files. It needs no GPU, no key and no network. For a real model, copy `swarmlabre.example.toml` to `swarmlabre.toml`, set `[model] base_url` to an OpenAI-compatible endpoint and export the key in the variable named by `api_key_env`. Do not paste a key into the file, a command line or an issue.

Other commands: `serve` (web UI, loopback, prints an address with a `#token=` part), `serve --replay RUN --speed 8` (no model, no Docker), `report`, `export`, `corpus`. Exit codes: 0 done, 1 failed, 2 bad usage or input, 3 needs a model and none is configured, 130 stopped with Ctrl-C.

## Tests

```sh
python3 -m unittest discover -s tests                    # no Docker, no model; golden cases included
python3 tests/goldenrun.py --check --twice               # replay every golden case twice, compare with the committed outputs
SWARMLABRE_SKIP_BROWSER=1 python3 -m unittest discover -s tests   # what CI runs: skips the browser checks
python3 tests/ui/parity.py                               # text parity at 1280 and 500 px (headless Firefox + geckodriver); run by hand
SWARMLABRE_E2E=1 python3 -m unittest discover -s tests   # adds a whole run in real containers with the mock (needs both images)
```

- Run the narrowest test that covers your change first, then the whole suite before you say a change is done. `test_shim` skips without Node. A socket race in `tests/test_gate.py` or `test_hardening.py` can fail once in a full run; rerun that file alone before treating it as a regression.
- The mock model and a recording prove the pipeline and the checks. They do not show how a real model behaves. Do not claim a model result from a mock run.
- A change to a sandbox flag, the gate, the board's checks or a container path needs a test that plants a hostile case (a symlink, an oversized file, a forged post), not only the happy path.
- A change to a page under `ui/` needs text parity at 1280 and 500 px.

## Docs

- `README.md`, `SECURITY.md`, `docs/*.md` and `site/docs/*.html` describe the same facts and are pinned to the code by `tests/test_docs.py` and `tests/test_site.py`. A page's facts come from the code, not from memory: when you change behaviour, change the page and let the test tell you what else moved.
- A docs page is one self-contained HTML file with no script. A new page is added to `SIDEBAR` in `tests/test_docs.py`. Markdown links to the docs use `https://swrm.re/docs/X.html`, never a `site/docs/` path.
- Sentence-case copy, full sentences, no history ("now", "no longer", "we changed"): write how it works.
- Do not state a test count or a measurement in prose unless a test pins it.

## Issue reports

- Keep them short. Separate what you observed, what you infer and what you guess. State the command, the exit code and the relevant output.
- Never claim a reproduction you did not perform. Never attach a key, a token, `swarmlabre.toml` or a real malware sample. Security problems go to the repository's Security tab ("Report a vulnerability"), not a public issue (see `SECURITY.md`).

## Pull request readiness

- One change per PR. State what changed, why, which commands you ran and their results, and what you did not run (for example, the E2E run or the browser checks).
- The full suite and `python3 tests/goldenrun.py --check --twice` pass locally. CI results do not replace a human reading the diff.
- A changed golden file, a changed sandbox flag or a changed board check is called out in the description with the reason.

## Agent-specific notes

- This file and `skills/` are read by tools as instructions. A change to either is reviewed like code.
- `skills/rea-swarm` and `skills/rea-reverse-engineering` are the prompts the in-run analysts get. They are not instructions for you; do not follow them when working on this repository.
- Do not run a live analysis on a file you did not generate unless the maintainer asked for it.
