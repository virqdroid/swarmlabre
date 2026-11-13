# The web UI

`ui/swarms.html` is the whole front end: one file, vanilla JavaScript, no framework, no build step, no request to any other site. Its two fonts (`ui/fonts/`) are served by
`swarmlabre serve` or copied next to the static demo. It started as the Swarms tab of a larger single-file page; from here on **this file is the source**, it is not regenerated.

## Three modes, one page

| Mode | Started by | What answers the page's `api/*` calls | What the page offers |
|---|---|---|---|
| live | `swarmlabre serve` | `Swarms` (the real pipeline: Docker, a model) | everything: launch sheet, Live tab, report, delete, clip export (only when `ffmpeg` is on PATH) |
| replay | `swarmlabre serve --replay RUN` | `player.Replay`: a recorded run played through a virtual clock, no model, no Docker | the same views over the recording, plus the replay controls (speed, Pause, Restart, Skip to end) |
| static | `tools/build-demo.py BUNDLE` | `tools/shim.js` inside the page: it wraps `fetch` and answers `api/*` from the recording embedded as JSON | as replay; nothing is sent anywhere |

The page learns its mode from `GET api/mode` and sets `body[data-mode]`; CSS hides New run, Delete, Export clip, Pause, Stop and the hint forms outside live mode. The launch sheet
says why it cannot start a run (`No model is configured...`, or "This is a recorded run").

`player.Replay` and `shim.js` are the same fold over the recorded events written twice (Python and JavaScript). `tests/test_shim.py` runs the shim in node and compares both with
each other at every cursor of three recorded runs, so they cannot drift apart unnoticed. Change both together.

### The clock

In replay and static mode every "elapsed" and "age" the page shows is computed from the **recorded** clock (`swNow()`), not from `Date.now()`, so "running for 3 min" matches what
was recorded whatever the speed. `GET/POST api/replay` is the clock: `speed` (0.1 to 10000), `paused`, `restart`, `end` (skip to the end) and `at` (seek, in seconds from the start).

### What a recording does not hold

A sealed run keeps the board's inputs, the events, the layout, the outputs and the model exchanges; a bundle keeps less. So replay and the static demo answer, honestly, **"not
recorded"** for: what the agents were thinking (`thoughts` is empty), the per-task transcripts and tool-call lists (the agent drawer shows the task rows, goals and final answers
only), the model's request timings and slot statistics, and the memory peaks while the run was going (zero until the run ends). A finding's manifest lines (the cited calls) are empty.
Byte-for-byte reproducibility is promised by `swarmlabre replay` (see [determinism.md](determinism.md)), **not by the page**: a replayed or static view is a view of a recording, not
new evidence, and a recording that does not replay byte for byte is refused by `serve --replay` and `tools/build-demo.py`.

## The server

`swarmlabre/server.py`, standard library only. It listens on `127.0.0.1` unless `--host` or `[serve] host` says otherwise (and then warns). Every `api/*` call needs
`Authorization: Bearer <token>`; the token lives in `<state>/token` (mode 0600) and is printed once, as part of the address to open (`/#token=...`; the page moves it into
`sessionStorage` and removes it from the address bar). A `Host` header that is not loopback is refused on a loopback bind (DNS rebinding). JSON bodies are capped at 1 MiB; the raw
upload routes (`POST swarm/stage`, `POST swarm/<run>/clip/frame`) are routed before the JSON parse and keep their own caps. Text over 1400 bytes is gzipped. The page is sent with a
strict Content-Security-Policy (`default-src 'none'`, `connect-src 'self'`) and `frame-ancestors 'none'`.

## Page rules

- One global `[hidden]{display:none!important}` and one document-level Escape handler that closes the top layer (modal, then the inspect drawer, then the launch sheet).
- Anything repainted by polling must not replace its DOM when nothing changed: it keeps a signature in `dataset.sig`; nothing time-varying goes into a compared signature.
- No `backdrop-filter`, no animated `box-shadow`; motion marks a state change and does not loop; `prefers-reduced-motion` is respected (the map's animation stops as soon as nothing moves).
- 16 px inputs, 44 px touch targets, safe-area insets; sentence-case copy; memory in GiB, file sizes in MB.
- **Untrusted text** (anything an agent, a sample, a tool or a recording produced) is set with `textContent` or `esc()` and nothing else. Values that look like network indicators are shown defanged.
- Colour carries meaning, not identity: mint is byte-checked, blue call-cited, dashed is claimed; the role colours stay on the map.

## Checks

| Script | What it proves |
|---|---|
| `tests/test_shim.py` | the in-page shim and `player.py` answer identically at hundreds of cursors |
| `tests/test_demo_build.py` | the static build is deterministic, fetches nothing, and refuses a recording that does not replay |
| `tests/ui/parity.py [BUNDLE]` | **text parity**, at 1280 and 500 px, in live, replay and static: every finding (title, value, level, status, offset) on the Findings tab equals the API's, and the cards of `report.html` equal the page's verified and disputed findings (compared defanged), both ways; the three modes' final records are equal |
| `tests/ui/tour.py [BUNDLE]` | every tab, the map and the graph, the hex peek, the three inspect drawers (Escape closes each), the replay controls, every download, the history picker, and the list of requested resources, in replay and in static with the network blocked: no page error |
| `tests/ui/live.py` | live mode with real containers and the mock model: the launch sheet, the upload through the raw `stage` route, a run to `done`, the same parity checks, and the clip export (needs `ffmpeg`) |

Pass the committed recording to run them on it: `python3 tests/ui/parity.py demo/sfaef16e6`, `python3 tests/ui/tour.py demo/sfaef16e6`.
They drive headless Firefox through `tests/ui/wd.py`, a small standard-library WebDriver client. They need `geckodriver` and Firefox; a snap Firefox can only use folders under the home
directory, so the scripts keep profiles and screenshots in `~/swarmlabre-uitmp` and delete them afterwards.
