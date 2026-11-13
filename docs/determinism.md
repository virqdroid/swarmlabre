# How swarmlabre keeps results reproducible

Three claims, from strongest to weakest. The README repeats them in one line each; this page says exactly what each one covers.

## 1. A recorded run replays to byte-identical files

`swarmlabre replay RUN` rebuilds a finished run offline (no model, no Docker, no network) and compares every output with the SHA-256 in the run's `manifest.json`:
`report.json`, `report.md`, `report.html`, `board.json`, `iocs.csv`, `iocs.stix.json`, `iocs.misp.json` and `detection.yar`.

What the replay re-runs, and what it takes as given:

| Step | Re-run? | From |
|---|---|---|
| The board's evidence checks (bytes at an offset, ATT&CK id and name, call citations, duplicates, caps) | yes, **full** level (the sample is kept) | `inputs.jsonl`: every post, resolution and spot check in the order the board received it, with the clock value it saw |
| The Reporter's summary, lint and assessment | yes | the Reporter's recorded text in `swarm.json` |
| Verdict and confidence caps, YARA rules and their matching, IOC grouping and defanging, STIX/MISP ids, the HTML page | yes | the board, the layout and the prepared files of the run |
| What the model said and what the tools printed | **no**: recorded | `model-trace.jsonl.gz` (every exchange, whole) and the agents' tool results inside the board inputs |

With no sample kept (`keep_sample = false`, or `--no-sample`) the replay is **downstream** level: the board is taken from the record, and the result says so. It never reports more than it checked.

`inputs_untouched` also checks that no recorded file changed since the run ended. Replay also checks that the kept sample is the one the manifest names (`sample`), and that the output files a bundle carries under `out/` are the recorded ones (`bundle_outputs`): the player serves and the demo embeds those, not only the rebuilt copies. A bundle is copied without following links.

What this does **not** do: nothing signs `manifest.json`, so someone who edits a file and recomputes its hash and the manifest's gets a replay that agrees. The hashes catch accidents and forgeries that forgot the manifest ([SECURITY.md](../SECURITY.md)). A rebuild that differs in even one byte, or a recorded file edited afterwards, makes `replay` exit 1.

What makes the rebuild repeatable: no wall-clock read in the build (one clock module, pinned to the run's end time), no local time zone (all times are UTC), no randomness (STIX and MISP ids are `uuid5` over the run id and the content), sorted keys, and no dependence on dict or set order. The test suite replays under different time zones and `PYTHONHASHSEED` values and expects the same hashes, and the golden cases (section 4) pin the bytes of 11 recorded runs.

## 2. A live run is pinned and recorded, not repeatable

Six agents share one model, so the order of their requests, the server's batching and the tool timings differ between runs. Pinning `temperature` and `seed` (the gate overwrites both in every request, whatever the agent's client asked for) removes the sampling noise the client controls; it cannot remove the rest. Two live runs on the same sample can therefore differ, for example in which agent posts first and so in finding numbers.

So a live run does not promise identical results. It promises that everything needed to reproduce *its* results offline is on disk.

Whether the model server honours `seed` at all is measured, not assumed: before a run the same short question is asked twice with one seed, and `swarm.json` / `manifest.json` record `seed_support` as `honoured`, `ignored` or `unknown`.

## 3. Replaying the agents against recorded model answers

`swarmlabre run SAMPLE --replay RUN` starts the containers as usual but answers every model request from the recorded trace. A reply is served only to a request whose body has the same SHA-256 as the recorded one; any other request gets an error and is counted (`replay_diverged` in the result). It also reuses the recorded run's task key (`nonce.key`): the per-task marker the agents echo back is an HMAC of that key, so the conversations repeat word for word. It needs Docker and the images.

Measured on the second demo sample (a dispute, a resolution, a round 2 and a duplicate reject): 0 unrecorded requests, and the same findings, ids, evidence levels, statuses and rejects. **Not reliable, measured:** repeated eleven times (three on each of two earlier commits, five on the tree that was uploaded), the count was 0 six times and 4 five times; the earlier reading that the later commit was reliable did not hold. Which agent posts first decides the finding numbers (`f1` is a different finding in the two runs), and the containers' timing is not controlled, so a replay through the containers can diverge; `replay_diverged` says so. The opt-in end-to-end test asserts 0 and can therefore fail without a bug (it is not in CI). The offline replay of claim 1 is not affected.

This is a **new run**, so its files differ from the recording (run id, times); the byte-identical claim is claim 1's. With a real model's tool use, timing-dependent tool output can still make a request differ from the recorded one, and `replay_diverged` then says so.

## Files of a run

| File | Content | Hashed in the manifest |
|---|---|---|
| `swarm.json` | the run record | yes |
| `board.jsonl` | the board's decisions | yes |
| `inputs.jsonl` | the board's inputs, in order | yes |
| `model-trace.jsonl.gz` | every model exchange (the request is kept as its hash; the reply whole), at most 64 MiB | yes |
| `layout.json`, `events.jsonl`, `detection.json` | the map, the event log, the stored YARA rules | yes |
| `manifest.json` | tool version, sample hash, model and sampling, image ids, ATT&CK version, report format, and the hashes above | no |
| `out/*` | the outputs | named by hash in `manifest.json` |

Everything in a run folder that came from a sample, a tool or a model is untrusted text: it is capped, never executed, and shown only as text.

### What the committed recordings name

The four recorded runs (`elf-benign`, `elf-dispute` = the demo bundle, `pe-basic`, `apk-basic`) under `demo/` and `tests/golden/` were made once with the real containers and the scripted mock model, then normalised through the reviewed update flow:

- **Tool version.** Their manifests and reports name `0.1.0` as the tool version and revision. A live run records the short commit id of the checkout it ran from instead (and "with local changes" when the tree was dirty);
  the recordings were changed so they do not name a commit that is not in this repository (`tests/goldenrun.py --update-golden --set-tool 0.1.0`; 30 files changed, and the diff of every one was only that string,
  the version and the hashes derived from them).
- **Image ids.** `manifest.json` names the two Docker image ids (`sha256:…`) of the machine that recorded them. They identify that build; they are not published images and nobody else's build has the same id.
- **`nonce.key`.** A random key that makes the per-task markers of that mock run repeatable (`run --replay` reuses it). It protects nothing: the runs are benign and the key is only a repeatability aid.
- **A sentence in `detection.json`.** The stored YARA result says the proof was made by swarmlabre's own matcher "(this box has no YARA program)". It is part of the recorded input, so it stays as recorded.

## A replayed or static view is a view of a recording

`swarmlabre serve --replay RUN` and the static demo (`tools/build-demo.py`) play a sealed run through the web UI. That is a presentation of what was recorded, folded from the run's events
at a virtual clock; it is **not new evidence** and it does not re-check anything. What the byte-for-byte guarantee covers is `swarmlabre replay` above. The player only guards the door: it runs
that replay first and refuses to show a recording that does not come out identical. It also cannot show what a bundle never held (the agents' thinking, per-task transcripts, the model's request
timings), and says so instead of inventing it ([ui.md](ui.md)).

## 4. Golden cases: the regression net

`tests/golden/<case>/` holds, for each case, `case.json` (what it proves), the **sealed trace** (`<run id>/`: the generated sample, the board's inputs in order, layout, events, manifest) and
`expected/` (the eight output files). `tests/test_golden.py` replays every trace with `swarmlabre replay` and compares every output **byte for byte** with `expected/`, replays it a second time
and requires the same bytes, and checks that `expected/` agrees with the hashes in the trace's own manifest. No Docker, no model, no network: the traces were recorded once.

| Case | Recorded how | What it proves |
|---|---|---|
| `rejects` | scripted | every reject code except `cap_exceeded`, one post each, next to accepted findings (byte-checked, call-cited, function, a second agent credited, technique) |
| `capped` | scripted | the 201st post of one role is rejected (`cap_exceeded`): 200 findings kept, 5 refused |
| `disputes` | scripted | a dispute settled as `stands`, `wrong` (finding refuted) and `unresolved`, one left open, the refused dispute posts, and a spot check of a disputed call-cited finding |
| `empty` | scripted | a run whose board stayed empty (no findings, no `board.jsonl`): verdict undetermined |
| `overclaim` | scripted | a Reporter verdict of malicious that cites only an unverified finding is shown as undetermined, low confidence |
| `benign-capped` | scripted | a benign verdict never goes above moderate confidence, even with two verified findings |
| `hostile` | scripted | strings in the sample that try to steer a model, a page or a spreadsheet reach the files only as cleaned, escaped or defanged text |
| `elf-benign` | real pipeline, mock model | the demo ELF end to end: benign verdict, four byte-checked findings, no rejects |
| `elf-dispute` | real pipeline, mock model | a UTF-16 string, a dispute raised by Static, a round-2 plan that settles it, a duplicate reject, YARA rules. Its trace is the committed demo bundle (`demo/sfaef16e6`) |
| `pe-basic` | real pipeline, mock model | a PE32+ with an import table through host parse, Ghidra prep and the report |
| `apk-basic` | real pipeline, mock model | an APK (binary manifest, DEX, assets) through host parse, jadx prep, the Mobile ATT&CK matrix and the report |

*Scripted* cases are lists of board inputs in `tests/golden_cases.py`, recorded through the same hooks a live run uses (no containers); a test re-records them and requires the committed trace
byte for byte. *Real pipeline* cases ran in the two containers with the scripted mock model once, then were sealed and exported; the samples are generated by `swarmlabre/corpus.py`
(`python3 -m swarmlabre corpus DIR`) from known-benign bytes: reserved example domains (RFC 2606), documentation addresses (RFC 5737), code that only exits, no EICAR. A script cannot be
a sample (swarmlabre takes ELF, PE and APK); the generator writes one anyway and a test pins the refusal message.

### Changing a golden file

A change to the report code changes golden bytes, on purpose or by mistake, and the tests fail until someone decides which. The decision is a reviewed update:

```sh
python3 tests/goldenrun.py --update-golden              # writes NOTHING to tests/golden/<case>. Re-records (scripted) or reseals (recorded) into tests/golden/.proposed,
                                                        # prints every added, removed and changed file with a diff, and a 12-character review token. Exit 1 if anything would change.
python3 tests/goldenrun.py --update-golden --accept TOKEN   # applies exactly the proposal that was shown; refuses a token that does not match the files on disk, and refuses when CI is set
python3 tests/goldenrun.py --proposal-dir DIR ...       # also copies the proposal out, to read it with `diff -ru`
python3 tests/goldenrun.py --record-real                # re-records the real-pipeline cases (Docker and the two images), as a proposal for the same review
```

*Resealing* rebuilds the outputs and the two inputs that depend on the code (`swarm.json`, `board.jsonl`) from the recorded inputs and rewrites the manifest hashes; the posts, the sample,
the layout and the events are never touched. A new case is the same flow: add it to `tests/golden_cases.py`, run `--update-golden`, read the list of new files, accept.

### CI (`.github/workflows/ci.yml`)

`tests`: `python3 -m unittest discover -s tests` (browser checks skipped). `determinism`: `tests/goldenrun.py --check --twice` under `PYTHONHASHSEED` 0, 1, 4242 and random, two time zones and
`python3 -X dev -W error`, with the printed `case/file sha256` tables compared across seeds; `--update-golden` must propose nothing (the recorder and the reseal reproduce the committed files on
the runner); the demo bundle replays. The Pages workflow replays the same bundle before it builds the site.

### What the cases do not cover

- **Only the board's side of the record.** A replay starts at `inputs.jsonl`, after the `@@SWARM <nonce>` scan. That a forged finding line (wrong nonce, indented, mid-line) never reaches the
  board is a unit test of `_scan` (`HostileStrings`), not a golden case. Agent turns, tool results and the model's replies are recorded but not re-run.
- **Caps:** the per-role cap of 200 posts is covered; the run-wide cap of 1,000 findings, the 400-reject cap and the 64 MiB model-trace cap are not.
- **Runs that did not end well:** no case for a failed, stopped or timed-out run, a run with fewer than six roles, or more than one planned round.
- **Samples:** one small hand-built ELF, PE and APK each. No packed or obfuscated file, no 32-bit or ARM PE/ELF, no multi-DEX APK, no sample larger than a few KB, no script (not a sample type).
- **Replay at the downstream level** (no sample kept) is tested on a generated run in `test_replay.py`, not in a golden case.
- **Other machines:** replay was checked on this host only (Python 3.12.3, Linux arm64). Another minor version, another OS or another CPU architecture is untested.
- **The containers** are not part of any golden check; the four real-pipeline traces (`elf-benign`, `elf-dispute`, `pe-basic`, `apk-basic`) record what they produced on one build of the two images.

### Found by the cases (all fixed)

- A run in which no agent posted anything never wrote `inputs.jsonl` or `board.jsonl`, and `replay` refused it as "not a recorded run" (an empty board is a legitimate result). Fixed.
- `Board.spot` stored a spot check's rows in the key order it was given, while `inputs.jsonl` is written with sorted keys: a live run with a spot check would not have replayed byte for byte. Fixed (one key order).
- A test of the 1 MiB JSON cap raced the server closing the connection and failed about one run in three. The test now declares the size and sends no body.
- `report.md` passed raw HTML and Markdown links from the sample or an agent through (only `|` and line breaks were escaped). Fixed: the lines of `report.md` are joined by `md_join`, which escapes every piece except the fenced YARA blocks the writer marks itself (`RawMd`): `<` and `>` become entities, `](` is broken (so no link or image target the text chose, such as `javascript:`) and a line may not start a link reference definition. The `hostile` golden case carries a tag, a `javascript:` link, an image and a reference definition; the diff of its `expected/report.md` was reviewed through `--update-golden`, and the other ten cases did not change. Text that only looks like a code fence is not trusted either: the `md_text` escape does not touch backticks, so a later fix (`md_prose`) puts a backslash in front of a line of the Reporter's text that opens a code fence, a heading or a setext underline and escapes `|` in it, because a fence that never closes would turn the rest of `report.md` into code in a viewer; the YARA fences are marked by the writer and are the only ones that stay.

### Checks that were run (2026-11-13, Python 3.12.3, one Linux arm64 host)

On a **clean clone** of this repository (`git clone` of the local repo, no state, no ignored files), repeated on the tree that was uploaded:

- `python3 -m unittest discover -s tests` with a PATH that held only `python3`, `node` and `sh` (no `docker`, `sg`, `git`, `firefox`): 164 tests, 4 skipped (2 end-to-end, 2 browser), 0 failed.
- The `run:` steps of both workflows, extracted from the YAML and executed as written with `CI=true`: all exit 0 (`tests/goldenrun.py --check --twice` under four seeds and two time zones with identical
  hash tables, 78 lines each; `--update-golden` proposes nothing; the demo bundle replays; the static demo builds and holds no fetchable address).
- `tests/ui/parity.py demo/sfaef16e6` (86 checks) and `tests/ui/tour.py demo/sfaef16e6` (144 checks) in headless Firefox: 0 failed.

In the working copy (not the clone), as mutation checks: one appended byte in an `expected/` file, one edited recorded post (manifest untouched), and one changed sentence in the report code each make the golden tests fail.

**Not checked:** the two workflow files have never run on GitHub (no remote exists; `act` and `actionlint` are not installed here; PyYAML parsed both and a structural check of jobs, steps and
`needs` passed). The action versions (`checkout@v4`, `setup-python@v5`) and the `ubuntu-latest` image are unverified. The browser checks are not in CI. The real-pipeline cases cannot be re-recorded
without Docker and the images.
