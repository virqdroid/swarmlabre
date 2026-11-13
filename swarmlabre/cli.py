"""Command line: `swarmlabre <command>`. Exit codes: 0 done, 1 the work failed, 2 bad usage or input, 3 needs a model and none is configured."""
import argparse
import json
import math
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

from . import __version__, client as clientmod, config as cfgmod, services

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_LATER = 0, 1, 2, 3
DEFAULT_BRIEF = "What does this sample do? Name its most important functions and say what each one is for."
REPORT_FILES = ("report.json", "report.md", "report.html", "board.json", "iocs.csv", "iocs.stix.json", "iocs.misp.json", "detection.yar")


def _swarms(cfg, runs_dir, client=None):
    from . import swarms
    ctx = services.make_ctx(cfg, runs_dir.parent, swarms.ROOT / "skills", client)
    ctx.state_dir = runs_dir
    return swarms.Swarms(ctx, cfg.get("swarm", {}))


def cmd_report(a, cfg):
    """Build every report format from a stored run folder (in place, into its out/), optionally copying the files to --out."""
    target = Path(a.run).expanduser()
    if not target.is_dir():                                   # a run id: look in the configured state folder
        target = cfgmod.state_dir(cfg) / "runs" / a.run
    if not target.is_dir() or not (target / "swarm.json").is_file():
        print("not a run folder (no swarm.json): %s" % a.run, file=sys.stderr)
        return EXIT_USAGE
    target = target.resolve()
    sw = _swarms(cfg, target.parent)
    rt = sw.rts.get(target.name)
    if not rt:
        print("the run record in %s is not readable" % target, file=sys.stderr)
        return EXIT_USAGE
    sw._write_out(rt)
    made = [n for n in REPORT_FILES if (target / "out" / n).is_file()]
    if a.out:
        dest = Path(a.out).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        for n in made:
            shutil.copyfile(target / "out" / n, dest / n)
    print(json.dumps({"run": target.name, "out": str(Path(a.out).expanduser() if a.out else target / "out"), "files": made}))
    return EXIT_OK if "report.json" in made else EXIT_FAIL


def cmd_run(a, cfg):
    """Analyse one sample: stage it, start the run, wait for it, print where the report is. Ctrl-C stops the run and keeps what the board holds."""
    import time
    if a.mock:
        cfg["model"]["mock"] = a.mock
    if a.replay:
        cfg["model"]["replay"] = a.replay
        if not a.brief:
            try:
                a.brief = json.loads((Path(a.replay).expanduser() / "swarm.json").read_text())["brief"]
            except (OSError, ValueError, KeyError):
                pass
    a.brief = a.brief or DEFAULT_BRIEF
    try:
        client = clientmod.from_config(cfg)
    except (ValueError, OSError) as e:
        print("model: %s" % e, file=sys.stderr)
        return EXIT_LATER if isinstance(e, clientmod.NoModel) else EXIT_USAGE
    if isinstance(client, clientmod.OpenAICompat) and client.info():
        print("seed: %s" % client.probe_seed(int(cfg["model"].get("seed") or 1)), file=sys.stderr)
    runs = cfgmod.state_dir(cfg) / "runs"
    sw = _swarms(cfg, runs, client)
    if sw._lock_run():                                # nobody else is running: containers of a crashed run are stale
        sw._unlock_run()
        sw.recover()
        sw.reap()
    code, body = sw.stage_file(a.sample)
    if code != 200:
        print(body.get("error", "cannot stage the sample"), file=sys.stderr)
        return EXIT_USAGE
    extra = {}
    if a.replay:                                    # the same task keys, so the conversations (which echo them) match the recording request for request
        try:
            extra["nonce_key"] = (Path(a.replay).expanduser() / "nonce.key").read_text().strip()
        except OSError:
            pass
    code, body = sw.start({"brief": a.brief, "tlp": a.tlp or None, **({"roles": a.roles.split(",")} if a.roles else {}), **extra})
    if code != 200:
        print(body.get("error", "cannot start"), file=sys.stderr)
        return EXIT_USAGE if code in (400, 404, 413) else EXIT_FAIL
    rid = body["run"]
    rt = sw.rts[rid]
    last = None
    try:
        while rt.thread.is_alive():
            rt.thread.join(2)
            now = (rt.rec.get("phase"), rt.rec["status"], sum(1 for t in rt.rec["tasks"] if t.get("state") == "done"))
            if now != last and not a.quiet:
                print("%s: %s, %d task%s done" % (rid, rt.rec.get("phase") or rt.rec["status"], now[2], "" if now[2] == 1 else "s"), file=sys.stderr, flush=True)
                last = now
    except KeyboardInterrupt:
        print("stopping %s ..." % rid, file=sys.stderr)
        sw.stop(rid)
        rt.thread.join(120)
        return 130
    rec = rt.rec
    out = rt.dir / "out"
    files = [n for n in REPORT_FILES if (out / n).is_file()]
    res = {"run": rid, "status": rec["status"], "reason": rec.get("reason"), "dir": str(rt.dir), "files": files, "counts": rec.get("counts")}
    if isinstance(client, clientmod.Replay):
        res["replay_diverged"] = len(client.diverged)          # requests with no recorded reply: 0 = the agents behaved exactly as in the recording
    print(json.dumps(res))
    if a.out and files:
        dest = Path(a.out).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        for n in files:
            shutil.copyfile(out / n, dest / n)
    return EXIT_OK if rec["status"] == "done" else EXIT_FAIL


def cmd_demo(a, cfg):
    from . import demo
    sample, script = demo.write(a.dir, a.variant)
    print(json.dumps({"sample": str(sample), "mock_script": str(script)}))
    print("try: swarmlabre run %s --mock %s" % (sample, script), file=sys.stderr)
    return EXIT_OK


def cmd_corpus(a, cfg):
    """Write the benign generated samples (ELF, PE, APK, a script, a hostile-string ELF) into a folder."""
    from . import corpus
    names = a.names or list(corpus.NAMES)
    bad = [n for n in names if n not in corpus.NAMES]
    if bad:
        print("no such sample %r (have: %s)" % (bad[0], ", ".join(corpus.NAMES)), file=sys.stderr)
        return EXIT_USAGE
    written = {n: str(corpus.write(n, a.dir)[0]) for n in names}
    print(json.dumps(written))
    return EXIT_OK


def cmd_replay(a, cfg):
    """Rebuild a recorded run offline and compare every output with the manifest. Exit 0 when everything is identical."""
    from . import replay
    target = Path(a.run).expanduser()
    if not target.is_dir():
        target = cfgmod.state_dir(cfg) / "runs" / a.run
    if not target.is_dir():
        print("not a run folder: %s" % a.run, file=sys.stderr)
        return EXIT_USAGE
    try:
        res = replay.replay(target, a.out, use_sample=not a.no_sample)
    except replay.ReplayError as e:
        print("replay: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(res, indent=1, sort_keys=True))
    return EXIT_OK if res["ok"] else EXIT_FAIL


def cmd_export(a, cfg):
    """Pack a sealed run into a small folder that `replay` can rebuild anywhere. The sample is left out unless --with-sample."""
    from . import replay
    target = Path(a.run).expanduser()
    if not target.is_dir():
        target = cfgmod.state_dir(cfg) / "runs" / a.run
    try:
        out = replay.export(target, a.dest, a.with_sample)
    except replay.ReplayError as e:
        print("export: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps({"bundle": str(out), "sample": (out / "input" / "sample").is_file()}))
    return EXIT_OK


def cmd_serve(a, cfg):
    """The web UI. Live: the real pipeline (needs Docker and a model). --replay RUN: a recorded run played back through the same UI, with no model and no Docker."""
    import threading
    from . import server
    sv = cfg.get("serve", {})
    host, port = a.host or sv.get("host", "127.0.0.1"), int(a.port if a.port is not None else sv.get("port", 8810))
    state = cfgmod.state_dir(cfg)
    token = server.load_token(state)
    sw = None
    if a.replay:
        from . import player
        try:
            speed = 1.0 if a.speed in (None, "real") else float(a.speed)
            if not math.isfinite(speed) or speed <= 0:
                raise ValueError("--speed must be 'real' or a number above 0")
            backend = player.Replay(a.replay, speed=speed, paused=a.paused)
        except (player.ReplayError, ValueError) as e:
            print("serve --replay: %s" % e, file=sys.stderr)
            return EXIT_USAGE
        app = server.App(backend, token, "replay", "This is a recorded run. Nothing can be started here.", host, extra={"run": backend.rid, "replay": backend.state()})
    else:
        try:
            client = clientmod.from_config(cfg)
        except (ValueError, OSError) as e:
            print("model: %s (the page opens, but a run cannot start)" % e, file=sys.stderr)
            client = None
        runs = state / "runs"
        sw = _swarms(cfg, runs, client)
        if sw._lock_run():
            sw._unlock_run()
            sw.recover()
            sw.reap()
        backend = sw
        app = server.App(backend, token, "live", "", host)
    prev = _sigterm_is_ctrl_c()
    try:
        try:
            srv = server.make_server(app, host, port)
        except OSError as e:
            print("cannot listen on %s:%s: %s" % (host, port, e), file=sys.stderr)
            return EXIT_FAIL
        if host not in server.LOOPBACK:
            print("warning: listening on %s, not only on this machine; the token is the only protection and the traffic is not encrypted" % host, file=sys.stderr)
        t = None
        try:
            print("swarmlabre %s on http://%s:%s/#token=%s" % ("replay" if a.replay else "serve", "[%s]" % host if ":" in host else host, srv.server_address[1], token), flush=True)
            t = server.serve_forever(srv)
            while t.is_alive():
                t.join(1)
        except KeyboardInterrupt:                # Ctrl-C, or SIGTERM at any moment after the address was printed
            print("stopping ...", file=sys.stderr)
        finally:
            if t is not None:
                srv.shutdown()                   # would wait for ever if serve_forever never ran
            srv.server_close()
    finally:
        _restore_sigterm(prev)
        if a.replay:
            backend.close()                  # removes the replay's temporary copy of the run, also when the port was taken or a signal arrived
        elif sw is not None:
            act = sw.active()
            if act:
                sw.stop(act.rec["id"])
                act.thread.join(120)
    return EXIT_OK


def _sigterm_is_ctrl_c():
    """A plain `kill` ends `serve` the way Ctrl-C does, so the cleanup in cmd_serve runs. Returns what to restore (None: not the main thread, nothing changed)."""
    import signal
    def raise_interrupt(signum, frame):
        raise KeyboardInterrupt
    try:
        return signal.signal(signal.SIGTERM, raise_interrupt)
    except ValueError:                       # signal handlers can only be set in the main thread
        return None


def _restore_sigterm(prev):
    import signal
    if prev is not None:
        try:
            signal.signal(signal.SIGTERM, prev)
        except (ValueError, TypeError):
            pass


def build_parser():
    p = argparse.ArgumentParser(prog="swarmlabre", description=__doc__.split("\n")[0])
    p.add_argument("--config", help="path of swarmlabre.toml (default: $SWARMLABRE_CONFIG, ./swarmlabre.toml, ~/.config/swarmlabre/)")
    p.add_argument("--version", action="version", version="swarmlabre " + __version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report", help="build the report files of a stored run")
    r.add_argument("run", help="a run folder or a run id (sXXXXXXXX)")
    r.add_argument("--out", help="also copy the report files into this folder")
    r.set_defaults(fn=cmd_report)
    d = sub.add_parser("demo", help="write a harmless demo sample and the script of a mock model that analyses it")
    d.add_argument("dir", help="folder to write the demo sample and mock-script into")
    d.add_argument("--variant", choices=("one", "two"), default="one", help="two = a second sample with a UTF-16 string, a dispute and a round-2 plan")
    d.set_defaults(fn=cmd_demo)
    c = sub.add_parser("corpus", help="write the benign generated samples (ELF, PE, APK, script, hostile strings) into a folder")
    c.add_argument("dir")
    c.add_argument("names", nargs="*", help="which samples (default: all)")
    c.set_defaults(fn=cmd_corpus)
    u = sub.add_parser("run", help="analyse a sample with the agent swarm")
    u.add_argument("sample", help="an ELF, PE or APK file")
    u.add_argument("--brief", default=None, help="the question the agents answer (default: what does it do, name its main functions)")
    u.add_argument("--replay", metavar="RUN", help="answer from the recorded model replies of an earlier run (containers still run; the agents get the exact recorded answers)")
    u.add_argument("--mock", metavar="SCRIPT", help="answer from a scripted mock model (a JSON file) instead of [model] base_url")
    u.add_argument("--roles", help="comma-separated roles (triage and reporter always run); default all six")
    u.add_argument("--tlp", help="report marking: CLEAR, GREEN, AMBER, AMBER+STRICT, RED")
    u.add_argument("--out", help="also copy the report files into this folder")
    u.add_argument("--quiet", action="store_true", help="no progress lines")
    u.set_defaults(fn=cmd_run)
    rp = sub.add_parser("replay", help="rebuild a recorded run offline and compare every output with its manifest")
    rp.add_argument("run", help="a run folder or a run id")
    rp.add_argument("--out", help="also write the rebuilt files into this folder")
    rp.add_argument("--no-sample", action="store_true", help="do not use the kept sample: re-run only the report building (the downstream level)")
    rp.set_defaults(fn=cmd_replay)
    ex = sub.add_parser("export", help="pack a sealed run into a folder that replay can rebuild elsewhere")
    ex.add_argument("run", help="a run folder or a run id")
    ex.add_argument("dest", help="folder to create <run id>/ in")
    ex.add_argument("--with-sample", action="store_true", help="include the sample (the bundle then replays at the full level)")
    ex.set_defaults(fn=cmd_export)
    sv = sub.add_parser("serve", help="start the web UI (live, or --replay RUN for a recorded run)")
    sv.add_argument("--host", help="address to listen on (default 127.0.0.1, this machine only)")
    sv.add_argument("--port", type=int, help="port (default 8810; 0 = any free port)")
    sv.add_argument("--replay", metavar="RUN", help="play a sealed run folder or an exported bundle through the UI: no model, no Docker")
    sv.add_argument("--speed", default=None, help="replay speed: 'real' (default) or a number, 8 = eight times faster")
    sv.add_argument("--paused", action="store_true", help="replay: start paused")
    sv.set_defaults(fn=cmd_serve)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        cfg, _ = cfgmod.load(a.config)
    except (FileNotFoundError, ValueError) as e:
        print("config: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    try:
        return a.fn(a, cfg)
    except services.NotReady as e:
        print(str(e), file=sys.stderr)
        return EXIT_LATER


if __name__ == "__main__":
    sys.exit(main())
