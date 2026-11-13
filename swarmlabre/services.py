"""The services `Swarms` needs from its host, as one namespace (`Ctx`). The host (the CLI or the server) builds them with `make_ctx`.

Without a model client the model services raise `NotReady` with a plain message, so `report` (which needs no model) works and `run` fails clearly.
"""
import shlex
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

from . import gate, reportschema, sandbox
from .textutil import plain, scrub, SECRETS


class NotReady(RuntimeError):
    pass


def _meminfo():
    """{"available": bytes} from /proc/meminfo (MemAvailable); zero where the file is missing."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return {"available": int(line.split()[1]) * 1024}
    except (OSError, ValueError):
        pass
    return {"available": 0}


class _Fields(dict):
    def __missing__(self, k):
        return ""


def notifier(cfg):
    """notify(kind, key, **fields): runs `[swarm] notify_cmd` with two extra arguments, the title and the text of a fixed template (run id, counts and fixed words only:
    never agent text, file names or steering). No command configured = nothing happens. Never raises."""
    try:
        cmd = shlex.split(str(cfg.get("swarm", {}).get("notify_cmd") or ""))
    except ValueError:
        cmd = []

    def notify(kind, key, **kw):
        if not cmd:
            return
        try:
            from .swarms import NOTIFY_RULES
            rule = NOTIFY_RULES.get(kind)
            if rule:
                text = rule["text"].format_map(_Fields({k: plain(v, 200) for k, v in kw.items()}))
                proc = subprocess.Popen(cmd + [rule["title"], text], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                threading.Thread(target=proc.wait, daemon=True).start()       # reap it
        except Exception:
            pass
    return notify


def _later(what):
    def f(*a, **k):
        raise NotReady("%s needs a model: set [model] in swarmlabre.toml or pass --mock" % what)
    return f


def make_ctx(cfg, state, skills_dir, client=None):
    """The services of one process. `client` = the model client (client.py); without one the model services say so."""
    sw, mc = cfg.get("swarm", {}), cfg.get("model", {})
    par = max(1, min(int(sw.get("max_parallel", 4)), 6))
    health = sandbox.Health()
    sampling = {"temperature": float(mc.get("temperature", 0.0))}
    if mc.get("seed") is not None:
        sampling["seed"] = int(mc["seed"])
    skills_dir = Path(skills_dir)
    ctx = SimpleNamespace(
        stats_file=Path(state) / "model-stats.json", state_dir=Path(state) / "runs", skills_dir=skills_dir, agent_cfg={"proxy_port": 8801},
        plain=plain, scrub=scrub, secrets=lambda: list(SECRETS), docker=sandbox.docker, mem_info=_meminfo,
        reserve=int(float(sw.get("memory_reserve_gb", 4)) * (1 << 30)),
        sys_window=lambda t0, t1: None, notify=notifier(cfg), parallel=lambda: par,
        validate_report=reportschema.validate_report, clean_notes=reportschema.clean_notes, trim_notes=reportschema.trim_notes,
        Sandbox=sandbox.Sandbox, posture=sandbox.posture, blockers=health.blockers,
        check_skills=lambda prof, asked: sandbox.check_skills(skills_dir, asked),
    )
    if client is None:
        ctx.served = lambda: None
        ctx.sampling = lambda: {}
        ctx.pi_config = ctx.model_gate = ctx.ask_model = _later("the model")
        return ctx
    ctx.served = client.info
    ctx.sampling = lambda: {**sampling, **client.sampling()}
    ctx.pi_config = lambda d, prof, chosen=(): sandbox.pi_config(d, prof, chosen, client.info(), mc, ctx.agent_cfg["proxy_port"])
    def _limits():
        info = client.info()
        return {"model": (info or {}).get("model"), "max_tokens": max(int(mc.get("max_tokens") or 0), 32768)}      # 32768 is what pi gets when only the context window is set (sandbox.pi_config)
    ctx.model_gate = lambda path, parallel, on: gate.Gate(client, parallel, on, sampling, _limits()).start_unix(path)
    ctx.ask_model = lambda srv, system, user, max_tokens=2048: srv.gate.ask(system, user, max_tokens, mc.get("extra_body") or None)
    return ctx
