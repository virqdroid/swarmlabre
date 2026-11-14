"""The one config file, `swarmlabre.toml`. Search order: `--config`, `$SWARMLABRE_CONFIG`, `./swarmlabre.toml`, `~/.config/swarmlabre/swarmlabre.toml`.

Missing file = defaults (every key has one). The file is only read, never written. A key's meaning is documented in `swarmlabre.example.toml`.
"""
import os
import tomllib
from pathlib import Path

DEFAULTS = {
    "paths": {"state": "~/.local/state/swarmlabre"},
    "model": {"base_url": "", "api_key_env": "SWARMLABRE_API_KEY", "model": "", "temperature": 0.0, "seed": 1,
              "context_window": 0, "max_tokens": 0, "reasoning": False, "thinking_toggle": False, "thinking_level": "medium", "extra_body": {}, "mock": "", "replay": ""},
    "serve": {"host": "127.0.0.1", "port": 8810},
    "swarm": {
        "enabled": True, "tlp": "AMBER", "report_org": "", "report_contact": "", "report_logo": False, "detection_rules": True,
        "keep_runs": 20, "keep_sample": True, "max_rounds": 2, "max_parallel": 4, "task_minutes": 20, "run_minutes": 0,
        "prep_minutes": 25, "prewarm_functions": 40, "sample_mb": 256, "max_sample_native_mb": 4, "max_sample_apk_mb": 16,
        "tools_memory_gb": 0, "tools_cpus": 4, "agent_memory_gb": 0, "wait_minutes": 30, "memory_reserve_gb": 4, "notify_cmd": "",
    },
}


def candidates(explicit=None):
    if explicit:
        yield Path(explicit)
    if os.environ.get("SWARMLABRE_CONFIG"):
        yield Path(os.environ["SWARMLABRE_CONFIG"])
    yield Path("swarmlabre.toml")
    yield Path("~/.config/swarmlabre/swarmlabre.toml").expanduser()


def defaults():
    return {k: dict(v) for k, v in DEFAULTS.items()}


def load(explicit=None):
    """The merged config (defaults under the file's sections) and the path it came from, or None."""
    cfg = defaults()
    found = None
    for p in candidates(explicit):
        if p.is_file():
            with open(p, "rb") as f:
                data = tomllib.load(f)
            for sec, vals in data.items():
                if isinstance(vals, dict):
                    cfg.setdefault(sec, {}).update(vals)
            found = p
            break
    else:
        if explicit:
            raise FileNotFoundError("config file not found: %s" % explicit)
    return cfg, found


def make_private_dir(path):
    """mkdir -p where every folder this call creates is mode 0700 (the umask can only remove bits); a folder that exists is left alone."""
    path = Path(path)
    missing = []
    while not path.exists() and path != path.parent:
        missing.append(path)
        path = path.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700, exist_ok=True)


def state_dir(cfg):
    return Path(str(cfg["paths"]["state"])).expanduser()
