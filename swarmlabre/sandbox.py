"""The containers of a run: the hardened `docker run` command, its checks, and the pi agent's config.

Every container is `--network none`, read-only root, all capabilities dropped, no-new-privileges, memory and pid limits. The model reaches the agent container
only through the run's Unix socket (gate.py), mounted read-only; no key ever enters a container.
"""
import grp
import json
import os
import pwd
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

AGENT_IMAGE = "swarmlabre-agent"
TOOLS_IMAGE = "swarmlabre-tools"


def docker(argv):
    """argv for a docker command. A long-lived service keeps the groups from when it started, so a docker group added later is missing until a re-login;
    `sg docker` picks it up per call."""
    try:
        if grp.getgrnam("docker").gr_gid not in os.getgroups():
            return ["sg", "docker", "-c", shlex.join(argv)]
    except KeyError:
        pass
    return list(argv)


class Sandbox:
    """Hardened container launcher. A harness hands it an image, an entry command, mounts and env; the profile sets limits."""
    NETWORKS = ("none",)               # the only network a swarm container may have: none

    def __init__(self, name, prof):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name):
            raise ValueError("bad sandbox name %r" % name)      # goes straight into docker --name
        self.name, self.prof = name, prof

    def argv(self, entry, mounts=(), env=None, workdir="/work", tmp_mb=512, home_mb=256, shared_tmpfs=False, proxy_dir=None, private=()):
        """`tmp_mb`/`home_mb` size /tmp and /home/agent; `shared_tmpfs` makes /tmp `mode=1777` and /work and /home/agent root-owned `0755`, so containers whose
        processes run as several uids (swarm roles, via `docker exec --user`) cannot create anything there; each uid gets its own tmpfs from `private` =
        [(path, uid, mb)] (mode 0700, owned by that uid), so no role can plant files in another role's folders. `proxy_dir` is the read-only /run/proxy
        mount (the per-run model socket)."""
        p, uid = self.prof, os.getuid()
        if p.get("network", "none") not in self.NETWORKS:
            raise ValueError("network %r is not allowed (only %s)" % (p.get("network"), ", ".join(self.NETWORKS)))
        sock = p.get("proxy") == "socket"
        if p.get("proxy") not in (None, "socket"):
            raise ValueError("proxy %r is not allowed (only \"socket\")" % p.get("proxy"))
        gid = pwd.getpwuid(uid).pw_gid                        # not os.getgid(): under `sg docker` that is the docker group
        mem = str(p.get("memory", "8g"))
        own = "mode=0755" if shared_tmpfs else "uid=%d,gid=%d" % (uid, gid)
        tmpown = "mode=1777" if shared_tmpfs else own
        a = ["docker", "run", "--rm", "-i", "--init", "--name", self.name, "--user", "%d:%d" % (uid, gid),
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
             "--pids-limit", str(p.get("pids", 256)), "--memory", mem, "--memory-swap", mem,
             "--cpus", str(p.get("cpus", 4)), "--network", "none",
             "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=%dm,%s" % (int(tmp_mb), tmpown),
             "--tmpfs", "/home/agent:rw,exec,nosuid,nodev,size=%dm,%s" % (int(home_mb), own),
             "--tmpfs", "%s:rw,exec,nosuid,nodev,size=%s,%s" % (workdir, p.get("scratch", "2g"), own)]
        for path, puid, mb in private:
            a += ["--tmpfs", "%s:rw,exec,nosuid,nodev,size=%dm,uid=%d,gid=%d,mode=0700" % (path, int(mb), int(puid), int(puid))]
        for host, inside, mode in mounts:
            a += ["-v", "%s:%s:%s" % (host, inside, mode)]
        if sock:
            if not proxy_dir:
                raise ValueError("a socket profile needs proxy_dir")
            a += ["-v", "%s:/run/proxy:ro" % proxy_dir]       # the directory, not the socket. A socket in a read-only mount still connects
        for k, v in (env or {}).items():
            a += ["-e", "%s=%s" % (k, v)]
        return docker(a + ["-w", workdir, p.get("image", AGENT_IMAGE)] + list(entry))

    def memory(self):
        """(limit, in use) in bytes from the container's cgroup; tmpfs pages are charged there too. None when not running."""
        r = subprocess.run(docker(["docker", "inspect", "--type", "container", "-f", "{{.Id}}", self.name]), capture_output=True, text=True, timeout=5)
        cg = Path("/sys/fs/cgroup/system.slice/docker-%s.scope" % r.stdout.strip())
        try:
            lim = (cg / "memory.max").read_text().strip()
            return (None if lim == "max" else int(lim)), int((cg / "memory.current").read_text())
        except (OSError, ValueError):
            return None

    def kill(self):
        """Remove the container by name. Killing the docker client alone leaves the container running."""
        try:
            subprocess.run(docker(["docker", "rm", "-f", self.name]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except Exception:
            pass


def posture(info):
    """What is wrong with a running container, from its `docker inspect` entry (empty list = locked down)."""
    h, bad = info.get("HostConfig", {}), []
    if not h.get("ReadonlyRootfs"): bad.append("writable root")
    if "ALL" not in (h.get("CapDrop") or []): bad.append("capabilities kept")
    if not any("no-new-privileges" in x for x in (h.get("SecurityOpt") or [])): bad.append("new privileges allowed")
    if h.get("Privileged"): bad.append("privileged")
    if h.get("NetworkMode") not in Sandbox.NETWORKS: bad.append("%s network" % h.get("NetworkMode"))
    if any("docker.sock" in b for b in (h.get("Binds") or [])): bad.append("docker socket mounted")
    if any(b.split(":")[1:2] == ["/run/proxy"] and not b.endswith(":ro") for b in (h.get("Binds") or [])): bad.append("proxy socket directory writable")
    if not h.get("Memory"): bad.append("no memory limit")
    if not h.get("PidsLimit"): bad.append("no pid limit")
    if (info.get("Config", {}).get("User") or "0").split(":")[0] in ("0", "root"): bad.append("runs as root")
    return bad


NET_PROBE = ("const os=require('os'),net=require('net');const nics=Object.entries(os.networkInterfaces()).filter(([k,v])=>v.some(a=>!a.internal)).map(([k])=>k);"
             "const c=net.connect({host:'1.1.1.1',port:443,timeout:3000});const out=r=>{console.log(JSON.stringify({nics,reach:r}));process.exit(0)};"
             "c.on('connect',()=>out(true));c.on('error',()=>out(false));c.on('timeout',()=>out(false));")


class Health:
    """The network check that gates Start: a throwaway container with `--network none` must have no interface besides loopback and must not reach the internet.
    `--network none` closes the network by construction; this proves docker honoured it. The result is kept 60 s (8 s after a failure)."""
    OK_TTL, BAD_TTL = 60, 8

    def __init__(self, image=AGENT_IMAGE):
        self.image, self.lock, self.cache = image, threading.Lock(), (0.0, [])

    def blockers(self):
        with self.lock:
            at, bad = self.cache
            if time.time() - at < (self.BAD_TTL if bad else self.OK_TTL):
                return list(bad)
            bad = []
            try:
                r = subprocess.run(docker(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--entrypoint", "node", self.image, "-e", NET_PROBE]),
                                   capture_output=True, text=True, timeout=40, stdin=subprocess.DEVNULL)
                got = json.loads((r.stdout.strip().splitlines() or ["null"])[-1])
                if r.returncode != 0 or not isinstance(got, dict) or not isinstance(got.get("nics"), list) or not isinstance(got.get("reach"), bool):
                    bad.append("the network check did not give a clear answer (exit %s): a run does not start until it does" % r.returncode)
                else:
                    if got["nics"]:
                        bad.append("a container with --network none has the interface(s) %s" % ", ".join(str(x) for x in got["nics"][:4]))
                    if got["reach"]:
                        bad.append("a container with --network none reached the internet")
            except (OSError, ValueError, subprocess.TimeoutExpired) as e:
                bad.append("the network check could not run (%s): a run does not start until it can" % type(e).__name__)      # fail closed: no answer is not a pass
            self.cache = (time.time(), bad)
            return list(bad)


# ---- skills and the pi agent's config

SKILL_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def check_skills(skills_dir, names):
    """The skill names for this run, each one a folder under skills_dir with a SKILL.md whose front matter has a matching name and a description.
    pi skips a broken SKILL.md silently, so a broken one is refused here."""
    names = list(dict.fromkeys(names))
    for n in names:
        if not isinstance(n, str) or not SKILL_NAME.fullmatch(n):
            raise ValueError("bad skill name %r" % (n,))
        f = Path(skills_dir) / n / "SKILL.md"
        try:
            head = f.read_text(errors="replace")[:4000]
        except OSError:
            raise ValueError("no skill named %r in skills/" % n)
        m = re.match(r"---\n(.*?)\n---", head, re.S)
        meta = m.group(1) if m else ""
        if not re.search(r"(?m)^name:\s*%s\s*$" % re.escape(n), meta) or not re.search(r"(?m)^description:\s*\S", meta):
            raise ValueError("skill %s: SKILL.md needs front matter with name: %s and a description" % (n, n))
    return names


def pi_config(d, prof, chosen, info, model_cfg, port=8801):
    """Write models.json, settings.json and system-prompt.md into folder d for the pi agent. Keyless: the base URL is the loopback forwarder of the run's socket.
    `info` = the client's {"backend", "model"}; `model_cfg` = the [model] section (context_window, max_tokens, reasoning, thinking_toggle). Returns `info` or None."""
    if not info:
        return None
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    m = {"id": info["model"], "name": info["model"]}
    ctx = int(model_cfg.get("context_window") or 0)
    if ctx > 0:
        m["contextWindow"] = ctx
        m["maxTokens"] = int(model_cfg.get("max_tokens") or min(32768, ctx // 4))
    if model_cfg.get("reasoning"):
        m["reasoning"] = True
        if model_cfg.get("thinking_toggle"):
            m["compat"] = {"thinkingFormat": "chat-template", "chatTemplateKwargs": {"enable_thinking": {"$var": "thinking.enabled"}}}
    (d / "models.json").write_text(json.dumps({"providers": {"swarmlabre": {"baseUrl": "http://127.0.0.1:%d/v1" % int(port), "api": "openai-completions", "apiKey": "none",
                                                                             "models": [m]}}}, indent=2))
    st = {"packages": [], "skills": ["/skills/%s" % s for s in chosen]}
    if model_cfg.get("reasoning"):
        st["defaultThinkingLevel"] = str(model_cfg.get("thinking_level") or "medium")
    (d / "settings.json").write_text(json.dumps(st, indent=2))
    sp = d / "system-prompt.md"
    text = str(prof.get("system_prompt", "")).strip()
    if text:
        sp.write_text(text + "\n")
    elif sp.exists():
        sp.unlink()
    return dict(info)
