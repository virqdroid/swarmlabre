"""A very small WebDriver (W3C) client for headless Firefox, standard library only. Used by the UI checks (parity, offline load, console errors).

    with Browser(width=1280) as b:
        b.get(url); b.wait_for("document.querySelector('#sw-map')"); b.js("return document.title"); b.screenshot(path)

Needs `geckodriver` and `firefox` on PATH (the Firefox snap works; give it a profile and screenshot folder under the home directory, not /tmp).
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

HOME_TMP = Path.home() / "swarmlabre-uitmp"          # a snap Firefox can use non-hidden folders under the home directory only


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebDriverError(Exception):
    pass


class Browser:
    def __init__(self, width=1280, height=900, offline=False, extra_prefs=None):
        HOME_TMP.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix="wd-", dir=HOME_TMP))
        self.port = free_port()
        self.log = open(self.dir / "driver.log", "w")
        self.proc = subprocess.Popen(["geckodriver", "--port", str(self.port), "--host", "127.0.0.1"], stdout=self.log, stderr=subprocess.STDOUT, cwd=str(self.dir))
        for _ in range(100):
            try:
                self._req("GET", "/status")
                break
            except OSError:
                time.sleep(0.1)
        prefs = {"devtools.console.stdout.content": True, "browser.cache.disk.enable": False, "browser.cache.memory.enable": False}
        if offline:
            # every request that is not to this machine goes to a proxy that is not there: an external fetch fails instead of working
            prefs.update({"network.proxy.type": 1, "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 9, "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 9,
                          "network.proxy.no_proxies_on": "127.0.0.1, localhost", "network.proxy.allow_hijacking_localhost": False})
        prefs.update(extra_prefs or {})
        caps = {"capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {"args": ["-headless", "-profile", str(self.dir / "profile")], "prefs": prefs, "log": {"level": "info"}}}}}
        (self.dir / "profile").mkdir()
        r = self._req("POST", "/session", caps)
        self.sid = r["value"]["sessionId"]
        self.size(width, height)

    def _req(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            msg = json.loads(e.read() or b"{}").get("value", {})
            raise WebDriverError("%s: %s" % (msg.get("error"), msg.get("message")))

    def _s(self, method, path, body=None):
        return self._req(method, "/session/%s%s" % (self.sid, path), body)["value"]

    def size(self, w, h):
        self._s("POST", "/window/rect", {"width": w, "height": h})
        inner = self.js("return [window.innerWidth, window.innerHeight]")
        if inner[0] != w:                                   # headless windows have no chrome, but be exact about the viewport
            self._s("POST", "/window/rect", {"width": w + (w - inner[0]), "height": h + (h - inner[1])})

    def get(self, url):
        self._s("POST", "/url", {"url": url})

    def js(self, script, *args):
        return self._s("POST", "/execute/sync", {"script": script, "args": list(args)})

    def handles(self):
        return self._s("GET", "/window/handles")

    def switch_to(self, handle):
        self._s("POST", "/window", {"handle": handle})

    def jsa(self, script, *args):
        """Like js(), but the script is async: it ends by calling the last argument (`arguments[arguments.length-1]`)."""
        return self._s("POST", "/execute/async", {"script": script, "args": list(args)})

    def wait_for(self, expr, timeout=30, interval=0.2):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                last = self.js("return !!(%s)" % expr)
                if last:
                    return True
            except WebDriverError as e:
                last = str(e)
            time.sleep(interval)
        raise WebDriverError("timed out waiting for %s (last: %s)" % (expr, last))

    def screenshot(self, path):
        png = self._s("GET", "/screenshot")
        Path(path).write_bytes(base64.b64decode(png))

    def click(self, css):
        el = self._s("POST", "/element", {"using": "css selector", "value": css})
        self._s("POST", "/element/%s/click" % list(el.values())[0])

    def console_log(self):
        """Firefox's own stdout (console.* with devtools.console.stdout.content and JavaScript errors), as geckodriver wrote it."""
        self.log.flush()
        return (self.dir / "driver.log").read_text(errors="replace")

    def close(self):
        try:
            self._req("DELETE", "/session/%s" % self.sid)
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
