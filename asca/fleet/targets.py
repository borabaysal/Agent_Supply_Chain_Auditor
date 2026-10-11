"""Find out which Hermes version each instance in the fleet is actually running.

Target specs (CLI ``--target NAME=SPEC`` or a fleet JSON file):

  local:/opt/hermes                     read hermes_cli/__init__.py from a local install dir
  http://host:9119                      a Hermes dashboard's /api/status ("version" field)
  docker:<container>[:/opt/hermes]      `docker exec <container> cat …/hermes_cli/__init__.py`
  ssh:<host>[:/opt/hermes]              `ssh -o BatchMode=yes <host> cat …/hermes_cli/__init__.py`

Only `cat` of a version file is executed remotely. Hermes itself is never run, and nothing
is written. The dashboard check calls `/api/status`, which the dashboard serves for its own
health display.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_INSTALL = "/opt/hermes"
_VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")   # container / ssh host
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]{1,255}$")


@dataclass
class Target:
    name: str
    spec: str


@dataclass
class Observation:
    name: str
    spec: str
    version: str | None
    source: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "spec": self.spec, "version": self.version, "source": self.source,
                "error": self.error}


def parse_target(s: str) -> Target:
    name, sep, spec = s.partition("=")
    if not sep:
        spec, name = s, s
    return Target(name=name.strip(), spec=spec.strip())


def load_fleet(path: Path) -> list[Target]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("targets", data) if isinstance(data, dict) else data
    out = []
    for t in items:
        if isinstance(t, str):
            out.append(parse_target(t))
        else:
            out.append(Target(name=t["name"], spec=t["spec"]))
    return out


def _version_from_text(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def _split_remote(spec_rest: str) -> tuple[str, str]:
    host, _, path = spec_rest.partition(":")
    return host, (path or DEFAULT_INSTALL)


def _run(cmd: list[str], timeout: float) -> str:
    if not shutil.which(cmd[0]):
        raise RuntimeError(f"{cmd[0]} not found on PATH")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)   # list args, no shell
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or f"exit {p.returncode}").strip().splitlines()[-1][:200])
    return p.stdout


def observe(t: Target, *, timeout: float = 15.0, run=_run, http_get=None) -> Observation:
    spec = t.spec
    try:
        if spec.startswith("local:") or spec.startswith("/"):
            root = Path(spec[6:] if spec.startswith("local:") else spec)
            f = root / "hermes_cli" / "__init__.py"
            return Observation(t.name, spec, _version_from_text(f.read_text(encoding="utf-8")), str(f))
        if spec.startswith(("http://", "https://")):
            url = spec.rstrip("/") + "/api/status"
            data = (http_get or _http_json)(url, timeout)
            v = data.get("version") if isinstance(data, dict) else None
            return Observation(t.name, spec, v, url, None if v else "no version in /api/status")
        for scheme in ("docker:", "ssh:"):
            if spec.startswith(scheme):
                host, path = _split_remote(spec[len(scheme):])
                if not _SAFE_NAME.match(host) or not _SAFE_PATH.match(path) or ".." in path:
                    raise ValueError("unsafe container/host name or path")
                f = f"{path.rstrip('/')}/hermes_cli/__init__.py"
                cmd = (["docker", "exec", host, "cat", f] if scheme == "docker:" else
                       ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(timeout)}", host, "cat", f])
                return Observation(t.name, spec, _version_from_text(run(cmd, timeout)), f"{scheme}{host}:{f}")
        raise ValueError("unknown target spec (use local:, http(s)://, docker:, ssh:)")
    except Exception as exc:   # one bad target must not hide the rest of the fleet
        return Observation(t.name, spec, None, "", f"{type(exc).__name__}: {exc}"[:240])


def _http_json(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "asca-fleet"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
