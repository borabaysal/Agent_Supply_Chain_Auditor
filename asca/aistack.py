"""Self-hosted AI gateways and apps next to your agents (the ARTEX playbook), rules ``aistack.*``.

Grounding: Amazon Threat Intelligence (Nov 13 2026) captured the working memory of ARTEX attack agents. They
fingerprint LLM gateways and AI app builders (LiteLLM, One API, New API, Dify, Langflow, RAGFlow, Open WebUI,
LobeChat, Ollama ...), pull the provider keys those apps hold, validate them and spend them on more hunting.
Their playbook: claimable unfinished installs, anonymous management endpoints, default admin credentials such
as "the LiteLLM default master key", Langflow CVE-2025-3248 and RAGFlow CVE-2026-28797.

Everything here is read as text. Nothing is started, nothing is contacted, no container is inspected.

| What | Where it is read | Severity |
|---|---|---|
| LiteLLM ``master_key`` / ``LITELLM_MASTER_KEY`` equal to ``sk-1234``, the value LiteLLM's own example config and ``.env.example`` shipped (v1.72/v1.74 stable tags) | proxy config YAML, ``.env``, compose ``environment`` | high, critical when published on all interfaces |
| LiteLLM proxy config with no master key at all (no auth on the proxy) | proxy config YAML, nothing in ``.env``/compose next to it | low, high when published on all interfaces |
| Open WebUI ``WEBUI_AUTH=False`` (no login) | ``.env``, compose | high, critical when published |
| Open WebUI open sign-up straight to a working role (``DEFAULT_USER_ROLE=user``/``admin``) | ``.env``, compose | medium (admin: high), +1 when published |
| ``OLLAMA_HOST`` bound to all interfaces (Ollama has no authentication) | shell profiles, launchd plists, systemd units, ``/etc/environment``, the environment | high (a specific address: medium) |
| A known AI gateway/app image whose ports compose publishes on all interfaces (Docker's published ports also bypass ufw/firewalld) | compose files | medium (Ollama: high) |
| Langflow < 1.3.0 (CVE-2025-3248, unauthenticated RCE, CISA KEV) and RAGFlow v0.24.0 (CVE-2026-28797) | site-packages metadata, compose image tags | critical |
| MONAI Label < 0.8.6 (CVE-2026-133968, exploited as a zero-day by Cairn agents, CISA KEV) and < 0.8.8 (two more critical RCEs) | ``monailabel`` dist-info, ``projectmonai/monailabel`` image tags | critical |
| MONAI Label without ``MONAI_LABEL_AUTH_ENABLE=True`` (authentication is off by default) | compose service ``environment``, ``.env`` next to it | high, critical when published on all interfaces |

Compose and ``.env`` files are found under the home folder (depth 4), the ``--repos`` roots and, on POSIX,
``/opt`` and ``/srv`` (depth 3), skipping dependency/cache folders, with a directory budget. Example files
(``*.example``, ``docs/``, ``tests/``) and LiteLLM's own source checkout are skipped.
"""
from __future__ import annotations

import os
import plistlib
import re
from pathlib import Path

from . import agentvers, fsutil, yamlmini
from .model import Finding, Severity, redact

AMAZON = "https://aws.amazon.com/blogs/security/amazon-threat-intelligence-observes-threat-actors-running-cybercrime-campaigns-with-artex-ai-agents/"
LITELLM_DEFAULT_KEYS = {"sk-1234"}
SYSTEM_DIRS = ["/opt", "/srv"]
DIR_BUDGET = 40000
_SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", "site-packages", "dist-packages", ".venv", "venv",
              ".cache", ".npm", ".pnpm-store", ".yarn", ".cargo", ".rustup", ".gradle", ".m2", "go", "Library",
              "AppData", ".Trash", ".local", ".vscode-server", ".cursor-server", ".ollama", "pkgs", ".tox", ".nox",
              "snap", "proc", "sys", ".docker", ".pyenv", ".nvm", ".bun", ".deno", "build", "dist", "target"}
_SKIP_PARTS = {"docs", "doc", "tests", "test", "examples", "example", "cookbook", "fixtures", "samples"}
_COMPOSE = re.compile(r"^(?:docker-)?compose(?:\.[\w.-]+)?\.ya?ml$", re.I)
_ENV = re.compile(r"^\.env(?:\.(?:local|prod|production|docker))?$")
_YAML_CFG = re.compile(r"(?:litellm|config|proxy).*\.ya?ml$", re.I)

# image regex -> product. dify/ragflow-style stacks put nginx in front: see _FRONTED.
PRODUCTS = [
    (re.compile(r"berriai/litellm|(?:^|/)litellm/litellm"), "LiteLLM"),
    (re.compile(r"(?:^|/)ollama/ollama"), "Ollama"),
    (re.compile(r"open-webui/open-webui"), "Open WebUI"),
    (re.compile(r"langflowai/langflow"), "Langflow"),
    (re.compile(r"langgenius/dify-(?:api|web)"), "Dify"),
    (re.compile(r"infiniflow/ragflow"), "RAGFlow"),
    (re.compile(r"(?:justsong|songquanpeng)/one-api"), "One API"),
    (re.compile(r"calciumion/new-api"), "New API"),
    (re.compile(r"labring/fastgpt"), "FastGPT"),
    (re.compile(r"lobehub/lobe-chat"), "LobeChat"),
    (re.compile(r"projectmonai/monailabel"), "MONAI Label"),
]
CAIRN = "https://aws.amazon.com/blogs/security/chinese-nexus-actors-cairn-ai-agents-found-a-zero-day-on-their-own/"
MONAI_RELEASES = "https://github.com/Project-MONAI/MONAILabel/releases"
_FRONTED = {"Dify"}          # its compose publishes the nginx service, not dify-api/dify-web
_PRODUCT_FIX = {
    "LiteLLM": "Set a long random `master_key` and keep the admin UI and `/key/*` routes off the internet.",
    "Ollama": "Ollama has no authentication: publish it on 127.0.0.1 only and put an authenticating proxy in front "
              "if other machines need it.",
    "Open WebUI": "Keep `WEBUI_AUTH` on, set `ENABLE_SIGNUP=False` once your accounts exist.",
    "Dify": "Finish setup before exposing it (the first visitor to /install becomes admin) and set `INIT_PASSWORD`.",
    "One API": "Change the `root` password from the documented default and update past the `isCliRequest` header "
               "bypass Amazon describes.",
    "New API": "Change the default root password and check the `isCliRequest` header bypass Amazon describes.",
    "RAGFlow": "Set `REGISTER_ENABLED=0` once your accounts exist.",
    "MONAI Label": "Set `MONAI_LABEL_AUTH_ENABLE=True` with a Keycloak realm, and run it as an unprivileged user "
                   "that can write only to the datastore.",
}
VULNS = [  # (product, source, package or image regex, range, ids, summary, fixed)
    ("Langflow", "pypi", "langflow", "< 1.3.0", "CVE-2025-3248",
     "unauthenticated remote code execution via /api/v1/validate/code (CISA KEV)", "1.3.0"),
    ("Langflow", "pypi", "langflow-base", "< 0.3.0", "CVE-2025-3248",
     "unauthenticated remote code execution via /api/v1/validate/code (CISA KEV)", "0.3.0 (langflow 1.3.0)"),
    ("Langflow", "image", "langflowai/langflow", "< 1.3.0", "CVE-2025-3248",
     "unauthenticated remote code execution via /api/v1/validate/code (CISA KEV)", "1.3.0"),
    ("RAGFlow", "image", "infiniflow/ragflow", "= 0.24.0", "CVE-2026-28797",
     "server-side template injection to RCE in the Agent 'Text Processing' component; needs an account, and "
     "self-registration is on by default (REGISTER_ENABLED=1)", None),
    # Amazon (Nov 20 2026): Cairn agents found the datastore path traversal and wrote a reverse shell into
    # sitecustomize.py. 0.8.6 fixed it; 0.8.7 and 0.8.8 (Nov 25) fixed two more critical RCEs (bundle_path on the
    # task PYTHONPATH; request values evaluated in the bundle config), so 0.8.8 is the first safe release.
    ("MONAI Label", "pypi", "monailabel", "< 0.8.6", "CVE-2026-133968",
     "datastore path traversal to arbitrary file write and code execution, exploited as a zero-day by Cairn AI "
     "agents (CISA KEV); 0.8.7 and 0.8.8 fix two more critical RCEs (GHSA-j5c7-p3x5-gw2x, GHSA-gfjg-c3x6-24gw)",
     "0.8.8"),
    ("MONAI Label", "image", "projectmonai/monailabel", "< 0.8.6", "CVE-2026-133968",
     "datastore path traversal to arbitrary file write and code execution, exploited as a zero-day by Cairn AI "
     "agents (CISA KEV); 0.8.7 and 0.8.8 fix two more critical RCEs (GHSA-j5c7-p3x5-gw2x, GHSA-gfjg-c3x6-24gw)",
     "0.8.8"),
    ("MONAI Label", "pypi", "monailabel", ">= 0.8.6, < 0.8.8", "GHSA-j5c7-p3x5-gw2x / GHSA-gfjg-c3x6-24gw",
     "remote code execution through a client-supplied bundle_path (fixed in 0.8.7) and through request values "
     "evaluated in the bundle config (fixed in 0.8.8), both critical", "0.8.8"),
    ("MONAI Label", "image", "projectmonai/monailabel", ">= 0.8.6, < 0.8.8", "GHSA-j5c7-p3x5-gw2x / GHSA-gfjg-c3x6-24gw",
     "remote code execution through a client-supplied bundle_path (fixed in 0.8.7) and through request values "
     "evaluated in the bundle config (fixed in 0.8.8), both critical", "0.8.8"),
]
_VULN_SOURCE = {"MONAI Label": f"Amazon's Cairn report, {CAIRN}; releases: {MONAI_RELEASES}"}
_BUMP = {Severity.LOW: Severity.MEDIUM, Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.CRITICAL,
         Severity.CRITICAL: Severity.CRITICAL}


# ------------------------------------------------------------------ helpers
def _false(v) -> bool:
    return str(v).strip().strip("'\"").lower() in ("false", "0", "no", "off")


def _true(v) -> bool:
    return str(v).strip().strip("'\"").lower() in ("true", "1", "yes", "on")


def read_env(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^export\s+", "", line)
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in "'\"" and v[-1:] == v[:1] and len(v) >= 2:
            v = v[1:-1]
        else:
            v = re.sub(r"\s+#.*$", "", v)
        out[k.strip()] = v
    return out


_VAR = re.compile(r"\$\{([A-Za-z_]\w*)(?:(:?[-?])([^}]*))?\}|\$([A-Za-z_]\w*)")


def interpolate(s, env: dict) -> str:
    """Compose-style ${VAR}, ${VAR:-default}, ${VAR-default}; an unresolved variable becomes '?'."""
    def sub(m):
        name = m.group(1) or m.group(4)
        op, default = m.group(2), m.group(3)
        val = env.get(name)
        if op == ":-" and not val:
            return default or ""
        if op == "-" and val is None:
            return default or ""
        return "?" if val is None else val
    return _VAR.sub(sub, str(s))


def bind_scope(host: str) -> str | None:
    """'all', 'loopback', 'address', or None when unknown."""
    h = host.strip().strip("[]").lower()
    if h == "?":
        return None
    if h in ("", "0.0.0.0", "::", "*"):
        return "all"
    if h in ("localhost", "::1") or h.startswith("127."):
        return "loopback"
    return "address"


def port_scopes(port, env: dict) -> list[tuple[str, str]]:
    """[(scope, shown)] for one compose ports entry (short or long syntax)."""
    if isinstance(port, dict):
        ip = interpolate(port.get("host_ip", ""), env)
        shown = f"{port.get('published', '(random)')}->{port.get('target', '?')}"
        sc = bind_scope(ip)
        return [(sc, shown)] if sc else []
    s = interpolate(port, env).split("/")[0].strip()
    if not s:
        return []
    if s.startswith("["):                      # [::1]:8080:80
        ip, _, rest = s[1:].partition("]")
        return [(sc, s)] if (sc := bind_scope(ip)) else []
    parts = s.split(":")
    if len(parts) >= 3:
        sc = bind_scope(":".join(parts[:-2]))
        return [(sc, s)] if sc else []
    return [("all", s)]                       # "8080:80", "80" (random host port), on 0.0.0.0


COMMAND_PRODUCTS = [(re.compile(r"\bmonailabel\s+start_server\b"), "MONAI Label")]


def product_of(image: str, command="") -> str | None:
    for rx, name in PRODUCTS:
        if rx.search(image.lower()):
            return name
    cmd = " ".join(str(c) for c in command) if isinstance(command, list) else str(command or "")
    for rx, name in COMMAND_PRODUCTS:
        if rx.search(cmd.lower()):
            return name
    return None


def _tag_version(image: str) -> str | None:
    tag = image.rsplit("/", 1)[-1].partition("@")[0]
    if ":" not in tag:
        return None
    m = re.match(r"^v?(\d+\.\d+(?:\.\d+)?)", tag.split(":", 1)[1])
    return m.group(1) if m else None


def _skipped_path(p: Path, base: Path) -> bool:
    try:
        rel = p.relative_to(base).parts[:-1]
    except ValueError:
        rel = p.parts[:-1]
    return any(x.lower() in _SKIP_PARTS for x in rel)


def _in_litellm_checkout(p: Path) -> bool:
    for d in list(p.parents)[:6]:
        cfg = d / ".git" / "config"
        if fsutil.is_file(cfg):
            try:
                return "berriai/litellm" in cfg.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                return False
    return False


def find_files(dirs: list[tuple[Path, int]], stats: dict) -> tuple[list[Path], bool]:
    """Candidate compose/.env/config files under (dir, depth) roots, and whether the budget ran out."""
    out, seen, visited = [], set(), 0
    for base, depth in dirs:
        if not fsutil.is_dir(base):
            continue
        stack = [(base, 0)]
        while stack:
            d, lvl = stack.pop()
            visited += 1
            if visited > DIR_BUDGET:
                stats["ai_stack_dirs"] = visited - 1
                return out, True
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue                      # other people's folders: skip, never abort
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if lvl < depth and e.name not in _SKIP_DIRS:
                            stack.append((Path(e.path), lvl + 1))
                    elif e.is_file(follow_symlinks=False) and (
                            _COMPOSE.match(e.name) or _ENV.match(e.name) or _YAML_CFG.search(e.name)):
                        p = Path(e.path)
                        if p not in seen and not _skipped_path(p, base) and e.stat().st_size < 512 * 1024:
                            seen.add(p)
                            out.append(p)
                except OSError:
                    continue
    stats["ai_stack_dirs"] = visited
    return out, False


# ------------------------------------------------------------------ checks
class _Ctx:
    def __init__(self):
        self.out: list[Finding] = []
        self.keys: set = set()
        self.exposed: dict[Path, set[str]] = {}       # dir -> products published on all interfaces

    def add(self, f: Finding):
        k = (f.rule, f.location, f.subject)
        if k not in self.keys:
            self.keys.add(k)
            self.out.append(f)


def _env_checks(ctx: _Ctx, env: dict, where: str, d: Path, service_product: str | None = None) -> None:
    """Auth settings in one environment (a .env file or one compose service)."""
    exposed = ctx.exposed.get(d, set())
    key = env.get("LITELLM_MASTER_KEY")
    if key is not None and key.strip() in LITELLM_DEFAULT_KEYS:
        _default_key(ctx, where, key.strip(), "LITELLM_MASTER_KEY", "LiteLLM" in exposed)
    if "WEBUI_AUTH" in env and _false(env["WEBUI_AUTH"]):
        pub = "Open WebUI" in exposed
        ctx.add(Finding(
            rule="aistack.auth-disabled", category="ai-stack", severity=Severity.CRITICAL if pub else Severity.HIGH,
            title="Open WebUI runs without login (`WEBUI_AUTH=False`)" + (" and is published on all interfaces"
                                                                        if pub else ""),
            location=where, subject="open-webui:WEBUI_AUTH",
            detail="Anyone who reaches it uses your connected models and can read the provider connections it holds "
                   f"(Open WebUI is on the ARTEX agents' target list, {AMAZON}).",
            remediation="Remove `WEBUI_AUTH=False` (it is meant for single-user setups on 127.0.0.1) and recreate the "
                        "container."))
    monai = service_product == "MONAI Label" or (service_product is None and any(
        k.startswith("MONAI_LABEL_") for k in env))
    if monai and not _true(env.get("MONAI_LABEL_AUTH_ENABLE", "False")):
        pub = "MONAI Label" in exposed
        contained = service_product == "MONAI Label" and not pub      # compose: loopback-only or not published
        ctx.add(Finding(
            rule="aistack.auth-disabled", category="ai-stack",
            severity=Severity.CRITICAL if pub else Severity.MEDIUM if contained else Severity.HIGH,
            title="MONAI Label runs without authentication"
                  + (" (`MONAI_LABEL_AUTH_ENABLE` is off)" if "MONAI_LABEL_AUTH_ENABLE" in env else
                     " (`MONAI_LABEL_AUTH_ENABLE` isn't set; the default is off)")
                  + (" and is published on all interfaces" if pub else ""),
            location=where, subject="monailabel:MONAI_LABEL_AUTH_ENABLE",
            detail="With authentication off, every endpoint (uploads, training, bundle inference) is open to anyone "
                   "who can connect. Cairn AI agents went from mapping a MONAI Label API to a root shell in about 11 "
                   f"minutes through its upload endpoint ({CAIRN})."
                   + (" Compose publishes it on loopback only (or not at all), so only this machine and its "
                      "containers reach it." if contained else
                      "" if pub else " Run outside Docker, `monailabel start_server` listens on 0.0.0.0 by default."),
            remediation=_PRODUCT_FIX["MONAI Label"] + " Keep the port on 127.0.0.1 or a VPN address."))
    role = str(env.get("DEFAULT_USER_ROLE", "")).strip().lower()
    webui = service_product == "Open WebUI" or any(k.startswith("WEBUI_") for k in env)
    if webui and role in ("user", "admin") and not _false(env.get("ENABLE_SIGNUP", "True")) \
            and not _false(env.get("WEBUI_AUTH", "True")):
        sev = Severity.HIGH if role == "admin" else Severity.MEDIUM
        pub = "Open WebUI" in exposed
        if pub:
            sev = _BUMP[sev]
        ctx.add(Finding(
            rule="aistack.open-signup", category="ai-stack", severity=sev,
            title=f"Open WebUI lets anyone sign up straight into the `{role}` role"
                  + (" and is published on all interfaces" if pub else ""),
            location=where, subject="open-webui:signup",
            detail="Sign-up is on (the default) and new accounts skip the `pending` approval step, so anyone who can "
                   "reach the page gets a working account" + (" with admin rights" if role == "admin" else "") + ".",
            remediation="Set `ENABLE_SIGNUP=False` after creating your accounts, and keep `DEFAULT_USER_ROLE=pending`."))


def _default_key(ctx: _Ctx, where: str, value: str, field: str, published: bool) -> None:
    ctx.add(Finding(
        rule="aistack.litellm-default-key", category="ai-stack",
        severity=Severity.CRITICAL if published else Severity.HIGH,
        title="LiteLLM master key is the example value from LiteLLM's own docs"
              + (" and the proxy is published on all interfaces" if published else ""),
        location=where, subject=f"litellm:{field}",
        detail=f"{field} = {redact(value)}, the value LiteLLM's example proxy config and .env.example shipped. The "
               f"master key is admin on the proxy: it lists and creates keys and reads the provider keys behind it. "
               f"\"The LiteLLM default master key\" is in the ARTEX agents' playbook ({AMAZON}).",
        remediation="Generate a long random key (`openssl rand -hex 32`, prefixed `sk-`), set it, restart the proxy, "
                    "and rotate the upstream provider keys if it was ever reachable from outside."))


def _litellm_config(ctx: _Ctx, p: Path, text: str, dir_env: dict, dir_texts: str) -> None:
    if "model_list" not in text or not re.search(r"^(general_settings|litellm_settings|router_settings)\s*:",
                                                 text, re.M) or _in_litellm_checkout(p):
        return
    try:
        doc = yamlmini.load(text)
    except (yamlmini.YamlError, ValueError):
        return
    if not isinstance(doc, dict) or "model_list" not in doc:
        return
    gs = doc.get("general_settings") if isinstance(doc.get("general_settings"), dict) else {}
    mk = gs.get("master_key")
    published = "LiteLLM" in ctx.exposed.get(p.parent, set())
    if isinstance(mk, str) and mk.startswith("os.environ/"):
        return              # set from the environment: a default value there is reported on the .env file itself
    if isinstance(mk, str) and mk.strip() in LITELLM_DEFAULT_KEYS:
        _default_key(ctx, f"{p}#general_settings.master_key", mk.strip(), "master_key", published)
    elif mk in (None, "") and "LITELLM_MASTER_KEY" not in dir_texts:
        ctx.add(Finding(
            rule="aistack.litellm-no-master-key", category="ai-stack",
            severity=Severity.HIGH if published else Severity.LOW,
            title="LiteLLM proxy config sets no master key" + (" and the proxy is published on all interfaces"
                                                              if published else ""),
            location=str(p), subject="litellm:no-master-key",
            detail="Without `general_settings.master_key` (or LITELLM_MASTER_KEY) the proxy doesn't authenticate "
                   "callers: anyone who reaches it spends your provider keys. Fine on 127.0.0.1 for one user; not "
                   "once it's reachable." + ("" if published else " Nothing next to this file sets it, but your "
                                             "environment might."),
            remediation="Set `master_key: os.environ/LITELLM_MASTER_KEY` with a long random value."))


def _compose(ctx: _Ctx, p: Path, doc, env: dict) -> list[tuple[str, dict, str | None]]:
    """Port findings; returns [(location, service env, product)] for the auth checks."""
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return []
    found = {n: product_of(interpolate(s.get("image", ""), env), s.get("command") or s.get("entrypoint") or "")
             for n, s in services.items() if isinstance(s, dict)}
    stack = {x for x in found.values() if x}
    envs = []
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = interpolate(svc.get("image", ""), env)
        prod = found.get(name) or (next(iter(stack & _FRONTED)) if stack & _FRONTED and "nginx" in
                                   (name + image).lower() else None)
        where = f"{p}#services.{name}"
        raw_env = svc.get("environment") or {}
        senv: dict = {}
        if isinstance(raw_env, list):
            senv = {str(x).split("=", 1)[0]: interpolate(str(x).split("=", 1)[1], env) for x in raw_env if "=" in str(x)}
        elif isinstance(raw_env, dict):
            senv = {str(k): interpolate("" if v is None else v, env) for k, v in raw_env.items()}
        if prod == "MONAI Label" and "MONAI_LABEL_AUTH_ENABLE" not in senv:
            # its auth switch may sit in an env_file (other keys there are reported on that file itself)
            ef = svc.get("env_file")
            for e in ([ef] if isinstance(ef, (str, dict)) else ef if isinstance(ef, list) else []):
                rel = e.get("path") if isinstance(e, dict) else e
                try:
                    v = read_env((p.parent / interpolate(rel, env)).read_text(encoding="utf-8-sig",
                                                                              errors="replace")).get(
                        "MONAI_LABEL_AUTH_ENABLE")
                except (OSError, TypeError, ValueError):
                    v = None
                if v is not None:
                    senv["MONAI_LABEL_AUTH_ENABLE"] = v
        envs.append((where, senv, prod))
        if not prod:
            continue
        ver = _tag_version(image)
        for vprod, src, pkg, rng, cve, summary, fixed in VULNS:
            if src == "image" and pkg in image.lower() and ver and agentvers.in_range(ver, rng):
                _vuln(ctx, vprod, f"{pkg}:{ver}", where, cve, summary, fixed)
        pubs = []
        if str(svc.get("network_mode", "")).strip() == "host":
            pubs.append("host network")
        for port in svc.get("ports") or []:
            pubs += [shown for sc, shown in port_scopes(port, env) if sc == "all"]
        if not pubs:
            continue
        ctx.exposed.setdefault(p.parent, set()).add(prod)
        ctx.add(Finding(
            rule="aistack.port-exposed", category="ai-stack",
            severity=Severity.HIGH if prod == "Ollama" else Severity.MEDIUM,
            title=f"{prod} (`{name}`) is published on all network interfaces ({', '.join(pubs[:3])})",
            location=where, subject=f"{prod}:{name}:{','.join(sorted(pubs))}",
            detail=f"Docker publishes these ports on 0.0.0.0, past ufw/firewalld, so anything that can reach this "
                   f"machine reaches {prod}. Exposed {prod} instances are what the ARTEX agents scan for ({AMAZON})."
                   + (" Ollama has no authentication at all." if prod == "Ollama" else ""),
            remediation=f"Bind to loopback (`\"127.0.0.1:{pubs[0].split(':')[0] if ':' in pubs[0] else '<port>'}:...\"`) "
                        f"and reach it over SSH/Tailscale or an authenticating reverse proxy. "
                        + _PRODUCT_FIX.get(prod, "")))
    return envs


def _vuln(ctx: _Ctx, prod, what, where, cve, summary, fixed) -> None:
    ctx.add(Finding(
        rule="aistack.vulnerable-version", category="ai-stack", severity=Severity.CRITICAL,
        title=f"{prod} {what.split(':', 1)[1]} has {cve}", location=where, subject=f"{what}:{cve}",
        detail=f"{cve}: {summary}. " + (f"Source: {_VULN_SOURCE[prod]}." if prod in _VULN_SOURCE else
                                         f"It is in the ARTEX agents' playbook ({AMAZON})."),
        remediation=(f"Upgrade to {fixed} or later" if fixed else
                     "The advisory (GHSA-vvwj-fvwh-4whx) lists no patched release; v0.25.0 notes a template-sandbox "
                     "change. Upgrade, keep it off the internet, and turn off self-registration") + "."))


_OLLAMA_LINE = re.compile(r"""(?:^|[\s;])(?:export\s+|set\s+-\w+\s+|setenv\s+|launchctl\s+setenv\s+)?OLLAMA_HOST(?:=|\s+)["']?([^"'\s;#]*)""")


def _ollama_value(v: str) -> str | None:
    v = re.sub(r"^\w+://", "", v.strip()).rstrip("/")
    if v.startswith("["):
        host = v[1:].partition("]")[0]
    elif v.count(":") == 1:
        host = v.split(":")[0]
    else:
        host = v
    return bind_scope(host)


def _ollama(ctx: _Ctx, where: str, value: str) -> None:
    sc = _ollama_value(value)
    if sc not in ("all", "address"):
        return
    ctx.add(Finding(
        rule="aistack.ollama-host", category="ai-stack",
        severity=Severity.HIGH if sc == "all" else Severity.MEDIUM,
        title=f"Ollama is set to listen on {'all interfaces' if sc == 'all' else 'a network address'} "
              f"(`OLLAMA_HOST={value}`)",
        location=where, subject=f"ollama:{value}",
        detail="Ollama has no authentication: anyone who reaches port 11434 can run, pull and delete models and "
               f"use your GPU. Exposed Ollama is on the ARTEX agents' target list ({AMAZON}).",
        remediation="Remove the setting (default 127.0.0.1:11434). If other machines need it, put an "
                    "authenticating reverse proxy in front, or bind to a Tailscale/VPN address only."))


def _host_ollama(ctx: _Ctx, home: Path, root: Path, env: dict) -> None:
    def rp(s: str) -> Path:
        return root / s.lstrip("/")
    files = [home / n for n in (".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile",
                                ".config/fish/config.fish")] + [rp("/etc/environment"), rp("/etc/profile")]
    units = [rp("/etc/systemd/system/ollama.service"), home / ".config/systemd/user/ollama.service"]
    for u in list(units):
        try:
            units += sorted(Path(str(u) + ".d").glob("*.conf"))
        except OSError:
            pass
    for p in files + units:
        if not fsutil.is_file(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#") or "OLLAMA_HOST" not in s:
                continue
            if s.startswith("Environment"):
                for m in re.finditer(r"OLLAMA_HOST=([^\s\"']*)", s):
                    _ollama(ctx, str(p), m.group(1))
            elif m := _OLLAMA_LINE.search(s):
                _ollama(ctx, str(p), m.group(1))
    plist_dirs = [home / "Library/LaunchAgents", rp("/Library/LaunchAgents"), rp("/Library/LaunchDaemons")]
    for d in plist_dirs:
        try:
            plists = sorted(d.glob("*.plist")) if fsutil.is_dir(d) else []
        except OSError:
            plists = []
        for p in plists:
            try:
                raw = p.read_bytes()
            except OSError:
                continue
            if b"OLLAMA_HOST" not in raw:
                continue
            try:
                doc = plistlib.loads(raw)
            except Exception:                          # noqa: BLE001 - any malformed plist: skip it
                continue
            ev = doc.get("EnvironmentVariables") if isinstance(doc, dict) else None
            if isinstance(ev, dict) and isinstance(ev.get("OLLAMA_HOST"), str):
                _ollama(ctx, str(p), ev["OLLAMA_HOST"])
            args = doc.get("ProgramArguments") if isinstance(doc, dict) else None
            if isinstance(args, list):
                joined = " ".join(str(a) for a in args)
                if m := re.search(r"setenv\s+OLLAMA_HOST\s+[\"']?([^\"'\s;]+)", joined):
                    _ollama(ctx, str(p), m.group(1))
    if env.get("OLLAMA_HOST"):
        _ollama(ctx, "environment (OLLAMA_HOST)", env["OLLAMA_HOST"])


def _sites(ctx: _Ctx, sites) -> None:
    from . import pystartup
    for s in sites:
        for name, ver, d in pystartup._dist_infos(s.path):
            n = re.sub(r"[-_.]+", "-", name).lower()
            for prod, src, pkg, rng, cve, summary, fixed in VULNS:
                if src == "pypi" and n == pkg and agentvers.in_range(ver, rng):
                    _vuln(ctx, prod, f"{pkg}:{ver}", str(d), cve, summary, fixed)


# ------------------------------------------------------------------ entry point
def audit(home: Path, stats: dict, *, repo_roots=(), root: Path = Path("/"), env: dict | None = None,
          sites=None, system_dirs=None) -> list[Finding]:
    env = dict(os.environ) if env is None else env
    ctx = _Ctx()
    dirs = [(Path(home), 4)] + [(Path(r), 5) for r in repo_roots]
    if system_dirs is not None or os.name == "posix":
        dirs += [(root / d.lstrip("/"), 3) for d in (SYSTEM_DIRS if system_dirs is None else system_dirs)]
    files, ran_out = find_files(dirs, stats)
    by_dir: dict[Path, list[Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, []).append(f)
    stats["ai_stack_files"] = len(files)
    parse_errors = []
    for d, fs in sorted(by_dir.items()):
        texts = {}
        for f in fs:
            try:
                texts[f] = f.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
        dir_env = {}
        for f in fs:
            if f.name == ".env" and f in texts:
                dir_env = read_env(texts[f])
        envs = []
        for f in fs:                                   # compose first: it decides what's published
            if _COMPOSE.match(f.name) and f in texts:
                if not re.search(r"^services\s*:", texts[f], re.M):
                    continue
                try:
                    doc = yamlmini.load(texts[f])
                except (yamlmini.YamlError, ValueError) as exc:
                    if any(product_of(m) for m in re.findall(r"image:\s*[\"']?([^\s\"']+)", texts[f])):
                        parse_errors.append(f"{f} ({str(exc)[:60]})")
                    continue
                envs += _compose(ctx, f, doc, dir_env)
        for where, senv, prod in envs:
            _env_checks(ctx, senv, where, d, prod)
        dir_texts = "\n".join(texts.values())
        for f in fs:
            if f not in texts:
                continue
            if _ENV.match(f.name):
                _env_checks(ctx, read_env(texts[f]), str(f), d)
            elif _YAML_CFG.search(f.name) and not _COMPOSE.match(f.name):
                _litellm_config(ctx, f, texts[f], dir_env, dir_texts)
    _host_ollama(ctx, Path(home), root, env)
    if sites is None:
        from . import pystartup
        sites = pystartup.discover(Path(home), repo_roots=list(repo_roots), system=root == Path("/"))
    _sites(ctx, sites)
    if parse_errors:
        ctx.add(Finding(
            rule="scanner.parse-error", category="scanner", severity=Severity.LOW,
            title=f"{len(parse_errors)} AI-stack compose file(s) couldn't be parsed", location=parse_errors[0].split(" (")[0],
            subject="aistack.compose", detail="; ".join(parse_errors[:5]) + ". Their ports weren't checked.",
            remediation="Check them by hand, or report the file shape so the parser can learn it."))
    if ran_out:
        ctx.add(Finding(
            rule="aistack.walk-budget", category="scanner", severity=Severity.INFO,
            title=f"AI-stack file search stopped after {DIR_BUDGET} folders", location=str(home), subject="budget",
            detail="Compose and .env files in the folders not reached weren't checked.",
            remediation="Pass the folders that hold your self-hosted stacks with --repos."))
    stats["ai_stack_findings"] = len(ctx.out)
    return ctx.out
