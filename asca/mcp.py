"""MCP server definitions: version pinning, transport, and inline credentials.

Supported config shapes
- Hermes ``config.yaml``         -> ``mcp_servers: {name: {command,args,env,url,headers}}``
- Claude Code / Desktop / Cursor -> ``{"mcpServers": {name: {...}}}`` (also nested under
  ``projects.<path>.mcpServers`` in ``~/.claude.json``)
- Project ``.mcp.json``           -> same as above
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .model import Finding, Severity
from .secrets import scan_text

# launchers that fetch-and-run a package by name on every start
_NODE_RUNNERS = {"npx", "bunx", "pnpx"}
_PY_RUNNERS = {"uvx", "pipx"}
_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$")
_DIGEST = re.compile(r"@sha256:[a-f0-9]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}

# Reference servers moved to github.com/modelcontextprotocol/servers-archived (archived 29 May 2025):
# "no security updates or bug fixes will be provided". Package names are read from each server's
# package.json / pyproject.toml in that repo. `mcp-server-git` is NOT here: git went back to the
# maintained modelcontextprotocol/servers repo. Pinning one of these doesn't help: no fixed version
# will ever be published. Glow Labs' MCPhantom research (Nov 2026) found coding agents still installing
# them from training data, including a prompt-injection-to-command-execution bug in the Puppeteer
# server that its maintainers declined to fix.
ARCHIVE_URL = "https://github.com/modelcontextprotocol/servers-archived"
MCPHANTOM_URL = ("https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-"
                 "mcp-servers-from-training-data")
# package -> (severity, why, maintained replacement or "")
ARCHIVED_SERVERS: dict[str, tuple[Severity, str, str]] = {
    "@modelcontextprotocol/server-puppeteer": (
        Severity.HIGH, "A prompt injection can make it start any process instead of the browser (Glow Labs, "
        "MCPhantom); the maintainers closed the report as out of scope and won't fix it.",
        "Microsoft's maintained Playwright server, `@playwright/mcp`"),
    "@modelcontextprotocol/server-github": (
        Severity.MEDIUM, "", "GitHub's own server, github.com/github/github-mcp-server"),
    "@modelcontextprotocol/server-brave-search": (
        Severity.MEDIUM, "", "Brave's own server, `@brave/brave-search-mcp-server`"),
    "@modelcontextprotocol/server-redis": (Severity.MEDIUM, "", "Redis' own server, github.com/redis/mcp-redis"),
    "mcp-server-sentry": (Severity.MEDIUM, "", "Sentry's own server, `@sentry/mcp-server`"),
    "@modelcontextprotocol/server-postgres": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-slack": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-gitlab": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-google-maps": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-gdrive": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-aws-kb-retrieval": (Severity.MEDIUM, "", ""),
    "@modelcontextprotocol/server-everart": (Severity.MEDIUM, "", ""),
    "mcp-server-sqlite": (Severity.MEDIUM, "", ""),
}
# Local additions (`--known-archived FILE`): one package name per line, `#` comments.
EXTRA_ARCHIVED: set[str] = set()


def load_known_archived(path) -> set[str]:
    names = set()
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(line.lower())
    return names


def _archived(location: str, name: str, pkg: str) -> list[Finding]:
    key = pkg.lower()
    if key in ARCHIVED_SERVERS:
        sev, why, repl = ARCHIVED_SERVERS[key]
        src = f"Listed in {ARCHIVE_URL}"
    elif key in EXTRA_ARCHIVED:
        sev, why, repl, src = Severity.MEDIUM, "", "", "Listed in your --known-archived file"
    else:
        return []
    return [Finding(
        rule="mcp.archived-server", category="pinning", severity=sev,
        title=f"MCP server `{name}` runs an archived package that will never be patched",
        location=location, subject=f"{name}:{key}",
        detail=(f"`{pkg}` is unmaintained: no security fixes or releases will come. {src}. "
                + (why + " " if why else "")
                + "Pinning a version doesn't help here, because no fixed version will ever exist. Coding agents "
                  f"still pick these names from their training data (Glow Labs, MCPhantom: {MCPHANTOM_URL})."),
        remediation=("Remove this server from the config"
                     + (f" and use {repl} instead." if repl else
                        " and use the service's own maintained MCP server, if it has one.")
                     + " Tell your agent to check a server's maintenance status before installing one."),
    )]


def iter_servers(doc, *, origin: str) -> list[tuple[str, str, dict]]:
    """Yield (location, name, spec) for every server in a parsed config document."""
    out: list[tuple[str, str, dict]] = []
    if not isinstance(doc, dict):
        return out
    # mcp_servers: Hermes, Codex · mcpServers: Claude/Cursor/Gemini/Windsurf · servers: VS Code mcp.json
    for key in ("mcp_servers", "mcpServers", "servers"):
        servers = doc.get(key)
        if isinstance(servers, dict):
            for name, spec in servers.items():
                if isinstance(spec, dict):
                    out.append((f"{origin}#{key}.{name}", str(name), spec))
    projects = doc.get("projects")
    if isinstance(projects, dict):
        for proj, pdoc in projects.items():
            if isinstance(pdoc, dict) and isinstance(pdoc.get("mcpServers"), dict):
                for name, spec in pdoc["mcpServers"].items():
                    if isinstance(spec, dict):
                        out.append((f"{origin}#projects[{proj}].mcpServers.{name}", str(name), spec))
    return out


def audit_server(location: str, name: str, spec: dict) -> list[Finding]:
    out: list[Finding] = []
    if spec.get("enabled") is False or spec.get("disabled") is True:
        return out
    command = spec.get("command")
    args = spec.get("args") or []
    if isinstance(command, str) and command.strip():
        argv = command.split() + [str(a) for a in args] if not args else [command] + [str(a) for a in args]
        out.extend(_audit_command(location, name, argv))
        from . import mcpvers                    # pinned != frozen, pinned != safe
        out.extend(mcpvers.audit(location, name, argv, spec.get("env") if isinstance(spec.get("env"), dict) else {}))
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    if isinstance(url, str) and url:
        out.extend(_audit_url(location, name, url))
    # inline credentials: env values and headers are the usual places keys get pasted
    for field in ("env", "headers"):
        block = spec.get(field)
        if isinstance(block, dict):
            for k, v in block.items():
                if not isinstance(v, str) or not v or v.startswith("${") or v.startswith("$"):
                    continue
                text = f"{k}={v}" if field == "env" else f"{k}: {v}"
                hits = scan_text(text, f"{location}.{field}.{k}", context=f"MCP server `{name}` {field}")
                bare = re.sub(r"(?i)^(bearer|token|basic)\s+", "", v.strip())
                if not hits and _credential_name(k) and len(bare) >= 16:
                    hits = scan_text(f"api_key={bare}", f"{location}.{field}.{k}",
                                     context=f"MCP server `{name}` {field}")
                for h in hits:
                    h.location = h.location.rsplit(":", 1)[0]  # synthetic line numbers are meaningless
                    h.remediation = (f"Rotate it and reference an environment variable instead "
                                     f"(e.g. `{k}: ${{{k.upper()}}}` where the client supports interpolation).")
                out.extend(hits)
    return out


def _credential_name(k: str) -> bool:
    return bool(re.search(r"(?i)(key|token|secret|password|authorization|auth|bearer)", k))


def _audit_command(location: str, name: str, argv: list[str]) -> list[Finding]:
    out: list[Finding] = []
    exe = argv[0].rsplit("/", 1)[-1]
    rest = argv[1:]
    if exe in _NODE_RUNNERS or (exe in ("npm", "pnpm", "yarn") and rest[:1] in (["exec"], ["dlx"])):
        pkg = _first_positional(rest[1:] if exe in ("npm", "pnpm", "yarn") else rest,
                                takes_value={"-p", "--package", "--registry", "--cache", "--prefix"})
        if pkg:
            out.extend(_archived(location, name, _npm_name(pkg)))
        if pkg and not _npm_pinned(pkg):
            out.append(_unpinned(location, name, pkg, f"{exe} fetches the latest matching release from the npm "
                                 f"registry on each start; a hijacked maintainer account or typosquat ships "
                                 f"straight into your agent.", f"{_npm_name(pkg)}@<exact-version>"))
    elif exe in _PY_RUNNERS:
        sub = rest
        if exe == "pipx" and rest[:1] == ["run"]:
            sub = rest[1:]
        spec = None
        if "--from" in sub:
            i = sub.index("--from")
            spec = sub[i + 1] if i + 1 < len(sub) else None
        else:
            spec = _first_positional(sub, takes_value={"--python", "--with", "--index-url", "--spec", "-p"})
        if "--spec" in sub:
            i = sub.index("--spec")
            spec = sub[i + 1] if i + 1 < len(sub) else spec
        if spec:
            out.extend(_archived(location, name, re.split(r"[<>=!~@ \[]", spec)[0]))
        if spec and not _py_pinned(spec):
            out.append(_unpinned(location, name, spec, f"{exe} resolves the newest PyPI release on each start.",
                                 f"{re.split(r'[<>=!~@ ]', spec)[0]}==<exact-version>"))
    elif exe in ("docker", "podman") and "run" in rest:
        image = _docker_image(rest[rest.index("run") + 1:])
        if image and not _DIGEST.search(image):
            tagged = ":" in image.rsplit("/", 1)[-1] and not image.endswith(":latest")
            out.append(Finding(
                rule="pin.mcp-docker", category="pinning",
                severity=Severity.MEDIUM if tagged else Severity.HIGH,
                title=f"MCP server `{name}` container image is not pinned by digest",
                location=location, subject=name,
                detail=f"Image `{image}` — tags are mutable; the registry can serve different bytes tomorrow.",
                remediation=f"Pin `{image.split('@')[0]}@sha256:<digest>` (see `docker inspect --format "
                            f"'{{{{index .RepoDigests 0}}}}'`).",
            ))
    for a in argv:
        if re.match(r"^git\+https?://", a) and not re.search(r"@[0-9a-f]{40}\b", a):
            out.append(_unpinned(location, name, a, "Installs from a git branch/tag that can move.",
                                 "git+https://…@<40-char commit sha>"))
    return out


def _unpinned(location: str, name: str, pkg: str, why: str, fix: str) -> Finding:
    return Finding(
        rule="pin.mcp-package", category="pinning", severity=Severity.HIGH,
        title=f"MCP server `{name}` runs an unpinned package",
        location=location, subject=f"{name}:{pkg}",
        detail=f"`{pkg}` — {why} MCP servers run with your agent's privileges and see its tool traffic.",
        remediation=f"Pin an exact, reviewed version: `{fix}`.",
    )


def _first_positional(args: list[str], takes_value: set[str]) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in takes_value:
            skip = True
            continue
        if a.startswith("-"):
            if "=" in a and a.split("=", 1)[0] in ("--package", "-p"):
                return a.split("=", 1)[1]
            continue
        return a
    return None


def _npm_name(spec: str) -> str:
    if spec.startswith("@"):
        scope, _, rest = spec.partition("/")
        return scope + "/" + rest.split("@", 1)[0]
    return spec.split("@", 1)[0]


def _npm_pinned(spec: str) -> bool:
    if spec.startswith((".", "/", "file:")):
        return True  # local path: not a registry fetch
    if spec.startswith(("http://", "https://", "github:", "git+")):
        return bool(re.search(r"#[0-9a-f]{40}$", spec))
    version = spec[len(_npm_name(spec)):].lstrip("@")
    return bool(_EXACT_VERSION.match(version))


def _py_pinned(spec: str) -> bool:
    if spec.startswith((".", "/")):
        return True
    if spec.startswith("git+"):
        return bool(re.search(r"@[0-9a-f]{40}$", spec))
    m = re.search(r"==\s*([0-9][^,;\s]*)$", spec)
    if m and "*" not in m.group(1):
        return True
    # uvx tool@1.2.3 form
    m = re.match(r"^[A-Za-z0-9_.\-\[\]]+@(\S+)$", spec)
    return bool(m and _EXACT_VERSION.match(m.group(1)))


def _docker_image(args: list[str]) -> str | None:
    takes_value = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--env-file",
                   "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "--mount", "-l", "--label",
                   "--add-host", "--cpus", "-m", "--memory", "--pull"}
    return _first_positional(args, takes_value)


def _audit_url(location: str, name: str, url: str) -> list[Finding]:
    out: list[Finding] = []
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if p.scheme == "http" and host not in _LOCAL_HOSTS and not host.endswith(".local"):
        out.append(Finding(
            rule="mcp.plaintext-transport", category="mcp", severity=Severity.HIGH,
            title=f"MCP server `{name}` uses plaintext HTTP to a remote host",
            location=location, subject=name,
            detail=f"`{p.scheme}://{host}` — tool calls, results and auth headers travel unencrypted and can be "
                   f"read or rewritten in transit.",
            remediation="Use https://, or reach the server over a private tunnel (e.g. Tailscale) bound to localhost.",
        ))
    if p.password or re.search(r"(?i)[?&](api[_-]?key|token|key|access_token)=[^&]{12,}", p.query or ""):
        from .model import redact
        secret = p.password or re.search(r"=([^&]+)", p.query).group(1)
        out.append(Finding(
            rule="secret.mcp-url", category="secrets", severity=Severity.HIGH,
            title=f"MCP server `{name}` URL embeds a credential",
            location=location, subject=name,
            detail=f"Credential in URL ({redact(secret)}); URLs end up in logs, history and error messages.",
            remediation="Rotate it and move it to an Authorization header sourced from an environment variable.",
        ))
    if p.scheme in ("http", "https"):
        out.append(Finding(
            rule="mcp.remote-unpinnable", category="pinning", severity=Severity.INFO,
            title=f"MCP server `{name}` is a remote service (cannot be version-pinned)",
            location=location, subject=name,
            detail=f"`{host}` controls what tools and descriptions it serves and can change them at any time.",
            remediation="Accept consciously; prefer a trusted operator, and review its tool list periodically.",
        ))
    return out
