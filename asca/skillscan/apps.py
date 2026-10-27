"""Check installed apps, plugins, MCP servers and packages against the official names.

Everything is read from disk (package folder names, plugin metadata, MCP client configs).
Nothing is executed: no `npm ls`, no `pip list`, no `git remote`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .. import discover, mcp, yamlmini
from ..model import Finding, Severity
from .lookalike import Matcher, fold
from .official import Official, _repo_slug


class Matchers:
    def __init__(self, o: Official):
        self.o = o
        self.skills = Matcher(o.skills, brands=o.brands)
        self.plugins = Matcher(o.plugins, brands=o.brands)
        self.oc_ext = Matcher(o.openclaw_extensions, brands=o.brands)
        self.mcp = Matcher(o.mcp)
        self.npm = Matcher(o.npm, brands=o.brands)
        self.pypi = Matcher(o.pypi, brands=o.brands)
        self.apps = Matcher([a["app"] for a in o.apps] + ["Claude", "ChatGPT", "Hermes"], brands=o.brands)


def _f(rule, sev, title, location, subject, detail, fix, category="lookalike") -> Finding:
    return Finding(rule=rule, category=category, severity=sev, title=title, location=location, subject=subject,
                   detail=detail, remediation=fix)


# ------------------------------------------------------------------ Hermes plugins

def _git_remote(d: Path) -> str:
    try:
        text = (d / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r'\[remote "origin"\][^\[]*?url\s*=\s*(\S+)', text, re.S)
    return m.group(1) if m else ""


def check_hermes_plugins(hermes_home: Path, mm: Matchers) -> list[Finding]:
    out: list[Finding] = []
    root = hermes_home / "plugins"
    if not root.is_dir():
        return out
    for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
        meta = {}
        try:
            meta = json.loads((d / ".hermes-catalog.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        claimed = meta.get("catalog_name") or d.name
        repo = meta.get("repo") or _git_remote(d)
        loc = str(d)
        entry = mm.o.plugins.get(claimed)
        if claimed in mm.o.removed_plugins:
            out.append(_f("lookalike.plugin-removed", Severity.HIGH,
                          f"Plugin `{claimed}` was removed from the Hermes catalog", loc, claimed,
                          f"Catalog reason: {mm.o.removed_plugins[claimed]}",
                          f"Uninstall it (`hermes plugins remove {claimed}`) and follow the catalog note."))
        if entry and repo and entry.get("repo") and _repo_slug(repo) != _repo_slug(entry["repo"]) and \
                _repo_slug(repo).split("/")[0] == _repo_slug(entry["repo"]).split("/")[0]:
            out.append(_f("lookalike.plugin-repo-moved", Severity.LOW,
                          f"Plugin `{claimed}` was installed from a repo the catalog no longer uses", loc, claimed,
                          f"Same owner, different repo: catalog now points to {_repo_slug(entry['repo'])}, this copy "
                          f"came from {_repo_slug(repo)}. Usually the plugin moved, so this copy won't get updates.",
                          f"Reinstall from the catalog (`hermes plugins install {claimed}`)."))
        elif entry and repo and entry.get("repo") and _repo_slug(repo) != _repo_slug(entry["repo"]):
            out.append(_f("lookalike.plugin-repo-mismatch", Severity.CRITICAL,
                          f"Plugin `{claimed}` is installed from a different repo than the catalog's", loc, claimed,
                          f"Catalog: {_repo_slug(entry['repo'])}; installed from: {_repo_slug(repo)}. A plugin "
                          f"under a catalog name from another repo is impersonating the reviewed one.",
                          "Remove it and reinstall from the catalog (`hermes plugins install <name>`)."))
        if not entry:
            m = mm.plugins.lookalike(claimed)
            if m:
                out.append(_f("lookalike.plugin", m.severity,
                              f"Plugin `{claimed}` looks like catalog plugin `{m.official}`", loc, claimed,
                              f"`{claimed}` {m.reason}. Source: {_repo_slug(repo) or 'unknown'}.",
                              f"If you wanted `{m.official}`, remove this plugin and install the catalog entry."))
            elif meta.get("tier"):
                pass
    return out


# ------------------------------------------------------------------ OpenClaw extensions

def check_openclaw_extensions(home: Path, mm: Matchers) -> list[Finding]:
    out: list[Finding] = []
    for base in (".openclaw", ".clawdbot", ".moltbot"):
        root = home / base / "extensions"
        if not root.is_dir():
            continue
        for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
            name = d.name
            try:
                pkg = json.loads((d / "package.json").read_text(encoding="utf-8"))
                name = str(pkg.get("name") or name)
            except (OSError, ValueError):
                pass
            for n in {name, d.name}:
                m = mm.oc_ext.lookalike(n.split("/")[-1]) or mm.npm.lookalike(n)
                if m:
                    out.append(_f("lookalike.openclaw-extension", m.severity,
                                  f"OpenClaw extension `{n}` looks like `{m.official}`", str(d), n,
                                  f"`{n}` {m.reason}.", "Verify where it came from; remove it if you didn't "
                                                        "install it on purpose."))
                    break
    return out


# ------------------------------------------------------------------ MCP servers

_PKG_TOKEN = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~<>=*-]+)?$", re.I)


def _pkg_name(tok: str) -> str:
    if tok.startswith("@"):
        scope, _, rest = tok[1:].partition("/")
        return "@" + scope + "/" + rest.split("@", 1)[0]
    return re.split(r"[@=<>~!]", tok, 1)[0]


def check_mcp_servers(config_paths: list[Path], hermes_config: Path | None, mm: Matchers) -> list[Finding]:
    out: list[Finding] = []
    docs = []
    for p in config_paths:
        try:
            docs.append((p, discover.load_mcp_doc(p)))
        except Exception:
            continue
    if hermes_config and hermes_config.is_file():
        try:
            docs.append((hermes_config, yamlmini.load(hermes_config.read_text(encoding="utf-8"))))
        except Exception:
            pass
    official_hosts = mm.o.domains
    for path, doc in docs:
        for loc, name, spec in mcp.iter_servers(doc, origin=str(path)):
            args = [str(a) for a in (spec.get("args") or [])]
            cmd = str(spec.get("command") or "")
            runner = cmd.rsplit("/", 1)[-1]
            toks = [t for t in args if not t.startswith("-") and _PKG_TOKEN.match(t)]
            if runner in ("npx", "bunx", "pnpm", "yarn", "npm"):
                matcher, eco = mm.npm, "npm"
            elif runner in ("uvx", "pipx", "uv"):
                matcher, eco = mm.pypi, "PyPI"
            else:
                toks, matcher, eco = [], None, ""
            for t in toks[:3]:
                pkg = _pkg_name(t)
                m = matcher.lookalike(pkg) if matcher else None
                if m:
                    out.append(_f("lookalike.mcp-package", max(m.severity, Severity.HIGH),
                                  f"MCP server `{name}` runs {eco} package `{pkg}`, a look-alike of `{m.official}`",
                                  loc, f"{name}:{pkg}", f"`{pkg}` {m.reason}. It runs with your agent's access "
                                                        f"every time the server starts.",
                                  f"Replace it with `{m.official}` (pinned to an exact version) after checking."))
            url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
            if isinstance(url, str) and url:
                host = (urlparse(url).hostname or "").lower()
                if host and host not in official_hosts:
                    hm = Matcher(official_hosts).lookalike(host)
                    if hm:
                        out.append(_f("lookalike.mcp-host", Severity.HIGH,
                                      f"MCP server `{name}` points at `{host}`, a look-alike of `{hm.official}`",
                                      loc, f"{name}:{host}", f"`{host}` {hm.reason}. Remote MCP servers receive "
                                                             f"your prompts' tool calls and OAuth tokens.",
                                      f"Use the vendor's real endpoint (`{hm.official}`) and re-authorize."))
            m = mm.mcp.lookalike(name)
            if m and m.severity >= Severity.HIGH:
                out.append(_f("lookalike.mcp-name", m.severity,
                              f"MCP server name `{name}` looks like catalog server `{m.official}`", loc, name,
                              f"`{name}` {m.reason}.", "Check that this server is the one you meant to add."))
    return out


# ------------------------------------------------------------------ installed packages and apps

def npm_global_dirs(home: Path) -> list[Path]:
    cands = [Path("/usr/local/lib/node_modules"), Path("/usr/lib/node_modules"),
             Path("/opt/homebrew/lib/node_modules"), home / ".npm-global/lib/node_modules",
             home / ".local/lib/node_modules", home / ".bun/install/global/node_modules"]
    cands += sorted((home / ".nvm/versions/node").glob("*/lib/node_modules"))
    cands += sorted((home / ".local/share/pnpm/global").glob("*/node_modules"))
    cands += sorted((home / "Library/pnpm/global").glob("*/node_modules"))
    return [c for c in cands if c.is_dir()]


def python_site_dirs(home: Path, extra: list[Path]) -> list[Path]:
    cands = list(extra)
    cands += sorted((home / ".local/lib").glob("python3*/site-packages"))
    cands += sorted(Path("/usr/local/lib").glob("python3*/site-packages"))
    return [c for c in cands if c.is_dir()]


def _npm_names(d: Path):
    for p in d.iterdir():
        if p.name.startswith("@") and p.is_dir():
            for q in p.iterdir():
                yield f"{p.name}/{q.name}", q
        elif not p.name.startswith("."):
            yield p.name, p


def _py_names(d: Path):
    for p in d.glob("*.dist-info"):
        yield re.sub(r"-[^-]+$", "", p.name[: -len(".dist-info")]).replace("_", "-").lower(), p


def check_packages(home: Path, site_dirs: list[Path], mm: Matchers) -> list[Finding]:
    out: list[Finding] = []
    former = {n for a in mm.o.apps for n in a.get("former_names", [])}
    for eco, dirs, names_of, matcher in (("npm", npm_global_dirs(home), _npm_names, mm.npm),
                                         ("PyPI", python_site_dirs(home, site_dirs), _py_names, mm.pypi)):
        for d in dirs:
            for name, p in names_of(d):
                if name in former:
                    out.append(_f("lookalike.former-name", Severity.MEDIUM,
                                  f"{eco} package `{name}` uses a former OpenClaw name", str(p), name,
                                  "OpenClaw was renamed from Clawdbot/Moltbot; packages under the old names aren't "
                                  "published by the project and were targeted by squatters.",
                                  "Uninstall it and install `openclaw` from the official instructions."))
                    continue
                m = matcher.lookalike(name)
                if m and (m.severity >= Severity.HIGH or len(name) >= 8):
                    out.append(_f(f"lookalike.{eco.lower()}-package", max(m.severity, Severity.HIGH),
                                  f"Installed {eco} package `{name}` looks like `{m.official}`", str(p), name,
                                  f"`{name}` {m.reason}.", f"Uninstall `{name}` unless you know exactly why it's "
                                                           f"there; the official package is `{m.official}`."))
    return out


def check_desktop_apps(mm: Matchers, dirs=(Path("/Applications"), Path.home() / "Applications")) -> list[Finding]:
    out: list[Finding] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for app in d.glob("*.app"):
            m = mm.apps.lookalike(app.stem)
            if m:
                out.append(_f("lookalike.app", m.severity, f"App `{app.name}` looks like `{m.official}`",
                              str(app), app.stem, f"`{app.stem}` {m.reason}.",
                              "Check the developer in Finder → Get Info / `codesign -dv`, and delete it if it "
                              "isn't signed by the real vendor."))
    return out


def check_name(name: str, mm: Matchers) -> list[tuple[str, str, str]]:
    """(kinds, verdict, detail) for a name you're about to install. Identical verdicts are merged."""
    official_in, alike = [], {}
    for kind, m in (("skill", mm.skills), ("hermes plugin", mm.plugins), ("openclaw extension", mm.oc_ext),
                    ("mcp catalog", mm.mcp), ("npm package", mm.npm), ("PyPI package", mm.pypi),
                    ("app", mm.apps)):
        if m.is_official(name):
            official_in.append(kind)
            continue
        lm = m.lookalike(name)
        if lm:
            key = (lm.severity, lm.reason)
            alike.setdefault(key, []).append(kind)
    res = []
    if official_in:
        res.append((", ".join(official_in), "official", "exact match"))
    for (sev, reason), kinds in sorted(alike.items(), key=lambda kv: -int(kv[0][0])):
        if official_in and sev < Severity.HIGH:
            continue   # an official name that's also near another official name is not a look-alike
        res.append((", ".join(kinds), f"look-alike ({sev.name.lower()})", reason))
    if name in mm.o.removed_plugins:
        res.append(("hermes plugin", "removed", mm.o.removed_plugins[name]))
    return res
