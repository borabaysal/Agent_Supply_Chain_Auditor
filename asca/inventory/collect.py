"""Discover installed IDE extensions, MCP servers, agent plugins and skills, read-only.

Every source is a file or folder read as text or JSON. Nothing is executed: no ``code
--list-extensions``, no ``npm ls``, no ``git``. Unreadable or corrupt state files are reported
as parse errors (fail closed) rather than skipped silently.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import discover, mcp, yamlmini
from ..skillscan import scan as skillscan
from .hashing import Budget, text_hash, tree_hash

# (ide label, extensions dir relative to $HOME)
IDE_DIRS = [
    ("vscode", ".vscode/extensions"), ("vscode-insiders", ".vscode-insiders/extensions"),
    ("vscode-server", ".vscode-server/extensions"), ("cursor", ".cursor/extensions"),
    ("cursor-server", ".cursor-server/extensions"), ("windsurf", ".windsurf/extensions"),
    ("windsurf-server", ".windsurf-server/extensions"), ("vscodium", ".vscode-oss/extensions"),
    ("vscodium-server", ".vscodium-server/extensions"),
]


@dataclass
class Item:
    kind: str                 # ide-extension | mcp-server | skill | hermes-plugin | claude-plugin | openclaw-extension
    source: str               # ide label, config file, skill ecosystem, …
    id: str                   # stable id within the source
    name: str                 # short name, used to pair "same name, different publisher"
    publisher: str = ""
    publisher_id: str = ""    # marketplace publisher UUID when the IDE records one
    publisher_name: str = ""  # display name
    version: str = ""
    origin: str = ""          # gallery | vsix | catalog | git | hub:<src>:<trust> | builtin | local | config
    policy: str = "managed"   # managed (tamper rule) | bundled | local | config
    path: str = ""
    hash: str | None = None
    files: int = 0
    bytes: int = 0
    partial: bool = False
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}|{self.source}|{self.id}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Collected:
    items: list[Item] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)    # (location, message)
    sources: list[str] = field(default_factory=list)


def _read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8", errors="replace"))


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v or "0"))


def _hash(item: Item, root: Path, mode: str, budget: Budget) -> Item:
    th = tree_hash(root, mode=mode, budget=budget)
    item.hash, item.files, item.bytes, item.partial, item.note = th.digest, th.files, th.bytes, th.partial, th.note
    return item


# ------------------------------------------------------------------ IDE extensions

def ide_extensions(home: Path, budget: Budget, out: Collected, extra: list[tuple[str, Path]] = ()) -> None:
    for label, rel in [*IDE_DIRS, *((l, p) for l, p in extra)]:
        root = rel if isinstance(rel, Path) and rel.is_absolute() else home / rel
        if not root.is_dir():
            continue
        out.sources.append(f"{label}:{root}")
        listed: list[tuple[Path, dict]] = []
        manifest = root / "extensions.json"
        manifest_ok = False
        if manifest.is_file():
            try:
                for e in _read_json(manifest):
                    loc = e.get("relativeLocation") or Path((e.get("location") or {}).get("fsPath")
                                                            or (e.get("location") or {}).get("path") or "").name
                    if loc:
                        listed.append((root / loc, e))
                manifest_ok = True
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                out.errors.append((str(manifest), f"{type(exc).__name__}: {exc}"[:160]))
                listed = []
        if not manifest_ok:   # no (usable) extensions.json: fall back to folders, skipping VS Code's .obsolete list
            obsolete = set()
            try:
                obsolete = set(_read_json(root / ".obsolete"))
            except (OSError, ValueError, TypeError):
                pass
            best: dict[str, tuple[Path, dict]] = {}
            for d in sorted(root.iterdir()):
                if not d.is_dir() or d.name.startswith(".") or d.name in obsolete or not (d / "package.json").is_file():
                    continue
                try:
                    pkg = _read_json(d / "package.json")
                except (OSError, ValueError):
                    continue
                eid = f"{pkg.get('publisher', '')}.{pkg.get('name', '')}".lower()
                if eid not in best or _vkey(pkg.get("version", "")) > _vkey(best[eid][1].get("version", "")):
                    best[eid] = (d, {"version": pkg.get("version", "")})
            listed = list(best.values())
        for d, entry in listed:
            pkg = {}
            try:
                pkg = _read_json(d / "package.json")
            except (OSError, ValueError) as exc:
                if d.exists():
                    out.errors.append((str(d / "package.json"), f"{type(exc).__name__}: {exc}"[:160]))
                continue
            meta = entry.get("metadata") or {}
            publisher = str(pkg.get("publisher", "")).lower()
            name = str(pkg.get("name", "")).lower()
            eid = ((entry.get("identifier") or {}).get("id") or f"{publisher}.{name}").lower()
            item = Item(kind="ide-extension", source=label, id=eid, name=name, publisher=publisher,
                        publisher_id=str(meta.get("publisherId") or ""),
                        publisher_name=str(meta.get("publisherDisplayName") or ""),
                        version=str(pkg.get("version") or entry.get("version") or ""),
                        origin=str(meta.get("source") or ("gallery" if meta.get("publisherId") else "")),
                        path=str(d))
            out.items.append(_hash(item, d, "code", budget))


# ------------------------------------------------------------------ MCP servers

_NODE = {"npx", "bunx", "pnpx"}
_PY = {"uvx", "pipx", "uv"}


def _pkg_from_args(runner: str, args: list[str]) -> str:
    for a in args:
        if a.startswith("-") or a in ("run", "exec", "dlx", "tool"):
            continue
        return a
    return ""


def mcp_identity(spec: dict) -> tuple[str, str, str]:
    """(publisher, version, launch-hash) of an MCP server definition. Env/header *values* are excluded."""
    cmd = str(spec.get("command") or "")
    args = [str(a) for a in (spec.get("args") or [])]
    url = str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or "")
    runner = cmd.rsplit("/", 1)[-1]
    publisher, version = runner or "", ""
    if url:
        m = re.match(r"^[a-z]+://([^/:@]+)", url, re.I)
        publisher = (m.group(1) if m else url).lower()
    elif runner in _NODE or (runner in ("npm", "pnpm", "yarn") and args[:1] in (["exec"], ["dlx"])):
        pkg = _pkg_from_args(runner, args)
        if pkg.startswith("@"):
            scope, _, rest = pkg.partition("/")
            publisher, _, version = scope, "", rest.partition("@")[2]
        else:
            name, _, version = pkg.partition("@")
            publisher = name
    elif runner in _PY:
        pkg = args[args.index("--from") + 1] if "--from" in args and args.index("--from") + 1 < len(args) \
            else _pkg_from_args(runner, args)
        if pkg.startswith("git+") and "@" in pkg.split("://", 1)[-1]:
            publisher, _, version = pkg.rpartition("@")
        else:
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[.*\])?\s*(?:==|@)\s*(\S+)$", pkg)
            publisher, version = (m.group(1), m.group(2)) if m else (re.split(r"[<>=!~@ \[]", pkg)[0], "")
        publisher = publisher.lower()
    elif runner in ("docker", "podman") and "run" in args:
        image = mcp._docker_image(args[args.index("run") + 1:]) or ""
        ref, _, digest = image.partition("@")
        repo, tag = (ref.rsplit(":", 1) if ":" in ref.rsplit("/", 1)[-1] else (ref, ""))
        publisher = (repo.rsplit("/", 1)[0] if "/" in repo else repo).lower()
        version = digest or tag
    env_keys = sorted((spec.get("env") or {}).keys()) if isinstance(spec.get("env"), dict) else []
    hdr_keys = sorted((spec.get("headers") or {}).keys()) if isinstance(spec.get("headers"), dict) else []
    launch = text_hash(cmd, json.dumps(args), url, ",".join(env_keys), ",".join(hdr_keys))
    return publisher, version, launch


def mcp_servers(config_paths: list[Path], hermes_config: Path | None, out: Collected) -> None:
    docs = []
    for p in config_paths:
        try:
            docs.append((p, discover.load_mcp_doc(p)))
        except (OSError, ValueError) as exc:
            out.errors.append((str(p), f"{type(exc).__name__}: {exc}"[:160]))
    if hermes_config and hermes_config.is_file():
        try:
            docs.append((hermes_config, yamlmini.load(hermes_config.read_text(encoding="utf-8"))))
        except Exception as exc:   # yamlmini.YamlError and friends: fail closed
            out.errors.append((str(hermes_config), f"{type(exc).__name__}: {exc}"[:160]))
    for path, doc in docs:
        out.sources.append(f"mcp:{path}")
        for loc, name, spec in mcp.iter_servers(doc, origin=str(path)):
            publisher, version, launch = mcp_identity(spec)
            disabled = spec.get("enabled") is False or spec.get("disabled") is True
            out.items.append(Item(kind="mcp-server", source=str(path), id=loc.split("#", 1)[-1], name=str(name),
                                  publisher=publisher, version=version, origin="config", policy="config",
                                  path=loc, hash=launch, note="disabled" if disabled else ""))


# ------------------------------------------------------------------ skills (Hermes, OpenClaw, Claude, Codex, …)

def _bundled_manifest(hermes_home: Path | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not hermes_home:
        return out
    try:
        for line in (hermes_home / "skills" / ".bundled_manifest").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _hub_lock(hermes_home: Path | None) -> dict:
    if not hermes_home:
        return {}
    try:
        return _read_json(hermes_home / "skills" / ".hub" / "lock.json").get("installed", {}) or {}
    except (OSError, ValueError, AttributeError):
        return {}


def skills(home: Path, hermes_home: Path | None, budget: Budget, out: Collected) -> None:
    bundled, lock = _bundled_manifest(hermes_home), _hub_lock(hermes_home)
    for root, eco in skillscan.default_roots(home, hermes_home):
        out.sources.append(f"skills:{eco}:{root}")
        for sk in skillscan.find_skills(root, eco, hermes_home):
            rel = sk.path.relative_to(root).as_posix()
            prov = sk.provenance
            item = Item(kind="skill", source=f"{eco}:{root}", id=rel, name=sk.dir_name, path=str(sk.path), origin=prov)
            if prov == "builtin":
                item.publisher, item.policy = "builtin", "bundled"
                item.version = "bundled:" + bundled.get(sk.dir_name, "")[:12]
            elif prov.startswith("hub:"):
                e = lock.get(sk.dir_name) or lock.get(sk.name) or {}
                ident = str(e.get("identifier") or "")
                parts = [p for p in ident.split("/") if p]
                item.publisher = (parts[1] if len(parts) > 2 else prov.split(":")[1]).lower()
                # Hermes rewrites content_hash on install/update, so "files changed, same lock hash" = tamper
                item.version = str(e.get("content_hash") or e.get("hash") or e.get("commit") or
                                   e.get("version") or "")[:40]
            elif prov.startswith("plugin:"):
                item.publisher, item.policy = prov, "managed"
            else:
                item.publisher, item.policy = "local", "local"
            if not item.version:
                item.version = str(skillscan._front_matter(sk.path / "SKILL.md").get("version") or "")
            out.items.append(_hash(item, sk.path, "all", budget))


# ------------------------------------------------------------------ Hermes plugins

def _git_head(d: Path) -> str:
    """HEAD commit read from .git files as text (never runs git)."""
    g = d / ".git"
    try:
        head = (g / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if not head.startswith("ref:"):
        return head[:40]
    ref = head[4:].strip()
    try:
        return (g / ref).read_text(encoding="utf-8").strip()[:40]
    except OSError:
        pass
    try:
        for line in (g / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return line.split()[0][:40]
    except OSError:
        pass
    return ""


def _git_remote_owner(d: Path) -> str:
    try:
        text = (d / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r'\[remote "origin"\][^\[]*?url\s*=\s*\S*?[/:]([^/\s]+)/[^/\s]+?(?:\.git)?\s', text + "\n", re.S)
    return m.group(1).lower() if m else ""


def hermes_plugins(hermes_home: Path, budget: Budget, out: Collected) -> None:
    root = hermes_home / "plugins"
    if not root.is_dir():
        return
    out.sources.append(f"hermes-plugins:{root}")
    for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
        if not any((d / f).exists() for f in ("plugin.yaml", "plugin.yml", "__init__.py", "package.json")):
            continue   # state-only folders (e.g. a plugin's data dir) aren't plugins
        cat = {}
        try:
            cat = _read_json(d / ".hermes-catalog.json")
        except (OSError, ValueError):
            pass
        meta = {}
        try:
            meta = yamlmini.load((d / "plugin.yaml").read_text(encoding="utf-8")) or {}
        except Exception:
            pass
        head = _git_head(d)
        repo_owner = ""
        m = re.search(r"github\.com[/:]([^/]+)/", str(cat.get("repo") or ""))
        if m:
            repo_owner = m.group(1).lower()
        publisher = repo_owner or _git_remote_owner(d) or str(meta.get("author") or "local").lower()
        if cat.get("sha"):
            version, origin = f"{meta.get('version', '')}@{str(cat['sha'])[:12]}".lstrip("@"), "catalog"
        elif head:
            version, origin = f"{meta.get('version', '')}@{head[:12]}".lstrip("@"), "git"
        else:
            version, origin = str(meta.get("version") or ""), "local"
        item = Item(kind="hermes-plugin", source="hermes", id=str(cat.get("catalog_name") or d.name), name=d.name,
                    publisher=publisher, version=version, origin=origin,
                    policy="local" if origin == "local" else "managed", path=str(d))
        out.items.append(_hash(item, d, "code", budget))


# ------------------------------------------------------------------ Claude Code plugins, OpenClaw extensions

def claude_plugins(home: Path, budget: Budget, out: Collected) -> None:
    f = home / ".claude" / "plugins" / "installed_plugins.json"
    if not f.is_file():
        return
    try:
        doc = _read_json(f)
    except (OSError, ValueError) as exc:
        out.errors.append((str(f), f"{type(exc).__name__}: {exc}"[:160]))
        return
    out.sources.append(f"claude-plugins:{f}")
    plugins = doc.get("plugins", doc) if isinstance(doc, dict) else {}
    for pid, recs in sorted(plugins.items() if isinstance(plugins, dict) else []):
        if not isinstance(recs, list):
            recs = [recs]
        for r in recs:
            if not isinstance(r, dict):
                continue
            name, _, market = str(pid).partition("@")
            p = Path(str(r.get("installPath") or ""))
            item = Item(kind="claude-plugin", source=str(r.get("scope") or "user") + (
                        f":{r['projectPath']}" if r.get("projectPath") else ""), id=str(pid), name=name,
                        publisher=market.lower(), version=str(r.get("version") or ""), origin="marketplace",
                        path=str(p))
            if p.is_dir():
                _hash(item, p, "all", budget)
            out.items.append(item)


def openclaw_extensions(home: Path, budget: Budget, out: Collected) -> None:
    for base in (".openclaw", ".clawdbot", ".moltbot"):
        root = home / base / "extensions"
        if not root.is_dir():
            continue
        out.sources.append(f"openclaw:{root}")
        for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
            pkg = {}
            try:
                pkg = _read_json(d / "package.json")
            except (OSError, ValueError):
                pass
            name = str(pkg.get("name") or d.name)
            author = pkg.get("author")
            author = author.get("name") if isinstance(author, dict) else author
            publisher = (name.split("/")[0] if name.startswith("@") else str(pkg.get("publisher") or author or
                                                                             "unknown")).lower()
            item = Item(kind="openclaw-extension", source=base, id=name.lower(), name=name.split("/")[-1].lower(),
                        publisher=publisher, version=str(pkg.get("version") or ""), origin="npm", path=str(d))
            out.items.append(_hash(item, d, "code", budget))


def collect(home: Path, hermes_home: Path | None, budget: Budget, *, mcp_configs: list[Path] = (),
            ide_dirs: list[tuple[str, Path]] = (), include_skills: bool = True) -> Collected:
    out = Collected()
    ide_extensions(home, budget, out, list(ide_dirs))
    claude_plugins(home, budget, out)
    openclaw_extensions(home, budget, out)
    cfgs = list(mcp_configs) + [p for p in discover.default_client_configs(home) if p not in mcp_configs]
    mcp_servers(cfgs, (hermes_home / "config.yaml") if hermes_home else None, out)
    if hermes_home:
        hermes_plugins(hermes_home, budget, out)
    if include_skills:
        skills(home, hermes_home, budget, out)
    # same key twice (e.g. a skill dir reachable from two roots): keep the first
    seen, uniq = set(), []
    for it in out.items:
        if it.key not in seen:
            seen.add(it.key)
            uniq.append(it)
    out.items = uniq
    return out
