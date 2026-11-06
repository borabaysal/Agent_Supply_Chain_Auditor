"""Agent configuration tamper: sandbox off, traffic re-routed, approvals and telemetry disabled.

Grounding: Symantec's Threat Hunter team (Oct 2026) found an unauthorized relay service that
installs the genuine Codex / Claude Code CLIs and then rewrites their config. It sets
``sandbox_mode = "danger-full-access"``, enables network access for the write sandbox, points
``base_url`` / ``ANTHROPIC_BASE_URL`` at its own servers, swaps in relay-issued tokens as
user-scope environment variables, and turns off telemetry and error reporting. HiddenLayer's
"Man-in-the-Model" research shows why a gateway in that position matters: whoever answers the
model calls can steer what the agent runs.

Each signal on its own is often a deliberate choice: a container with no sandbox, a company
LLM gateway, telemetry off for privacy. So singles are medium/low, a known relay domain is
critical, and the relay *combination* (an endpoint override plus a disabled sandbox or
approvals or telemetry) is high. Accepted choices go in the baseline like any other finding.
Values of keys and tokens are never read into findings; only their presence is reported.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from . import yamlmini
from .model import Finding, Severity

SYMANTEC = "https://www.security.com/threat-intelligence/openai-claude-unauthorized-relays"

# Relay infrastructure published by Symantec (exact hosts for shared domains).
RELAY_DOMAINS = ["aiok.me", "sorryios.io", "sorryios.chat", "nuoda.vip", "rawchat.cn", "sharedchat.cc",
                 "mirbuds.com", "claudechn.com", "vibe.skk.moe"]

# First-party model endpoints. Subdomains count (api.anthropic.com, eu.api.openai.com, …).
OFFICIAL = ["anthropic.com", "claude.ai", "openai.com", "chatgpt.com", "openai.azure.com", "azure.com",
            "amazonaws.com", "googleapis.com", "nousresearch.com"]
# Well-known third-party gateways/providers: reported as info so the choice stays visible.
KNOWN_PROVIDERS = ["openrouter.ai", "api.together.xyz", "together.ai", "groq.com", "deepseek.com", "mistral.ai",
                   "x.ai", "fireworks.ai", "cerebras.ai", "perplexity.ai", "moonshot.ai", "z.ai", "bigmodel.cn",
                   "nebius.com", "hyperbolic.xyz", "novita.ai", "huggingface.co", "cohere.com", "cohere.ai",
                   "ai.gateway.vercel.app", "gateway.ai.cloudflare.com", "inference.net", "portkey.ai"]

BASE_URL_KEYS = {"base_url", "api_base", "openai_base_url", "chatgpt_base_url", "anthropic_base_url", "baseurl",
                 "endpoint"}
ENDPOINT_ENV = ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "CODEX_BASE_URL",
                "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "CLAUDE_CODE_API_BASE_URL"]
TOKEN_ENV = ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "CODEX_API_KEY", "OPENAI_API_KEY"]
TELEMETRY_ENV = ["DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                 "DISABLE_BUG_COMMAND"]
SHELL_FILES = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish",
               ".config/environment.d/ai.conf"]

RESET_FIX = ("If you didn't set this up on purpose, restore the vendor defaults (delete the override), log out and "
             "back in to the CLI, rotate the API key/token it used, and check how the change got there (a "
             "one-line 'setup' script from a reseller is the known pattern).")


def _host(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return ""


def _match(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def classify_endpoint(url: str) -> str:
    """relay | official | local | provider | unknown | empty"""
    h = _host(url)
    if not h:
        return "empty"
    if _match(h, RELAY_DOMAINS):
        return "relay"
    if _match(h, OFFICIAL):
        return "official"
    if h in ("localhost", "host.docker.internal") or h.endswith((".local", ".internal", ".lan", ".ts.net")):
        return "local"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "local"
    except ValueError:
        pass
    if _match(h, KNOWN_PROVIDERS):
        return "provider"
    return "unknown"


def _truthy(v) -> bool:
    return str(v).strip().strip("'\"").lower() in ("1", "true", "yes", "on")


class _Agent:
    """Signals collected for one agent (Codex, Claude Code, Hermes) before scoring."""

    def __init__(self, name: str):
        self.name = name
        self.endpoints: list[tuple[str, str, str]] = []      # (location, key, url)
        self.unsafe: list[tuple[str, str]] = []               # (location, what)
        self.telemetry_off: list[str] = []                    # locations
        self.tokens: list[tuple[str, str]] = []               # (location, var)


def _endpoint_findings(agent: _Agent) -> tuple[list[Finding], bool]:
    out = []
    overridden = False
    for loc, key, url in agent.endpoints:
        kind = classify_endpoint(url)
        host = _host(url)
        if kind == "relay":
            overridden = True
            out.append(Finding(
                rule="agent.relay-endpoint", category="agent-config", severity=Severity.CRITICAL,
                title=f"{agent.name} sends its traffic to a known unauthorized relay ({host})", location=loc,
                subject=f"{agent.name}:{key}:{host}",
                detail=f"`{key}` points at `{host}`, which Symantec lists as infrastructure of a relay service "
                       f"that disables agent sandboxes and swaps credentials ({SYMANTEC}). Every prompt, file and "
                       f"secret the agent handles goes through it, and it can alter the agent's instructions.",
                remediation=RESET_FIX))
        elif kind in ("unknown", "provider"):
            overridden = overridden or kind == "unknown"
            out.append(Finding(
                rule="agent.endpoint-override", category="agent-config",
                severity=Severity.MEDIUM if kind == "unknown" else Severity.INFO,
                title=f"{agent.name} uses a non-default model endpoint ({host})", location=loc,
                subject=f"{agent.name}:{key}:{host}",
                detail=(f"`{key}` = `{host}`. Whoever runs this endpoint sees everything the agent sends and "
                        f"chooses what it gets back, which is enough to steer a coding agent (HiddenLayer, "
                        f"'Man-in-the-Model').")
                       + (" It's a well-known provider, listed so the choice stays visible." if kind == "provider"
                          else ""),
                remediation="Fine if it's your company gateway or a provider you chose; accept it in the baseline. "
                            "Otherwise remove the override and rotate the key it used."))
    return out, overridden


def score(agent: _Agent) -> list[Finding]:
    out, overridden = _endpoint_findings(agent)
    for loc, what in agent.unsafe:
        out.append(Finding(
            rule="agent.sandbox-disabled", category="agent-config", severity=Severity.HIGH,
            title=f"{agent.name}: {what}", location=loc, subject=f"{agent.name}:{what}",
            detail="With the sandbox or approvals off, anything the model decides to run executes with your full "
                   "user rights, including whatever a prompt injection or a malicious endpoint tells it to.",
            remediation="Use the vendor default (Codex `workspace-write`, Claude Code `default` permissions, Hermes "
                        "`smart` approvals). Keep full access to throwaway containers, and accept it in the "
                        "baseline there."))
    for loc in sorted(set(agent.telemetry_off)):
        out.append(Finding(
            rule="agent.telemetry-disabled", category="agent-config", severity=Severity.LOW,
            title=f"{agent.name}: telemetry and error reporting are switched off", location=loc,
            subject=f"{agent.name}:telemetry:{loc}",
            detail="Often a privacy choice. It's listed because the relay service in Symantec's report switches "
                   "these off too, which hides usage from the vendor.",
            remediation="Nothing to do if you turned it off yourself."))
    for loc, var in agent.tokens:
        out.append(Finding(
            rule="agent.token-in-config", category="agent-config", severity=Severity.MEDIUM,
            title=f"{agent.name}: `{var}` is set in {Path(loc).name}", location=loc, subject=f"{agent.name}:{var}:{loc}",
            detail="A credential set in a settings or shell file is used by every tool that reads that variable. "
                   "The relay pattern installs its own token this way so it survives logouts and reboots. "
                   "(The value isn't read into this report.)",
            remediation="Prefer the CLI's own login or a secrets manager. If you didn't put it there, rotate it."))
    if overridden and (agent.unsafe or agent.telemetry_off or agent.tokens):
        locs = sorted({l for l, *_ in agent.endpoints} | {l for l, _ in agent.unsafe} | set(agent.telemetry_off))
        out.append(Finding(
            rule="agent.relay-pattern", category="agent-config", severity=Severity.HIGH,
            title=f"{agent.name} looks reconfigured by a relay: endpoint override plus "
                  + " and ".join(x for x, on in (("unsafe sandbox/approvals", agent.unsafe),
                                                  ("telemetry off", agent.telemetry_off),
                                                  ("a token in config", agent.tokens)) if on),
            location=locs[0], subject=f"{agent.name}:relay-pattern",
            detail=f"This is the combination Symantec observed ({SYMANTEC}). Files: {', '.join(locs)}.",
            remediation=RESET_FIX))
    return out


# ------------------------------------------------------------------ readers

def _codex(home: Path, env: dict, agent: _Agent, errors: list[Finding]) -> None:
    root = Path(env.get("CODEX_HOME") or home / ".codex")
    p = root / "config.toml"
    if not p.is_file():
        return
    try:
        import tomllib
        doc = tomllib.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:   # includes ModuleNotFoundError on 3.10
        errors.append(_parse_error(p, exc))
        return
    scopes = [("", doc)] + [(f"profiles.{k}.", v) for k, v in (doc.get("profiles") or {}).items() if isinstance(v, dict)]
    for prefix, d in scopes:
        if str(d.get("sandbox_mode", "")).strip() == "danger-full-access":
            agent.unsafe.append((f"{p}#{prefix}sandbox_mode", f"sandbox_mode = \"danger-full-access\" ({prefix or 'top level'})"))
        sw = d.get("sandbox_workspace_write") or {}
        if isinstance(sw, dict) and _truthy(sw.get("network_access", False)):
            agent.unsafe.append((f"{p}#{prefix}sandbox_workspace_write.network_access",
                                 "network access enabled for the write sandbox"))
        if str(d.get("approval_policy", "")).strip() == "never" and str(d.get("sandbox_mode", "")) == "danger-full-access":
            agent.unsafe.append((f"{p}#{prefix}approval_policy", "approval_policy = \"never\" with full access"))
        for k in ("openai_base_url", "chatgpt_base_url", "base_url"):
            if isinstance(d.get(k), str) and d[k]:
                agent.endpoints.append((f"{p}#{prefix}{k}", k, d[k]))
        for name, prov in (d.get("model_providers") or {}).items():
            if isinstance(prov, dict) and isinstance(prov.get("base_url"), str) and prov["base_url"]:
                agent.endpoints.append((f"{p}#{prefix}model_providers.{name}.base_url", f"model_providers.{name}",
                                        prov["base_url"]))
        for k, v in (d.get("env") or {}).items() if isinstance(d.get("env"), dict) else []:
            _env_pair(str(p), k, v, agent)


def _env_pair(loc: str, k: str, v, agent: _Agent) -> None:
    k = str(k)
    if k in ENDPOINT_ENV and v:
        agent.endpoints.append((f"{loc}#env.{k}", k, str(v)))
    elif k in TOKEN_ENV and v:
        agent.tokens.append((loc, k))
    elif k in TELEMETRY_ENV and _truthy(v):
        agent.telemetry_off.append(loc)


def _claude(home: Path, env: dict, agent: _Agent, errors: list[Finding], extra: list[Path]) -> None:
    files = [home / ".claude" / "settings.json", home / ".claude" / "settings.local.json",
             Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
             Path("/etc/claude-code/managed-settings.json"), *extra]
    for p in files:
        if not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(_parse_error(p, exc))
            continue
        if not isinstance(doc, dict):
            continue
        for k, v in (doc.get("env") or {}).items() if isinstance(doc.get("env"), dict) else []:
            _env_pair(str(p), k, v, agent)
        perms = doc.get("permissions") or {}
        if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
            agent.unsafe.append((f"{p}#permissions.defaultMode", "permissions.defaultMode = bypassPermissions"))
        if doc.get("skipDangerousModePermissionPrompt") is True:
            agent.unsafe.append((f"{p}#skipDangerousModePermissionPrompt", "dangerous-mode prompt skipped"))
        if isinstance(doc.get("apiKeyHelper"), str) and re.search(r"\b(curl|wget|nc|https?://)", doc["apiKeyHelper"]):
            agent.unsafe.append((f"{p}#apiKeyHelper", "apiKeyHelper fetches credentials from the network"))


def _walk_urls(node, path: str = ""):
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else str(k)
            if str(k).lower() in BASE_URL_KEYS and isinstance(v, str) and v.strip():
                yield p, v.strip()
            else:
                yield from _walk_urls(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_urls(v, f"{path}[{i}]")


def _hermes(home: Path | None, agent: _Agent, errors: list[Finding]) -> None:
    if not home:
        return
    p = home / "config.yaml"
    if not p.is_file():
        return
    try:
        doc = yamlmini.load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        errors.append(_parse_error(p, exc))
        return
    if not isinstance(doc, dict):
        return
    for keypath, url in _walk_urls({k: v for k, v in doc.items() if k not in ("mcp_servers",)}):
        agent.endpoints.append((f"{p}#{keypath}", keypath, url))
    appr = doc.get("approvals") or {}
    if isinstance(appr, dict) and str(appr.get("mode", "")).lower() in ("off", "yolo", "never", "none"):
        agent.unsafe.append((f"{p}#approvals.mode", f"approvals.mode = {appr.get('mode')}"))


def _shell(home: Path, agents: dict[str, _Agent]) -> None:
    rx = re.compile(r"^\s*(?:export\s+|set\s+-gx\s+|setenv\s+)?([A-Z_][A-Z0-9_]*)\s*[= ]\s*['\"]?([^'\"\s#]*)", re.M)
    for rel in SHELL_FILES:
        p = home / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in rx.finditer(text):
            k, v = m.group(1), m.group(2)
            target = agents["Claude Code"] if k.startswith(("ANTHROPIC", "CLAUDE", "DISABLE_")) else agents["Codex"]
            if k in ENDPOINT_ENV or k in TOKEN_ENV or k in TELEMETRY_ENV:
                if k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
                    continue   # common for SDK use; the secrets check covers values
                _env_pair(str(p), k, v or "1", target)


def _process_env(env: dict, agents: dict[str, _Agent]) -> None:
    for k in ENDPOINT_ENV:
        if env.get(k):
            target = agents["Claude Code"] if k.startswith(("ANTHROPIC", "CLAUDE")) else agents["Codex"]
            target.endpoints.append((f"environment:{k}", k, env[k]))


def _parse_error(p: Path, exc: Exception) -> Finding:
    return Finding(rule="scanner.parse-error", category="scanner", severity=Severity.HIGH,
                   title=f"Couldn't parse {p.name}", location=str(p), subject=str(p),
                   detail=f"{type(exc).__name__}: {str(exc)[:160]}",
                   remediation="Fix the file; until then its agent settings aren't checked.")


def audit(home: Path, hermes_home: Path | None, stats: dict, *, env: dict | None = None,
          extra_claude: list[Path] = ()) -> list[Finding]:
    env = dict(os.environ) if env is None else env
    agents = {n: _Agent(n) for n in ("Codex", "Claude Code", "Hermes")}
    errors: list[Finding] = []
    _codex(home, env, agents["Codex"], errors)
    _claude(home, env, agents["Claude Code"], errors, list(extra_claude))
    _hermes(hermes_home, agents["Hermes"], errors)
    _shell(home, agents)
    _process_env(env, agents)
    out = errors
    for a in agents.values():
        out += score(a)
    stats["agent_endpoints"] = sum(len(a.endpoints) for a in agents.values())
    return out
