"""Keys in agent transcripts that were also sent to a model provider, and provider routing that points at
providers with a published prompt-exposure incident. Rules ``secret.sent-to-provider`` and
``agent.provider-routing``.

Grounding: Dragos (HD Moore, Nov 19 2026) sent ~2 million prompts holding canary credentials through AI routers
and providers. Bait AWS keys sent in prompts were stolen at three inference providers and used for tens of
thousands of AWS API calls; some stolen requests were marked Zero Data Retention. "Every hop can see the entire
prompt and response", and "AI agents will happily send whatever they can read, including credentials." OpenRouter
(Nov 22) off-boarded three providers, removed 125 endpoints from ZDR eligibility and listed the providers' own
incident notices.

The session-history check already reports a key saved in a transcript as a local leak. A transcript is what the
agent sent to its model, so the same key also went to whoever serves that model. This module reads the agent's
configured endpoint (Hermes ``model`` + ``provider_routing``, Codex ``model_provider``/``model_providers``,
Claude Code ``ANTHROPIC_BASE_URL``) and says where:

| Where the agent's prompts go | ``secret.sent-to-provider`` |
|---|---|
| the model vendor's own API (Anthropic, OpenAI, Google, AWS, Azure, Nous, DeepSeek, ...) or a local server | no finding |
| an unrecognised endpoint (company gateway, or a reseller relay) | medium |
| a router (OpenRouter, ...) or a third-party host of other vendors' models | high |
| a provider with a published incident, and transcripts holding the key were written on/after its window began | critical |

``agent.provider-routing``: Hermes ``provider_routing.only``/``order`` naming a provider with a published incident
(medium), or an agent pointed straight at one (medium).

Static: only config files and file timestamps are read. Nothing is contacted. The endpoint is today's setting; if
it was different when a session ran, the finding says so and the key may have gone elsewhere.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import agentcfg, fsutil, yamlmini
from .model import Finding, Severity

DRAGOS = "https://www.dragos.com/blog/ai-supply-chain-security-canary-tokens"
OPENROUTER = "https://openrouter.ai/blog/announcements/data-processing-incidents-on-inference-providers/"

ROUTERS = {"openrouter.ai": "OpenRouter", "ai-gateway.vercel.sh": "Vercel AI Gateway",
           "ai.gateway.vercel.app": "Vercel AI Gateway", "requesty.ai": "Requesty", "kilocode.ai": "Kilo Code",
           "kilo.ai": "Kilo Code", "opencode.ai": "OpenCode", "aimlapi.com": "AI/ML API",
           "router.huggingface.co": "Hugging Face Inference Providers", "unify.ai": "Unify", "portkey.ai": "Portkey"}
# Third-party hosts serving other vendors' open models.
HOSTS = ["together.xyz", "together.ai", "novita.ai", "fireworks.ai", "groq.com", "cerebras.ai", "hyperbolic.xyz",
         "nebius.com", "nebius.ai", "deepinfra.com", "inference.net", "phala.network", "phala.com", "atlascloud.ai",
         "gmi-serving.com", "gmicloud.ai", "chutes.ai", "parasail.io", "baseten.co", "siliconflow.cn",
         "siliconflow.com", "sambanova.ai", "lambda.ai", "primeintellect.ai", "featherless.ai", "kluster.ai",
         "nscale.com", "streamlake.ai"]
# Model vendors' own APIs: Dragos' "go directly to a first-tier provider" (smallest exposure). No finding.
FIRST_PARTY = agentcfg.OFFICIAL + ["deepseek.com", "x.ai", "mistral.ai", "moonshot.ai", "moonshot.cn", "kimi.com",
                                   "z.ai", "bigmodel.cn", "minimax.io", "minimaxi.com", "minimax.chat", "cohere.com",
                                   "cohere.ai", "perplexity.ai", "aliyuncs.com", "nvidia.com", "xiaomimimo.com",
                                   "tencentmaas.com", "stepfun.com", "arcee.ai", "ollama.com", "volces.com",
                                   "longcat.chat", "glm.ai", "azuredatabricks.net"]

# Hermes `model.provider` slugs (hermes_cli/models_catalog_static.py) -> (shown name, host for incident matching, kind)
HERMES_SLUGS = {
    "openrouter": ("OpenRouter", "openrouter.ai", "router"), "ai-gateway": ("Vercel AI Gateway", "", "router"),
    "kilocode": ("Kilo Code", "", "router"), "opencode-zen": ("OpenCode Zen", "", "router"),
    "opencode-go": ("OpenCode Go", "", "router"), "huggingface": ("Hugging Face Inference Providers", "", "router"),
    "novita": ("NovitaAI", "novita.ai", "host"), "gmi": ("GMI Cloud", "gmicloud.ai", "host"),
    "fireworks": ("Fireworks AI", "fireworks.ai", "host"), "lmstudio": ("LM Studio", "", "local"),
}
_HERMES_FIRST = {"nous", "anthropic", "openai-codex", "openai-api", "gemini", "vertex", "bedrock", "azure-foundry",
                 "deepseek", "xai", "xai-oauth", "zai", "kimi-coding", "kimi-coding-cn", "minimax", "minimax-oauth",
                 "minimax-cn", "alibaba", "qwen-oauth", "xiaomi", "tencent-tokenhub", "tencent-tokenplan", "nvidia",
                 "stepfun", "arcee", "ollama-cloud"}


@dataclass(frozen=True)
class Incident:
    name: str
    aliases: tuple[str, ...]        # provider names/slugs as routers spell them (normalised: lower, alnum only)
    hosts: tuple[str, ...]
    start: str | None               # first day request content may be exposed (UTC), None = not stated
    end: str
    what: str
    source: str


# Providers that published a notice that request content was exposed (linked from OpenRouter's Nov 22 list).
# OpenRouter didn't name the three providers it off-boarded, and Together says it wasn't one of them, so this
# table lists notices, not removals. Windows are each provider's own.
INCIDENTS = [
    Incident("Together AI", ("together", "togetherai"), ("together.xyz", "together.ai"), "2026-06-01", "2026-07-31",
             "stored prompt samples from serverless requests (MiniMax M3, GLM-5.2, Kimi K2.6; mainly 24 Jun and 4, 8, "
             "14 Jul) were downloaded by an unauthorized party, who tested the credentials in them",
             "https://www.together.ai/blog/security-event-prompt-leakage-for-requests-in-june-and-july-of-2026"),
    Incident("Phala", ("phala",), ("phala.network", "phala.com"), "2026-10-21", "2026-11-08",
             "an attacker controlled the inference server for DeepSeek V4 Flash 0731 requests routed by OpenRouter; "
             "Phala says to treat request contents as exposed",
             "https://phala.com/posts/phala-november-preliminary-incident-report"),
    Incident("NovitaAI", ("novita", "novitaai"), ("novita.ai",), "2026-05-28", "2026-11-11",
             "a routing misconfiguration forwarded some MiniMax requests to MiniMax's official API, whose security "
             "system logged and later opened URLs found in them",
             "https://novita.ai/blog/minimax-requests-privacy-notice/"),
    Incident("GMI Cloud", ("gmi", "gmicloud"), ("gmicloud.ai", "gmi-serving.com"), "2026-10-18", "2026-11-18",
             "an unauthorized party accessed a logging system that kept about three days of prompt and response "
             "content; a researcher's test keys from that period were used",
             "https://www.gmicloud.ai/en/blog/security-incident-affecting-gmi-cloud-endpoints-on-openrouter"),
    Incident("Atlas Cloud", ("atlascloud", "atlas"), ("atlascloud.ai",), None, "2026-11-21",
             "MiniMax M3, M2.7 and M3.1 Flash requests went to MiniMax's API, whose security system logged and opened "
             "URLs in them; Atlas Cloud says to treat any secret sent to those models as exposed",
             "https://www.atlascloud.ai/blog/ai-updates/security-and-privacy-commitment"),
]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def incident_for(name_or_host: str) -> Incident | None:
    n = _norm(name_or_host)
    h = agentcfg._host(name_or_host) if "." in str(name_or_host) else ""
    for inc in INCIDENTS:
        if n and n in inc.aliases:
            return inc
        if h and agentcfg._match(h, inc.hosts):
            return inc
    return None


@dataclass
class Route:
    agent: str              # Hermes | Codex | Claude Code
    label: str              # shown name (host or provider name)
    host: str
    kind: str               # router | host | unknown | first | local
    location: str
    pinned: list[tuple[str, str]] = field(default_factory=list)   # (location, provider name) from only/order
    ignored: list[str] = field(default_factory=list)
    data_collection: str = ""


def classify(url: str) -> str:
    h = agentcfg._host(url)
    if not h or ("." not in h and h != "localhost" and ":" not in h):
        return "empty"                    # unset or a placeholder (`your-base-url`)
    base = agentcfg.classify_endpoint(url)
    if base == "local":
        return "local"
    if base == "relay":
        return "router"                   # agentcfg reports relays as critical already
    if any(h == d or h.endswith("." + d) for d in ROUTERS):
        return "router"
    if agentcfg._match(h, HOSTS):
        return "host"
    if agentcfg._match(h, FIRST_PARTY):
        return "first"
    return "unknown"


def _router_name(host: str) -> str:
    for d, n in ROUTERS.items():
        if host == d or host.endswith("." + d):
            return n
    return host


# ------------------------------------------------------------------ readers (config files only)
def _hermes_routes(cfg: Path, agent: str) -> list[Route]:
    if not fsutil.is_file(cfg):
        return []
    try:
        doc = yamlmini.load(cfg.read_text(encoding="utf-8")) or {}
    except Exception:                       # noqa: BLE001 - agentcfg reports the parse error
        return []
    if not isinstance(doc, dict):
        return []
    model = doc.get("model") if isinstance(doc.get("model"), dict) else {}
    slug = str(model.get("provider") or "").strip()
    url = str(model.get("base_url") or "").strip()
    custom = doc.get("providers") if isinstance(doc.get("providers"), dict) else {}
    if not url and slug in custom and isinstance(custom[slug], dict):
        url = str(custom[slug].get("api") or custom[slug].get("base_url") or "").strip()
    r: Route | None = None
    if url:
        kind = classify(url)
        if slug in HERMES_SLUGS and HERMES_SLUGS[slug][2] == "router" and kind == "unknown":
            kind = "router"
        host = agentcfg._host(url)
        r = Route(agent, _router_name(host) if kind == "router" else host, host, kind, f"{cfg}#model.base_url")
    elif slug in HERMES_SLUGS:
        name, host, kind = HERMES_SLUGS[slug]
        r = Route(agent, name, host, kind, f"{cfg}#model.provider")
    elif slug in _HERMES_FIRST:
        r = Route(agent, slug, "", "first", f"{cfg}#model.provider")
    if r is None:
        return []
    pr = doc.get("provider_routing") if isinstance(doc.get("provider_routing"), dict) else {}
    for key in ("only", "order"):
        vals = pr.get(key)
        if isinstance(vals, str):
            vals = [vals]
        for i, v in enumerate(vals or []):
            r.pinned.append((f"{cfg}#provider_routing.{key}[{i}]", str(v)))
    ign = pr.get("ignore")
    r.ignored = [str(x) for x in ([ign] if isinstance(ign, str) else ign or [])]
    r.data_collection = str(pr.get("data_collection") or "")
    return [r]


def _codex_routes(home: Path, env: dict) -> list[Route]:
    p = Path(env.get("CODEX_HOME") or home / ".codex") / "config.toml"
    out = []
    if fsutil.is_file(p):
        try:
            import tomllib
            doc = tomllib.loads(p.read_text(encoding="utf-8"))
        except (ModuleNotFoundError, OSError, ValueError):
            doc = {}
        scopes = [("", doc)] + [(f"profiles.{k}.", v) for k, v in (doc.get("profiles") or {}).items()
                                if isinstance(v, dict)]
        provs = doc.get("model_providers") if isinstance(doc.get("model_providers"), dict) else {}
        for prefix, d in scopes:
            mp = str(d.get("model_provider") or "")
            if mp and isinstance(provs.get(mp), dict) and provs[mp].get("base_url"):
                out.append((f"{p}#{prefix}model_provider ({mp})", str(provs[mp]["base_url"])))
            for k in ("openai_base_url", "base_url"):
                if isinstance(d.get(k), str) and d[k]:
                    out.append((f"{p}#{prefix}{k}", d[k]))
    for k in ("OPENAI_BASE_URL", "OPENAI_API_BASE", "CODEX_BASE_URL"):
        if env.get(k):
            out.append((f"environment:{k}", env[k]))
    return [_route("Codex", loc, url) for loc, url in out]


def _claude_routes(home: Path, env: dict, extra: list[Path]) -> list[Route]:
    out = []
    files = [home / ".claude" / "settings.json", home / ".claude" / "settings.local.json",
             *fsutil.system(Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
                            Path("/etc/claude-code/managed-settings.json")), *extra]
    for p in files:
        if not fsutil.is_file(p):
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        e = doc.get("env") if isinstance(doc, dict) and isinstance(doc.get("env"), dict) else {}
        if e.get("ANTHROPIC_BASE_URL"):
            out.append((f"{p}#env.ANTHROPIC_BASE_URL", str(e["ANTHROPIC_BASE_URL"])))
    rx = re.compile(r"^\s*(?:export\s+|set\s+-gx\s+)?ANTHROPIC_BASE_URL\s*[= ]\s*['\"]?([^'\"\s#]+)", re.M)
    for rel in agentcfg.SHELL_FILES:
        try:
            text = (home / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out += [(str(home / rel), m.group(1)) for m in rx.finditer(text)]
    if env.get("ANTHROPIC_BASE_URL"):
        out.append(("environment:ANTHROPIC_BASE_URL", env["ANTHROPIC_BASE_URL"]))
    return [_route("Claude Code", loc, url) for loc, url in out]


def _route(agent: str, loc: str, url: str) -> Route:
    kind = classify(url)
    host = agentcfg._host(url)
    return Route(agent, _router_name(host) if kind == "router" else host, host, kind, loc)


def routes(home: Path, hermes_home: Path | None, env: dict | None = None,
           extra_claude: list[Path] = ()) -> dict[str, list[Route]]:
    """Session-history root label prefix -> the endpoints that agent's prompts go to."""
    env = dict(os.environ) if env is None else env
    out: dict[str, list[Route]] = {}
    if hermes_home is not None:
        out["Hermes"] = _hermes_routes(hermes_home / "config.yaml", "Hermes")
        prof = hermes_home / "profiles"
        if fsutil.is_dir(prof):
            try:
                for p in sorted(prof.iterdir()):
                    if p.is_dir() and not p.is_symlink():
                        out[f"Hermes@{p.name}"] = _hermes_routes(p / "config.yaml", f"Hermes (profile {p.name})")
            except OSError:
                pass
    out["Codex"] = _codex_routes(home, env)
    out["Claude Code"] = _claude_routes(home, env, list(extra_claude))
    return out


def _routes_for_root(label: str, table: dict[str, list[Route]]) -> list[Route]:
    m = re.match(r"Hermes .*\(profile (.+)\)$", label)
    if m:
        return table.get(f"Hermes@{m.group(1)}", [])
    for prefix in ("Hermes", "Codex", "Claude Code"):
        if label.startswith(prefix):
            return table.get(prefix, [])
    return []          # Cursor: its own backend, not configurable here


# ------------------------------------------------------------------ findings
def _day(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%d")


def _newest(files) -> float | None:
    best = None
    for f in files:
        try:
            m = Path(f).stat().st_mtime
        except OSError:
            continue
        best = m if best is None else max(best, m)
    return best


def _candidates(r: Route) -> list[tuple[Incident, str]]:
    """Incidents that could apply to this route, with how (direct / pinned / pool)."""
    out = []
    direct = incident_for(r.host) or (incident_for(r.label) if r.kind == "host" else None)
    if direct:
        out.append((direct, "direct"))
    if r.kind == "router":                 # `only`/`order` naming a provider with an incident
        out += [(i, "pinned") for i in (incident_for(name) for _, name in r.pinned) if i]
    return out


def sent_to_provider(secrets: list[dict], table: dict[str, list[Route]]) -> list[Finding]:
    """secrets: [{label, hash, preview, roots: {label: path}, files: {label: [paths]}, severity}] from sessions."""
    out = []
    for s in secrets:
        for root_label, root_path in sorted(s["roots"].items()):
            for r in _routes_for_root(root_label, table):
                if r.kind in ("first", "local", "empty"):
                    continue
                newest = _newest(s["files"].get(root_label, []))
                hits = []
                for inc, how in _candidates(r):
                    overlap = newest is None or inc.start is None or _day(newest) >= inc.start
                    hits.append((inc, how, overlap))
                crit = [h for h in hits if h[2]]
                sev = (Severity.CRITICAL if crit else Severity.HIGH if r.kind in ("router", "host")
                       else Severity.MEDIUM)
                where = {"router": f"the router {r.label}", "host": f"{r.label}, a third-party model host",
                         "unknown": f"{r.host}, an endpoint asca doesn't recognise (a company gateway, or a "
                                    f"reseller relay)"}[r.kind]
                detail = (f"{s['preview']} is in {root_label} ({len(s['files'].get(root_label, []))} file(s), newest "
                          f"written {_day(newest) if newest else 'unknown'}). A transcript is what the agent sent to "
                          f"its model, and {r.agent} is set to send its prompts to {where} ({r.location}). Whoever "
                          f"serves those requests saw this key: Dragos' bait keys sent in prompts were stolen at "
                          f"three inference providers and used against AWS, some from requests marked Zero Data "
                          f"Retention ({DRAGOS}).")
                if r.kind == "router" and not r.pinned:
                    detail += (" No `provider_routing.only` is set, so the router picks the provider per request "
                               "from its whole pool"
                               + (f"; OpenRouter lists providers that published incidents ({OPENROUTER})."
                                  if r.label == "OpenRouter" else "."))
                if r.data_collection.lower() == "deny":
                    detail += " `data_collection: deny` is set; Dragos found it isn't honoured everywhere."
                for inc, how, overlap in hits:
                    detail += (f" {inc.name} ({'pinned in provider_routing' if how == 'pinned' else 'this endpoint'}) "
                               f"published an incident: {inc.what}"
                               + (f", {inc.start} to {inc.end}" if inc.start else f", until {inc.end}")
                               + (f" ({inc.source})." if overlap else
                                  f"; these transcripts were last written before that window ({inc.source})."))
                detail += (" This is today's setting: if the agent used a different endpoint when these sessions "
                           "ran, the key went there instead.")
                out.append(Finding(
                    rule="secret.sent-to-provider", category="secrets", severity=sev,
                    title=f"{s['label']} from agent history was sent to {r.label}"
                          + (f" ({', '.join(sorted({h[0].name for h in crit}))} published a prompt-exposure incident)"
                             if crit else ""),
                    location=str(root_path), subject=f"{s['label']}:{s['hash'][:12]}:{r.host or r.label}",
                    detail=detail,
                    remediation=("Rotate this key: it left your machine inside a prompt, so deleting the transcript "
                                 "doesn't take it back. Check where it was used since the newest transcript date "
                                 "(AWS: CloudTrail for GetCallerIdentity, S3 listing, Secrets Manager / Parameter "
                                 "Store reads, new IAM users or Bedrock keys; Dragos saw the user agents "
                                 "`artex-agent` and `artex-judge-r121`). Then keep secrets out of what the agent "
                                 "reads (.env outside the workspace, the provider's secret filtering), and pin the "
                                 "providers you trust: Hermes `provider_routing: {only: [...], data_collection: "
                                 "deny}`, or go to the model vendor's own API.")))
    return out


def routing(table: dict[str, list[Route]]) -> list[Finding]:
    out = []
    seen = set()
    for rs in table.values():
        for r in rs:
            for loc, name in r.pinned:
                inc = incident_for(name)
                if inc and (loc, inc.name) not in seen:
                    seen.add((loc, inc.name))
                    out.append(Finding(
                        rule="agent.provider-routing", category="agent-config", severity=Severity.MEDIUM,
                        title=f"{r.agent} routing pins {inc.name}, which published a prompt-exposure incident",
                        location=loc, subject=f"{r.agent}:pin:{_norm(name)}",
                        detail=f"`{name}` is in the provider list {r.agent} sends prompts to through {r.label}. "
                               f"{inc.name}: {inc.what}"
                               + (f" ({inc.start} to {inc.end})" if inc.start else f" (until {inc.end})")
                               + f" ({inc.source}). OpenRouter's list of notices: {OPENROUTER}.",
                        remediation="If you didn't choose it on purpose, remove it from `only`/`order` (or add it to "
                                    "`ignore`), and rotate any secret your prompts carried during its window."))
            inc = incident_for(r.host) if r.host else None
            if inc and r.kind == "host":
                key = (r.location, inc.name)
                if key not in seen:
                    seen.add(key)
                    out.append(Finding(
                        rule="agent.provider-routing", category="agent-config", severity=Severity.MEDIUM,
                        title=f"{r.agent} sends its prompts straight to {inc.name}, which published a prompt-exposure "
                              f"incident",
                        location=r.location, subject=f"{r.agent}:direct:{_norm(inc.name)}",
                        detail=f"{inc.name}: {inc.what}" + (f" ({inc.start} to {inc.end})" if inc.start else
                                                             f" (until {inc.end})") + f" ({inc.source}).",
                        remediation="Rotate any secret your prompts carried during that window. Keeping the provider "
                                    "is your call; accept this finding in the baseline once you've checked."))
    return out
