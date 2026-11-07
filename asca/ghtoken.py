"""GitHub tokens your agents can use, and what they're allowed to do (opt-in, online).

Agents and the tools they call reuse whatever GitHub credentials are lying around: the
``gh`` CLI login, ``GH_TOKEN`` / ``GITHUB_TOKEN``, and ``~/.git-credentials``. A prompt
injection or a malicious skill gets the token's full rights, so a token with
``delete_repo`` or ``admin:org`` turns "the agent pushed something odd" into "the agent
deleted the repo" or "changed who's in the org".

GitHub only reveals a classic token's scopes in the ``X-OAuth-Scopes`` header of an
authenticated API response, so this check makes **one HTTPS request per distinct token**,
sent only to that token's own host (``api.github.com``, or ``https://<host>/api/v3`` for
GitHub Enterprise Server). That's why it's opt-in (``--github-token-scopes``). Tokens are
never printed: findings show only a 4-character prefix, the length and a short hash.
The macOS Keychain / OS keyring (gh's default store) isn't read; ``gh`` is never run.
"""
from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import yamlmini
from .model import Finding, Severity, redact

# Scope -> (severity, why). Anything not listed is normal for a developer token.
RISKY = {
    "delete_repo": (Severity.HIGH, "can delete repositories"),
    "admin:org": (Severity.HIGH, "can change org members, teams and settings"),
    "admin:enterprise": (Severity.HIGH, "can administer the enterprise"),
    "site_admin": (Severity.HIGH, "is a GitHub Enterprise site admin"),
    "admin:org_hook": (Severity.HIGH, "can add org webhooks that receive every org event"),
    "admin:public_key": (Severity.HIGH, "can add SSH keys to the account"),
    "admin:gpg_key": (Severity.MEDIUM, "can add signing keys to the account"),
    "admin:ssh_signing_key": (Severity.MEDIUM, "can add signing keys to the account"),
    "admin:repo_hook": (Severity.MEDIUM, "can add repo webhooks that receive pushes and code"),
    "workflow": (Severity.MEDIUM, "can change GitHub Actions workflows, which run with the repo's secrets"),
    "write:packages": (Severity.MEDIUM, "can publish packages (a supply-chain path into anyone who installs them)"),
    "delete:packages": (Severity.MEDIUM, "can delete packages"),
    "user": (Severity.MEDIUM, "can change the account profile and emails"),
    "codespace": (Severity.MEDIUM, "can create codespaces and read their secrets"),
}
# Implied parents: holding "admin:org" also covers write:org/read:org etc.; GitHub reports the parent only.
TOKEN_RX = re.compile(r"^(ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{20,}$")
ENV_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


@dataclass
class Token:
    value: str
    host: str
    sources: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return {"ghp_": "classic personal access token", "gho_": "OAuth token (gh login)", "ghu_": "GitHub App user token",
                "ghs_": "GitHub App installation token", "ghr_": "refresh token",
                "github_pat_": "fine-grained personal access token"}.get(
            next((p for p in ("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_") if self.value.startswith(p)), ""),
            "token")


def _api_base(host: str) -> str:
    return "https://api.github.com" if host in ("github.com", "api.github.com") else f"https://{host}/api/v3"


def _gh_config_dirs(home: Path, env: dict) -> list[Path]:
    if env.get("GH_CONFIG_DIR"):
        return [Path(env["GH_CONFIG_DIR"])]
    xdg = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    out = [xdg / "gh"]
    if env.get("APPDATA"):
        out.append(Path(env["APPDATA"]) / "GitHub CLI")
    return out


def discover(home: Path, hermes_home: Path | None = None, env: dict | None = None) -> list[Token]:
    env = dict(os.environ) if env is None else env
    found: dict[str, Token] = {}

    def add(value: str, host: str, source: str) -> None:
        value = value.strip()
        if not TOKEN_RX.match(value):
            return
        t = found.setdefault(value, Token(value, host or "github.com"))
        if source not in t.sources:
            t.sources.append(source)

    for d in _gh_config_dirs(home, env):
        p = d / "hosts.yml"
        try:
            doc = yamlmini.load(p.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            continue
        for host, cfg in (doc.items() if isinstance(doc, dict) else []):
            stack = [cfg]
            while stack:                       # oauth_token at host level and under users.<name>
                node = stack.pop()
                if isinstance(node, dict):
                    for k, v in node.items():
                        if k == "oauth_token" and isinstance(v, str):
                            add(v, str(host), f"{p} ({host})")
                        else:
                            stack.append(v)
    for var in ENV_VARS:
        if env.get(var):
            add(env[var], env.get("GH_HOST", "github.com") if "ENTERPRISE" in var else "github.com", f"environment:{var}")
    cred_files = [home / ".git-credentials", Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "git" / "credentials"]
    if hermes_home:
        cred_files.append(hermes_home / "home" / ".git-credentials")
    seen = set()
    for p in cred_files:
        try:
            key = p.resolve()
            if key in seen:
                continue
            seen.add(key)
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            u = urlparse(line.strip())
            if u.scheme in ("https", "http") and u.hostname and u.password:
                add(unquote(u.password), u.hostname, str(p))
            elif u.scheme in ("https", "http") and u.hostname and u.username and TOKEN_RX.match(unquote(u.username)):
                add(unquote(u.username), u.hostname, str(p))
    return list(found.values())


def fetch_headers(token: str, host: str, timeout: float = 10.0) -> tuple[int, dict[str, str]]:
    """GET <api>/user with the token. Returns (status, lower-cased headers). HTTPS only."""
    req = urllib.request.Request(_api_base(host) + "/user", headers={
        "Authorization": f"token {token}", "Accept": "application/vnd.github+json", "User-Agent": "asca"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:     # noqa: S310 (fixed https URL)
            return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}


def audit(tokens: list[Token], stats: dict, fetch=None) -> list[Finding]:
    fetch = fetch or fetch_headers
    stats["github_tokens"] = len(tokens)
    out: list[Finding] = []
    for t in tokens:
        tid = redact(t.value)
        loc = t.sources[0]
        also = f" Also found in: {', '.join(t.sources[1:])}." if len(t.sources) > 1 else ""
        try:
            status, h = fetch(t.value, t.host)
        except (OSError, ValueError) as exc:
            out.append(Finding(rule="github.token-unchecked", category="github", severity=Severity.LOW,
                               title=f"Couldn't check a GitHub token's scopes ({t.host})", location=loc, subject=tid,
                               detail=f"{t.kind} {tid}: {type(exc).__name__}: {str(exc)[:120]}.{also}",
                               remediation="Check network access to the GitHub API; the check retries next run."))
            continue
        if status == 401:
            out.append(Finding(
                rule="github.token-invalid", category="github", severity=Severity.LOW,
                title=f"A stored GitHub token no longer works ({t.host})", location=loc, subject=tid,
                detail=f"{t.kind} {tid} was rejected (HTTP 401): revoked or expired, but still stored.{also}",
                remediation="Delete it from where it's stored, so it isn't mistaken for a live credential."))
            continue
        if status >= 400:
            out.append(Finding(rule="github.token-unchecked", category="github", severity=Severity.LOW,
                               title=f"Couldn't check a GitHub token's scopes (HTTP {status})", location=loc,
                               subject=tid, detail=f"{t.kind} {tid}.{also}",
                               remediation="Retry later; rate limits or SSO enforcement can cause this."))
            continue
        scopes = h.get("x-oauth-scopes")
        if scopes is None:
            out.append(Finding(
                rule="github.token-unchecked", category="github", severity=Severity.INFO,
                title=f"Fine-grained GitHub token: permissions aren't visible to asca ({t.host})", location=loc,
                subject=tid, detail=f"{t.kind} {tid}. GitHub doesn't report fine-grained permissions in API "
                                    f"responses.{also}",
                remediation="Review it at github.com → Settings → Developer settings → Fine-grained tokens: limit "
                            "it to the repos the agent needs, no Administration permission."))
        else:
            have = {s.strip() for s in scopes.split(",") if s.strip()}
            risky = sorted((RISKY[s][0], s) for s in have if s in RISKY)
            if risky:
                sev = max(r[0] for r in risky)
                out.append(Finding(
                    rule="github.token-scope", category="github", severity=sev,
                    title=f"GitHub token has more power than an agent needs: {', '.join(s for _, s in risky)}",
                    location=loc, subject=f"{tid}:{','.join(sorted(have))}",
                    detail=f"{t.kind} {tid} on {t.host}. "
                           + "; ".join(f"`{s}` {RISKY[s][1]}" for _, s in risky)
                           + f". All scopes: {', '.join(sorted(have)) or '(none)'}. Any agent, skill or MCP server "
                             f"that can read this token gets these rights.{also}",
                    remediation="Replace it with a token that has only what the agent uses (usually `repo`, or a "
                                "fine-grained token for specific repos), then revoke this one. For the gh CLI: "
                                "`gh auth refresh --remove-scopes delete_repo,admin:org` (adjust to the list)."))
        exp = h.get("github-authentication-token-expiration")
        if t.value.startswith("ghp_") and not exp:
            out.append(Finding(
                rule="github.token-no-expiry", category="github", severity=Severity.LOW,
                title="Classic GitHub token never expires", location=loc, subject=f"{tid}:no-expiry",
                detail=f"{t.kind} {tid}. A leaked token without an expiry date works until someone notices.{also}",
                remediation="Recreate it with an expiry (90 days or less), or switch to a fine-grained token."))
    return out
