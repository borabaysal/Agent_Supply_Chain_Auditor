"""Developer credential files: what a credential stealer would take from this machine.

The agent-framework PyPI stealer (Elastic Security Labs, Nov 2026) collected the Azure CLI token cache
(``~/.azure``), ``pip.conf``, ``.npmrc``, ``.netrc``, ``.git-credentials``, Docker ``config.json`` and Hugging
Face tokens. asca's key scan covers agent folders; this reads those developer files as text (nothing is run)
and reports, per file:

- ``devcred.plaintext`` (low): the file holds a usable credential in plain text, e.g. an npm ``_authToken``, a
  ``.pypirc``/``.netrc`` password, ``user:pass@`` in a pip index URL, Docker ``auths`` with no credential store,
  a plaintext Azure token cache, a Hugging Face token file, ``.git-credentials`` entries. Values are never
  shown, only ``prefix… (len, sha256:tag)``. Low because these files are where those tools keep credentials by
  default; the point is knowing what's exposed and moving long-lived ones to a keychain or an env reference.
- ``secret.file-permissions`` (medium/high): the file is readable by group or everyone (POSIX).
- ``devcred.summary`` (info): one line listing everything a stealer would get.

References such as ``${NPM_TOKEN}`` and ``%(...)`` aren't credentials and aren't counted.
"""
from __future__ import annotations

import configparser
import json
import os
import re
from pathlib import Path

from . import fsutil, secrets
from .model import Finding, Severity, redact

_REF = re.compile(r"^\$\{[^}]+\}$|^%\([^)]+\)s?$|^\$[A-Z_][A-Z0-9_]*$")
_URL_CRED = re.compile(r"[a-z][a-z0-9+.-]*://([^/\s:@]*):([^/\s@]+)@([^/\s:]+)", re.I)

FIX = {
    "npm token": "Reference it instead: `//registry.npmjs.org/:_authToken=${NPM_TOKEN}` with the token in your "
                 "secret manager or CI secrets; use a granular token with an expiry (`npm token list` shows yours).",
    "PyPI token": "Use Trusted Publishing from CI, or store the token in your keychain (twine reads it via "
                  "`keyring`) and delete the password line; use a project-scoped token.",
    "package index password": "Keep the index password in your keychain (pip supports `keyring`) or pass "
                              "PIP_INDEX_URL only for the install, not in pip.conf.",
    "netrc password": "Move these logins to a credential helper or keychain and delete the password entries.",
    "Docker registry credentials": "Set a credential store (`\"credsStore\": \"osxkeychain\"`, `desktop`, `wincred` "
                                   "or `pass`), then `docker logout` and `docker login` again so the base64 "
                                   "`auth` entries disappear.",
    "Azure CLI token cache": "Run `az logout` where you don't need a session (agent and build hosts especially) "
                             "and use a managed identity or short-lived federated credentials for automation.",
    "Hugging Face token": "Use a fine-grained, read-only token, and `huggingface-cli logout` on machines that "
                          "don't need it.",
    "GitHub token": "Switch git to a keychain helper (`git config --global credential.helper osxkeychain`, "
                    "`manager` on Windows, `libsecret` on Linux), re-authenticate, then delete the file.",
    "git credentials": "Switch git to a keychain helper (`osxkeychain`, `manager`, `libsecret`), "
                       "re-authenticate, then delete the file.",
}


def _first(*paths) -> list[Path]:
    return [Path(p) for p in paths if p]


def targets(home: Path, env: dict | None = None) -> list[tuple[str, Path]]:
    """[(kind, path)] of developer credential files to read; missing ones are skipped later."""
    env = dict(os.environ) if env is None else env
    xdg_cfg = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    xdg_cache = Path(env.get("XDG_CACHE_HOME") or home / ".cache")
    hf_home = Path(env["HF_HOME"]) if env.get("HF_HOME") else xdg_cache / "huggingface"
    docker = Path(env["DOCKER_CONFIG"]) if env.get("DOCKER_CONFIG") else home / ".docker"
    azure = Path(env["AZURE_CONFIG_DIR"]) if env.get("AZURE_CONFIG_DIR") else home / ".azure"
    out = [("npmrc", p) for p in _first(env.get("NPM_CONFIG_USERCONFIG") or env.get("npm_config_userconfig"),
                                        home / ".npmrc")]
    out += [("pypirc", home / ".pypirc")]
    out += [("pipconf", p) for p in _first(env.get("PIP_CONFIG_FILE"), xdg_cfg / "pip" / "pip.conf",
                                           home / ".pip" / "pip.conf",
                                           home / "Library" / "Application Support" / "pip" / "pip.conf",
                                           Path(env["APPDATA"]) / "pip" / "pip.ini" if env.get("APPDATA") else None)]
    out += [("netrc", p) for p in _first(env.get("NETRC"), home / ".netrc", home / "_netrc")]
    out += [("docker", docker / "config.json")]
    out += [("azure", azure / n) for n in ("msal_token_cache.json", "accessTokens.json",
                                           "service_principal_entries.json")]
    out += [("hf", p) for p in _first(env.get("HF_TOKEN_PATH"), hf_home / "token", home / ".huggingface" / "token")]
    out += [("gitcreds", p) for p in (home / ".git-credentials", xdg_cfg / "git" / "credentials")]
    seen, uniq = set(), []
    for kind, p in out:
        k = os.path.normcase(os.path.normpath(str(p)))
        if k not in seen:
            seen.add(k)
            uniq.append((kind, p))
    return uniq


def _plain(v: str) -> bool:
    v = v.strip().strip("'\"")
    return bool(v) and not _REF.match(v)


def _npmrc(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if re.search(r"(^|:)(_authToken|_auth|_password)$", k) and _plain(v):
            out.append(("npm token", v.strip("'\"")))
    return out


def _pypirc(text: str) -> list[tuple[str, str]]:
    cp = configparser.RawConfigParser()
    cp.read_string(text)
    return [("PyPI token", cp.get(s, "password").strip()) for s in cp.sections()
            if cp.has_option(s, "password") and _plain(cp.get(s, "password"))]


def _urls(text: str, label: str) -> list[tuple[str, str]]:
    return [(label, m.group(2)) for m in _URL_CRED.finditer(text) if _plain(m.group(2))]


def _netrc(text: str) -> list[tuple[str, str]]:
    toks = re.sub(r"#[^\n]*", " ", text).split()
    return [("netrc password", toks[i + 1]) for i, t in enumerate(toks[:-1]) if t == "password" and _plain(toks[i + 1])]


def _docker(text: str) -> list[tuple[str, str]]:
    d = json.loads(text)
    if not isinstance(d, dict):
        return []
    helpers = d.get("credHelpers") if isinstance(d.get("credHelpers"), dict) else {}
    out = []
    for reg, e in (d.get("auths") or {}).items() if isinstance(d.get("auths"), dict) else []:
        if not isinstance(e, dict) or reg in helpers:
            continue
        for key in ("auth", "identitytoken", "registrytoken"):
            if isinstance(e.get(key), str) and e[key].strip():
                out.append(("Docker registry credentials", e[key].strip()))
    return out


def _gitcreds(text: str) -> list[tuple[str, str]]:
    out = []
    for m in _URL_CRED.finditer(text):
        if _plain(m.group(2)):
            out.append(("GitHub token" if m.group(3).lower().endswith("github.com") else "git credentials", m.group(2)))
    return out


PARSERS = {"npmrc": _npmrc, "pypirc": _pypirc, "pipconf": lambda t: _urls(t, "package index password"),
           "netrc": _netrc, "docker": _docker, "gitcreds": _gitcreds}


def audit(home: Path, stats: dict, env: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    exposed: list[str] = []
    for kind, path in targets(home, env):
        if not fsutil.is_file(path):
            continue
        label = f"~/{path.relative_to(home).as_posix()}" if str(path).startswith(str(home)) else str(path)
        out += secrets.audit_permissions(path, label=label)
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        if kind == "azure":
            creds = [("Azure CLI token cache", text.strip())] if text.strip() not in ("", "{}", "[]") else []
        elif kind == "hf":
            creds = [("Hugging Face token", text.strip())] if text.strip() else []
        else:
            try:
                creds = PARSERS[kind](text)
            except (ValueError, configparser.Error) as exc:
                out.append(Finding(
                    rule="scanner.parse-error", category="scanner", severity=Severity.LOW,
                    title=f"{label} couldn't be parsed", location=str(path), subject=kind,
                    detail=f"{type(exc).__name__}: {exc}"[:200] + ". Not checked for plain-text credentials.",
                    remediation="Fix the file so it can be audited."))
                continue
        if not creds:
            continue
        what = creds[0][0]
        n = len(creds)
        shown = "Azure tokens (a JSON cache)" if kind == "azure" else \
            ", ".join(redact(v) for _, v in creds[:3]) + (f" and {n - 3} more" if n > 3 else "")
        exposed.append(f"{what} ({label})")
        out.append(Finding(
            rule="devcred.plaintext", category="secrets", severity=Severity.LOW,
            title=f"{what} stored in plain text in {label}" + (f" ({n} entries)" if n > 1 else ""),
            location=str(path), subject=f"{kind}:{what}",
            detail=f"{shown}. Any process running as you can read it; the agent-framework PyPI stealer "
                   f"collected exactly these files (Elastic, Nov 2026).",
            remediation=FIX.get(what, "Move it to a keychain or an environment reference.")))
    stats["dev_credential_files"] = len(exposed)
    if exposed:
        out.append(Finding(
            rule="devcred.summary", category="secrets", severity=Severity.INFO,
            title=f"A credential stealer running as you would get {len(exposed)} developer credential file(s)",
            location=str(home), subject="devcred.summary",
            detail="; ".join(exposed) + ". Rotate the ones you rely on after any compromised package install.",
            remediation="Start with long-lived publish tokens (npm, PyPI) and cloud sessions."))
    return out
