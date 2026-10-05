"""Secret detection (patterns + file permissions). Never returns raw secret values."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .model import Finding, Severity, redact

# (rule id, regex, severity, label). Group 1 (if present) is the secret itself.
PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    ("secret.private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
     Severity.CRITICAL, "Private key"),
    ("secret.aws-access-key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), Severity.HIGH, "AWS access key id"),
    ("secret.github-token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
     Severity.HIGH, "GitHub token"),
    ("secret.anthropic-key", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})"), Severity.HIGH, "Anthropic API key"),
    ("secret.openrouter-key", re.compile(r"\b(sk-or-v1-[a-f0-9]{48,})"), Severity.HIGH, "OpenRouter API key"),
    ("secret.openai-key", re.compile(r"\b(sk-(?:proj-|svcacct-)?(?!ant-|or-v1-)[A-Za-z0-9_-]{32,})"), Severity.HIGH,
     "OpenAI-style API key"),
    ("secret.slack-token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})"), Severity.HIGH, "Slack token"),
    ("secret.telegram-bot-token", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"), Severity.HIGH,
     "Telegram bot token"),
    ("secret.google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), Severity.HIGH, "Google API key"),
    ("secret.stripe-live-key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})"), Severity.HIGH, "Stripe live key"),
    ("secret.hf-token", re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"), Severity.HIGH, "Hugging Face token"),
    ("secret.eth-private-key", re.compile(
        r"(?i)(?:private[_-]?key|priv[_-]?key|wallet[_-]?key)\s*[:=]\s*['\"]?(0x[a-f0-9]{64})\b"),
     Severity.CRITICAL, "Wallet private key"),
    ("secret.generic-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
        r"\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=.]{24,})"),
     Severity.MEDIUM, "Hard-coded credential assignment"),
]

_PLACEHOLDER = re.compile(r"(?i)(x{6,}|your[_-]|example|placeholder|changeme|dummy|redacted|<|\$\{|\{\{|\*{4,}|test(?:ing)?_?key)")

TEXT_SUFFIX_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl",
                    ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".db", ".sqlite", ".mp3", ".mp4", ".woff",
                    ".woff2", ".ttf", ".parquet", ".lock"}
MAX_FILE_BYTES = 512 * 1024


def scan_text(text: str, location: str, *, context: str) -> list[Finding]:
    found: list[Finding] = []
    seen: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        specific_hit = False
        for rule, rx, sev, label in PATTERNS:
            # the generic rule is a fallback: skip it when a specific rule already explained the line
            if rule == "secret.generic-assignment" and specific_hit:
                continue
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if rule != "secret.private-key" and _PLACEHOLDER.search(value):
                    continue
                if rule == "secret.generic-assignment" and _looks_low_entropy(value):
                    continue
                if rule != "secret.private-key" and _looks_like_words(value):
                    continue
                # one finding per secret value: "sk-or-v1-…" also satisfies the broader
                # OpenAI pattern, and the more specific rule (listed first) wins.
                if any(value in s or s in value for s in seen):
                    specific_hit = True
                    continue
                seen.add(value)
                preview = "" if rule == "secret.private-key" else f" ({redact(value)})"
                found.append(Finding(
                    rule=rule, category="secrets", severity=sev,
                    title=f"{label} in {context}", location=f"{location}:{lineno}", subject=label,
                    detail=f"Literal secret material{preview}. Anything that reads this file — backups, "
                           f"git history, an agent's context — gets the credential.",
                    remediation="Rotate the credential, move it to an env file with 0600 permissions "
                                "(or a secrets manager), and reference it by variable name.",
                ))
                specific_hit = True
    return found


_KNOWN_PREFIX = re.compile(r"^(sk-ant-(?:api\d\d-|admin\d\d-)?|sk-or-v1-|sk-proj-|sk-svcacct-|sk-|ghp_|github_pat_|"
                           r"xox[abprs]-|hf_|AIza|(?:sk|rk)_live_)")


def _looks_like_words(v: str) -> bool:
    """Fixture keys such as ``sk-ant-local-dummy-value`` are lowercase words joined by
    separators; real keys are random base62/hex and virtually always mix case or digits."""
    body = _KNOWN_PREFIX.sub("", v)
    return bool(re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", body))


def _looks_low_entropy(v: str) -> bool:
    if len(set(v)) < 8:
        return True
    # code references, not literals: settings.bybit_api_secret, os.environ.get, self.cfg.token
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\.?", v):
        return True
    # identifiers like "some_function_name_here" are not secrets
    return bool(re.fullmatch(r"[a-z_]+", v)) or bool(re.fullmatch(r"[A-Z_]+", v))


def scan_file(path: Path, *, context: str, display: str | None = None) -> list[Finding]:
    try:
        if path.suffix.lower() in TEXT_SUFFIX_SKIP or path.stat().st_size > MAX_FILE_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:4096]:
        return []
    return scan_text(data.decode("utf-8", "replace"), display or str(path), context=context)


SENSITIVE_FILES = [".env", "auth.json", ".git-credentials", ".netrc", "credentials.json", ".credentials.json",
                   "id_rsa", "id_ed25519", "id_ecdsa"]


def audit_permissions(path: Path, *, label: str) -> list[Finding]:
    """Flag credential files readable by group/other (POSIX only)."""
    if os.name != "posix" or not path.exists() or path.is_symlink():
        return []
    try:
        mode = path.stat().st_mode
    except OSError:
        return []
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        world = bool(mode & stat.S_IROTH)
        return [Finding(
            rule="secret.file-permissions", category="secrets",
            severity=Severity.HIGH if world else Severity.MEDIUM,
            title=f"{label} is readable by {'everyone' if world else 'group'}",
            location=str(path), subject=label,
            detail=f"Mode {stat.filemode(mode)} ({oct(mode & 0o777)}). Other local users or processes "
                   f"(including other containers sharing the volume) can read the credentials.",
            remediation=f"chmod 600 {path}",
        )]
    return []
