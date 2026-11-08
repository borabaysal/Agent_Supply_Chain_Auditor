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
        r"\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=.]{24,})"),  # also JSON: "api_key": "…"
     Severity.MEDIUM, "Hard-coded credential assignment"),
]

_PLACEHOLDER = re.compile(r"(?i)(x{6,}|your[_-]|example|placeholder|changeme|dummy|redacted|<|\$\{|\{\{|\*{4,}|test(?:ing)?_?key)")

TEXT_SUFFIX_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl",
                    ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".db", ".sqlite", ".mp3", ".mp4", ".woff",
                    ".woff2", ".ttf", ".parquet", ".lock"}
MAX_FILE_BYTES = 512 * 1024


def iter_line_secrets(line: str, seen: set[str]):
    """Yield ``(rule, severity, label, value, end)`` for each distinct secret on one line.

    ``seen`` holds values already reported by the caller; overlapping values are skipped
    (``sk-or-v1-…`` also satisfies the broader OpenAI pattern and the more specific rule,
    listed first, wins). Provider-key patterns run first, then passwords typed into commands
    (PGPASSWORD=, sshpass -p, user:pass@host, Bearer …), and the generic assignment rule is a
    fallback for lines nothing else explained. Callers must redact ``value`` before it
    reaches a Finding.
    """
    specific_hit = False

    def fresh(value: str) -> bool:
        nonlocal specific_hit
        if any(value in s or s in value for s in seen):
            specific_hit = True
            return False
        seen.add(value)
        specific_hit = True
        return True

    for rule, rx, sev, label in PATTERNS:
        if rule == "secret.generic-assignment":
            for hit in iter_command_secrets(line):
                if fresh(hit[3]):
                    yield hit
            if specific_hit:
                continue
        for m in rx.finditer(line):
            value = m.group(1) if m.groups() else m.group(0)
            if rule != "secret.private-key" and _PLACEHOLDER.search(value):
                continue
            if rule == "secret.generic-assignment" and _looks_low_entropy(value):
                continue
            if rule != "secret.private-key" and _looks_like_words(value):
                continue
            if fresh(value):
                yield rule, sev, label, value, m.end()


def scan_text(text: str, location: str, *, context: str) -> list[Finding]:
    found: list[Finding] = []
    seen: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for rule, sev, label, value, _end in iter_line_secrets(line, seen):
            preview = "" if rule == "secret.private-key" else f" ({redact(value)})"
            found.append(Finding(
                rule=rule, category="secrets", severity=sev,
                title=f"{label} in {context}", location=f"{location}:{lineno}", subject=label,
                detail=f"Literal secret material{preview}. Anything that reads this file — backups, "
                       f"git history, an agent's context — gets the credential.",
                remediation="Rotate the credential, move it to an env file with 0600 permissions "
                            "(or a secrets manager), and reference it by variable name.",
            ))
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


# ---------------------------------------------------------------- passwords typed into commands
# Coding agents save the literal command they were allowed to run ("don't ask again"), and
# transcripts keep every command. Provider keys are caught by PATTERNS above; these catch the
# passwords and tokens that have no recognisable prefix (Apiiro, Nov 2026: 743 of 1,379 leaked
# secrets in Claude Code allow rules were passwords/tokens next to a host, mostly DB logins).
_V = r"""(['"]?)([^\s'"`;|&<>]{3,128})\1"""          # optional quotes, then the value (group 2 of the pair)
CMD_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("env", re.compile(r"\b(?:PGPASSWORD|MYSQL_PWD|REDISCLI_AUTH|SSHPASS|MONGO(?:DB)?_PASSWORD)\s*=\s*" + _V),
     "Database password in a command"),
    ("mysql", re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n|;&]*?\s-p(?!\s)" + _V),
     "MySQL password in a command (-p)"),
    ("opt", re.compile(r"(?<![\w-])--password[= ](?!-)" + _V), "Password option in a command (--password)"),
    ("sshpass", re.compile(r"\bsshpass\s+-p\s*" + _V), "SSH password in a command (sshpass -p)"),
    ("curl", re.compile(r"\bcurl\b[^\n|;&]*?\s(?:-u|--user)\s*(['\"]?)[^\s:'\"]{1,64}:([^\s'\"`;|&<>]{3,128})\1"),
     "HTTP basic-auth password in a command (curl -u)"),
    ("url", re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|https?|ftps?|smtps?|ldaps?)"
                       r"://[^\s:/@'\"<>]{1,64}:()([^\s@/'\"<>]{3,128})@"), "Password in a connection URL"),
    ("bearer", re.compile(r"(?i)\bbearer\s+()([A-Za-z0-9._~+/-]{20,}=*)"), "Bearer token in a command"),
]
_CMD_FAKE = {"password", "passwd", "pass", "pwd", "secret", "changeme", "mypassword", "yourpassword", "your_password",
             "password123", "pass123", "secret123", "mysecretpassword", "foo", "bar", "foobar", "test", "testing",
             "example", "admin", "root", "postgres", "mysql", "user", "username", "guest", "token", "hunter2",
             "xxx", "xxxx", "abc123", "123456", "12345678", "qwerty", "letmein", "pa55word", "p@ssw0rd", "dbpass",
             "db_password", "db_pass", "mypass", "yourpass", "apikey", "api_key", "your_token", "mytoken", "access_token",
             "tok", "pat", "key", "pw", "pwd123", "s3cret", "secret!", "passw0rd", "pa$$word"}
_HOST_RXS = (re.compile(r"(?:^|\s)(?:-h|--host[= ]|-H(?=\s+\d))\s*['\"]?([A-Za-z0-9.\-]+|\[[0-9a-f:]+\])"),
             re.compile(r"\bhost\s*=\s*['\"]?([A-Za-z0-9.\-]+)"),
             re.compile(r"[@/]([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)\b"))
PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".home", ".localdomain", ".test", ".example", ".invalid",
                    ".localhost", ".svc", ".cluster.local")
DOC_HOSTS = ("example.com", "example.org", "example.net")


def classify_host(host: str | None) -> str:
    """public | private (loopback, RFC1918, link-local, *.local, docker names, documentation hosts) | none"""
    if not host:
        return "none"
    h = host.strip("[]").lower().rstrip(".")
    if h in ("localhost", "host.docker.internal") or h.endswith(PRIVATE_SUFFIXES) or "." not in h and ":" not in h:
        return "private"            # bare names (db, postgres, redis) are compose/k8s service names
    if any(h == d or h.endswith("." + d) for d in DOC_HOSTS):
        return "private"
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return "private" if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified) else "public"
    except ValueError:
        return "public"


def _cmd_host(line: str, kind: str, m: re.Match) -> str | None:
    if kind == "url":
        hm = re.match(r"([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])", line[m.end():])
        return hm.group(1) if hm else None
    for rx in _HOST_RXS:
        hm = rx.search(line)
        if hm:
            return hm.group(1)
    return None


def _fake_value(v: str) -> bool:
    """Placeholders, variables and benchmarked look-alikes that aren't real passwords."""
    from urllib.parse import unquote
    lv = v.lower()
    if lv in _CMD_FAKE or _PLACEHOLDER.search(v) or v[0] in "$%{(*<[" or "$(" in v:
        return True
    if "\\" in v or "[^" in v or "," in v:                      # regex/sed fragments, port lists
        return True
    if any(c.isspace() for c in unquote(v)):                    # a%20secret: a phrase, not a password
        return True
    if re.fullmatch(r"[*x.\-_]+|[A-Z][A-Z0-9_]*", v):          # ****, xxx, DB_PASSWORD (a variable name)
        return True
    return bool(re.fullmatch(r"(?i)(my|your|the|some)?_?(db|database|mysql|pg|redis|ssh|root|admin|user)?_?"
                             r"(pass(word|wd)?|pwd|secret|token)s?_?(here|123)?", v))


def iter_command_secrets(line: str):
    """Yield ``(rule, severity, label, value, end)`` for passwords/tokens typed into commands."""
    for kind, rx, label in CMD_PATTERNS:
        for m in rx.finditer(line):
            value = m.group(2)
            # bearer values have no prefix: require some randomness (JWTs look like a.b.c, so not _looks_low_entropy)
            if _fake_value(value) or (kind == "bearer" and (len(set(value)) < 10 or _looks_like_words(value)
                                                             or not re.search(r"\d", value))):
                continue
            if kind == "url" and value.lower() in ("x-oauth-basic", ""):
                continue
            host = _cmd_host(line, kind, m)
            if kind == "url" and not host:
                continue                # "https://user:tok@" in prose: no host, nothing to log in to
            where = classify_host(host)
            if kind in ("env", "mysql", "opt") and where == "none":
                where = "private"       # no host given: local socket
            if where == "private":
                yield "secret.command-password-private", Severity.LOW, label + " (local or private host)", value, m.end()
            else:
                yield "secret.command-password", Severity.HIGH, label, value, m.end()


RULE_SEVERITY = {"secret.command-password": Severity.HIGH, "secret.command-password-private": Severity.LOW,
                 "secret.generic-assignment": Severity.MEDIUM}


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
