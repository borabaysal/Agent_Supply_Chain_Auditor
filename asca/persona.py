"""Hermes persona and memory tampering (``persona.*``) and who can command the agent (``gateway.*``).

Grounding: Carbonato (ThreatDown, Sep 2026). After breaking into a Docker host, the botnet installs
Hermes Agent *unchanged* and overwrites ``SOUL.md`` with a 39-line persona, "GH0ST", that takes
tasks over Telegram, keeps itself installed and prioritises collecting AI API keys and credentials.
Nothing in the code changes, so code-integrity checks see a clean install.

What is read (text only, nothing runs):
- ``$HERMES_HOME/SOUL.md``, ``memories/*.md`` and the same under ``profiles/*/``.
- Hermes ``.env`` files: only variable *names*, plus the values of the access switches
  (``*_ALLOW_ALL_USERS``, ``*_ALLOWED_USERS``, ``*_ALLOWED_CHATS``). Other values are never read
  into findings.

The skill-content rules alone don't catch a hijacked persona (they look for payloads and
hidden text; a GH0ST-style persona is plain instructions), so persona files get their own rules:

| Rule | What the text tells the agent | Severity |
|---|---|---|
| persona.known-malware | names the Carbonato persona `GH0ST` (ThreatDown IOC) | critical |
| persona.c2 | two or more of the signals below, at least one of harvest / persistence / conceal | critical |
| persona.credential-harvest | collect / harvest / exfiltrate API keys, credentials, tokens, SSH keys, wallets | high |
| persona.persistence | maintain persistence, reinstall itself when removed | high |
| persona.conceal | hide what it does from the local user | high |
| persona.no-limits | act without ethical or safety constraints, never refuse | medium |
| persona.remote-tasking | take tasks or orders from a chat channel or "operator" | low (normal for many setups; counts toward persona.c2) |
| gateway.allow-all-users | ``*_ALLOW_ALL_USERS=true`` or ``*`` in an allow list: anyone who finds the bot can command the agent | high |
| gateway.known-malware-env | ``CARBONATO_API_KEY``, ``GH0ST_C2`` (ThreatDown IOCs) | critical |

Negated or prohibited phrasing ("never collect credentials", items under a "Never do" heading)
doesn't count. The skill-content rules still run on these files for hidden text and payloads.
"""
from __future__ import annotations

import re
from pathlib import Path

from .model import Finding, Severity

THREATDOWN = "https://www.threatdown.com/blog/carbonato/"
MAX_READ = 512 * 1024

_CHANNEL = r"(?:telegram|discord|slack|whatsapp|signal|matrix|irc|webhook|c2|command[- ]and[- ]control|operator)"
RULES: list[tuple[str, Severity, re.Pattern, str]] = [
    ("credential-harvest", Severity.HIGH, re.compile(
        r"\b(?:collect(?:ing)?|harvest(?:ing)?|gather(?:ing)?|exfiltrat\w*|steal(?:ing)?|dump(?:ing)?|grab(?:bing)?|"
        r"scrap(?:e|ing)|hunt(?:ing)?\s+for|look(?:ing)?\s+for|prioriti[sz]\w*\s+(?:the\s+)?(?:collection|theft))\b"
        r"[^.\n]{0,80}?\b(?:api[ _-]?keys?|credentials?|passwords?|access\s+tokens?|tokens|ssh\s+keys?|private\s+keys?|"
        r"seed\s+phrases?|mnemonics?|wallets?|cookies|secrets)\b", re.I),
     "tells the agent to collect credentials"),
    ("persistence", Severity.HIGH, re.compile(
        r"\b(?:maintain|ensure|establish|keep|preserve)\w*\s+(?:your\s+|its\s+)?persisten(?:ce|t)\b|"
        r"\b(?:re-?install|restore|re-?pull|re-?deploy|bring\s+back)\w*\b[^.\n]{0,60}\b(?:if|when|whenever)\b[^.\n]{0,60}"
        r"\b(?:delete|remove|disappear|kill|stop)\w*|"
        r"\b(?:if|when|whenever)\b[^.\n]{0,60}\b(?:deleted|removed|killed|stopped|disappears?|wiped)\b[^.\n]{0,30}"
        r"\b(?:re-?install|restore|re-?deploy|re-?pull|bring\s+back|restart)\w*\s+(?:yourself|itself|the\s+agent|"
        r"this\s+agent|the\s+implant)\b", re.I),
     "tells the agent to keep itself installed"),
    ("conceal", Severity.HIGH, re.compile(
        r"\b(?:never|don'?t|do\s+not)\s+(?:tell|inform|alert|notify|let)\s+(?:the\s+)?(?:local\s+)?(?:user|owner|human|admin)\w*"
        r"\s+(?:what|about|that)\s+you\b|\bhide\s+(?:your\s+|all\s+)?(?:activity|actions|tracks|presence)\b|"
        r"\bwithout\s+the\s+(?:user|owner)\s+(?:noticing|knowing)\b", re.I),
     "tells the agent to hide what it does from the user"),
    ("no-limits", Severity.MEDIUM, re.compile(
        r"\bwithout\s+(?:any\s+)?(?:ethical|moral|safety)\s+(?:constraints?|restrictions?|limits?|limitations?|"
        r"considerations?|concerns?|guardrails?)\b|\bwithout\s+(?:any\s+)?(?:refus\w+|guardrails)\b|\bnever\s+refuse\b|"
        r"\bignore\s+(?:all\s+|any\s+|your\s+)?(?:safety|ethic\w*)\b", re.I),
     "removes the agent's ethical or safety limits"),
    ("remote-tasking", Severity.LOW, re.compile(
        r"\b(?:execute|carry\s+out|run|perform|follow|obey|complete|act\s+on)\b[^.\n]{0,60}\b(?:tasks?|commands?|instructions?|"
        r"orders?)\b[^.\n]{0,60}\b" + _CHANNEL + r"\b|\b(?:tasks?|commands?|orders?|instructions?)\s+(?:from|via|over|"
        r"through|sent\s+(?:to\s+you\s+)?(?:via|over|in|on))\s+(?:the\s+)?" + _CHANNEL + r"\b", re.I),
     "takes tasks from a chat channel or an operator"),
]
KNOWN_MALWARE = re.compile(r"\bGH0ST\b")
MALWARE_ENV = {"CARBONATO_API_KEY", "GH0ST_C2", "FSOCIETY_DISABLE_TUNNEL"}
# Persona rules fire on instructions to the agent, not on prose that describes an attack ("a stealer
# collects credentials", "worth stealing"): the verb must start a sentence or list item, or follow
# "you"/"your job is to"/"prioritise"/"always"…
_IMPERATIVE_LEAD = re.compile(
    r"(?:^\s*(?:[-*+>]|\d+[.)])?\s*|[.!?:;]\s+|\n\s*(?:[-*+>]|\d+[.)])?\s*|\b(?:you\s+(?:must|should|will|shall|always|need\s+to|are\s+to|"
    r"have\s+to)?|your\s+(?:job|goal|task|mission|purpose|priority)\s+is\s+to|always|also|then|first,?|and|"
    r"prioriti[sz]e|focus\s+on|make\s+sure\s+(?:to|you)|be\s+sure\s+to|remember\s+to|keep)\s+)$", re.I)
_NEEDS_IMPERATIVE = {"credential-harvest", "persistence"}
_NEGATION = re.compile(r"\b(?:never|not|don'?t|no|avoid|refuse\s+to|must\s+not|shouldn'?t|forbidden|prohibited)\b"
                       r"[^.\n]{0,40}$", re.I)
_PROHIBITION_HEADING = re.compile(r"^#{1,6}\s*.*\b(?:never|don'?t|do\s+not|forbidden|prohibited|red\s+flags?|"
                                  r"pitfalls?|anti-?patterns?|must\s+not|avoid)\b", re.I)


def targets(home: Path) -> list[tuple[Path, str]]:
    roots = [(home, "")]
    try:
        roots += [(p, f"profile `{p.name}` ") for p in sorted((home / "profiles").iterdir())
                  if p.is_dir() and not p.is_symlink()]
    except OSError:
        pass
    out: list[tuple[Path, str]] = []
    for root, label in roots:
        if (root / "SOUL.md").is_file():
            out.append((root / "SOUL.md", f"{label}persona (SOUL.md)"))
        mem = root / "memories"
        if mem.is_dir():
            out += [(p, f"{label}memory ({p.name})") for p in sorted(mem.glob("*.md"))
                    if p.is_file() and not p.is_symlink()]
    return out


def _negated(text: str, pos: int) -> bool:
    start = text.rfind("\n", 0, pos) + 1
    return bool(_NEGATION.search(text[start:pos]))


def _under_prohibition(text: str, pos: int) -> bool:
    for line in reversed(text[:pos].splitlines()):
        if line.lstrip().startswith("#"):
            return bool(_PROHIBITION_HEADING.match(line.strip()))
    return False


def _line(text: str, pos: int) -> tuple[int, str]:
    n = text.count("\n", 0, pos) + 1
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    return n, text[s:e if e != -1 else len(text)].strip()[:160]


def scan_text(text: str) -> list[tuple[str, Severity, int, str, str]]:
    """(rule, severity, line, snippet, why) for each signal; at most one hit per rule."""
    hits = []
    for rule, sev, rx, why in RULES:
        for m in rx.finditer(text):
            if _negated(text, m.start()) or _under_prohibition(text, m.start()):
                continue
            if rule in _NEEDS_IMPERATIVE and not m.group(0).lower().startswith("prioriti") \
                    and not _IMPERATIVE_LEAD.search(text[max(0, m.start() - 60):m.start()]):
                continue
            n, snip = _line(text, m.start())
            hits.append((rule, sev, n, snip, why))
            break
    return hits


def audit_file(path: Path, label: str, official=None) -> list[Finding]:
    try:
        text = path.read_bytes()[:MAX_READ].decode("utf-8", "replace")
    except OSError:
        return []
    out: list[Finding] = []
    m = KNOWN_MALWARE.search(text)
    if m:
        n, snip = _line(text, m.start())
        out.append(Finding(
            rule="persona.known-malware", category="persona", severity=Severity.CRITICAL,
            title=f"Hermes {label} names the Carbonato botnet's persona `GH0ST`",
            location=f"{path}:{n}", subject=f"{path.name}:GH0ST",
            detail=(f"line {n}: `{snip}`. ThreatDown lists a SOUL.md containing \"GH0ST\" as the Carbonato "
                    f"indicator: the botnet overwrites the persona so the agent takes orders over Telegram and "
                    f"collects API keys ({THREATDOWN})."),
            remediation=REMEDIATE_IOC))
    hits = scan_text(text)
    signals = {h[0] for h in hits}
    for rule, sev, n, snip, why in hits:
        out.append(Finding(
            rule=f"persona.{rule}", category="persona", severity=sev,
            title=f"Hermes {label} {why}",
            location=f"{path}:{n}", subject=f"{path.name}:{rule}:{snip[:60]}",
            detail=(f"line {n}: `{snip}`. Persona and memory files are loaded into every conversation, so an "
                    f"instruction here steers everything the agent does."
                    + (" On its own this is often a normal setup (you send the agent tasks over Telegram); it's "
                       "reported so a rewritten persona is visible." if rule == "remote-tasking" else "")),
            remediation=REMEDIATE))
    strong = signals & {"credential-harvest", "persistence", "conceal"}
    if len(signals) >= 2 and strong:
        out.append(Finding(
            rule="persona.c2", category="persona", severity=Severity.CRITICAL,
            title=f"Hermes {label} reads like a hijacked persona ({', '.join(sorted(signals))})",
            location=str(path), subject=f"{path.name}:c2",
            detail=(f"Several instructions together ({', '.join(sorted(signals))}) match how Carbonato rewrote "
                    f"Hermes' SOUL.md: take tasks over Telegram, keep itself installed, collect AI API keys and "
                    f"credentials ({THREATDOWN})."),
            remediation=REMEDIATE_IOC))
    if official is not None:          # hidden text, encoded payloads etc. from the skill-content rules
        from .skillscan import scan as skillscan
        for h in skillscan.scan_file(path, official):
            out.append(Finding(
                rule=f"persona.{h.rule}", category="persona", severity=h.severity,
                title=f"{h.title}: Hermes {label}", location=f"{path}:{h.line}",
                subject=f"{path.name}:{h.rule}:{h.text[:60]}",
                detail=f"line {h.line}: `{h.text}`. {h.explain}", remediation=REMEDIATE))
    return out


REMEDIATE = ("Open the file and check the line is yours. If you didn't write it, restore the persona or memory from a "
             "backup (or delete the line), then rotate the API keys and tokens this agent can reach and look at what "
             "it did recently (session history, cron jobs, Telegram chat).")
REMEDIATE_IOC = ("Treat the host as compromised: stop the agent, take it off the network, and check for the Carbonato "
                 "indicators in ThreatDown's report (gh0st/ or fsociety/ containers, an exposed Docker API, unknown "
                 "SSH keys). Rotate every key the agent could reach before reinstalling from a clean image.")


# ------------------------------------------------------------------ who can command the agent

_TRUE = {"1", "true", "yes", "on"}


def _env_pairs(path: Path) -> dict[str, str]:
    """Variable names → raw values. Callers only use values of the access switches."""
    out = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


def env_files(home: Path) -> list[Path]:
    files = [home / ".env"]
    try:
        files += [p / ".env" for p in sorted((home / "profiles").iterdir()) if p.is_dir()]
    except OSError:
        pass
    return [p for p in files if p.is_file()]


def access_settings(env: dict[str, str]) -> dict[str, str]:
    """The access switches only: who may command the agent and where it reports."""
    return {k: v for k, v in env.items()
            if re.search(r"(?:ALLOWED_USERS|ALLOWED_CHATS|ALLOW_ALL_USERS|HOME_CHANNEL)$", k)}


def audit_env(home: Path) -> list[Finding]:
    out: list[Finding] = []
    for p in env_files(home):
        env = _env_pairs(p)
        for name in sorted(MALWARE_ENV & set(env)):
            out.append(Finding(
                rule="gateway.known-malware-env", category="persona", severity=Severity.CRITICAL,
                title=f"Hermes .env defines `{name}`, a Carbonato botnet indicator",
                location=str(p), subject=name,
                detail=f"ThreatDown lists `{name}` among the variables of the Carbonato implant ({THREATDOWN}).",
                remediation=REMEDIATE_IOC))
        lists = {k: v for k, v in env.items() if re.search(r"ALLOWED_(?:USERS|CHATS)$", k) and v}
        for k, v in sorted(lists.items()):
            if "*" in [x.strip() for x in v.split(",")]:
                out.append(_allow_all(p, k, f"`{k}` contains `*`, which Hermes treats as \"everyone\"."))
        for k, v in sorted(env.items()):
            if k.endswith("ALLOW_ALL_USERS") and v.lower() in _TRUE:
                scoped = [x for x in lists if not x.startswith("GATEWAY_")]
                out.append(_allow_all(
                    p, k, f"`{k}={v}`." + (f" It applies to platforms without their own allow list ({len(scoped)} "
                                           f"platform list(s) are set, so it may not reach every bot)." if scoped else
                                           " No allow list is set, so it applies to every connected platform."),
                    sev=Severity.MEDIUM if scoped and k == "GATEWAY_ALLOW_ALL_USERS" else Severity.HIGH))
    return out


def _allow_all(p: Path, k: str, why: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule="gateway.allow-all-users", category="persona", severity=sev,
        title=f"Anyone who finds the bot can command this Hermes agent (`{k}`)",
        location=str(p), subject=k,
        detail=(f"{why} The agent runs commands and reads files with your permissions, so an open gateway hands that "
                f"to strangers. Carbonato's implant sets `GATEWAY_ALLOW_ALL_USERS` ({THREATDOWN})."),
        remediation=(f"Remove `{k}` (or the `*`) and list your own user ID in `TELEGRAM_ALLOWED_USERS` (or the "
                     f"platform's allow list), then restart the gateway."))
