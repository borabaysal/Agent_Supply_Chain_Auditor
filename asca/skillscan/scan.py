"""Scan skill folders: find skills, work out where they came from, run content and name checks."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .. import yamlmini
from ..model import Finding, Severity
from . import rules as R
from .lookalike import Matcher
from .official import Official

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".archive", ".curator_backups", "quarantine",
             ".locks", "index-cache", ".scan-cache", ".hub", "dist", "build", ".next"}
MAX_FILE_BYTES = 512 * 1024
MAX_FILES_PER_SKILL = 400
SECURITY_TOPIC = re.compile(r"(secur|red[-_ ]?team|pentest|jailbreak|prompt[-_ ]?inject|malware|threat|exploit|"
                            r"vuln|forensic|incident|audit|scanner|ctf|hardening|scam|fraud|phish|stealer)", re.I)

REMEDIATE_INJECTION = ("Read the flagged lines. If you didn't write this skill and can't explain them, uninstall "
                       "it, then review recent agent sessions and memory files for changes it may have caused.")
REMEDIATE_MALWARE = ("Don't run this skill. Remove it, check whether it already ran (shell history, agent logs, "
                     "LaunchAgents/crontab), and if it did, rotate every key and password the agent could reach.")


@dataclass
class Skill:
    path: Path                 # skill directory
    name: str                  # front-matter name or dir name
    dir_name: str
    root: Path
    ecosystem: str             # hermes | openclaw | claude | codex | generic
    provenance: str = "local"  # builtin | hub:<source>:<trust> | plugin:<name> | local | unknown
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def official_provenance(self) -> bool:
        return self.provenance == "builtin" or self.provenance.startswith("hub:official")


# ------------------------------------------------------------------ discovery

def default_roots(home: Path, hermes_home: Path | None) -> list[tuple[Path, str]]:
    roots: list[tuple[Path, str]] = []
    if hermes_home:
        roots.append((hermes_home / "skills", "hermes"))
        plugins = hermes_home / "plugins"
        if plugins.is_dir():
            roots += [(p / "skills", "hermes") for p in sorted(plugins.iterdir()) if (p / "skills").is_dir()]
    for base in (".openclaw", ".clawdbot", ".moltbot"):
        b = home / base
        roots.append((b / "skills", "openclaw"))
        if b.is_dir():
            roots += [(w / "skills", "openclaw") for w in sorted(b.glob("workspace*")) if (w / "skills").is_dir()]
            ext = b / "extensions"
            if ext.is_dir():
                roots += [(e / "skills", "openclaw") for e in sorted(ext.iterdir()) if (e / "skills").is_dir()]
    roots += [(home / ".claude" / "skills", "claude"), (home / ".codex" / "skills", "codex"),
              (home / ".agents" / "skills", "generic")]
    seen, out = set(), []
    for r, eco in roots:
        if r.is_dir() and r.resolve() not in seen:
            seen.add(r.resolve())
            out.append((r, eco))
    return out


def find_skills(root: Path, ecosystem: str, hermes_home: Path | None = None) -> list[Skill]:
    out: list[Skill] = []
    bundled, lock = _hermes_provenance(hermes_home) if ecosystem == "hermes" else (set(), {})
    plugin_owner = root.parent.name if root.parent.parent.name == "plugins" else None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        md = next((f for f in filenames if f.lower() == "skill.md"), None)
        if not md:
            continue
        d = Path(dirpath)
        fm = _front_matter(d / md)
        name = str(fm.get("name") or d.name).strip()
        sk = Skill(path=d, name=name, dir_name=d.name, root=root, ecosystem=ecosystem,
                   description=str(fm.get("description") or "")[:300], tags=_tags(fm))
        if plugin_owner:
            sk.provenance = f"plugin:{plugin_owner}"
        elif d.name in lock or name in lock:
            e = lock.get(d.name) or lock.get(name)
            sk.provenance = f"hub:{e.get('source', '?')}:{e.get('trust_level', '?')}"
        elif d.name in bundled:
            sk.provenance = "builtin"
        elif (d / ".clawhub").exists() or _clawhub_meta(d):
            sk.provenance = "hub:clawhub:community"
        elif ecosystem != "hermes":
            sk.provenance = "unknown"
        out.append(sk)
    return out


def _clawhub_meta(d: Path) -> bool:
    """ClawHub installs drop a small `_meta.json` (slug/owner/version) next to SKILL.md."""
    try:
        meta = json.loads((d / "_meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(meta, dict) and "slug" in meta


def _hermes_provenance(hermes_home: Path | None) -> tuple[set[str], dict]:
    bundled, lock = set(), {}
    if not hermes_home:
        return bundled, lock
    try:
        for line in (hermes_home / "skills" / ".bundled_manifest").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                bundled.add(line.split(":", 1)[0].strip())
    except OSError:
        pass
    try:
        lock = json.loads((hermes_home / "skills" / ".hub" / "lock.json").read_text(encoding="utf-8")).get(
            "installed", {}) or {}
    except (OSError, ValueError):
        pass
    return bundled, lock


def _front_matter(md: Path) -> dict:
    try:
        text = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    try:
        d = yamlmini.load(text[3:end])
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _tags(fm: dict) -> list[str]:
    tags = fm.get("tags")
    meta = fm.get("metadata")
    if not tags and isinstance(meta, dict):
        h = meta.get("hermes") or meta.get("openclaw") or {}
        tags = h.get("tags") if isinstance(h, dict) else None
    return [str(t) for t in tags] if isinstance(tags, list) else []


# ------------------------------------------------------------------ content scan

def _sha8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:8]


_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{28,}")


def _snippet(line: str) -> str:
    s = _LONG_TOKEN.sub(lambda m: m.group(0)[:6] + "…", line.strip())
    s = s.replace("`", "'")
    return s if len(s) <= 140 else s[:139] + "…"


def _kind(path: Path) -> str:
    suf = path.suffix.lower()
    if suf in R.CODE_SUFFIXES:
        return "code"
    if suf in R.CONFIG_SUFFIXES:
        return "config"
    return "prose"


def _lower(sev: Severity, steps: int) -> Severity:
    return Severity(max(int(Severity.INFO), int(sev) - steps))


_BINARY_MAGIC = {b"\x7fELF": "ELF executable", b"MZ": "Windows executable", b"\xcf\xfa\xed\xfe": "Mach-O executable",
                 b"\xce\xfa\xed\xfe": "Mach-O executable", b"\xca\xfe\xba\xbe": "Mach-O universal binary",
                 b"PK\x03\x04": "ZIP archive", b"Rar!": "RAR archive", b"7z\xbc\xaf": "7-Zip archive"}


@dataclass
class _Hit:
    rule: str
    category: str
    severity: Severity
    title: str
    explain: str
    file: Path
    line: int
    text: str
    note: str = ""
    raw: Severity | None = None    # rule severity before prose/context adjustment


def _line_of(text: str, pos: int) -> tuple[int, str]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text.count("\n", 0, pos) + 1, text[start: end if end >= 0 else len(text)]


def _in_html_comment(text: str, pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= pos < b for a, b in spans)


def _fence_spans(text: str) -> list[tuple[int, int]]:
    spans, start = [], None
    for m in re.finditer(r"^\s*(```|~~~)", text, re.M):
        if start is None:
            start = m.start()
        else:
            spans.append((start, m.end()))
            start = None
    return spans


def _quoted_example(text: str, pos: int, fences: list[tuple[int, int]]) -> bool:
    """Role markers inside a code fence, backticks or a string literal are documentation of chat templates."""
    if any(a <= pos < b for a, b in fences):
        return True
    before = text[max(0, pos - 3): pos]
    return any(q in before for q in ("'", '"', "`"))


def _negated(text: str, pos: int) -> bool:
    """'never start without the user's consent' / 'do not bypass approvals' say the opposite."""
    before = text[max(0, pos - 45): pos].lower()
    return bool(re.search(r"\b(never|not|n't|no|only|always\s+ask|must\s+not|avoid|refuse|don't|won't)\b[^.!?\n]*$",
                          before))


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _trusted_install(line: str, official: Official) -> bool:
    for url in re.findall(r"https?://[^\s'\"|)]+", line):
        host = _url_host(url)
        full = host + urlparse(url).path
        trusted = R.TRUSTED_INSTALL_HOSTS | official.domains
        if not any(host == t or host.endswith("." + t) or full.startswith(t) for t in trusted):
            return False
    return True


def _official_download(url: str, official: Official) -> bool:
    host = _url_host(url)
    if any(host == d or host.endswith("." + d) for d in official.domains):
        return True
    m = re.match(r"https?://(?:github\.com|raw\.githubusercontent\.com|objects\.githubusercontent\.com)/([^/]+/[^/]+)",
                 url)
    return bool(m and m.group(1).lower() in official.repos)


def scan_file(path: Path, official: Official) -> list[_Hit]:
    hits: list[_Hit] = []
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(min(size, MAX_FILE_BYTES))
    except OSError:
        return hits
    for magic, label in _BINARY_MAGIC.items():
        if head.startswith(magic):
            sev = Severity.MEDIUM if "archive" in label else Severity.HIGH
            hits.append(_Hit("bundled-binary", "malicious-install", sev, f"Bundles a {label}",
                             "Skills are instructions and small scripts; a compiled binary or archive inside one "
                             "can't be reviewed by reading it.", path, 0, path.name))
            return hits
    if b"\x00" in head[:8192]:
        return hits
    text = head.decode("utf-8", "replace")
    kind = _kind(path)
    comments = [(m.start(), m.end()) for m in R.HTML_COMMENT.finditer(text)] if kind == "prose" else []
    fences = _fence_spans(text) if kind == "prose" else []

    # hidden characters
    tags = R.TAG_CHARS.findall(text)
    if tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        pos = R.TAG_CHARS.search(text).start()
        n, _ = _line_of(text, pos)
        hits.append(_Hit("hidden-unicode-tags", "hidden-content", Severity.CRITICAL,
                         "Contains invisible Unicode tag characters",
                         f"Invisible 'tag' characters smuggle text the model reads but you can't see. Decoded: "
                         f"'{_snippet(decoded)[:100]}'", path, n, "(invisible)"))
    for rx, rid, sev, title, why in (
            (R.BIDI, "hidden-bidi", Severity.HIGH, "Contains bidirectional-override characters",
             "Bidi controls make text display in a different order than it's read (Trojan Source)."),
            (R.ZERO_WIDTH, "hidden-zero-width", Severity.MEDIUM, "Contains zero-width characters",
             "Zero-width characters can hide words from a human reviewer or break up keywords to dodge scanners.")):
        found = list(rx.finditer(text))
        if found and (rid != "hidden-zero-width" or len(found) >= 3):
            n, line = _line_of(text, found[0].start())
            hits.append(_Hit(rid, "hidden-content", sev, title, f"{why} ({len(found)} found)", path, n,
                             _snippet(rx.sub("�", line))))

    # agent-directed text hidden in HTML comments (invisible when the markdown is rendered)
    for a, b in comments:
        inner = text[a + 4: b - 3]
        if len(inner.strip()) > 20 and R.AGENT_DIRECTED.search(inner):
            n, _ = _line_of(text, a)
            hits.append(_Hit("hidden-comment", "hidden-content", Severity.MEDIUM,
                             "Has agent-directed text inside an HTML comment",
                             "HTML comments don't show when the skill is rendered, but the model reads them.",
                             path, n, _snippet(inner)))

    # encoded payloads
    for m in R.BASE64_BLOB.finditer(text):
        if "base64," in text[max(0, m.start() - 40): m.start()]:   # data: URIs (images, fonts)
            continue
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=False)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() or c in "\n\r\t" for c in dec) < 0.9 * len(dec):
            continue
        inner = [r for r in R.RULES if r.pattern.search(dec)] or (
            [None] if re.search(r"(https?://|\bcurl\b|\bwget\b|/bin/(ba)?sh|\bexec\b|\beval\b)", dec) else [])
        if inner:
            n, _ = _line_of(text, m.start())
            hits.append(_Hit("encoded-payload", "malicious-install", Severity.CRITICAL,
                             "Hides commands inside a base64 blob",
                             f"The blob decodes to: '{_snippet(dec)[:110]}'", path, n, m.group(0)[:12] + "…"))

    # pattern rules
    for rule in R.RULES:
        if rule.code_only and kind == "prose":
            continue
        for m in rule.pattern.finditer(text):
            n, line = _line_of(text, m.start())
            sev = rule.prose_severity if (kind == "prose" and rule.prose_severity is not None) else rule.severity
            note = ""
            if rule.id == "exec.pipe-shell" and _trusted_install(line, official):
                sev, note = Severity.LOW, " (vendor install script)"
            if rule.id == "inject.override" and _quoted_example(text, m.start(), fences):
                sev, note = Severity.MEDIUM, " (quoted)"
            if rule.id in ("exec.download-binary", "exec.download-archive"):
                if _official_download(m.group(0), official):
                    continue
                near = text[max(0, m.start() - 400): m.end() + 400]
                if re.search(r"(prerequisite|required|requires|must\s+(first\s+)?install|before\s+using|"
                             r"download\s+(and|&)\s+run)", near, re.I):
                    sev, note = Severity.HIGH, " (presented as a required prerequisite)"
            if rule.id in ("inject.conceal", "inject.approval-bypass") and _negated(text, m.start()):
                continue
            if rule.id == "inject.role-tag" and _quoted_example(text, m.start(), fences):
                sev, note = Severity.LOW, " (quoted as a chat-template example)"
            if comments and _in_html_comment(text, m.start(), comments):
                sev = Severity(min(int(Severity.CRITICAL), int(sev) + 1))
                note += " (hidden in an HTML comment)"
            hits.append(_Hit(rule.id, rule.category, sev, rule.title, rule.explain, path, n, _snippet(line), note,
                             raw=rule.severity))
            break   # first occurrence per rule per file is enough; the count isn't the point
    return hits


def _skill_files(skill: Skill):
    count = 0
    for dirpath, dirnames, filenames in os.walk(skill.path):
        d = Path(dirpath)
        # nested skills are scanned on their own
        dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS and not (d / x / "SKILL.md").exists()]
        for f in sorted(filenames):
            p = d / f
            if p.is_symlink() or not p.is_file():
                continue
            count += 1
            if count > MAX_FILES_PER_SKILL:
                return
            yield p


def scan_skill(skill: Skill, official: Official, skills_matcher: Matcher) -> list[Finding]:
    findings: list[Finding] = []
    hits: list[_Hit] = []
    for p in _skill_files(skill):
        hits.extend(scan_file(p, official))

    # context: reviewed official skills and security-education skills quote attacks on purpose
    downgrade, why = 0, ""
    if skill.official_provenance:
        downgrade, why = 2, "official skill, likely documentation"
    elif SECURITY_TOPIC.search(" ".join([skill.name, skill.description, *skill.tags])):
        downgrade, why = 1, "security-topic skill, may be quoting attacks"

    cred = [h for h in hits if h.category == "credential-access"
            and (h.raw or h.severity) >= Severity.MEDIUM and h.rule != "cred.env-dump" or
            (h.rule == "cred.env-dump" and _kind(h.file) == "code")]
    sink = [h for h in hits if (h.category == "exfiltration" and (h.raw or h.severity) >= Severity.HIGH)
            or h.rule == "exec.reverse-shell"]
    for h in hits:
        sev = h.severity
        if downgrade and h.category not in ("hidden-content",) and h.rule not in ("encoded-payload",):
            sev = _lower(sev, downgrade)
        rel = h.file
        findings.append(Finding(
            rule=f"skill.{h.rule}", category=h.category, severity=sev,
            title=f"{h.title}: skill `{skill.name}`",
            location=str(rel), subject=f"{skill.name}:{_sha8(h.text)}",
            detail=(f"line {h.line}: `{h.text}`. {h.explain}{h.note}"
                    + (f" Severity lowered ({why})." if downgrade and sev != h.severity else "")),
            remediation=REMEDIATE_MALWARE if h.category in ("credential-access", "exfiltration", "malicious-install")
            else REMEDIATE_INJECTION))
    if cred and sink:
        sev = Severity.CRITICAL if not downgrade else _lower(Severity.CRITICAL, downgrade)
        findings.append(Finding(
            rule="skill.cred-plus-exfil", category="exfiltration", severity=sev,
            title=f"Reads credentials and has a way to send them out: skill `{skill.name}`",
            location=str(skill.path), subject=skill.name,
            detail=(f"Credential access ({cred[0].file.name}:{cred[0].line}) and an outbound sink "
                    f"({sink[0].file.name}:{sink[0].line}) in the same skill is the shape of a stealer."
                    + (f" Severity lowered ({why})." if downgrade else "")),
            remediation=REMEDIATE_MALWARE))
    findings += name_findings(skill, skills_matcher, official)
    return findings


# ------------------------------------------------------------------ names

def name_findings(skill: Skill, matcher: Matcher, official: Official) -> list[Finding]:
    out: list[Finding] = []
    names = {skill.name, skill.dir_name}
    for n in names:
        m = matcher.lookalike(n)
        if m:
            out.append(Finding(
                rule="lookalike.skill", category="lookalike", severity=m.severity,
                title=f"Skill name `{n}` looks like official skill `{m.official}`",
                location=str(skill.path), subject=n,
                detail=f"`{n}` {m.reason}. Installed from: {skill.provenance}.",
                remediation=f"Check where this skill came from. If you meant `{m.official}`, uninstall this one and "
                            f"install the official skill; if it's your own, rename it so it can't be mistaken."))
    # exact official name, but not installed from an official source
    exact = next((n for n in names if matcher.is_official(n)), None)
    if exact and not skill.official_provenance:
        prov_official = official.skills.get(exact, "")
        if skill.provenance.startswith("hub:") or skill.provenance == "unknown":
            sev = Severity.HIGH if skill.provenance.startswith("hub:") else Severity.LOW
            out.append(Finding(
                rule="lookalike.shadow", category="lookalike", severity=sev,
                title=f"Skill `{exact}` uses an official skill's name but isn't the official one",
                location=str(skill.path), subject=exact,
                detail=(f"`{exact}` is an official skill ({prov_official}), but this copy came from "
                        f"{skill.provenance}. Cloned skills under official names were how ClawHavoc "
                        f"(Jan–Feb 2026) spread on ClawHub."),
                remediation="Compare it with the official skill. If it isn't identical and you didn't intend a "
                            "replacement, uninstall it and install the official one."))
    if skill.name != skill.dir_name and matcher.is_official(skill.name) and not matcher.is_official(skill.dir_name) \
            and not skill.official_provenance:
        out.append(Finding(
            rule="lookalike.claimed-name", category="lookalike", severity=Severity.MEDIUM,
            title=f"Skill folder `{skill.dir_name}` declares the official name `{skill.name}`",
            location=str(skill.path / "SKILL.md"), subject=skill.name,
            detail="The agent sees the front-matter name, not the folder name, so this skill presents itself as "
                   "the official one.",
            remediation="Make the front-matter `name:` match the folder, or remove the skill if it isn't yours."))
    return out
