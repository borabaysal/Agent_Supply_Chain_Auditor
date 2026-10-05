"""Core data model: severities, findings, and the audit report.

Design notes
- A Finding never carries a secret value. Checks that detect secrets must pass
  a redacted preview (see ``redact``) — the report, the JSON file and the
  Telegram alert are all built from Finding fields only.
- ``fingerprint`` is stable across runs (rule + location + subject) so users can
  suppress accepted risks in a baseline file without hiding new ones.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}; choose from {[s.name.lower() for s in cls]}") from exc


@dataclass
class Finding:
    rule: str            # e.g. "git.fsmonitor"
    category: str        # pinning | repo-config | secrets | mcp | integrity | scanner
    severity: Severity
    title: str
    location: str        # file path (and key / line) where the problem lives
    subject: str = ""    # skill / server / key name the finding is about
    detail: str = ""     # why it matters
    remediation: str = ""
    suppressed: bool = False
    suppress_reason: str = ""

    @property
    def fingerprint(self) -> str:
        raw = "\x00".join((self.rule, self.location, self.subject))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name.lower()
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class Report:
    targets: dict
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    fail_on: Severity = Severity.HIGH
    generated_at: str = ""
    version: str = ""

    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def failing(self) -> list[Finding]:
        return [f for f in self.active() if f.severity >= self.fail_on]

    @property
    def passed(self) -> bool:
        return not self.failing

    def counts(self) -> dict[str, int]:
        out = {s.name.lower(): 0 for s in reversed(Severity)}
        for f in self.active():
            out[f.severity.name.lower()] += 1
        out["suppressed"] = sum(1 for f in self.findings if f.suppressed)
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.suppressed, -int(f.severity), f.category, f.location, f.rule))


def redact(secret: str) -> str:
    """Safe, non-reversible description of a secret: 4-char prefix, length, hash tag.

    The hash lets a user confirm *which* key leaked (compare against their own
    hash) without the report containing anything usable.
    """
    secret = secret.strip()
    prefix = secret[:4] if len(secret) >= 16 else ""
    tag = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}… (len={len(secret)}, sha256:{tag})"
