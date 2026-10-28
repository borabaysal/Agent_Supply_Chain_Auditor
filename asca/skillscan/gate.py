"""Per-rule gate: decide which findings *block* a skill and which only warn.

Pattern rules are tripwires, so by default asca-skills reports and warns. A gate turns
selected rules into hard stops:

- **Pre-install hook:** scan the downloaded skill folder with `--gate default`. Exit code 3
  means "don't install it".
- **Already installed:** `--quarantine DIR` moves every skill with a gated finding out of
  the agent's skills folder (never deletes). `asca-skills restore NAME` puts it back.

The default gate holds only near-certain signals: things legitimate skills essentially
never do, where a false block costs less than a missed stealer. Everything else stays
a warning for a human to review.
"""
from __future__ import annotations

import fnmatch
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from ..model import Finding

PRESETS: dict[str, list[str]] = {
    # hidden instructions, decode-and-run, credential theft with an outbound sink, AMOS-style
    # password dialogs, Gatekeeper/Defender tampering, reverse shells, catalog impersonation
    "default": [
        "skill.hidden-unicode-tags", "skill.encoded-payload", "skill.exec.obfuscated", "skill.cred-plus-exfil",
        "skill.exec.password-prompt", "skill.exec.gatekeeper", "skill.exec.reverse-shell",
        "lookalike.plugin-repo-mismatch",
    ],
    # plus the ClawHavoc delivery tricks and look-alike names at high or above
    "strict": [
        "@default", "skill.exec.password-archive", "skill.exec.download-archive", "skill.exfil.capture-host",
        "skill.cred.os-store", "skill.cred.browser-wallet", "skill.inject.conceal", "skill.inject.override",
        "lookalike.*",
    ],
}


@dataclass(frozen=True)
class GateRule:
    pattern: str            # fnmatch on Finding.rule, e.g. "skill.exec.*"
    min_severity: str = ""  # ":low"/":medium"/… suffix; empty = high. Findings that context lowered
    #                         below this (quoted examples, security docs, builtin skills) only warn.

    def matches(self, f: Finding) -> bool:
        if not fnmatch.fnmatchcase(f.rule, self.pattern):
            return False
        from ..model import Severity
        return f.severity >= Severity.parse(self.min_severity or "high")


def parse(specs: list[str]) -> list[GateRule]:
    """Gate specs: preset names (`default`, `strict`), rule globs, and optional `:severity` suffixes.
    Comma-separated values and repeated flags both work. Unknown presets raise ValueError."""
    out: list[GateRule] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        item = item.strip()
        if not item or item in seen:
            return
        seen.add(item)
        name = item[1:] if item.startswith("@") else item
        if name in PRESETS:
            for x in PRESETS[name]:
                add(x)
            return
        if "." not in name and "*" not in name:
            raise ValueError(f"unknown gate preset or rule {item!r} (presets: {', '.join(PRESETS)})")
        pat, _, sev = name.partition(":")
        if sev:
            from ..model import Severity
            Severity.parse(sev)   # validate early
        out.append(GateRule(pat, sev))

    for spec in specs:
        for item in spec.split(","):
            add(item)
    return out


def gated(findings: list[Finding], rules: list[GateRule]) -> list[Finding]:
    return [f for f in findings if not f.suppressed and any(r.matches(f) for r in rules)]


# ------------------------------------------------------------------ quarantine

MANIFEST = "quarantine.json"


def _manifest(qdir: Path) -> dict:
    try:
        return json.loads((qdir / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"items": []}


def _save(qdir: Path, data: dict) -> None:
    (qdir / MANIFEST).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def quarantine(skill_dir: Path, name: str, reasons: list[str], qdir: Path) -> Path:
    """Move a skill folder into *qdir* (atomic rename on the same filesystem) and record why."""
    qdir.mkdir(parents=True, exist_ok=True)
    try:
        qdir.chmod(0o700)
    except OSError:
        pass
    dest = qdir / f"{name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    shutil.move(str(skill_dir), str(dest))
    data = _manifest(qdir)
    data["items"].append({"name": name, "original": str(skill_dir), "quarantined": str(dest),
                          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "reasons": reasons})
    _save(qdir, data)
    return dest


def restore(name: str, qdir: Path) -> tuple[bool, str]:
    data = _manifest(qdir)
    items = [i for i in data["items"] if i["name"] == name and Path(i["quarantined"]).exists()]
    if not items:
        return False, f"no quarantined skill named {name!r} in {qdir}"
    item = items[-1]
    orig = Path(item["original"])
    if orig.exists():
        return False, f"{orig} exists again; move it aside first"
    orig.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(item["quarantined"], str(orig))
    data["items"].remove(item)
    _save(qdir, data)
    return True, f"restored {name} to {orig}"
