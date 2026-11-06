"""Compare today's inventory with the last one and turn the differences into findings.

| Change | Rule | Severity |
|---|---|---|
| known-bad id@version installed | inventory.known-bad | critical (every run until removed) |
| files changed, same version (third-party item) | inventory.tamper | high |
| publisher changed for the same id, or same name now from another publisher | inventory.publisher-changed | high |
| new item | inventory.new | medium |
| new item from a publisher never seen before and not approved | inventory.new-publisher | medium |
| MCP server launch definition changed, same version | inventory.definition-changed | medium |
| install origin changed to a side-loaded VSIX | inventory.origin-changed | medium |
| bundled skill edited locally (Hermes didn't update it) | inventory.modified-bundled | low |
| item couldn't be fully hashed (budget) | inventory.hash-budget | low |
| version changed (same publisher), your own skill edited, removed | inventory.version-changed / .edited / .removed | info (digest only) |
"""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding, Severity
from .collect import Item

# Offline list of id@version builds publicly confirmed as malicious. Extend with --known-bad FILE.
KNOWN_BAD = [
    {"kind": "ide-extension", "id": "anthropic.claude-code", "versions": ["2.1.312", "2.1.313"],
     "summary": "Tampered build served by the Cursor extension marketplace on 2026-10-29 (macOS/Windows): "
                "adds an attacker SSH key labelled svc-telemetry, persistence and a reverse SSH tunnel.",
     "reference": "https://cursor.com/blog/claude-code-extension-security-notice"},
]

TAMPER_FIX = ("Don't open the IDE/agent until you know why. Compare the folder with a fresh copy of the same "
              "version from the publisher, check persistence (LaunchAgents, crontab, ~/.ssh/authorized_keys), "
              "and reinstall from the official source. If code ran, rotate credentials the user could reach.")


def load_known_bad(path: Path | None) -> list[dict]:
    out = list(KNOWN_BAD)
    if path:
        data = json.loads(path.read_text(encoding="utf-8"))
        out += data.get("known_bad", data) if isinstance(data, dict) else data
    return out


def _pub(d) -> tuple[str, str]:
    if isinstance(d, Item):
        return d.publisher, d.publisher_id
    return d.get("publisher", ""), d.get("publisher_id", "")


def _label(d) -> str:
    g = (lambda k: getattr(d, k)) if isinstance(d, Item) else (lambda k: d.get(k, ""))
    where = {"ide-extension": g("source"), "skill": g("source").split(":", 1)[0]}.get(g("kind"), g("kind"))
    return f"{g('id')} ({where})"


def _f(rule, sev, title, it, subject, detail, fix="") -> Finding:
    loc = (it.path or it.key) if isinstance(it, Item) else it.get("path", "")
    return Finding(rule=rule, category="inventory", severity=sev, title=title, location=loc or "", subject=subject,
                   detail=detail, remediation=fix)


def state_findings(items: list[Item], known_bad: list[dict]) -> list[Finding]:
    """Findings about the current state alone (reported every run)."""
    out = []
    for it in items:
        for kb in known_bad:
            if kb.get("kind", it.kind) == it.kind and it.id.lower() == str(kb["id"]).lower() \
                    and it.version in kb.get("versions", []):
                out.append(_f("inventory.known-bad", Severity.CRITICAL,
                              f"Known-malicious build installed: {it.id} {it.version}", it,
                              f"{it.key}@{it.version}", f"{kb.get('summary', '')} Installed in {it.source}.",
                              f"Follow the publisher's advisory now: {kb.get('reference', '')}. Uninstalling may "
                              f"not be enough if the payload ran."))
        if it.partial or (it.hash is None and it.kind != "mcp-server"):
            out.append(_f("inventory.hash-budget", Severity.LOW, f"{_label(it)} was only partly hashed", it, it.key,
                          f"{it.note or 'not hashed'}; {it.files} files / {it.bytes // 1024} KiB hashed. Changes "
                          f"outside the hashed part won't be noticed.",
                          "Raise --item-cap-mb / --total-mb if this item matters to you."))
    return out


def diff(prev: dict, items: list[Item], *, approved: set[str], same_limits: bool = True) -> list[Finding]:
    """prev: {key: item-dict} from the last state. Returns change findings."""
    out: list[Finding] = []
    cur = {it.key: it for it in items}
    known_pubs = {(d.get("kind"), d.get("publisher", "").lower()) for d in prev.values()}
    approved = {a.lower() for a in approved}
    removed = {k: d for k, d in prev.items() if k not in cur}
    # removed + added with the same kind/source/name but another publisher = a swap, not two unrelated events
    swapped_from: dict[str, dict] = {}
    for k, it in cur.items():
        if k in prev:
            continue
        for rk, d in removed.items():
            if d.get("kind") == it.kind and d.get("source") == it.source and d.get("name") == it.name \
                    and d.get("publisher", "").lower() != it.publisher.lower() and it.kind != "skill":
                swapped_from[k] = d
                break
    swapped_removed = {(d.get("kind"), d.get("source"), d.get("id")) for d in swapped_from.values()}

    for k, it in sorted(cur.items()):
        p = prev.get(k)
        if p is None:
            if k in swapped_from:
                old = swapped_from[k]
                out.append(_f("inventory.publisher-changed", Severity.HIGH,
                              f"{it.name} is now from a different publisher: {old.get('publisher')} → {it.publisher}",
                              it, f"{k}@{it.publisher}", f"Was {old.get('id')} {old.get('version')}; now {it.id} "
                              f"{it.version}. Same name, new publisher is how look-alike and hijacked packages "
                              f"replace a trusted one.", TAMPER_FIX))
                continue
            pub_known = (it.kind, it.publisher.lower()) in known_pubs or it.publisher.lower() in approved \
                or it.publisher_id.lower() in approved or it.publisher_name.lower() in approved
            out.append(_f("inventory.new", Severity.MEDIUM, f"New {it.kind}: {_label(it)} {it.version}".rstrip(),
                          it, f"{k}@{it.version}",
                          f"Publisher {it.publisher or 'unknown'}"
                          + (f" ({it.publisher_name})" if it.publisher_name else "")
                          + f", origin {it.origin or 'unknown'}, {it.files} files hashed.",
                          "If you didn't install this, find out what did (an agent, an IDE auto-install, a "
                          "workspace recommendation) before using it."))
            if not pub_known and it.publisher not in ("", "local", "builtin"):
                out.append(_f("inventory.new-publisher", Severity.MEDIUM,
                              f"First {it.kind} from publisher `{it.publisher}`", it, f"{it.kind}|{it.publisher}",
                              f"No {it.kind} from this publisher was installed before and it isn't in your "
                              f"approved list ({_label(it)}).",
                              "Check the publisher, then add it to `approved_publishers` in your baseline file."))
            continue
        old_pub, old_pid = p.get("publisher", ""), p.get("publisher_id", "")
        if (old_pub and old_pub.lower() != it.publisher.lower()) or (old_pid and it.publisher_id
                                                                     and old_pid != it.publisher_id):
            out.append(_f("inventory.publisher-changed", Severity.HIGH,
                          f"{_label(it)}: publisher changed ({old_pub or old_pid} → {it.publisher or it.publisher_id})",
                          it, f"{k}@{it.publisher}:{it.publisher_id}",
                          "The same item now names a different publisher (or marketplace publisher ID). That "
                          "happens on account transfers, and on takeovers.", TAMPER_FIX))
        if it.version != p.get("version", ""):
            out.append(_f("inventory.version-changed", Severity.INFO,
                          f"{_label(it)}: {p.get('version') or '?'} → {it.version or '?'}", it,
                          f"{k}@{it.version}", f"Publisher {it.publisher}.", ""))
        elif it.hash and p.get("hash") and it.hash != p.get("hash"):
            if not same_limits:
                out.append(_f("inventory.rehashed", Severity.INFO, f"{_label(it)}: re-hashed with new limits", it,
                              f"{k}:{it.hash[:12]}", "Hash limits changed since the last run; not compared.", ""))
            elif it.policy == "managed":
                out.append(_f("inventory.tamper", Severity.HIGH,
                              f"{_label(it)} {it.version}: files changed without a version change", it,
                              f"{k}@{it.version}:{it.hash[:12]}",
                              f"Content hash changed ({p['hash'][:12]} → {it.hash[:12]}) while the version stayed "
                              f"{it.version or 'unset'}. Legitimate updates change the version; edits in place are "
                              f"how injected code hides.", TAMPER_FIX))
            elif it.policy == "config":
                out.append(_f("inventory.definition-changed", Severity.MEDIUM,
                              f"MCP server {it.name}: launch definition changed", it, f"{k}:{it.hash[:12]}",
                              f"Command, arguments, URL or env/header *names* changed in {it.source} (values are "
                              f"never read into the inventory).",
                              "Check the config change was yours (or an install you ran)."))
            elif it.policy == "bundled":
                out.append(_f("inventory.modified-bundled", Severity.LOW,
                              f"Bundled skill {it.name} was edited locally", it, f"{k}:{it.hash[:12]}",
                              "The skill differs from last run but Hermes' bundled-manifest hash didn't change, so "
                              "the edit came from this host (you, the agent's curator, or something else).",
                              "Expected if you or your agent edit skills; otherwise look at what changed."))
            else:
                out.append(_f("inventory.edited", Severity.INFO, f"{_label(it)} edited", it,
                              f"{k}:{it.hash[:12]}", "Local item, so edits are expected.", ""))
        if p.get("origin") in ("gallery", "marketplace") and it.origin == "vsix":
            out.append(_f("inventory.origin-changed", Severity.MEDIUM, f"{_label(it)} is now side-loaded (VSIX)",
                          it, f"{k}:vsix", "It used to come from the marketplace; a side-loaded VSIX skips the "
                          "marketplace's checks.", "Reinstall from the marketplace unless you side-loaded it."))
    for k, d in sorted(removed.items()):
        if (d.get("kind"), d.get("source"), d.get("id")) in swapped_removed:
            continue
        out.append(Finding(rule="inventory.removed", category="inventory", severity=Severity.INFO,
                           title=f"Removed: {_label(d)} {d.get('version', '')}".rstrip(), location=d.get("path", ""),
                           subject=f"{k}@{d.get('version', '')}", detail="", remediation=""))
    return out
