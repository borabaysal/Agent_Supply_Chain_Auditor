"""Report rendering (Markdown + JSON) and Telegram alerting."""
from __future__ import annotations

import html
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .model import Report, Severity

ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def to_json(r: Report) -> str:
    return json.dumps({
        "tool": "agent-supply-chain-auditor", "version": r.version, "generated_at": r.generated_at,
        "result": "PASS" if r.passed else "FAIL", "fail_on": r.fail_on.name.lower(),
        "targets": r.targets, "stats": r.stats, "counts": r.counts(),
        "findings": [f.to_dict() for f in r.sorted_findings()],
    }, indent=2, ensure_ascii=False) + "\n"


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(r: Report) -> str:
    c = r.counts()
    verdict = "✅ PASS" if r.passed else "❌ FAIL"
    lines = [
        "# Agent Supply-Chain Audit",
        "",
        f"**Result: {verdict}** — fails on `{r.fail_on.name.lower()}` or above · generated {r.generated_at} · "
        f"asca {r.version}",
        "",
        "| critical | high | medium | low | info | suppressed |",
        "|---|---|---|---|---|---|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} | {c['suppressed']} |",
        "",
        "## Scope",
        "",
    ]
    for k, v in r.targets.items():
        if isinstance(v, list):
            v = ", ".join(f"`{x}`" for x in v) or "—"
        else:
            v = f"`{v}`" if v else "—"
        lines.append(f"- **{k}**: {v}")
    if r.stats:
        lines.append("- **inventory**: " + ", ".join(f"{k}={v}" for k, v in sorted(r.stats.items())))
    lines.append("")

    active = [f for f in r.sorted_findings() if not f.suppressed]
    if r.failing:
        lines += ["## Failing findings", ""]
        for f in r.failing:
            lines += _finding_block(f)
    rest = [f for f in active if f.severity < r.fail_on]
    if rest:
        lines += ["## Other findings", "", "| sev | category | finding | location |", "|---|---|---|---|"]
        for f in rest:
            sev = f.severity.name.lower()
            lines.append(f"| {ICON[sev]} {sev} | {f.category} | {_md_cell(f.title)} | `{_md_cell(f.location)}` |")
        lines.append("")
        lines += ["<details><summary>Details for other findings</summary>", ""]
        for f in rest:
            lines += _finding_block(f)
        lines += ["</details>", ""]
    sup = [f for f in r.findings if f.suppressed]
    if sup:
        lines += ["## Suppressed by baseline", "", "| fingerprint | finding | reason |", "|---|---|---|"]
        for f in sup:
            lines.append(f"| `{f.fingerprint}` | {_md_cell(f.title)} | {_md_cell(f.suppress_reason)} |")
        lines.append("")
    if not active:
        lines += ["No findings. 🎉", ""]
    lines += ["---", "_Secrets are never written to this report: only a 4-char prefix, length and a short hash._", ""]
    return "\n".join(lines)


def _finding_block(f) -> list[str]:
    sev = f.severity.name.lower()
    return [
        f"### {ICON[sev]} [{sev.upper()}] {f.title}",
        "",
        f"- **rule**: `{f.rule}` · **category**: {f.category} · **fingerprint**: `{f.fingerprint}`",
        f"- **where**: `{f.location}`",
        f"- **why**: {f.detail}" if f.detail else "",
        f"- **fix**: {f.remediation}" if f.remediation else "",
        "",
    ]


# ------------------------------------------------------------------- Telegram

TELEGRAM_LIMIT = 4096


def telegram_text(r: Report, *, host: str, report_path: str | None, max_items: int = 8) -> str:
    c = r.counts()
    e = html.escape
    head = "✅ <b>PASS</b>" if r.passed else "❌ <b>FAIL</b>"
    parts = [
        f"🛡️ <b>Agent supply-chain audit</b> — {head}",
        f"Host: <code>{e(host)}</code>",
        f"🟥 {c['critical']} · 🟧 {c['high']} · 🟨 {c['medium']} · 🟦 {c['low']}"
        + (f" · suppressed {c['suppressed']}" if c["suppressed"] else ""),
    ]
    items = r.failing or []
    if items:
        parts.append("")
        parts.append(f"<b>Failing (≥{r.fail_on.name.lower()}):</b>")
        for f in items[:max_items]:
            sev = f.severity.name.lower()
            parts.append(f"{ICON[sev]} {e(f.title)}\n   <code>{e(_tail(f.location, 70))}</code>")
        if len(items) > max_items:
            parts.append(f"…and {len(items) - max_items} more")
    if report_path:
        parts.append("")
        parts.append(f"Report: <code>{e(report_path)}</code>")
    text = "\n".join(parts)
    if len(text) > TELEGRAM_LIMIT:
        text = text[: TELEGRAM_LIMIT - 20] + "\n…(truncated)"
    return text


def _tail(s: str, n: int) -> str:
    return s if len(s) <= n else "…" + s[-(n - 1):]


def send_telegram(text: str, *, token: str, chat_id: str, timeout: float = 15.0,
                  api_base: str = "https://api.telegram.org") -> tuple[bool, str]:
    """Send one message. Returns (ok, description). The token is never included in the description."""
    url = f"{api_base}/bot{token}/sendMessage"
    body = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": "true",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        if payload.get("ok"):
            return True, f"sent (message_id={payload.get('result', {}).get('message_id')})"
        return False, f"telegram error: {payload.get('description', 'unknown')}"
    except urllib.error.HTTPError as exc:
        try:
            desc = json.loads(exc.read().decode("utf-8", "replace")).get("description", "")
        except Exception:
            desc = ""
        return False, f"HTTP {exc.code} {desc}".strip()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"network error: {type(exc).__name__}: {getattr(exc, 'reason', exc)}".replace(token, "***")


def load_env_file(path: Path) -> dict[str, str]:
    """Minimal dotenv reader (KEY=VALUE, optional quotes, `export ` prefix). Values stay in memory only."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def resolve_telegram(args_chat: str | None, env_file: Path | None) -> tuple[str | None, str | None]:
    fileenv = load_env_file(env_file) if env_file else {}
    get = lambda k: os.environ.get(k) or fileenv.get(k)  # noqa: E731
    token = get("ASCA_TELEGRAM_BOT_TOKEN") or get("TELEGRAM_BOT_TOKEN")
    chat = args_chat or get("ASCA_TELEGRAM_CHAT_ID") or get("TELEGRAM_CHAT_ID") or get("TELEGRAM_HOME_CHANNEL")
    if chat and chat.startswith("telegram:"):
        chat = chat.split(":", 1)[1]
    return token, chat
