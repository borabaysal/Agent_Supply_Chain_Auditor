"""What to do when a key leaked: provider-specific steps, and a local "blast radius" card for AWS keys.

Every secret finding (in config, transcripts, allow rules, MCP env …) gets the steps for its
provider in its remediation, instead of a generic "rotate it". Nothing here calls a provider.

AWS card: for each AWS access key ID asca found, ``~/.aws/credentials`` and ``~/.aws/config`` are
read locally (configparser, never sent anywhere; the secret access key is never read into a
finding) to say which profile the key belongs to, whether it's a long-lived IAM user key (AKIA…) or
temporary (ASIA…), and which roles that profile can assume through ``source_profile``. AWS isn't
called, so effective permissions stay unknown; the card says so.
"""
from __future__ import annotations

import configparser
import hashlib
import os
import re
from pathlib import Path

from .model import Finding

# label (as in secrets.PATTERNS / session and allow-rule findings) -> steps
STEPS: dict[str, str] = {
    "Anthropic API key": ("Anthropic: create a new key and delete this one at https://console.anthropic.com/settings/keys, "
                          "then check Usage for spend you don't recognise."),
    "OpenAI-style API key": ("OpenAI (sk-…): revoke it at https://platform.openai.com/api-keys and create a new one; check "
                             "Usage. Other providers that use sk- keys (DeepSeek, Moonshot …) have the same page in "
                             "their console."),
    "OpenRouter API key": ("OpenRouter: delete it at https://openrouter.ai/settings/keys, create a new key with a credit "
                           "limit, and check Activity."),
    "GitHub token": ("GitHub: revoke it at https://github.com/settings/tokens (classic) or "
                     "https://github.com/settings/personal-access-tokens (fine-grained); review "
                     "https://github.com/settings/security-log, and look for new deploy keys, webhooks and Actions "
                     "secrets in the repos it could reach."),
    "Slack token": "Slack: rotate it in the app's settings at https://api.slack.com/apps (OAuth & Permissions).",
    "Telegram bot token": ("Telegram: in @BotFather send /mybots → your bot → API Token → Revoke current token. The old "
                           "token stops at once, so put the new one in the bot's .env and restart it right away."),
    "Google API key": ("Google: regenerate or delete it at https://console.cloud.google.com/apis/credentials and add API "
                       "and application restrictions to the new key."),
    "Stripe live key": "Stripe: roll the key at https://dashboard.stripe.com/apikeys and review recent API requests.",
    "Hugging Face token": "Hugging Face: invalidate and refresh it at https://huggingface.co/settings/tokens.",
    "Private key": ("Private key: generate a new key pair, replace the public key everywhere this one is trusted "
                    "(servers' authorized_keys, GitHub deploy keys, signing), then delete the old one."),
    "Wallet private key": ("Wallet key: move the funds to a new wallet created on a clean device now; the old key can't "
                           "be revoked."),
    "AWS access key id": ("AWS: deactivate the key first (`aws iam update-access-key --user-name <user> --access-key-id "
                          "<ID> --status Inactive`), create a new one (`aws iam create-access-key --user-name <user>`), "
                          "then delete the old one (`aws iam delete-access-key …`). Check what it did: `aws cloudtrail "
                          "lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<ID>`. Better: "
                          "move to IAM Identity Center (SSO) so no long-lived key sits on disk."),
}
_TAG = re.compile(r"sha256:([0-9a-f]{8})")


def label_of(f: Finding) -> str | None:
    if f.category != "secrets" or f.rule.startswith("devcred."):   # stored, not leaked: no revoke steps
        return None
    for label in sorted(STEPS, key=len, reverse=True):
        if label.lower() in f"{f.title} {f.subject}".lower():
            return label
    return None


# ------------------------------------------------------------------ AWS profiles

def _read_ini(p: Path) -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        cp.read(p, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        pass
    return cp


def aws_profiles(home: Path) -> dict[str, dict]:
    """profile -> {key_tag, key_prefix, temporary, roles, region, sso, process}. No secret values."""
    cfile = Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or home / ".aws" / "credentials")
    kfile = Path(os.environ.get("AWS_CONFIG_FILE") or home / ".aws" / "config")
    creds, conf = _read_ini(cfile), _read_ini(kfile)
    out: dict[str, dict] = {}
    for sec in creds.sections():
        kid = creds.get(sec, "aws_access_key_id", fallback="").strip()
        if not kid:
            continue
        out[sec] = {"key_tag": hashlib.sha256(kid.encode()).hexdigest()[:8], "key_prefix": kid[:4],
                    "temporary": kid.startswith("ASIA") or creds.has_option(sec, "aws_session_token"),
                    "roles": [], "region": "", "file": str(cfile)}
    for sec in conf.sections():
        name = sec[len("profile "):] if sec.startswith("profile ") else sec
        src = conf.get(sec, "source_profile", fallback="").strip()
        role = conf.get(sec, "role_arn", fallback="").strip()
        if src and role and src in out:
            out[src]["roles"].append((name, role))
        if name in out:
            out[name]["region"] = conf.get(sec, "region", fallback="")
    return out


def aws_card(tag: str, profiles: dict[str, dict]) -> str:
    hits = [(n, p) for n, p in profiles.items() if p["key_tag"] == tag]
    if not hits:
        return (" Blast radius: this key ID isn't in your ~/.aws/credentials, so it's someone else's key, an old one, "
                "or one used from another machine. Find its owner with `aws sts get-access-key-info "
                "--access-key-id <ID>` (shows the account) before rotating.")
    parts = []
    for name, p in hits:
        kind = ("temporary credentials (ASIA…/session token): they expire on their own; to cut them off now, revoke "
                "the role's active sessions in the IAM console" if p["temporary"] else
                "a long-lived IAM user key (AKIA…): it works until someone deactivates it")
        roles = (" Through `source_profile` it can also assume: " + ", ".join(f"`{r}` ({n2})" for n2, r in p["roles"][:6])
                 + "." if p["roles"] else "")
        parts.append(f"profile `{name}` in {p['file']}" + (f" (region {p['region']})" if p["region"] else "")
                     + f", {kind}.{roles}")
    return (" Blast radius (from local files only, AWS wasn't called): this is " + " and ".join(parts)
            + " What it can actually do depends on that user's or role's IAM policies (`aws iam "
              "list-attached-user-policies`).")


def enrich(findings: list[Finding], home: Path) -> None:
    """Add provider steps (and the AWS card) to secret findings. Changes text only, never fingerprints."""
    profiles = None
    for f in findings:
        label = label_of(f)
        if not label:
            continue
        steps = STEPS[label]
        if steps not in f.remediation:
            f.remediation = (f.remediation.rstrip() + " " if f.remediation else "") + "Steps: " + steps
        if label == "AWS access key id":
            m = _TAG.search(f"{f.subject} {f.detail}")
            if m and "Blast radius" not in f.detail:
                if profiles is None:
                    profiles = aws_profiles(home)
                f.detail += aws_card(m.group(1), profiles)
