"""Content rules for skill files: prompt injection, hidden text, credential theft, exfiltration
and ClickFix-style malicious installs (the ClawHavoc / AMOS playbook).

Rules are regexes over text. They're tripwires for a human review, not a verdict. The scanner
combines them per skill (credential access + an outbound sink = critical) and adjusts
severity for documentation context, so a security tutorial that *quotes* an attack isn't
treated like a skill that *performs* it. Every rule needs an `explain` that tells the user
why it matters in plain language.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


@dataclass(frozen=True)
class Rule:
    id: str
    category: str      # prompt-injection | hidden-content | credential-access | exfiltration | malicious-install
    severity: Severity
    pattern: re.Pattern
    title: str
    explain: str
    code_only: bool = False      # only in scripts (not prose)
    prose_severity: Severity | None = None   # different severity when found in markdown prose


def R(id, cat, sev, rx, title, explain, *, flags=re.I, code_only=False, prose=None):
    return Rule(id, cat, sev, re.compile(rx, flags), title, explain, code_only, prose)


RULES: list[Rule] = [
    # ---------------------------------------------------------------- prompt injection
    R("inject.override", "prompt-injection", H,
      r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|every\s+)?(of\s+)?(the\s+|your\s+|my\s+)?"
      r"(previous|prior|above|earlier|preceding|system|original|existing)\s+"
      r"(instructions?|prompts?|rules|directives|guidelines|messages?|context)",
      "Tells the agent to ignore its instructions",
      "Classic prompt injection: a skill has no reason to cancel the agent's system prompt."),
    R("inject.role-tag", "prompt-injection", H,
      r"(<\|?im_start\|?>\s*system|<\|system\|>|^\s*<system>|\[/?SYSTEM\]|\[INST\]|BEGIN SYSTEM PROMPT|"
      r"you are now (in )?(developer|dan|jailbreak|god|unrestricted) mode)",
      "Fake system/role markers",
      "Spoofed chat-template or 'system' markers try to make skill text look like a higher-priority message.",
      flags=re.I | re.M),
    R("inject.conceal", "prompt-injection", H,
      r"(without\s+(the\s+)?(user'?s?|human'?s?|owner'?s?)\s+(knowledge|consent|approval|permission|noticing)|"
      r"\b(do\s*n[o']?t|never)\s+(tell|inform|notify|alert|mention\s+(this|it)\s+to|reveal\s+(this|it)\s+to)\s+"
      r"(the\s+)?(user|human|operator|owner)\b(?!\s+to\b)|"
      r"\b(hide|conceal|keep)\s+(this|these|it|that)\s+(secret\s+)?from\s+(the\s+)?(user|human|operator|owner)|"
      r"\bsilently\s+(send|upload|post|forward|transmit|exfiltrate|copy)\b)",
      "Tells the agent to hide actions from the user",
      "Legitimate skills don't need to keep things from you. Concealment plus any network or file action "
      "is how data theft gets past a human in the loop."),
    R("inject.approval-bypass", "prompt-injection", H,
      r"\b(bypass|circumvent|disable|turn\s+off|switch\s+off|get\s+around|work\s+around)\s+(the\s+|any\s+|all\s+|"
      r"your\s+)?(user'?s?\s+)?(approval|confirmation|permission|consent)\s*(prompts?|checks?|system|dialogs?|"
      r"requests?|gates?)|\b(bypass|circumvent|evade)\s+(the\s+|any\s+|your\s+)?(safety|security|guardrails?|"
      r"sandbox|content\s+filter|skills?\s+guard)",
      "Tries to switch off approvals or safety checks",
      "Disabling the approval prompt removes the one moment where you'd notice a harmful command."),
    R("inject.yolo-flag", "prompt-injection", M,
      r"(--dangerously-skip-permissions|--yolo\b|--always-approve\b|--full-auto\b|HERMES_YOLO|"
      r"approvals?\s*[:=]\s*['\"]?(off|never|none)\b)",
      "Runs an agent with approvals switched off",
      "A skill script that launches an agent with every approval disabled can do anything without asking.",
      prose=L),
    R("inject.persistence", "prompt-injection", M,
      r"\b(add|write|append|save|insert|put|inject)\b[^\n]{0,40}\b(to|into|in)\s+(your\s+|the\s+)?"
      r"(MEMORY\.md|USER\.md|AGENTS\.md|CLAUDE\.md|SOUL\.md|GEMINI\.md|\.cursorrules|system\s+prompt|"
      r"other\s+skills?|every\s+skill|all\s+skills)",
      "Writes itself into memory, AGENTS.md or other skills",
      "A skill that edits the agent's standing instructions keeps influencing it after you remove the skill."),
    R("inject.tool-hijack", "prompt-injection", M,
      r"(\b(always|must)\s+(use|call|invoke|run|load|prefer)\s+this\s+(skill|tool|plugin)\s+"
      r"(first|before|instead|for\s+(every|all|any))|\bbefore\s+(responding|answering)\s+(to\s+)?(any|every)\b|"
      r"\bbefore\s+(using\s+)?any\s+other\s+(tool|skill|action))",
      "Claims priority over other tools",
      "Skills that insist on running first are trying to sit in front of everything the agent does."),
    R("inject.secret-ask", "prompt-injection", H,
      r"\b(paste|send|share|give|enter|type|provide|reply\s+with)\s+(me\s+|us\s+)?(your\s+|the\s+)?"
      r"(seed\s+phrase|recovery\s+phrase|secret\s+recovery|mnemonic|private\s+key|wallet\s+password|"
      r"keychain\s+password|login\s+password|system\s+password|mac\s+password|sudo\s+password)",
      "Asks for seed phrases, private keys or passwords",
      "No skill needs your wallet seed, private key or system password typed into a chat."),

    # ---------------------------------------------------------------- credential access
    R("cred.ssh-cloud", "credential-access", M,
      r"(~|\$HOME|\$\{HOME\}|%USERPROFILE%|/home/\w+|/Users/\w+|os\.path\.expanduser\(['\"]~)?/?"
      r"\.(ssh/(id_[a-z0-9]+|authorized_keys|known_hosts|config)|aws/credentials|config/gcloud|kube/config|"
      r"docker/config\.json|git-credentials|netrc|npmrc|pypirc|azure/|gnupg)",
      "Reads SSH keys or cloud/registry credentials",
      "These files unlock your servers, cloud accounts and package publishing.", prose=L),
    R("cred.agent-store", "credential-access", M,
      r"\.(hermes|openclaw|clawdbot|moltbot|claude|codex|gemini|config/goose)/[^\s'\"`)]*"
      r"(\.env\b|auth\.json|credentials|openclaw\.json|\.credentials\.json|oauth|tokens?\b)",
      "Reads an agent's credential store",
      "Agent .env/auth files hold every provider API key and bot token the agent uses.", prose=L),
    R("cred.os-store", "credential-access", C,
      r"(security\s+(dump-keychain|export\b)|security\s+find-(generic|internet)-password(?![^\n]*\s-s\s)|"
      r"login\.keychain(-db)?\b|\bKeychains/|CredEnumerate|cmdkey\s+/list|vaultcmd\s+/list|DPAPI|"
      r"CryptUnprotectData)",
      "Dumps the OS keychain / credential manager",
      "Dumping the keychain (or reading items without naming the one you need) is what infostealers like AMOS do.",
      prose=H),
    R("cred.os-item", "credential-access", L,
      r"(security\s+find-(generic|internet)-password[^\n]*\s-s\s|secret-tool\s+lookup|Get-StoredCredential)",
      "Reads a named keychain item",
      "Reading one named secret is normal for a credential helper; listed so you know where the skill's token "
      "comes from."),
    R("cred.browser-wallet", "credential-access", C,
      r"((Chrome|Chromium|Brave[- ]Browser|Microsoft[/ ]Edge|Opera|Vivaldi|Firefox|Profiles)[^\n]{0,80}"
      r"(Login Data|Local State|Web Data|Cookies|key4\.db|logins\.json)|Cookies\.binarycookies|wallet\.dat|"
      r"Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|"
      r"(?i:(exodus|electrum|atomic\s*wallet|metamask|phantom|trust\s*wallet|ledger\s+live)[^\n]{0,40}"
      r"(wallet|vault|seed|keystore|leveldb))|Telegram Desktop/tdata|/tdata\b)",
      "Reads browser passwords/cookies or crypto wallets",
      "Browser credential databases and wallet files are the main targets of crypto-stealer skills.",
      flags=0, prose=H),
    R("cred.env-dump", "credential-access", M,
      r"(\bprintenv\b(?!\s+[A-Z_]{2,})|(?<![\w-])env\s*(\||>(?!\s*/dev/null))|\bset\s*\|\s*(curl|nc|base64)|"
      r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(keys|entries|values)\(\s*process\.env\s*\)|"
      r"json\.dumps\(\s*(dict\()?\s*os\.environ|str\(\s*os\.environ\s*\)|"
      r"Get-ChildItem\s+env:|\bgci\s+env:|\bcat\s+[^\n|;]*\.env\b)",
      "Dumps all environment variables or .env files",
      "The whole environment usually contains API keys; reading all of it is rarely needed.", code_only=False,
      prose=L),

    # ---------------------------------------------------------------- exfiltration
    R("exfil.capture-host", "exfiltration", H,
      r"\b(webhook\.site|requestbin\.(com|net)|pipedream\.net|hookbin\.com|beeceptor\.com|interact\.sh|"
      r"[a-z0-9]+\.oast\.(fun|pro|me|site|live|online)|burpcollaborator\.net|canarytokens\.(com|org)|"
      r"[a-z0-9-]+\.requestcatcher\.com)",
      "Sends data to a request-capture service",
      "These services exist to collect whatever is sent to them, a common exfiltration endpoint."),
    R("exfil.tunnel", "exfiltration", M,
      r"\b([a-z0-9-]+\.ngrok(-free)?\.(io|app|dev)|[a-z0-9-]+\.trycloudflare\.com|[a-z0-9-]+\.loca\.lt|"
      r"[a-z0-9-]+\.serveo\.net)",
      "Talks to an ad-hoc tunnel URL",
      "Throwaway tunnel hostnames hide who is on the other end.", prose=L),
    R("exfil.paste-chat", "exfiltration", M,
      r"(discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot[^\s/]*/send(Document|Message)|"
      r"pastebin\.com/api|rentry\.(co|org)|glot\.io|transfer\.sh|file\.io|0x0\.st|paste\.ee|hastebin|"
      r"termbin\.com|bashupload\.com|temp\.sh|gofile\.io)",
      "Posts to a paste site, file drop or chat webhook",
      "Paste sites and chat webhooks are easy, anonymous drop points for stolen data.", prose=L),
    R("exfil.raw-ip", "exfiltration", H,
      r"\b(https?|wss?|ftp)://(?!(127\.|10\.|0\.0\.0\.0|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.))"
      r"\d{1,3}(\.\d{1,3}){3}(:\d+)?",
      "Contacts a raw IP address",
      "Skipping DNS to talk to a bare public IP is typical of malware command-and-control."),
    R("exfil.upload", "exfiltration", H,
      r"(curl\b[^\n]*\s(-F|--form|-T|--upload-file|--data-binary\s+@|-d\s+@|--data\s+@)|"
      r"\bnc(at)?\s+(-[a-z]*\s+)*[\w.-]+\s+\d{2,5}\s*<|/dev/tcp/|/dev/udp/|"
      r"Invoke-WebRequest[^\n]*-Method\s+Post[^\n]*-InFile)",
      "Uploads files to a remote host",
      "Uploading local files is exactly how stolen credentials leave the machine.", flags=0, prose=M),

    # ---------------------------------------------------------------- malicious install / ClickFix
    R("exec.obfuscated", "malicious-install", C,
      r"(base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|"
      r"echo\s+['\"]?[A-Za-z0-9+/=]{40,}['\"]?\s*\|\s*base64\s+(-d|--decode|-D)|"
      r"eval\s*\(\s*(atob|Buffer\.from|unescape|String\.fromCharCode)|"
      r"exec\s*\(\s*(base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex|marshal\.loads|__import__)|"
      r"eval\s*\(\s*compile\(|FromBase64String\([^\n]*(iex|Invoke-Expression)|"
      r"(iex|Invoke-Expression)[^\n]*FromBase64String|powershell[^\n]*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,})",
      "Decodes and runs a hidden payload",
      "Encoding a command and executing it on the fly hides what actually runs, the ClawHavoc dropper pattern."),
    R("exec.gatekeeper", "malicious-install", C,
      r"(xattr\s+(-[a-z]*d[a-z]*\s+com\.apple\.quarantine|-c\b|-cr\b|-rc\b)|spctl\s+--master-disable|"
      r"Set-MpPreference\s+-Disable|Add-MpPreference\s+-Exclusion|csrutil\s+disable|"
      r"Unblock-File|Set-ExecutionPolicy\s+(Bypass|Unrestricted))",
      "Removes macOS quarantine / disables antivirus",
      "Stripping Gatekeeper's quarantine flag or Defender lets an unsigned binary run without any warning."),
    R("exec.password-archive", "malicious-install", H,
      r"(\b(extract|unzip|unpack|decompress|open)\b[^\n]{0,80}\b(pass(word)?|pwd|pw)\s*(is\s*)?[:=]?\s*"
      r"[`'\"][^`'\"\s]{2,40}[`'\"]|unzip\s+-P\s+\S+|7z\s+x\s+[^\n]*-p\S+)",
      "Ships a password-protected archive",
      "Passwords on archives are used to stop antivirus from scanning the payload (seen in ClawHavoc skills)."),
    R("exec.password-prompt", "malicious-install", C,
      r"(osascript[^\n]*(display\s+dialog|with\s+hidden\s+answer)|with\s+hidden\s+answer|"
      r"Get-Credential[^\n]*-Message|zenity\s+--password|kdialog\s+--password|sudo\s+-S\b)",
      "Pops a fake password prompt",
      "A dialog asking for your Mac/system password is how AMOS steals it."),
    R("exec.reverse-shell", "malicious-install", C,
      r"(bash\s+-i\s*>&\s*/dev/tcp|\bnc(at)?\b[^\n]*\s-(e|c)\s+/bin/(ba)?sh|socat\b[^\n]*exec:|"
      r"mkfifo\s+[^\n]*\|\s*/bin/(ba)?sh|python[23]?\s+-c\s+['\"]import\s+socket[^\n]*subprocess|"
      r"New-Object\s+System\.Net\.Sockets\.TCPClient)",
      "Opens a reverse shell",
      "A reverse shell hands an attacker interactive control of your machine."),
    R("exec.pipe-shell", "malicious-install", M,
      r"((curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(-?\w+\s+)?(ba|z|da|fi|k)?sh\b|"
      r"(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b|"
      r"\b(bash|sh|zsh)\s+-c\s+[\"']?\$\((curl|wget)|"
      r"\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*iex\b|"
      r"\biex\s*\(\s*(New-Object\s+Net\.WebClient|iwr|irm))",
      "Pipes a downloaded script straight into a shell",
      "Whatever the server returns runs immediately, with no chance to read it first.", prose=L),
    R("exec.download-binary", "malicious-install", M,
      r"https?://[^\s)'\"`>]+\.(exe|dmg|pkg|msi|scr|bat|cmd|ps1|vbs|jar|appimage)\b",
      "Downloads an executable",
      "Skills shouldn't need you to download and run binaries, the 'fake prerequisite' trick."),
    R("exec.download-archive", "malicious-install", M,
      r"https?://[^\s)'\"`>]+\.(zip|7z|rar)\b(?=[^\n]{0,200}\b(run|execute|launch|install|open\s+the|"
      r"double[- ]click|extract\s+(it\s+)?with)\b)",
      "Downloads an archive and tells you to run what's inside",
      "Downloading an archive and running its contents is how ClawHavoc delivered its stealer on Windows."),
    R("exec.persistence", "malicious-install", M,
      r"(crontab\s+-[le]?\s*[^\n]*(curl|wget|base64|nc\b)|\(crontab\s+-l|~/Library/LaunchAgents|"
      r"launchctl\s+(load|bootstrap)|schtasks\s+/create|CurrentVersion\\\\?Run\b|"
      r"systemctl\s+--user\s+enable|>>\s*~/\.(bashrc|zshrc|profile|bash_profile))",
      "Installs itself to run at login or on a schedule",
      "Persistence keeps malicious code running after the skill is gone.", prose=L),
]

# Prose/markdown file suffixes (everything else that is text is treated as code)
PROSE_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".mdx", ""}
CODE_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".psm1", ".bat", ".cmd",
                 ".rb", ".pl", ".php", ".applescript", ".scpt", ".vbs", ".lua", ".go", ".rs", ".java"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env"}

# Domains whose install one-liners are widely used and published by the vendor itself.
TRUSTED_INSTALL_HOSTS = {
    "openclaw.ai", "hermes-agent.nousresearch.com", "astral.sh", "sh.rustup.rs", "rustup.rs", "bun.sh",
    "deno.land", "get.docker.com", "raw.githubusercontent.com/Homebrew", "brew.sh", "install.python-poetry.org",
    "get.pnpm.io", "claude.ai", "ollama.com", "nodejs.org", "github.com/nvm-sh", "raw.githubusercontent.com/nvm-sh",
    "cli.github.com", "sdk.cloud.google.com", "awscli.amazonaws.com", "tailscale.com", "fly.io", "railway.app",
    "vercel.com", "supabase.com", "uv.astral.sh", "pyenv.run", "get.sdkman.io", "install.determinate.systems",
}

# Hidden-content characters
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
ZERO_WIDTH = re.compile("[\u200B\u200C\u200D\u2060\u180E]|(?<!^)\uFEFF")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
AGENT_DIRECTED = re.compile(
    r"(\b(assistant|ai|agent|llm|model|claude|hermes)\s*[:,]\s|\byou\s+(must|should|will|are\s+now|need\s+to)\b|"
    r"\bignore\s+(all|any|the|previous|prior|above)\b|\bsystem\s+prompt\b|\bdo\s+not\s+(tell|mention|show)\b|"
    r"\b(curl|wget)\s+\S|\brun\s+the\s+following\b|\bexecute\s+(this|the)\b|\bsend\s+(the|all|your)\s+\w+\s+to\b)",
    re.I)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
