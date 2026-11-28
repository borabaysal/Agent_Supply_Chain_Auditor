# Meta Muse: what it can leave on a Mac (research, step 1)

Status: **static findings only, not yet observed on a real install.** Everything below was read from the
public downloads without installing or running them. Paths named here are paths the code *refers to*; whether and
when they're written, and with what permissions, must be confirmed on a throwaway macOS VM (plan at the end). No
asca checks are proposed until then.

Candidate: `research-meta-muse-local-state` (proposed by Bora, 2026-11-27).

## Sources checked (2026-11-27)

| What | Source |
|---|---|
| Product: Muse runs on a hosted "Muse Secure VM"; app on iOS, Android, Mac, web and WhatsApp | https://ai.meta.com/muse/ ; https://about.fb.com/news/2026/09/introducing-muse-personal-ai-agent/ |
| UK launch 24 Nov 2026; ICO and CMA monitoring | https://www.theguardian.com/technology/2026/nov/24/meta-launches-muse-uk-ai-agent-do-christmas-shopping |
| Mac app download | https://ai.meta.com/muse/download/ ("Download for macOS", a direct DMG from Meta's CDN, not the Mac App Store) |
| Chrome extension "Muse from Meta", ~500,000 users | https://chromewebstore.google.com/detail/muse-from-meta/jnakhhjmpmoohbjgfccbccfoifnmbdjd |
| Computer use on Mac ("Muse can now drive any app on your Mac") | https://www.meta.com/blog/meta-connect-2026-everything-we-announced/ |
| How the extension browses (Muse tab group, Esc to take over) | https://www.meta.com/help/superintelligence/2124746764949121/ |

## Artifacts analysed

| Artifact | Version | sha256 |
|---|---|---|
| `Muse-14.1.dmg` (from the download page above) | app 14.1, build 1124369063 | `af5e2bbc7dda9490bb7ddcf5cbedbb5289281fac9b2f8be0fdb428e56ace6985` |
| Chrome extension CRX (Google's update endpoint) | 2.1.12 (manifest v3) | `f4c2525756ec817ea968f526b60de7e9e3eaf9cace0b2921b5bc65e28e54e482` |

Method: the CRX was unpacked and its manifest and JavaScript read as text. The DMG was opened with 7-Zip on Linux;
`Info.plist`, the provisioning profile, the entitlements in the code signature and the printable strings of the
main binary were read. Nothing was executed.

## 1. Mac app (`Muse.app`)

**Identity**
- Bundle ID `com.meta.endo` (internal name "Endo"; "Hatch" is the web/agent client), version 14.1, team
  `V9WTTPBFK9` (Meta Platforms, Inc.), Developer ID distribution. Requires macOS 15 or later.
- Not sandboxed per the entitlements read (no `com.apple.security.app-sandbox`); keychain access group `V9WTTPBFK9.*`.
  To confirm with `codesign` on the VM.
- Updates itself with Sparkle from `https://www.facebook.com/endo/release/appcast.xml?channel=production`
  (EdDSA-signed appcast). Ships `EndoCrashpadHandler` (crash reporter).
- URL schemes: `hatch://`, `endo-window://`.

**Permission prompts it declares** (`Info.plist` usage strings): Apple Events/Automation ("send messages and emails,
manage notes, organize your inbox"), Calendars (full access), Reminders (full access), Contacts (read and update),
Photos ("syncs your photos and videos"), Desktop, Documents and Downloads folders, network and removable volumes,
microphone, camera, speech recognition, location.

**Computer use** (strings in the binary): needs Accessibility and Screen Recording; "Always allow covers computer
control on this Mac, including app launches, clicks, and keystrokes. It has no time limit." There is a setting
**"Allow computer use while this Mac is locked."** Full Disk Access is mentioned as an option for file access.

**Local paths the code names** (to confirm on the VM):

| Path | What the strings suggest |
|---|---|
| `~/Library/Application Support/com.meta.prototypes.endo.tokens` | token storage (there's also a `.migration` variant; strings mention access/refresh tokens and "Migrated the session to a refresh token") |
| `~/Library/Application Support/Hatch/` and `.../Hatch/recipient-send-receipts` | app data |
| `~/Library/Caches/com.meta.endo/DebugLogs/` | debug logs |
| `~/Library/Caches/com.meta.endo/PrivateScreenRecordings` | screen recordings |
| `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` + host `com.meta.muse.endo` | the app registers itself as the Chrome extension's native host (manifest not bundled, so it's written at run time) |
| `FBAnalyticsUnifiedEventStore.sqlite` | analytics event store |
| a **built-in browser** (Chromium; strings for `--user-data-dir=`, "Chromium Safe Storage") | separate from your Chrome |

**Other apps' data it can read** (strings; each behind a connector or permission):
- **WhatsApp desktop**: a "local WhatsApp connector" reads messages from the installed app's `ChatStorage.sqlite`
  (paths under `~/Library/Containers/net.whatsapp.WhatsApp`, `~/Library/Group Containers/group.net.whatsapp.*`);
  "respects WhatsApp's Advanced Chat Privacy setting".
- **Apple Notes**: reads `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` directly.
- Also named: `~/Library/Application Support/AddressBook`, `CallHistoryDB`, Safari `CloudTabs.db`, and the profile
  folders of Chrome, Chrome Beta/Canary/Dev, Brave, Edge, Arc, Chromium and Firefox.
- **Chrome profile import**: copies Chrome **cookies, history and saved passwords** into the built-in browser. macOS
  shows a Keychain prompt to read Chrome's encryption key; passwords go to a "Secure store"; cookies "overwrite the
  built-in browser's cookies and site data".
- It reads the user TCC database path (`~/Library/Application Support/com.apple.TCC/TCC.db`), likely to check its own
  grants.

**Guardrail visible in the strings:** file tools reject "credential files (keychains, `~/.ssh`, `~/.gnupg`, `~/.aws`,
a password store)".

**Persistence:** uses `SMAppService` and links to Login Items settings, so a login item or background item is likely.
No LaunchAgent plist is bundled.

There are also Windows strings ("computer use on this Windows PC", "Run on startup"), so a Windows build seems to
exist or be planned. Not checked.

## 2. Chrome extension "Muse from Meta" 2.1.12

**Permissions**: `debugger`, `tabs`, `tabGroups`, `webNavigation`, `storage`, `alarms`, `declarativeNetRequest`,
`nativeMessaging`, `sidePanel`, `contextMenus`. Host permissions only for Meta's own hosts (`muse.ai`,
`agent.meta.ai`, `hatch.meta.ai`, `hatch.club`, `hatch.ecto1.ai`, `production.museai.com`), which can also message it
(`externally_connectable`).

What that means:
- **`debugger` is the big one.** With it the extension drives a tab through the Chrome DevTools Protocol, so it
  doesn't need host permissions for the sites it works on. The code uses `Runtime.evaluate` / `callFunctionOn` (run
  JavaScript in the page), `Input.dispatchMouseEvent` / `dispatchKeyEvent` (click and type),
  `Page.startScreencast` (stream the page as images) and `Page.addScriptToEvaluateOnNewDocument`. Chrome shows a
  "started debugging this browser" bar while it's attached.
- **Scope in code:** it attaches to tabs it owns (the Muse tab group / "shared tabs", stored as `muse.sharedTabs`). A
  server-supplied site blocklist is cached in IndexedDB (`muse-blocklist`) and enforced with session
  `declarativeNetRequest` rules. A probe script checks whether passkeys (WebAuthn) are usable on a page.
- **`nativeMessaging` → `com.meta.muse.endo`**, the Mac app. That's the bridge from the desktop app into your real
  Chrome.
- **Local storage:** `chrome.storage.local` keys include `muse.clientId`, `muse.pairing`, `muse.sharedTabs`,
  `muse.status`, `muse.lastMuse` and others. On disk that's the Chrome profile's
  `Local Extension Settings/jnakhhjmpmoohbjgfccbccfoifnmbdjd` (LevelDB). Its session key pair is generated as a
  **non-extractable** X25519 WebCrypto key, which is good practice. Whether any auth token sits in that storage needs
  the VM.

## 3. Questions only a real install can answer

1. Which of the paths above exist after sign-in and one task, with what owner and permissions (0600/0700, or readable
   by other local users)?
2. Is `com.meta.prototypes.endo.tokens` a file or a folder? Plain text, JSON or encrypted? Or are tokens in the
   Keychain (and under which service names)?
3. Is there a local conversation or memory store ("conversation cache" is named), and is it encrypted?
4. What does `PrivateScreenRecordings` hold after a computer-use task, and how long does it stay?
5. The exact native-messaging manifest: which binary it launches and which extension origins it allows.
6. Login and background items registered (`sfltool dumpbtm`), and TCC grants after onboarding.
7. The built-in browser's profile location and whether imported cookies are readable there.
8. Does the extension's LevelDB hold a bearer token after pairing?

## 4. VM test plan (Bora runs, pastes output back; shapes only, never values)

Requirements: macOS **15+** VM (the app requires 15.0), a **test** Meta account, no real payment details, no real
Chrome profile. Run in Terminal; every command prints paths, sizes, permissions or names, not contents.

```bash
# 0. Baseline before installing
touch /tmp/muse-start; sleep 1
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null > /tmp/muse-launch-before.txt

# 1. Install: open Muse-14.1.dmg, drag Muse to Applications, sign in with the TEST account, grant the prompts
#    it asks for during onboarding, connect ONE test connector, run ONE small task (e.g. "create a note named test").
#    Install the Chrome extension, pair it, run one browser task.

# 2. Signature and sandbox
codesign -dv --verbose=2 /Applications/Muse.app 2>&1 | grep -E 'Identifier|TeamIdentifier|flags|Runtime|Authority' 
codesign -d --entitlements - /Applications/Muse.app 2>/dev/null | grep -E 'sandbox|keychain|automation|disable|allow' 
spctl -a -vv /Applications/Muse.app 2>&1

# 3. Every file written since the baseline under ~/Library (paths, permissions and size only)
find ~/Library -newer /tmp/muse-start \( -ipath '*endo*' -o -ipath '*hatch*' -o -ipath '*muse*' -o -ipath '*com.meta*' \) \
  -exec stat -f '%Sp %Su %z %N' {} \; 2>/dev/null | sed "s#$HOME#~#" | head -300

# 4. The named locations
for p in "Application Support/com.meta.prototypes.endo.tokens" "Application Support/Hatch" \
         "Caches/com.meta.endo/DebugLogs" "Caches/com.meta.endo/PrivateScreenRecordings" \
         "Application Support/Google/Chrome/NativeMessagingHosts/com.meta.muse.endo.json"; do
  echo "== $p"; ls -la@ "$HOME/Library/$p" 2>&1 | sed "s#$HOME#~#" | head -20; done
file ~/Library/Application\ Support/com.meta.prototypes.endo.tokens* 2>/dev/null

# 5. Shape of the token store if it is a file (key names and value lengths only)
python3 - <<'EOF'
import json, os, glob
for p in glob.glob(os.path.expanduser("~/Library/Application Support/com.meta.prototypes.endo.tokens*")):
    if os.path.isfile(p):
        raw = open(p, "rb").read()
        print(p.replace(os.path.expanduser("~"), "~"), len(raw), "bytes")
        try:
            d = json.loads(raw)
            print("  JSON keys:", {k: (type(v).__name__, len(str(v))) for k, v in (d.items() if isinstance(d, dict) else [])})
        except Exception:
            print("  not JSON; printable ratio:", round(sum(32 <= b < 127 for b in raw) / max(1, len(raw)), 2))
EOF

# 6. Native messaging manifest (no secrets in it: binary path + allowed extension origins)
cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.meta.muse.endo.json 2>/dev/null

# 7. Keychain item NAMES only (no -d flag: secrets are not printed)
security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null \
  | grep -E '"(svce|labl)"<blob>=' | grep -i -E 'meta|muse|endo|hatch|chromium' | sort -u

# 8. Login / background items and LaunchAgents
sudo sfltool dumpbtm 2>/dev/null | grep -i -B2 -A8 -E 'meta|muse|endo' | grep -E 'Name|Identifier|URL|Disposition|Type'
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null > /tmp/muse-launch-after.txt
diff /tmp/muse-launch-before.txt /tmp/muse-launch-after.txt

# 9. Privacy grants (needs Full Disk Access for Terminal)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service, client, auth_value from access where client like '%meta%' or client like '%endo%';" 2>&1
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service, client, auth_value from access where client like '%meta%' or client like '%endo%';" 2>&1

# 10. Extension storage on disk (file names, sizes, and key NAMES only)
EXT=~/Library/Application\ Support/Google/Chrome/Default/Local\ Extension\ Settings/jnakhhjmpmoohbjgfccbccfoifnmbdjd
ls -la "$EXT" 2>&1 | sed "s#$HOME#~#"
cat "$EXT"/*.log "$EXT"/*.ldb 2>/dev/null | strings | grep -oE 'muse\.[A-Za-z.]+|hatch\.[A-Za-z.-]+' | sort -u
cat "$EXT"/*.log "$EXT"/*.ldb 2>/dev/null | strings | grep -c -E 'eyJ[A-Za-z0-9_-]{20,}'   # JWT-shaped values: count only

# 11. Listening ports
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -i -E 'muse|endo|chromium' 
```

Paste the output back with anything that looks like a value (emails, tokens) replaced by `<x>`.

## 5. What could become asca checks (only after step 4, and only with Bora's go-ahead)

- Inventory: Muse app version and Developer ID team, and the Chrome extension's version and permissions. That
  argues for a separate browser-extension inventory candidate: asca only reads IDE extensions today, and this is a
  500k-user extension with `debugger` + `nativeMessaging`.
- macOS privacy grants to `com.meta.endo` (asca's TCC check already reports Full Disk Access and Accessibility for
  agent apps; add Screen Recording and the "while locked" computer-use setting if it's readable locally).
- Token store or local memory readable by other users, or tokens in plain text (fingerprints only).
- Chrome cookies or passwords imported into the built-in browser (an extra copy of your sessions).
