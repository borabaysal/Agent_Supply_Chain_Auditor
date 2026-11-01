"""Literal secrets in agents' saved session / transcript history.

Agents persist every tool result. When an agent reads ``.env`` or prints a config, the key
lands in a transcript that outlives the original file (and is readable by any later skill
that "summarises past sessions"). This module streams those transcripts through the same
secret patterns as the rest of asca and reports each distinct secret once.

Design
- Never returns secret values: findings carry ``redact()`` previews only.
- Bounded: a per-file byte cap plus a total byte and file budget, newest files first;
  hitting the budget is itself reported, so a partial scan is never a silent pass.
- Streams line by line; cheap substring triggers skip 1 MiB batches with nothing key-like.
- JSON string escapes are undone before matching so ``\\"api_key\\": \\"…\\"`` and
  ``\\n``-joined ``.env`` dumps inside a JSON line are seen like plain text.
- Cursor keeps chats in SQLite (``state.vscdb``); those are read with stdlib ``sqlite3`` in
  read-only URI mode (falling back to ``immutable=1``), chat-related keys only.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from . import secrets
from .model import Finding, Severity, redact

RULE = "secret.session-history"
PERM_RULE = "secret.session-history-permissions"
BUDGET_RULE = "secret.session-history-budget"

MiB = 1024 * 1024
DEFAULT_FILE_CAP = 32 * MiB        # bytes read from any one transcript
DEFAULT_BUDGET = 1024 * MiB        # bytes read across all transcripts
DEFAULT_MAX_FILES = 100_000
EXAMPLES = 5                       # example locations listed per secret
BATCH = 1 * MiB
SMALL_FILE = 4 * MiB               # files up to this size are prefetched whole by worker threads
PREFETCH_THREADS = 8
PREFETCH_BYTES = 64 * MiB          # bound on prefetched-but-unscanned bytes
WINDOW, OVERLAP = 4000, 256        # long (unescaped) lines are scanned in overlapping windows

# Lower-case literals at least one of which occurs in any text that secrets.PATTERNS can match.
# Substring tests run at memory speed; a combined regex was ~200x slower on real transcripts.
TRIGGER_TOKENS = (
    "-----begin", "akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk-", "xox", ":aa",
    "aiza", "_live_", "hf_", "priv", "wallet", "password",
    *(a + sep + b for a, b in (("api", "key"), ("api", "secret"), ("secret", "key"), ("access", "token"),
                               ("auth", "token"), ("client", "secret")) for sep in ("_", "-", "")),
)


def triggered(text: str) -> bool:
    low = text.lower()
    return any(t in low for t in TRIGGER_TOKENS)


CURSOR_KEYS = ("%chat%", "%composer%", "%bubble%", "%aiService%", "%prompt%")

REMEDIATION = ("Rotate the key now: moving it out of .env (or deleting the file the agent read) does not remove the "
               "copies already saved in transcripts. Then delete or redact the old transcripts that contain it, "
               "restrict their permissions (chmod 700 on the history directory), and shorten the agent's "
               "history/transcript retention or disable persistence where the agent offers a setting.")


@dataclass
class Root:
    agent: str           # label shown in findings, e.g. "Hermes sessions"
    path: Path           # directory (or single file) holding history
    suffixes: tuple[str, ...] = ()   # empty = any text file
    kind: str = "text"   # text | sqlite


@dataclass
class _Secret:
    rule: str
    label: str
    preview: str
    root: Root
    count: int = 0
    files: set = field(default_factory=set)
    examples: list = field(default_factory=list)
    roots: set = field(default_factory=set)
    example_files: set = field(default_factory=set)


@dataclass
class Budget:
    total_bytes: int = DEFAULT_BUDGET
    file_bytes: int = DEFAULT_FILE_CAP
    max_files: int = DEFAULT_MAX_FILES
    used_bytes: int = 0
    used_files: int = 0
    skipped_files: int = 0
    skipped_bytes: int = 0
    truncated_files: int = 0

    def exhausted(self) -> bool:
        return self.used_bytes >= self.total_bytes or self.used_files >= self.max_files


def default_roots(home: Path, hermes_home: Path | None, env: dict | None = None) -> list[Root]:
    env = os.environ if env is None else env
    roots: list[Root] = []
    if hermes_home is not None:
        homes = [hermes_home]
        prof = hermes_home / "profiles"
        if prof.is_dir():
            try:
                homes += sorted(p for p in prof.iterdir() if p.is_dir() and not p.is_symlink())
            except OSError:
                pass
        for h in homes:
            tag = "" if h == hermes_home else f" (profile {h.name})"
            roots.append(Root(f"Hermes sessions{tag}", h / "sessions", (".json", ".jsonl")))
            roots.append(Root(f"Hermes cron output{tag}", h / "cron" / "output"))
    claude = Path(env["CLAUDE_CONFIG_DIR"]).expanduser() if env.get("CLAUDE_CONFIG_DIR") else home / ".claude"
    roots.append(Root("Claude Code transcripts", claude / "projects", (".jsonl",)))
    codex = Path(env["CODEX_HOME"]).expanduser() if env.get("CODEX_HOME") else home / ".codex"
    roots.append(Root("Codex sessions", codex / "sessions", (".jsonl",)))
    roots.append(Root("Codex prompt history", codex / "history.jsonl"))
    for user in _cursor_user_dirs(home, env):
        roots.append(Root("Cursor chat store", user / "globalStorage", kind="sqlite"))
        roots.append(Root("Cursor chat store", user / "workspaceStorage", kind="sqlite"))
    return roots


def _cursor_user_dirs(home: Path, env) -> list[Path]:
    cands = [home / ".config" / "Cursor" / "User", home / "Library" / "Application Support" / "Cursor" / "User"]
    if env.get("APPDATA"):
        cands.append(Path(env["APPDATA"]) / "Cursor" / "User")
    return [c for c in cands if c.is_dir()]


# ------------------------------------------------------------------ file discovery

def _files(root: Root, unreadable: list[str]):
    """(path, size, mtime) of candidate history files; symlinks and special files are skipped."""
    p = root.path
    try:
        st = p.lstat()
    except OSError:
        return  # not present: nothing to report
    if stat.S_ISREG(st.st_mode):
        yield p, st.st_size, st.st_mtime
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    want = "state.vscdb" if root.kind == "sqlite" else None
    for dirpath, dirnames, filenames in os.walk(p, onerror=lambda e: unreadable.append(str(e.filename))):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in filenames:
            if want and name != want:
                continue
            if not want and root.suffixes and not name.endswith(root.suffixes):
                continue
            if not want and Path(name).suffix.lower() in secrets.TEXT_SUFFIX_SKIP:
                continue
            fp = Path(dirpath) / name
            try:
                st = fp.lstat()
            except OSError:
                unreadable.append(str(fp))
                continue
            if stat.S_ISREG(st.st_mode):
                yield fp, st.st_size, st.st_mtime


# ------------------------------------------------------------------ text scanning

_BS = "\uffff"


def unescape(line: str) -> str:
    """Undo JSON string escaping (up to 3 levels: tool-call arguments are JSON inside JSON) so values look
    like plain text."""
    for _ in range(3):
        if "\\" not in line:
            break
        line = (line.replace("\\\\", _BS).replace("\\n", "\n").replace("\\r", "\n").replace("\\t", "\t")
                .replace('\\"', '"').replace("\\/", "/").replace(_BS, "\\"))
    return line


def _segments(text: str):
    """(offset, segment) over lines, with long lines split into overlapping windows."""
    pos = 0
    for seg in text.split("\n"):
        if len(seg) <= WINDOW:
            yield pos, seg
        else:
            step = WINDOW - OVERLAP
            for i in range(0, len(seg) - OVERLAP, step):
                yield pos + i, seg[i: i + WINDOW]
        pos += len(seg) + 1


def candidate_lines(text: str):
    """(0-based line index, line) for lines of *text* that contain a trigger token, without a per-line loop."""
    low = text.lower()
    hits: set[int] = set()
    for t in TRIGGER_TOKENS:
        i = low.find(t)
        while i != -1:
            hits.add(i)
            i = low.find(t, i + 1)
    lineno, prev, last_start = 0, 0, -1
    for pos in sorted(hits):
        lineno += text.count("\n", prev, pos)
        prev = pos
        start = text.rfind("\n", 0, pos) + 1
        if start == last_start:
            continue
        last_start = start
        end = text.find("\n", pos)
        yield lineno, text[start: end if end != -1 else len(text)]


def scan_line(raw: str):
    """Yield (rule, label, identity, value) for each secret in one transcript line."""
    text = unescape(raw)
    seen: set[str] = set()
    for off, seg in _segments(text):
        if not triggered(seg):
            continue
        for rule, _sev, label, value, end in secrets.iter_line_secrets(seg, seen):
            if rule == "secret.private-key":
                # the header is identical for every key; identify the key by the body that follows
                body = re.sub(r"\s+", "", text[off + end: off + end + 200])[:120]
                identity = value + body
            else:
                identity = value
            yield rule, label, identity, value


def _record(found: dict, root: Root, where: str, rule: str, label: str, identity: str, value: str, fname: str):
    h = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
    s = found.get(h)
    if s is None:
        preview = "(private key block; no preview)" if rule == "secret.private-key" else redact(value)
        s = found[h] = _Secret(rule, label, preview, root)
    s.count += 1
    s.files.add(fname)
    s.roots.add(root.agent)
    if len(s.examples) < EXAMPLES and fname not in s.example_files:
        s.example_files.add(fname)
        s.examples.append(where)


def _scan_blob(block: bytes, first_line: int, path: Path, root: Root, found: dict) -> None:
    text = block.decode("utf-8", "replace")
    for ln_off, ln in candidate_lines(text):
        for rule, label, ident, value in scan_line(ln):
            _record(found, root, f"{path}:{first_line + ln_off}", rule, label, ident, value, str(path))


def _read_small(path: Path, cap: int) -> bytes:
    """Prefetch helper (runs in a worker thread): whole content of a small file, up to *cap* bytes."""
    with open(path, "rb") as fh:
        return fh.read(cap)


def _scan_text_file(path: Path, size: int, root: Root, budget: Budget, found: dict) -> bool:
    cap = min(budget.file_bytes, max(0, budget.total_bytes - budget.used_bytes))
    if size > cap:
        budget.truncated_files += 1
    with open(path, "rb") as fh:
        head = fh.read(8192)
        if b"\x00" in head:
            return True  # binary: not a transcript
        fh.seek(0)
        read, line_base, carry = 0, 1, b""

        def process(block: bytes, first_line: int) -> None:
            _scan_blob(block, first_line, path, root, found)

        # stream whole lines in ~1 MiB blocks (a single long line is carried until it ends or the cap)
        while read < cap:
            chunk = fh.read(min(BATCH, cap - read))
            if not chunk:
                break
            read += len(chunk)
            data = carry + chunk
            cut = data.rfind(b"\n")
            if cut == -1:
                carry = data
                continue
            block, carry = data[: cut + 1], data[cut + 1:]
            process(block, line_base)
            line_base += block.count(b"\n")
        if carry:
            process(carry, line_base)
    budget.used_bytes += read
    return True


def _sqlite_connect(path: Path) -> sqlite3.Connection:
    base = "file:" + quote(str(path.resolve()))
    last = None
    for q in ("?mode=ro", "?mode=ro&immutable=1"):
        try:
            con = sqlite3.connect(base + q, uri=True, timeout=1.0)
            con.execute("PRAGMA query_only=1")
            con.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            return con
        except sqlite3.Error as exc:
            last = exc
    raise last  # type: ignore[misc]


def _scan_sqlite(path: Path, root: Root, budget: Budget, found: dict) -> None:
    con = _sqlite_connect(path)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cap = min(budget.file_bytes, max(0, budget.total_bytes - budget.used_bytes))
        read = 0
        for table in ("ItemTable", "cursorDiskKV"):
            if table not in tables:
                continue
            where = " OR ".join("key LIKE ?" for _ in CURSOR_KEYS)
            for key, value in con.execute(f"SELECT key, value FROM {table} WHERE {where}", CURSOR_KEYS):
                if value is None:
                    continue
                data = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
                data = data[: max(0, cap - read)]
                read += len(data)
                text = data.decode("utf-8", "replace")
                for i, ln in enumerate(text.split("\n"), 1):
                    for rule, label, ident, val in scan_line(ln):
                        _record(found, root, f"{path}#{key}:{i}", rule, label, ident, val, str(path))
                if read >= cap:
                    budget.truncated_files += 1
                    break
            if read >= cap:
                break
        budget.used_bytes += read
    finally:
        con.close()


# ------------------------------------------------------------------ permissions

def _reach(path: Path) -> tuple[bool, bool]:
    """Can group / other traverse every ancestor of *path*? (A 0700 parent hides 0644 files.)"""
    g = o = True
    for anc in reversed(path.parents):
        try:
            m = anc.stat().st_mode
        except OSError:
            return False, False
        g = g and bool(m & stat.S_IXGRP)
        o = o and bool(m & stat.S_IXOTH)
    return g, o


def audit_permissions(root: Root, limit: int = 200_000) -> list[Finding]:
    """One finding per history root listing transcript files/dirs that group/other can actually read."""
    if os.name != "posix":
        return []
    p = root.path
    try:
        st = p.lstat()
    except OSError:
        return []
    if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        return []
    g, o = _reach(p)
    exposed: list[tuple[str, int]] = []
    world = False
    n = 0
    stack = [(p, st.st_mode, g, o)]
    while stack and n < limit:
        cur, mode, cg, co = stack.pop()
        n += 1
        readable_g = cg and bool(mode & stat.S_IRGRP)
        readable_o = co and bool(mode & stat.S_IROTH)
        if readable_g or readable_o:
            exposed.append((str(cur), mode))
            world = world or readable_o
        if stat.S_ISDIR(mode):
            ng, no = cg and bool(mode & stat.S_IXGRP), co and bool(mode & stat.S_IXOTH)
            if not (ng or no):
                continue  # nobody else can enter: children are private whatever their mode
            try:
                entries = sorted(os.scandir(cur), key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                try:
                    est = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(est.st_mode) or stat.S_ISREG(est.st_mode):
                    stack.append((Path(e.path), est.st_mode, ng, no))
    if not exposed:
        return []
    ex = ", ".join(f"{path} ({stat.filemode(m)})" for path, m in exposed[:EXAMPLES])
    who = "everyone" if world else "group members"
    return [Finding(
        rule=PERM_RULE, category="secrets", severity=Severity.MEDIUM,
        title=f"{root.agent} readable by {who}", location=str(p), subject=root.agent,
        detail=f"{len(exposed)} transcript file(s)/dir(s) are readable by {who} (every parent directory is "
               f"traversable too). Transcripts hold tool output, which often includes keys the agent read. "
               f"Examples: {ex}.",
        remediation=f"chmod -R go-rwx {p}  (and set the agent's umask / history retention so new transcripts "
                    f"stay private)",
    )]


# ------------------------------------------------------------------ entry point

def audit(roots: list[Root], stats: dict, budget: Budget | None = None) -> list[Finding]:
    budget = budget or Budget()
    found: dict[str, _Secret] = {}
    out: list[Finding] = []
    unreadable: dict[str, list[str]] = {}
    files: list[tuple[float, int, int, Path, Root]] = []
    for idx, root in enumerate(roots):
        bad = unreadable.setdefault(root.agent + "\x00" + str(root.path), [])
        for fp, size, mtime in _files(root, bad):
            files.append((-mtime, idx, size, fp, root))
        out += audit_permissions(root)
    files.sort(key=lambda t: (t[0], t[1], str(t[3])))   # newest first: recent keys are likelier to be live
    seen_paths: set[str] = set()
    plan: list[tuple[int, Path, Root]] = []
    for _neg, _idx, size, fp, root in files:
        if str(fp) in seen_paths:
            continue
        seen_paths.add(str(fp))
        plan.append((size, fp, root))

    # Opening many small files is latency-bound (≈1 ms each on container volumes), so small text files are
    # read by a few threads ahead of the scanner. In-flight bytes are bounded; large files stream inline.
    pool = ThreadPoolExecutor(max_workers=PREFETCH_THREADS)
    pending: deque = deque()
    nxt = 0
    inflight = 0
    try:
        while nxt < len(plan) or pending:
            while nxt < len(plan) and len(pending) < 256 and inflight < PREFETCH_BYTES:
                size, fp, root = plan[nxt]
                nxt += 1
                fut = None
                if root.kind == "text" and size <= SMALL_FILE:
                    fut = pool.submit(_read_small, fp, min(size, budget.file_bytes))
                    inflight += size
                pending.append((size, fp, root, fut))
            size, fp, root, fut = pending.popleft()
            if fut is not None:
                inflight -= size
            if budget.exhausted():
                budget.skipped_files += 1
                budget.skipped_bytes += size
                if fut is not None:
                    fut.cancel()
                continue
            budget.used_files += 1
            try:
                if root.kind == "sqlite":
                    _scan_sqlite(fp, root, budget, found)
                elif fut is not None:
                    data = fut.result()
                    cap = min(budget.file_bytes, max(0, budget.total_bytes - budget.used_bytes))
                    if size > cap:
                        budget.truncated_files += 1
                    data = data[:cap]
                    budget.used_bytes += len(data)
                    if b"\x00" not in data[:8192]:
                        _scan_blob(data, 1, fp, root, found)
                else:
                    _scan_text_file(fp, size, root, budget, found)
            except (OSError, sqlite3.Error, ValueError) as exc:
                unreadable[root.agent + "\x00" + str(root.path)].append(f"{fp} ({type(exc).__name__})")
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    for key, bad in sorted(unreadable.items()):
        if not bad:
            continue
        agent, rootpath = key.split("\x00", 1)
        out.append(Finding(
            "scanner.parse-error", "scanner", Severity.MEDIUM, f"{agent}: {len(bad)} history file(s) unreadable",
            rootpath, subject=agent,
            detail=f"These were NOT scanned for secrets (fail closed): {', '.join(bad[:EXAMPLES])}"
                   + (" …" if len(bad) > EXAMPLES else ""),
            remediation="Run the audit as the user that owns the agent's history, or fix the file permissions."))

    for h, s in sorted(found.items(), key=lambda kv: (kv[1].root.agent, kv[1].label, kv[0])):
        sev = Severity.MEDIUM if s.rule == "secret.generic-assignment" else Severity.HIGH
        out.append(Finding(
            rule=RULE, category="secrets", severity=sev,
            title=f"{s.label} saved in agent session history",
            location=str(s.root.path), subject=f"{s.label}:{h[:12]}",
            detail=(f"{s.preview} appears {s.count} time(s) in {len(s.files)} transcript file(s) "
                    f"({', '.join(sorted(s.roots))}). Examples: {', '.join(s.examples)}. Usually the agent's own "
                    f"tool output (it read a .env or printed a config); any later skill or agent that reads past "
                    f"sessions gets the key."),
            remediation=REMEDIATION))

    stats["session_history_files"] = budget.used_files
    stats["session_history_bytes"] = budget.used_bytes
    stats["session_history_secrets"] = len(found)
    stats["session_history_truncated_files"] = budget.truncated_files
    if budget.skipped_files:
        stats["session_history_skipped_files"] = budget.skipped_files
        out.append(Finding(
            BUDGET_RULE, "scanner", Severity.LOW, "Session-history scan stopped at its budget",
            "session-history", subject="budget",
            detail=f"{budget.skipped_files} older transcript file(s) (~{budget.skipped_bytes // MiB} MiB) were not "
                   f"scanned after reading {budget.used_bytes // MiB} MiB / {budget.used_files} files (newest first).",
            remediation="Raise --session-budget-mb / --session-max-files, or prune old transcripts."))
    return out
