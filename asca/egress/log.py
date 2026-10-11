"""Append-only JSONL egress log, one file per UTC day, mode 0600.

Privacy rules, enforced here so no caller can bypass them:
- never record headers, bodies, cookies, auth, or query strings;
- plain-HTTP paths are kept without the query/fragment and truncated;
- HTTPS is tunnelled (CONNECT), so only host:port and byte counts are known.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

PATH_MAX = 160


def clean_path(path: str) -> str:
    p = path.split("?", 1)[0].split("#", 1)[0]
    return p if len(p) <= PATH_MAX else p[: PATH_MAX - 1] + "…"


class EgressLog:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self._day = None
        self._fh = None

    def _file_for(self, day: str):
        if day != self._day or self._fh is None:
            if self._fh:
                self._fh.close()
            path = self.dir / f"egress-{day}.jsonl"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._fh = os.fdopen(fd, "a", encoding="utf-8", buffering=1)  # line-buffered
            self._day = day
        return self._fh

    def write(self, record: dict) -> None:
        if "path" in record and record["path"]:
            record["path"] = clean_path(record["path"])
        ts = record.setdefault("ts", time.time())
        day = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
        self._file_for(day).write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def iter_records(directory: Path, since: float, until: float):
    """Records with since < ts <= until, across day files. Corrupt lines are counted, not fatal."""
    directory = Path(directory)
    bad = 0
    if not directory.is_dir():
        return
    start = datetime.fromtimestamp(max(since, 0), timezone.utc).strftime("%Y-%m-%d")
    for f in sorted(directory.glob("egress-*.jsonl")):
        if f.stem[len("egress-"):] < start:
            continue
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                ts = r.get("ts", 0)
                if since < ts <= until:
                    yield r
    if bad:
        yield {"kind": "_corrupt", "count": bad, "ts": until}


def prune(directory: Path, keep_days: int, now: float | None = None) -> int:
    now = now or time.time()
    cutoff = datetime.fromtimestamp(now - keep_days * 86400, timezone.utc).strftime("%Y-%m-%d")
    removed = 0
    for f in Path(directory).glob("egress-*.jsonl"):
        if f.stem[len("egress-"):] < cutoff:
            f.unlink(missing_ok=True)
            removed += 1
    return removed
