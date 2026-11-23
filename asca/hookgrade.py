"""Grade a hook command by what it runs and which way data flows (user-level hooks)."""
from __future__ import annotations

import re

from .model import Severity

_POS = r"(?:^|[\s;|&(`$\"'])"            # command position: start, after a separator, quote or subshell
FETCH_TOOL = re.compile(_POS + r"(curl|wget|ncat|nc|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|bitsadmin|"
                        r"certutil)(?=\s)", re.I)
# a shell that reads its script from stdin (`| sh`, `| bash -s`), not one that runs a file (`| sh x.sh`)
PIPE_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\s*(?:$|[;&|)\"']|-s\b|-\s)|\|\s*(?:iex|Invoke-Expression)\b",
                        re.I)
DECODE_RUN = re.compile(r"base64\s+(?:-d|--decode|-D)\b[^;\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|FromBase64String",
                        re.I)
RAW_SOCKET = re.compile(r"/dev/(?:tcp|udp)/|" + _POS + r"(?:nc|ncat)\s[^;\n]*\s-e\s", re.I)
URL = re.compile(r"https?://([^/\s'\"`:]+|\[[0-9a-f:]+\])", re.I)
LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)$", re.I)
SAVED = re.compile(r"\s(?:-o|-O|--output|-OutFile)\s+(['\"]?)([^\s'\";|&]+)\1|>\s*(['\"]?)([^\s'\";|&]+)\3")


def _runs(cmd: str, path: str) -> bool:
    p = re.escape(path)
    return bool(re.search(_POS + r"(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby|source|\.|chmod\s+[^;|&]*)\s+" + p
                          + r"(?:\s|$|[;&|])", cmd)
                or re.search(r"(?:^|[;&|]\s*)" + p + r"(?:\s|$|[;&|])", cmd))


def grade(cmd: str) -> tuple[Severity, str]:
    """(severity, reason). HIGH: downloads and runs code, decodes into a shell, or opens a raw socket.
    MEDIUM: talks to a non-local host. INFO: everything else."""
    m = RAW_SOCKET.search(cmd)
    if m:
        return Severity.HIGH, f"opens a raw network connection (`{m.group(0).strip()}`)"
    if DECODE_RUN.search(cmd):
        return Severity.HIGH, "decodes base64 and runs it"
    tool = FETCH_TOOL.search(cmd)
    if tool:
        hosts = [h for h in URL.findall(cmd)]
        if hosts and all(LOOPBACK.match(h) for h in hosts):
            return Severity.INFO, "talks only to a service on this machine"
        if PIPE_SHELL.search(cmd):
            return Severity.HIGH, f"downloads with `{tool.group(1)}` and pipes it into a shell"
        for s in SAVED.finditer(cmd):
            path = s.group(2) or s.group(4)
            if path and path != "-" and _runs(cmd, path):
                return Severity.HIGH, f"downloads with `{tool.group(1)}` to `{path}` and runs it"
        return Severity.MEDIUM, f"talks to the network with `{tool.group(1)}`"
    return Severity.INFO, ""
