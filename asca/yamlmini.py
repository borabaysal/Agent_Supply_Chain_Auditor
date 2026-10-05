"""Tiny block-YAML reader for agent config files (stdlib only).

The auditor deliberately has zero third-party dependencies — a supply-chain
auditor that pulls an unpinned YAML library would be ironic. If PyYAML is
importable we use it (safe_load only); otherwise this parser handles the block
subset Hermes writes: nested mappings, ``- item`` lists, scalars, quoted
strings, comments, and inline ``[]`` / ``{}`` / simple flow lists.

Anything it cannot parse raises ``YamlError``; callers turn that into a
finding instead of silently treating the file as empty (fail closed).
"""
from __future__ import annotations

import json
import re


class YamlError(ValueError):
    pass


def load(text: str):
    try:  # pragma: no cover - depends on environment
        import yaml  # type: ignore
    except ImportError:
        return _MiniParser(text).parse()
    try:  # pragma: no cover
        return yaml.safe_load(text)
    except Exception as exc:  # pragma: no cover
        raise YamlError(str(exc)) from exc


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(raw: str):
    s = raw.strip()
    if s == "":
        return None
    if (s[0] == s[-1] == '"') and len(s) >= 2:
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s[1:-1]
    if (s[0] == s[-1] == "'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [] if not inner else [_scalar(p) for p in _split_flow(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        if not inner:
            return {}
        out = {}
        for part in _split_flow(inner):
            k, _, v = part.partition(":")
            out[str(_scalar(k))] = _scalar(v)
        return out
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", s):
        return int(s)
    if re.fullmatch(r"[-+]?\d*\.\d+", s):
        return float(s)
    return s


def _split_flow(s: str) -> list[str]:
    parts, depth, quote, cur = [], 0, None, []
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


# Plain keys may contain ':' (e.g. "host.docker.internal:11434:") — only ": " or a
# trailing ':' ends the key, so the lazy match stops at the first such separator.
_KEY_RE = re.compile(r"""^(?P<key>"[^"]*"|'[^']*'|[^\s#'"\-].*?|-[^\s:].*?)\s*:(?:\s+(?P<val>.*)|$)""")


def _unclosed_quote(v: str) -> bool:
    v = v.strip()
    if not v or v[0] not in "'\"":
        return False
    q, body = v[0], v[1:]
    if q == "'":
        body = body.replace("''", "")
    else:
        body = re.sub(r'\\.', "", body)
    return q not in body


class _MiniParser:
    def __init__(self, text: str):
        self.lines: list[tuple[int, str, int]] = []
        for n, raw in enumerate(text.splitlines(), 1):
            if raw.strip() in ("---", "..."):
                continue
            lead = raw[: len(raw) - len(raw.lstrip())]
            if "\t" in lead and raw.strip():
                raise YamlError(f"line {n}: tab indentation")
            line = _strip_comment(raw)
            if line.strip():
                self.lines.append((len(line) - len(line.lstrip(" ")), line.strip(), n))
        self.i = 0

    def parse(self):
        if not self.lines:
            return None
        value = self._block(self.lines[0][0])
        if self.i != len(self.lines):
            raise YamlError(f"line {self.lines[self.i][2]}: unexpected indentation")
        return value

    def _is_item(self, text: str) -> bool:
        return text == "-" or text.startswith("- ")

    def _block(self, indent: int):
        if self._is_item(self.lines[self.i][1]):
            return self._list(indent)
        return self._map(indent)

    def _child(self, parent_indent: int, *, allow_same_list: bool = False):
        if self.i < len(self.lines):
            ind, text, _ = self.lines[self.i]
            if ind > parent_indent and not self._is_item(text) and not _KEY_RE.match(text):
                # plain scalar continued on the following, more-indented line(s)
                chunks = []
                while self.i < len(self.lines) and self.lines[self.i][0] > parent_indent:
                    chunks.append(self.lines[self.i][1])
                    self.i += 1
                return _scalar(" ".join(chunks))
            if ind > parent_indent or (allow_same_list and ind == parent_indent and self._is_item(text)):
                return self._block(ind)
        return None

    def _map(self, indent: int) -> dict:
        out: dict = {}
        while self.i < len(self.lines):
            ind, text, n = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"line {n}: unexpected indentation")
            if self._is_item(text):
                break
            m = _KEY_RE.match(text)
            if not m:
                raise YamlError(f"line {n}: expected 'key: value'")
            key = str(_scalar(m.group("key")))
            val = m.group("val")
            self.i += 1
            if val is None or val.strip() == "":
                out[key] = self._child(indent, allow_same_list=True)
            elif val.strip() in ("|", ">", "|-", ">-", "|+", ">+"):
                ind_char = val.strip()
                text = self._literal(indent, fold=ind_char.startswith(">"))
                # chomping: "|"/">" (clip) keeps one trailing newline, "-" strips it
                out[key] = text if ind_char.endswith("-") or not text else text + "\n"
            else:
                # a plain scalar may wrap onto following lines indented deeper than its key
                cont = []
                quoted = _unclosed_quote(val)
                while self.i < len(self.lines) and self.lines[self.i][0] > indent:
                    if quoted:  # inside a multi-line quoted scalar anything goes until it closes
                        cont.append(self.lines[self.i][1])
                        self.i += 1
                        quoted = _unclosed_quote(" ".join([val, *cont]))
                        continue
                    if _KEY_RE.match(self.lines[self.i][1]):  # "mapping values not allowed here"
                        raise YamlError(f"line {self.lines[self.i][2]}: unexpected indentation")
                    cont.append(self.lines[self.i][1])
                    self.i += 1
                out[key] = _scalar(" ".join([val, *cont])) if cont else _scalar(val)
        return out

    def _literal(self, indent: int, fold: bool) -> str:
        chunks = []
        while self.i < len(self.lines) and self.lines[self.i][0] > indent:
            chunks.append(self.lines[self.i][1])
            self.i += 1
        return (" " if fold else "\n").join(chunks)

    def _list(self, indent: int) -> list:
        out: list = []
        while self.i < len(self.lines):
            ind, text, n = self.lines[self.i]
            if ind != indent or not self._is_item(text):
                break
            rest = text[1:].strip()
            self.i += 1
            if not rest:
                out.append(self._child(indent))
            elif _KEY_RE.match(rest) and not rest.startswith(("'", '"', "[", "{")):
                # "- key: value" opens an inline mapping; its sibling keys sit at the
                # column where "key" starts (indent + 2 for the usual "- " prefix).
                item_indent = indent + (len(text) - len(rest))
                self.lines.insert(self.i, (item_indent, rest, n))
                out.append(self._map(item_indent))
            else:
                out.append(_scalar(rest))
        return out
