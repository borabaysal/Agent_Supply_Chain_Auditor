"""Look-alike name detection: typosquats, homoglyphs, separator games and brand-affix clones.

The question is always "does this name try to pass for an official one without being it?".
Exact matches are handled by the caller (they're either official or a name collision); this
module only classifies *near* matches.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..model import Severity

# Common Cyrillic/Greek/Latin-extended homoglyphs → ASCII. NFKC already folds fullwidth forms.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b",
    "н": "h", "п": "n", "г": "r", "ł": "l", "ı": "i", "ɑ": "a", "ο": "o", "α": "a", "ε": "e", "ι": "i",
    "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "ℓ": "l",
})
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
                       "|": "l", "!": "i"})
_SEP = re.compile(r"[\s\-_.]+")

# suffixes malware authors bolt onto a trusted name ("openclaw-core", "hermes-agent-pro")
BRAND_AFFIXES = ("core", "utility", "utils", "util", "helper", "helpers", "runtime", "installer", "setup",
                 "update", "updater", "pro", "premium", "official", "free", "cracked", "unlocked", "plus",
                 "fixed", "patch", "patched", "driver", "bridge", "daemon", "service", "loader", "launcher")


def fold(name: str) -> str:
    """Unicode → ASCII skeleton without leetspeak: NFKC, lowercase, homoglyphs, separators removed."""
    s = unicodedata.normalize("NFKC", name).lower().translate(_CONFUSABLES)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return _SEP.sub("", s.lstrip("@").replace("/", ""))


def skeleton(name: str) -> str:
    """fold() plus leetspeak and the classic 'rn'→'m', 'vv'→'w' visual merges."""
    return fold(name).translate(_LEET).replace("rn", "m").replace("vv", "w")


def _mixed_script(name: str) -> bool:
    """Latin letters plus at least one character that folds to a Latin letter (Cyrillic а, Greek ο…)."""
    latin = any("a" <= c.lower() <= "z" for c in name)
    disguised = any(ord(c) > 127 and c.lower().translate(_CONFUSABLES) != c.lower() for c in name)
    return latin and disguised


def has_non_ascii(name: str) -> bool:
    return any(ord(c) > 127 for c in name)


def damerau(a: str, b: str, cap: int = 3) -> int:
    """Optimal-string-alignment distance, early exit above *cap*."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


@dataclass
class Match:
    official: str
    reason: str
    severity: Severity


class Matcher:
    """Index of official names for one kind (skills, plugins, packages, …)."""

    def __init__(self, names, brands=()):
        self.names = {n for n in names if n}
        self.lower = {n.lower() for n in self.names}
        self.by_fold: dict[str, str] = {}
        self.by_skel: dict[str, str] = {}
        self.by_len: dict[int, list[tuple[str, str]]] = {}
        for n in sorted(self.names):
            f, k = fold(n), skeleton(n)
            self.by_fold.setdefault(f, n)
            self.by_skel.setdefault(k, n)
            self.by_len.setdefault(len(f), []).append((f, n))
        self.brands = [b.lower() for b in brands]

    def is_official(self, name: str) -> bool:
        return name in self.names or name.lower() in self.lower

    def lookalike(self, name: str) -> Match | None:
        if not name or self.is_official(name):
            return None
        f, k = fold(name), skeleton(name)
        non_ascii = has_non_ascii(name)
        if f in self.by_fold:
            off = self.by_fold[f]
            if non_ascii:
                return Match(off, f"uses look-alike Unicode characters to spell `{off}`", Severity.CRITICAL)
            return Match(off, f"differs from official `{off}` only by case or separators", Severity.MEDIUM)
        if k in self.by_skel:
            off = self.by_skel[k]
            return Match(off, f"is `{off}` spelled with digit/letter swaps (leetspeak, rn→m)", Severity.HIGH)
        brand = self._brand_affix(f)
        if brand:
            return brand
        if len(f) >= 5:
            best = None
            for L in (len(f) - 1, len(f), len(f) + 1):
                for of, off in self.by_len.get(L, ()):
                    if damerau(f, of, 1) == 1 and not self._benign_edit(f, of):
                        best = best or off
            if best:
                sev = Severity.HIGH if non_ascii else Severity.MEDIUM
                return Match(best, f"is one character away from official `{best}` (possible typosquat)", sev)
        if non_ascii and _mixed_script(name):
            return Match(f, "mixes look-alike non-Latin letters into a Latin name (reads as "
                            f"`{f}`)", Severity.HIGH)
        clone = re.match(r"^(.{4,}?)[-_]([a-z0-9]{2,4})$", name.lower())
        if clone and any(c.isdigit() for c in clone.group(2)) and clone.group(1) in self.lower:
            off = next(n for n in self.names if n.lower() == clone.group(1))
            return Match(off, f"is official `{off}` plus a random-looking suffix `-{clone.group(2)}` "
                              f"(pattern used by cloned ClawHub skills)", Severity.MEDIUM)
        return None

    def _brand_affix(self, f: str) -> Match | None:
        for b in self.brands:
            bf = fold(b)
            if f == bf or bf not in f:
                continue
            rest = f.replace(bf, "", 1)
            if rest in BRAND_AFFIXES:
                return Match(b, f"is the `{b}` brand plus `{rest}`, which no official package uses "
                                f"(fake-prerequisite pattern, e.g. `openclaw-core`)", Severity.HIGH)
        return None

    @staticmethod
    def _benign_edit(a: str, b: str) -> bool:
        """Plural/singular and trailing version digit are normal naming, not squatting."""
        lo, hi = sorted((a, b), key=len)
        return hi in (lo + "s", lo + "es") or (hi[:-1] == lo and hi[-1].isdigit())
