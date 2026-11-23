"""MCP launchers: dependency drift (``mcp.launcher-dep-drift``) and vulnerable pinned versions
(``mcp.vulnerable-version``).

**Pinned isn't frozen.** ``npx -y pkg@1.4.2`` or ``uvx pkg==1.4.2`` fixes the server's own version, but
its dependencies are resolved again from the registry, within the ranges the package allows, whenever
the launcher rebuilds its cache. Corelight (Nov 2026) watched one MCP server pinned to one release and commit
run with 15 different dependency sets across 19 builds in five weeks. So every exact-pinned ``npx``/``bunx``/
``pnpx``/``npm exec``/``uvx``/``pipx`` launch gets an INFO note, unless the launch line installs from
constraints or a lock (``--constraints``/``-c``, ``--with-requirements``, ``--require-hashes``, ``--locked``,
``--frozen``). Images pinned by digest and local paths are frozen already.

**Pinned isn't safe.** The pinned version is matched against a small bundled table of verified MCP server
advisories, and with ``--online-advisories`` against OSV and GitHub advisories for every pinned package.

| package | affected | advisory |
|---|---|---|
| ``awslabs.document-loader-mcp-server`` (PyPI) | ``>= 1.0.10, < 1.0.21`` | CVE-2026-130901, AWS bulletin 2026-195-AWS |

For document-loader, AWS says setting ``DOCUMENT_BASE_DIR`` (to the document folder, never ``/``) mitigates
it when you can't upgrade, so a set value lowers the finding to medium, and ``/`` is flagged on its own.
"""
from __future__ import annotations

import re
import urllib.error

from .model import Finding, Severity

ADVISORIES: dict[tuple[str, str], list[dict]] = {
    ("PyPI", "awslabs-document-loader-mcp-server"): [{
        "ids": ["CVE-2026-130901", "AWS-2026-195"], "ranges": [">= 1.0.10, < 1.0.21"], "fixed": "1.0.21",
        "severity": "high",
        "summary": "Path traversal: when DOCUMENT_BASE_DIR is unset or empty and CI or test environment variables "
                   "are present, the default base-directory restriction isn't applied.",
        "url": "https://aws.amazon.com/security/security-bulletins/2026-195-aws/"}],
}
REVIEWED_AT = "2026-11-23"
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
        "low": Severity.LOW}
_FROZEN_FLAGS = {"--constraints", "-c", "--constraint", "--with-requirements", "--require-hashes", "--locked",
                 "--frozen", "--build-constraints", "--overrides"}

# pinned launches seen in this run, for the optional online lookup: (location, name, ecosystem, package, version)
LAUNCHES: list[tuple[str, str, str, str, str]] = []


def norm(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name.lower()


def pinned_launch(argv: list[str]) -> dict | None:
    """{runner, ecosystem, package, version, frozen} for an exact-pinned package launcher, else None."""
    from . import mcp
    exe = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    exe = exe[:-4] if exe.endswith((".cmd", ".exe")) else exe
    rest = argv[1:]
    frozen = any(a.split("=", 1)[0] in _FROZEN_FLAGS for a in rest)
    if exe in mcp._NODE_RUNNERS or (exe in ("npm", "pnpm", "yarn") and rest[:1] in (["exec"], ["dlx"])):
        pkg = mcp._first_positional(rest[1:] if exe in ("npm", "pnpm", "yarn") else rest,
                                    takes_value={"-p", "--package", "--registry", "--cache", "--prefix"})
        if not pkg or pkg.startswith((".", "/", "file:", "http:", "https:", "git", "github:")):
            return None
        name = mcp._npm_name(pkg)
        ver = pkg[len(name):].lstrip("@")
        if mcp._EXACT_VERSION.match(ver):
            return {"runner": exe, "ecosystem": "npm", "package": name, "version": ver.lstrip("v"), "frozen": frozen}
        return None
    if exe in mcp._PY_RUNNERS:
        sub = rest[1:] if exe == "pipx" and rest[:1] == ["run"] else rest
        spec = None
        for flag in ("--from", "--spec"):
            if flag in sub and sub.index(flag) + 1 < len(sub):
                spec = sub[sub.index(flag) + 1]
        spec = spec or mcp._first_positional(sub, takes_value={"--python", "--with", "--index-url", "-p", "--from",
                                                               "--spec", *_FROZEN_FLAGS})
        if not spec or spec.startswith((".", "/", "git+")):
            return None
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*|@)(v?\d[^,;\s]*)$", spec)
        if m and "*" not in m.group(2) and mcp._EXACT_VERSION.match(m.group(2)):
            return {"runner": exe, "ecosystem": "PyPI", "package": m.group(1), "version": m.group(2).lstrip("v"),
                    "frozen": frozen}
    return None


def _root(v) -> bool:
    return isinstance(v, str) and v.strip().rstrip("/\\") in ("", "C:", "c:") and v.strip() not in ("",)


def _vuln_finding(location, name, launch, rows, env) -> Finding:
    from . import agentvers
    pkg, ver = launch["package"], launch["version"]
    sev = max((_SEV.get(r.get("severity", ""), Severity.MEDIUM) for r in rows), default=Severity.MEDIUM)
    ids = sorted({i for r in rows for i in r["ids"]})
    note = ""
    if norm("PyPI", pkg) == "awslabs-document-loader-mcp-server" and launch["ecosystem"] == "PyPI":
        base = (env or {}).get("DOCUMENT_BASE_DIR")
        if isinstance(base, str) and base.strip() and not _root(base):
            sev, note = Severity.MEDIUM, (" DOCUMENT_BASE_DIR is set, which AWS lists as the mitigation until you "
                                          "upgrade.")
        else:
            note = " DOCUMENT_BASE_DIR isn't set here, so the restriction depends on the vulnerable default."
    fixed = sorted({r["fixed"] for r in rows if r.get("fixed")}, key=lambda v: agentvers.parse(v) or ())
    return Finding(
        rule="mcp.vulnerable-version", category="mcp", severity=sev,
        title=f"MCP server `{name}` runs {pkg} {ver}, which has {len(rows)} known "
              f"vulnerabilit{'y' if len(rows) == 1 else 'ies'}",
        location=location, subject=f"{name}:{pkg}@{ver}:{','.join(ids)}",
        detail="; ".join(f"{'/'.join(r['ids'])}: {r['summary']}" + (f" ({r['url']})" if r.get("url") else "")
                         for r in rows)[:900] + "." + note + " Pinning kept this version in place.",
        remediation=f"Pin a fixed release: `{pkg}{'==' if launch['ecosystem'] == 'PyPI' else '@'}"
                    f"{fixed[-1] if fixed else '<fixed-version>'}`, then restart the agent.")


def audit(location: str, name: str, argv: list[str], env: dict | None = None) -> list[Finding]:
    from . import agentvers
    out: list[Finding] = []
    launch = pinned_launch(argv)
    if (env or {}).get("DOCUMENT_BASE_DIR") is not None and _root((env or {}).get("DOCUMENT_BASE_DIR")) \
            and "document-loader" in " ".join(argv):
        out.append(Finding(
            rule="mcp.document-loader-root", category="mcp", severity=Severity.MEDIUM,
            title=f"MCP server `{name}`: DOCUMENT_BASE_DIR is the filesystem root",
            location=f"{location}.env.DOCUMENT_BASE_DIR", subject=f"{name}:DOCUMENT_BASE_DIR",
            detail="Setting it to `/` removes the base-directory restriction, so the agent (and any prompt "
                   "injection) can load any file the user can read (AWS bulletin 2026-195-AWS).",
            remediation="Set DOCUMENT_BASE_DIR to the folder that holds your documents."))
    if not launch:
        return out
    LAUNCHES.append((location, name, launch["ecosystem"], launch["package"], launch["version"]))
    rows = [r for r in ADVISORIES.get((launch["ecosystem"], norm(launch["ecosystem"], launch["package"])), [])
            if any(agentvers.in_range(launch["version"], rng) for rng in r["ranges"])]
    if rows:
        out.append(_vuln_finding(location, name, launch, rows, env))
    if not launch["frozen"]:
        how = ("a local install from the package's lockfile (`npm ci` in a dedicated folder) or a container image "
               "pinned by digest" if launch["ecosystem"] == "npm" else
               "a dedicated environment installed once from the project's hash-pinned requirements "
               "(`uv pip install --require-hashes -r requirements.txt`, then `--no-deps` for the server) or a "
               "container image pinned by digest")
        out.append(Finding(
            rule="mcp.launcher-dep-drift", category="mcp", severity=Severity.INFO,
            title=f"MCP server `{name}` is pinned to {launch['package']} {launch['version']}, but its dependencies "
                  f"aren't",
            location=location, subject=f"{name}:{launch['ecosystem']}:{launch['package']}@{launch['version']}",
            detail=f"`{launch['runner']}` resolves the server's dependencies again from the registry whenever it "
                   f"rebuilds its cache, within whatever ranges the package allows. Corelight saw one MCP server "
                   f"pinned to one release run with 15 different dependency sets over 19 builds in five weeks. A "
                   f"malicious dependency release only has to be live during one rebuild.",
            remediation=f"Freeze it: run the server from {how}, and point the agent config at that. Someone then "
                        f"owns updates on purpose."))
    return out


def online(launches=None, *, osv=None, ghsa=None, timeout: float = 20.0) -> tuple[list[Finding], list[str]]:
    """OSV + GitHub advisories for every pinned launch seen (--online-advisories). Returns (findings, errors).
    Advisories already in the bundled table aren't repeated."""
    from . import advisories as adv
    osv = osv or adv.query_osv
    ghsa = ghsa or adv.query_ghsa
    out, errors = [], []
    seen_pkgs: dict[tuple[str, str, str], list] = {}
    for location, name, eco, pkg, ver in (LAUNCHES if launches is None else launches):
        key = (eco, pkg, ver)
        if key not in seen_pkgs:
            found = []
            for label, fn, e in (("osv.dev", osv, eco), ("GitHub advisories", ghsa, "pip" if eco == "PyPI" else eco)):
                try:
                    found += fn(e, pkg, ver, timeout)
                except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
                    errors.append(f"{label} {pkg}: {type(exc).__name__}")
            seen_pkgs[key] = adv.merge(found)
        bundled = {i for r in ADVISORIES.get((eco, norm(eco, pkg)), []) for i in r["ids"]}
        rows = [{"ids": sorted(a.ids), "summary": a.summary, "fixed": a.fixed.split(",")[0].strip(),
                 "severity": a.severity.name.lower(), "url": a.url}
                for a in seen_pkgs[key] if not (a.ids & bundled)]
        if rows:
            f = _vuln_finding(location, name, {"package": pkg, "version": ver, "ecosystem": eco}, rows, {})
            f.detail += " (from osv.dev and GitHub advisories)"
            out.append(f)
    return out, errors
