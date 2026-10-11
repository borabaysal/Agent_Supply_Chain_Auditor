"""Tests for asca.egress: proxy, attribution, log privacy, sampler, diff/summary, CLI."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from asca.egress import attrib, cli, log as elog, sampler, summary
from asca.egress.proxy import Proxy, _split_hostport

linux_only = pytest.mark.skipif(not Path("/proc/net/tcp").exists(), reason="needs Linux /proc")


# ------------------------------------------------------------------ helpers

class _Origin(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):  # noqa: N802
        _Origin.seen.append((self.path, dict(self.headers)))
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def origin():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_port
    srv.shutdown()


def records(d: Path) -> list[dict]:
    return [json.loads(l) for f in sorted(d.glob("*.jsonl")) for l in f.read_text().splitlines()]


async def _with_proxy(tmp_path, fn, **kw):
    p = await Proxy(tmp_path, port=0, **kw).start()
    task = asyncio.create_task(p.serve_forever())
    try:
        return await fn(p)
    finally:
        task.cancel()
        await p.close()


# ------------------------------------------------------------------ proxy

def test_http_forward_strips_query_and_proxy_headers(tmp_path, origin):
    async def go(p):
        r, w = await asyncio.open_connection("127.0.0.1", p.port)
        w.write(f"GET http://127.0.0.1:{origin}/a/b?token=SECRET HTTP/1.1\r\nHost: x\r\n"
                f"Proxy-Authorization: Basic Zm9v\r\nUser-Agent: t\r\n\r\n".encode())
        await w.drain()
        data = await asyncio.wait_for(r.read(), 10)
        w.close()
        return data

    data = asyncio.run(_with_proxy(tmp_path, go, attribute=False))
    assert data.startswith(b"HTTP/1.0 200") or data.startswith(b"HTTP/1.1 200")
    path, headers = _Origin.seen[-1]
    assert path == "/a/b?token=SECRET"                    # forwarded intact upstream...
    assert "Proxy-Authorization" not in headers           # ...without proxy credentials
    rec = [r for r in records(tmp_path) if r.get("kind") == "http"][0]
    assert rec["path"] == "/a/b" and rec["status"] == 200 and rec["host"] == "127.0.0.1"
    assert "SECRET" not in json.dumps(records(tmp_path)) and "Zm9v" not in json.dumps(records(tmp_path))


def test_connect_tunnel_counts_bytes_and_logs_host(tmp_path, origin):
    async def go(p):
        r, w = await asyncio.open_connection("127.0.0.1", p.port)
        w.write(f"CONNECT 127.0.0.1:{origin} HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n\r\n".encode())
        await w.drain()
        assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
        w.write(b"GET /tunnel HTTP/1.0\r\n\r\n")   # opaque payload through the tunnel
        await w.drain()
        body = await asyncio.wait_for(r.read(), 10)
        w.close()
        return body

    body = asyncio.run(_with_proxy(tmp_path, go, attribute=False))
    assert body.endswith(b"hello")
    rec = [r for r in records(tmp_path) if r.get("kind") == "connect"][0]
    assert rec["port"] == origin and rec["status"] == 200 and rec["bytes_down"] >= 5 and rec["bytes_up"] > 0
    assert "path" not in rec                                # tunnel contents are never parsed


def test_upstream_failure_is_502_and_logged(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()

    async def go(p):
        r, w = await asyncio.open_connection("127.0.0.1", p.port)
        w.write(f"CONNECT 127.0.0.1:{dead} HTTP/1.1\r\n\r\n".encode())
        await w.drain()
        return await asyncio.wait_for(r.read(), 10)

    assert asyncio.run(_with_proxy(tmp_path, go, attribute=False)).startswith(b"HTTP/1.1 502")
    rec = [r for r in records(tmp_path) if r.get("kind") == "connect"][0]
    assert rec["status"] == 502 and "upstream" in rec["error"]


def test_bad_and_non_proxy_requests(tmp_path):
    async def go(p):
        out = []
        for raw in (b"garbage\r\n\r\n", b"GET /relative HTTP/1.1\r\n\r\n"):
            r, w = await asyncio.open_connection("127.0.0.1", p.port)
            w.write(raw)
            await w.drain()
            out.append(await asyncio.wait_for(r.read(), 5))
        return out

    a, b = asyncio.run(_with_proxy(tmp_path, go, attribute=False))
    assert a.startswith(b"HTTP/1.1 400") and b.startswith(b"HTTP/1.1 400")


def test_refuses_clients_outside_allowlist(tmp_path):
    async def go(p):
        r, w = await asyncio.open_connection("127.0.0.1", p.port)
        w.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await w.drain()
        try:
            return await asyncio.wait_for(r.read(), 5)
        except ConnectionResetError:   # refusal may surface as a reset; either way nothing is served
            return b""

    assert asyncio.run(_with_proxy(tmp_path, go, attribute=False, allow=["10.0.0.0/8"])) == b""
    assert [r["kind"] for r in records(tmp_path) if r["kind"] == "refused"] == ["refused"]


def test_cli_refuses_open_proxy(capsys):
    assert cli.run(["proxy", "--host", "0.0.0.0"]) == 2
    assert "refusing" in capsys.readouterr().err


@pytest.mark.parametrize("s,default,exp", [("h:8443", 443, ("h", 8443)), ("h", 443, ("h", 443)),
                                           ("[::1]:9", 80, ("::1", 9)), ("[::1]", 80, ("::1", 80)),
                                           ("h:bad", 80, ("h", 80))])
def test_split_hostport(s, default, exp):
    assert _split_hostport(s, default) == exp


# ------------------------------------------------------------------ attribution

def test_proc_net_hex_roundtrip():
    assert attrib.decode_hex_ip(attrib._hex_addr("127.0.0.1", 0)[0]) == "127.0.0.1"
    assert attrib.decode_hex_ip(attrib._hex_addr("2001:db8::1", 0)[0]) == "2001:db8::1"
    assert attrib.decode_hex_ip("0000000000000000FFFF00000100007F") == "127.0.0.1"   # v4-mapped


@linux_only
def test_attribution_finds_this_process_and_env_label(tmp_path, origin, monkeypatch):
    """Real /proc lookup: a child with ASCA_EGRESS_LABEL connects through the proxy."""
    import subprocess

    async def go(p):
        code = (f"import socket;s=socket.create_connection(('127.0.0.1',{p.port}));"
                f"s.sendall(b'CONNECT 127.0.0.1:{origin} HTTP/1.1\\r\\n\\r\\n');s.recv(100);s.close()")
        env = {**os.environ, "ASCA_EGRESS_LABEL": "unit-test-agent"}
        await asyncio.to_thread(subprocess.run, [sys.executable, "-c", code], env=env, timeout=20, check=True)
        await asyncio.sleep(0.3)

    asyncio.run(_with_proxy(tmp_path, go))
    rec = [r for r in records(tmp_path) if r.get("kind") == "connect"][0]
    assert rec["client"]["agent"] == "unit-test-agent" and rec["client"]["pid"]
    assert rec["client"]["proc"].startswith("python")


def test_known_agent_recognition(tmp_path):
    proc = tmp_path / "proc"
    for pid, ppid, cmd in ((300, 200, "/usr/bin/curl https://x"), (200, 100, "/bin/bash -c x"),
                           (100, 1, "/opt/hermes/.venv/bin/python3 /opt/hermes/.venv/bin/hermes gateway run")):
        d = proc / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())
        (d / "stat").write_text(f"{pid} (x) S {ppid} 0 0")
        (d / "environ").write_bytes(b"PATH=/bin\0")
    c = attrib.describe(300, proc)
    assert c.agent == "hermes-gateway" and c.proc.startswith("curl") and len(c.chain) == 3


def test_attribute_never_raises(tmp_path):
    assert attrib.attribute(("bogus", 1), ("x", 2), tmp_path).agent == "unknown"


def test_cron_context_reads_running_jobs(tmp_path):
    import sqlite3
    (tmp_path / "cron").mkdir()
    con = sqlite3.connect(tmp_path / "cron" / "executions.db")
    con.execute("CREATE TABLE executions (job_id TEXT, status TEXT)")
    con.executemany("INSERT INTO executions VALUES (?,?)", [("j1", "running"), ("j2", "completed")])
    con.commit()
    con.close()
    (tmp_path / "cron" / "jobs.json").write_text(json.dumps({"jobs": [{"id": "j1", "name": "Nightly"}]}))
    assert attrib.CronContext(tmp_path).running() == ["Nightly"]
    assert attrib.CronContext(None).running() == []


# ------------------------------------------------------------------ sampler

def _fake_proc(tmp_path, rows, fds):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (proc / "net" / "tcp").write_text(hdr + "".join(
        f"   0: {attrib._hex_addr(l, 0)[0]}:{lp:04X} {attrib._hex_addr(r, 0)[0]}:{rp:04X} {st} 0:0 0:0 0 1000 0 {ino}\n"
        for l, lp, r, rp, st, ino in rows))
    (proc / "net" / "tcp6").write_text(hdr)
    for pid, inode, cmd in fds:
        d = proc / str(pid)
        (d / "fd").mkdir(parents=True)
        os.symlink(f"socket:[{inode}]", d / "fd" / "3")
        (d / "cmdline").write_bytes(cmd.encode())
        (d / "stat").write_text(f"{pid} (x) S 1 0")
    return proc


def test_sampler_reports_external_established_once(tmp_path):
    proc = _fake_proc(tmp_path, [
        ("10.0.0.5", 50000, "1.1.1.1", 443, "01", 11),      # external, established -> report
        ("10.0.0.5", 50001, "10.0.0.9", 443, "01", 12),     # private -> ignore
        ("10.0.0.5", 50002, "8.8.8.8", 53, "06", 13),       # TIME_WAIT -> ignore
        ("10.0.0.5", 50003, "9.9.9.9", 443, "01", 14),      # the proxy's own upstream leg -> ignore
    ], [(500, 11, "sneaky"), (600, 14, "asca-egress")])
    s = sampler.Sampler(self_pid=600, proc=proc)
    first = s.sample()
    assert [(r["ip"], r["client"]["proc"]) for r in first] == [("1.1.1.1", "sneaky")]
    assert s.sample() == []                                  # not re-reported while open


# ------------------------------------------------------------------ log

def test_log_privacy_and_permissions(tmp_path):
    lg = elog.EgressLog(tmp_path / "logs")
    lg.write({"kind": "http", "host": "h", "path": "/p?api_key=abc#frag" + "x" * 500, "ts": 1_800_000_000})
    lg.close()
    f = next((tmp_path / "logs").glob("*.jsonl"))
    r = json.loads(f.read_text())
    assert r["path"].startswith("/p") and "api_key" not in r["path"] and len(r["path"]) <= elog.PATH_MAX
    if os.name == "posix":
        assert (f.stat().st_mode & 0o077) == 0 and ((tmp_path / "logs").stat().st_mode & 0o077) == 0


def test_log_prune_and_corrupt_lines(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "egress-2000-01-01.jsonl").write_text("{}\n")
    (d / "egress-2099-01-01.jsonl").write_text('{"ts": 4070908800, "kind": "x"}\nnot json\n')
    assert elog.prune(d, 30) == 1 and not (d / "egress-2000-01-01.jsonl").exists()
    recs = list(elog.iter_records(d, 4070908799, 4070908801))
    assert recs[0]["kind"] == "x" and recs[-1] == {"kind": "_corrupt", "count": 1, "ts": 4070908801}


# ------------------------------------------------------------------ summary

@pytest.mark.parametrize("host,exp", [("api.github.com", "github.com"), ("a.b.example.co.uk", "example.co.uk"),
                                      ("evil.github.io", "evil.github.io"), ("x.y.s3.amazonaws.com", "s3.amazonaws.com"),
                                      ("1.2.3.4", "1.2.3.4"), ("localhost", "localhost")])
def test_registrable(host, exp):
    assert summary.registrable(host) == exp


def _write(d: Path, recs):
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "egress-2099-01-01.jsonl", "a") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def _c(host, agent, ts, **kw):
    return {"ts": ts, "kind": "connect", "host": host, "port": 443, "status": 200, "client": {"agent": agent}, **kw}


T = 4070908800  # 2099-01-01


def test_summary_classifies_differences(tmp_path):
    logs = tmp_path / "logs"
    _write(logs, [{"ts": T, "kind": "proxy_start"}, _c("api.github.com", "hermes-gateway", T + 1),
                  _c("pypi.org", "hermes-gateway", T + 2)])
    b = summary.load_baseline(tmp_path / "b.json")
    d1 = summary.compute(logs, b, since=T - 1, until=T + 10)
    assert d1.first_run and d1.new_domains                     # everything new on first run
    b = summary.learn(b, logs, d1)
    _write(logs, [
        _c("paste.evil.xyz", "weather_trader.py", T + 20),
        _c("uploads.github.com", "hermes-gateway", T + 21),
        _c("pypi.org", "python3 job.py", T + 22, cron=["Nightly"]),
        _c("pypi.org", "hermes-gateway", T + 23),                # known pair -> nothing
        {"ts": T + 24, "kind": "connect", "host": "45.9.148.3", "port": 8443, "client": {"agent": "curl"}},
        {"ts": T + 25, "kind": "direct", "ip": "1.1.1.1", "port": 443, "client": {"agent": "sneaky"}},
        _c("api.github.com", "hermes-gateway", T + 26, status=502, error="upstream"),
    ])
    d2 = summary.compute(logs, b, since=T + 10, until=T + 30)
    assert not d2.first_run and d2.has_changes
    assert set(d2.new_domains) == {"evil.xyz"}
    assert set(d2.new_hosts) == {"uploads.github.com"}
    assert set(d2.new_pairs) == {("python3 job.py [cron: Nightly]", "pypi.org")}
    assert set(d2.ip_literals) == {"45.9.148.3:8443"}
    assert [v["dest"] for v in d2.direct.values()] == ["1.1.1.1:443"]
    assert d2.failures["api.github.com"] == 1
    b = summary.learn(b, logs, d2)
    d3 = summary.compute(logs, b, since=T + 30, until=T + 40)
    assert not d3.has_changes                                  # learned; quiet afterwards


def test_summary_detects_dead_proxy(tmp_path):
    b = {"version": 1, "hosts": {"x": {"agents": ["a"]}}, "direct": {}, "last_run": 0}
    d = summary.compute(tmp_path / "none", b, since=T, until=T + 86400)
    assert not d.proxy_alive and d.has_changes
    _write(tmp_path / "logs", [{"ts": T + 5, "kind": "heartbeat"}])
    assert summary.compute(tmp_path / "logs", b, since=T, until=T + 86400).proxy_alive


def test_telegram_text_escapes_and_bounds(tmp_path):
    logs = tmp_path / "logs"
    _write(logs, [{"ts": T, "kind": "heartbeat"}] +
           [_c(f"h{i}.evil<{i}>.xyz", "<agent>", T + i) for i in range(1, 40)])
    b = {"version": 1, "hosts": {"known.com": {"agents": ["a"]}}, "direct": {}, "last_run": 0}
    txt = summary.to_telegram(summary.compute(logs, b, since=T - 1, until=T + 50), "host<1>", "/r.md")
    assert "<agent>" not in txt and "&lt;agent&gt;" in txt and "host&lt;1&gt;" in txt
    assert "more" in txt and len(txt) <= 4096


def test_cli_summary_exit_codes_and_alert_on_change(tmp_path, monkeypatch):
    from asca import report
    sent = []
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    envf = tmp_path / "e.env"
    envf.write_text("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=5\n")
    st = tmp_path / "state"
    now = time.time()
    _write(st / "logs", [{"ts": now - 50, "kind": "proxy_start"}, _c("api.github.com", "a", now - 40)])
    args = ["--dir", str(st), "summary", "--format", "none", "--telegram", "change", "--env-file", str(envf)]
    assert cli.run(args) == 0 and sent == []                     # first run: learn, no alert
    _write(st / "logs", [_c("new.example.net", "a", time.time())])
    assert cli.run(args) == 1 and len(sent) == 1 and "example.net" in sent[0]
    assert cli.run(args) == 0 and len(sent) == 1                 # nothing new since
    assert (st / "baseline.json").stat().st_mode & 0o077 == 0
    assert st.stat().st_mode & 0o077 == 0


def test_cli_env_prints_exports(capsys):
    assert cli.run(["env", "--port", "9", "--label", "my-agent"]) == 0
    out = capsys.readouterr().out
    assert "HTTPS_PROXY=http://127.0.0.1:9" in out and "NO_PROXY=localhost" in out and "ASCA_EGRESS_LABEL=my-agent" in out


def test_sampler_ignore_list(tmp_path):
    proc = _fake_proc(tmp_path, [("10.0.0.5", 50000, "1.1.1.1", 443, "01", 11),
                                 ("10.0.0.5", 50001, "2.2.2.2", 443, "01", 12)],
                      [(500, 11, "/opt/bin/tailscaled --tun=x"), (501, 12, "curl")])
    got = sampler.Sampler(proc=proc, ignore=["tailscaled"]).sample()
    assert [r["client"]["proc"] for r in got] == ["curl"]


def test_direct_baseline_tolerates_ip_rotation_within_network(tmp_path):
    logs = tmp_path / "logs"
    _write(logs, [{"ts": T, "kind": "heartbeat"},
                  {"ts": T + 1, "kind": "direct", "ip": "149.154.166.110", "port": 443, "client": {"agent": "gw"}}])
    b = summary.load_baseline(tmp_path / "b.json")
    b = summary.learn(b, logs, summary.compute(logs, b, since=T - 1, until=T + 5))
    _write(logs, [{"ts": T + 10, "kind": "direct", "ip": "149.154.166.120", "port": 443, "client": {"agent": "gw"}},
                  {"ts": T + 11, "kind": "direct", "ip": "149.154.167.1", "port": 443, "client": {"agent": "gw"}}])
    d = summary.compute(logs, b, since=T + 5, until=T + 20)
    assert [v["net"] for v in d.direct.values()] == ["149.154.167.0/24"]   # same /24 = known
