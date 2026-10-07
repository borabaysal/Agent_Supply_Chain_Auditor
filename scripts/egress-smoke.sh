#!/usr/bin/env bash
# end-to-end smoke test for asca-egress (run from repo root)
set -u
D=${1:-${TMPDIR:-/tmp}/asca-egress-smoke}
PORT=${2:-18899}
rm -rf "$D"
python3 -m asca.egress --dir "$D" proxy --port "$PORT" --sample-direct 1 --hermes-home "${HERMES_HOME:-/nonexistent}" >"$D.out" 2>&1 &
PP=$!
sleep 1.5
cat "$D.out"
eval "$(python3 -m asca.egress env --port $PORT)"
ASCA_EGRESS_LABEL=smoke-curl curl -s -o /dev/null -w "https %{http_code}\n" https://api.github.com/zen
curl -s -o /dev/null -w "http %{http_code}\n" "http://example.com/some/path?token=SECRET123"
python3 -c "import urllib.request;print('py', urllib.request.urlopen('https://pypi.org/simple/', timeout=15).status)"
curl -s -o /dev/null -w "badhost %{http_code}\n" https://nonexistent.invalid/
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy
ASCA_EGRESS_LABEL=sneaky python3 -c "import socket,time;s=socket.create_connection(('1.1.1.1',443),timeout=5);time.sleep(4)"
kill "$PP"; wait "$PP" 2>/dev/null
python3 - "$D" <<'EOF'
import sys,json,glob
for f in glob.glob(sys.argv[1]+'/logs/*.jsonl'):
    for l in open(f):
        r=json.loads(l); c=r.get('client',{})
        print(r['kind'], r.get('host') or r.get('ip') or '', r.get('port',''), r.get('status',''), r.get('path',''), '|', c.get('agent',''), '|', r.get('bytes_down',''), r.get('error','')[:50])
EOF
echo "secret-in-log: $(cat "$D"/logs/*.jsonl | grep -c SECRET123)"
stat -c '%a %n' "$D/logs" "$D"/logs/*.jsonl
