#!/usr/bin/env bash
# Runs the agent under the packaged systemd unit, with its sandbox, and
# checks that it starts with UDP tracing, traces the TCP and UDP traffic of
# another process and sends it to a collector.
#
# Requires root, systemd as PID 1 (e.g. a GitHub runner), python3 and ss.
# Usage: test/packaging/agent-unit.sh path/to/shawk path/to/shawk-collector
set -euo pipefail

SHAWK="$(realpath "${1:?usage: agent-unit.sh path/to/shawk path/to/shawk-collector}")"
COLLECTOR="$(realpath "${2:?usage: agent-unit.sh path/to/shawk path/to/shawk-collector}")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
UNIT=shawk-agent-unittest.service
BIN=/usr/local/bin/shawk-unittest
TCP_PORT=21438
UDP_PORT=21437
PIDS=()

cleanup() {
	set +e
	systemctl stop "$UNIT" 2>/dev/null
	rm -f "/run/systemd/system/$UNIT" "$BIN"
	systemctl daemon-reload
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

journal() { journalctl -u "$UNIT" -o cat --no-pager; }

fail() {
	echo "FAIL: $*" >&2
	echo "--- journal of $UNIT" >&2
	journal | tail -30 >&2
	echo "--- collector" >&2
	tail -20 "$WORK/collector.log" >&2
	exit 1
}

wait_for() { # description, command...
	local what="$1"
	shift
	for _ in $(seq 60); do
		if "$@"; then
			return 0
		fi
		sleep 0.5
	done
	fail "$what"
}

cat >"$WORK/collector.yaml" <<EOF
receivers:
  otlp/shawk:
    protocols:
      grpc: { endpoint: "127.0.0.1:4327" }
exporters:
  debug: { verbosity: detailed }
service:
  telemetry: { metrics: { level: none } }
  pipelines:
    metrics: { receivers: [otlp/shawk], exporters: [debug] }
EOF
"$COLLECTOR" --config "$WORK/collector.yaml" >"$WORK/collector.log" 2>&1 &
PIDS+=($!)
wait_for "the collector does not listen" sh -c "ss -Hltn 'src 127.0.0.1:4327' | grep -q ."

# Installed outside the checkout, which ProtectHome hides, like the README
# installs a build by hand; the options replace /etc/shawk/agent.env.
install -m 0755 "$SHAWK" "$BIN"
sed -e "s|^ExecStart=/usr/bin/shawk |ExecStart=$BIN |" \
	-e 's|^EnvironmentFile=.*|Environment="SHAWK_AGENT_OPTS=-otlp-endpoint http://127.0.0.1:4327 -interval 1s"|' \
	"$ROOT/packaging/systemd/shawk-agent.service" >"/run/systemd/system/$UNIT"
grep -q "^ExecStart=$BIN " "/run/systemd/system/$UNIT" || fail "ExecStart was not replaced"
systemctl daemon-reload
systemctl start "$UNIT"

started() { journal | grep -q 'msg="agent started"'; }
wait_for "the agent did not start" started
journal | grep 'msg="agent started"'
journal | grep -q 'msg="agent started".* udp=true' || fail "UDP tracing is not available in the sandbox"

# Traffic of another process over TCP and UDP.
python3 - "$TCP_PORT" "$UDP_PORT" <<'PY'
import socket, sys

tcp, udp = int(sys.argv[1]), int(sys.argv[2])
ln = socket.create_server(("127.0.0.1", tcp))
c = socket.create_connection(("127.0.0.1", tcp))
s, _ = ln.accept()
c.sendall(b"x" * 100)
s.recv(100)
c.close()
s.close()
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", udp))
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cli.sendto(b"x", ("127.0.0.1", udp))
data, peer = srv.recvfrom(10)
srv.sendto(data, peer)
cli.recvfrom(10)
PY
for port in "$TCP_PORT" "$UDP_PORT"; do
	wait_for "no series of port $port reached the collector" grep -q "server.port: Int($port)" "$WORK/collector.log"
done
grep -q 'network.transport: Str(udp)' "$WORK/collector.log" || fail "no UDP series"
if journal | grep -q 'level=ERROR'; then
	fail "the agent reported errors"
fi
systemctl is-active --quiet "$UNIT" || fail "the agent stopped"
echo "PASS"
