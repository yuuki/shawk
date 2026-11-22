#!/usr/bin/env bash
# Runs the agent under the packaged systemd unit, with its sandbox, and
# checks that it reports ready once its programs are attached, starts with
# UDP tracing, traces the TCP and UDP traffic of another process, learns a
# translation of addresses from conntrack and sends them to a collector,
# that a failure to attach the programs fails the start, and that it reads
# a bearer token from a credential of systemd and sends it over TLS to a
# collector verified by another name than the address of the endpoint.
#
# Requires root, systemd as PID 1 (e.g. a GitHub runner), python3, openssl,
# ss and iptables with NAT.
# Usage: test/packaging/agent-unit.sh path/to/shawk path/to/shawk-collector
set -euo pipefail

SHAWK="$(realpath "${1:?usage: agent-unit.sh path/to/shawk path/to/shawk-collector}")"
COLLECTOR="$(realpath "${2:?usage: agent-unit.sh path/to/shawk path/to/shawk-collector}")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
UNIT=shawk-agent-unittest.service
# The same unit, with bpf(2) denied.
FAILING=shawk-agent-unittest-failing.service
# The same unit, with a token from a credential, over TLS.
TOKEN=shawk-agent-unittest-token.service
BIN=/usr/local/bin/shawk-unittest
# The certificate of the collector, where PrivateTmp does not hide it.
TLS_DIR=/run/shawk-unittest-tls
TCP_PORT=21438
UDP_PORT=21437
TLS_PORT=21439
# A REDIRECT in OUTPUT sends VIRTUAL:9 to the TCP listener.
VIRTUAL=198.51.100.7
REDIRECT=(OUTPUT -d "$VIRTUAL/32" -p tcp --dport 9 -j REDIRECT --to-ports "$TCP_PORT")
PIDS=()

cleanup() {
	set +e
	systemctl stop "$UNIT" "$FAILING" "$TOKEN" 2>/dev/null
	iptables -t nat -D "${REDIRECT[@]}" 2>/dev/null
	rm -f "/run/systemd/system/$UNIT" "/run/systemd/system/$FAILING" "/run/systemd/system/$FAILING.d/nobpf.conf" \
		"/run/systemd/system/$TOKEN" "/run/systemd/system/$TOKEN.d/token.conf" "$BIN"
	rmdir "/run/systemd/system/$FAILING.d" "/run/systemd/system/$TOKEN.d" 2>/dev/null
	rm -rf "$TLS_DIR"
	systemctl daemon-reload
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

journal() { journalctl -u "$UNIT" -o cat --no-pager; }

fail() {
	echo "FAIL: $*" >&2
	echo "--- journal of $UNIT and $TOKEN" >&2
	journalctl -u "$UNIT" -u "$TOKEN" -o cat --no-pager | tail -30 >&2
	echo "--- collectors" >&2
	tail -n 20 "$WORK/collector.log" "$WORK/token-collector.log" >&2 2>/dev/null || true
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
# Translations are learned once nf_conntrack is loaded, as NAT rules load it.
modprobe nf_conntrack
systemctl daemon-reload
# Type=notify: start returns once the agent reported ready, i.e. once its
# programs are attached and the existing sockets adopted.
systemctl start "$UNIT" || fail "the agent did not start"
systemctl is-active --quiet "$UNIT" || fail "the agent is not active once started"

# The log line comes before READY=1, but journald may store it later.
started() { journal | grep -q 'msg="agent started"'; }
wait_for "the agent did not log its start" started
journal | grep 'msg="agent started"'
journal | grep -q 'msg="agent started".* udp=true' || fail "UDP tracing is not available in the sandbox"
# The kprobes on nf_conntrack, loaded before the agent started, attach with
# perf_event_open.
journal | grep -q 'msg="learning translations of addresses from conntrack"' ||
	fail "translations are not learned from conntrack in the sandbox"

# Traffic of another process over TCP and UDP, and over TCP through the
# REDIRECT.
iptables -t nat -I "${REDIRECT[@]}"
python3 - "$TCP_PORT" "$UDP_PORT" "$VIRTUAL" <<'PY'
import socket, sys

tcp, udp, virtual = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ln = socket.create_server(("127.0.0.1", tcp))
for addr in (("127.0.0.1", tcp), (virtual, 9)):
    c = socket.create_connection(addr, timeout=5)
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
wait_for "the translation of the REDIRECT did not reach the collector" \
	grep -q "shawk.translation.virtual.address: Str($VIRTUAL)" "$WORK/collector.log"
grep -q "shawk.translation.backend.port: Int($TCP_PORT)" "$WORK/collector.log" || fail "no translation to port $TCP_PORT"
if journal | grep -q 'level=ERROR'; then
	fail "the agent reported errors"
fi
systemctl is-active --quiet "$UNIT" || fail "the agent stopped"

# Without bpf(2) the programs are not attached, and the start fails instead
# of leaving an active unit that traces nothing.
cp "/run/systemd/system/$UNIT" "/run/systemd/system/$FAILING"
mkdir -p "/run/systemd/system/$FAILING.d"
printf '[Service]\nSystemCallFilter=~bpf\nRestart=no\n' >"/run/systemd/system/$FAILING.d/nobpf.conf"
systemctl daemon-reload
if systemctl start "$FAILING"; then
	journalctl -u "$FAILING" -o cat --no-pager | tail -20 >&2
	fail "the agent started without bpf(2)"
fi
systemctl is-failed --quiet "$FAILING" || fail "the unit without bpf(2) did not fail"
# The agent exited with its error, rather than hanging until systemd gave
# up waiting for READY=1.
[ "$(systemctl show -p Result --value "$FAILING")" = exit-code ] ||
	fail "the unit without bpf(2) failed with $(systemctl show -p Result --value "$FAILING"), not exit-code"
journalctl -u "$FAILING" -o cat --no-pager | grep -q 'starting tracer' ||
	fail "the agent without bpf(2) did not fail to start its tracer"

# A token from a credential (LoadCredential=, as LoadCredentialEncrypted=
# would decrypt it into the same directory), read by the agent at
# ${CREDENTIALS_DIRECTORY} in its sandbox, and sent over TLS to a collector
# at 127.0.0.1 whose certificate names collector.example only.
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj /CN=collector.example -addext subjectAltName=DNS:collector.example \
	-keyout "$TLS_DIR/collector.key" -out "$TLS_DIR/collector.crt" 2>"$WORK/openssl.log" ||
	fail "openssl did not make the certificate of the collector: $(cat "$WORK/openssl.log")"
head -c 32 /dev/urandom | base64 | tr -d '=+/' >"$WORK/token"
python3 - "$TLS_PORT" "$TLS_DIR" "$WORK/token" >"$WORK/token-collector.log" 2>&1 <<'PY' &
import http.server, ssl, sys

port, tls, token = int(sys.argv[1]), sys.argv[2], open(sys.argv[3]).read().strip()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ok = self.headers.get("Authorization") == "Bearer " + token
        print("authorized" if ok else "unauthorized", flush=True)
        self.send_response(200 if ok else 401)
        self.end_headers()

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(tls + "/collector.crt", tls + "/collector.key")
ctx.sni_callback = lambda sock, name, c: print("sni", name, flush=True)
srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
PIDS+=($!)
wait_for "the collector of tokens does not listen" sh -c "ss -Hltn 'src 127.0.0.1:$TLS_PORT' | grep -q ."
cp "/run/systemd/system/$UNIT" "/run/systemd/system/$TOKEN"
mkdir -p "/run/systemd/system/$TOKEN.d"
{
	echo '[Service]'
	echo "LoadCredential=otlp-token:$WORK/token"
	echo "Environment=\"SHAWK_AGENT_OPTS=-otlp-endpoint https://127.0.0.1:$TLS_PORT -otlp-protocol http/protobuf -otlp-ca-file $TLS_DIR/collector.crt -otlp-server-name collector.example -interval 1s\""
	echo 'ExecStart='
	# shellcheck disable=SC2016 # systemd expands the variables
	echo "ExecStart=$BIN agent"' $SHAWK_AGENT_OPTS -otlp-bearer-token-file ${CREDENTIALS_DIRECTORY}/otlp-token'
} >"/run/systemd/system/$TOKEN.d/token.conf"
systemctl stop "$UNIT"
systemctl daemon-reload
systemctl start "$TOKEN" || fail "the agent with a token did not start"
wait_for "no request with the token reached the collector" grep -q '^authorized' "$WORK/token-collector.log"
grep -q '^sni collector.example$' "$WORK/token-collector.log" || fail "the agent did not ask for collector.example"
if grep -q '^unauthorized' "$WORK/token-collector.log"; then
	fail "the agent sent a request without its token"
fi
# Through a file: grep -q would stop journalctl early, and pipefail would
# then hide a match.
journalctl -u "$TOKEN" -o cat --no-pager >"$WORK/token-journal"
if grep -qF -- "$(cat "$WORK/token")" "$WORK/token-journal"; then
	fail "the agent logged its token"
fi
echo "PASS"
