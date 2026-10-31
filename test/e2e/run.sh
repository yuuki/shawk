#!/usr/bin/env bash
# End-to-end test: simulates hosts with network namespaces on a bridge, runs
# an agent in each of them, sends to a collector with the shawk connector
# and checks the dependencies it wrote to PostgreSQL and the metrics it
# forwarded.
#
#   ext (no agent) --> lb:80 haproxy --> app:8080 puma --> db:5432 postgres
#                                        app puma ------> 127.0.0.1:6379 redis-server (on app)
#                                        app puma ==persistent==> db:5433 postgres
#                                                         db:9187 exporter (unused)
#
# Requires root, iproute2, python3, psql and unshare (util-linux).
# SHAWK_E2E_POSTGRES_DSN is a database dedicated to the test: its schemas
# shawk and shawk_v1 are dropped and recreated.
# Usage: test/e2e/run.sh path/to/shawk path/to/shawk-collector
set -euo pipefail

SHAWK="$(realpath "${1:?usage: run.sh path/to/shawk path/to/shawk-collector}")"
COLLECTOR="$(realpath "${2:?usage: run.sh path/to/shawk path/to/shawk-collector}")"
DSN="${SHAWK_E2E_POSTGRES_DSN:?set SHAWK_E2E_POSTGRES_DSN to a database dedicated to the test}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
PREFIX="shawke2e"
NET=10.231.0
PIDS=()

declare -A ADDR=([lb]=$NET.5 [app]=$NET.11 [db]=$NET.10 [ext]=$NET.50)

cleanup() {
	set +e
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	wait 2>/dev/null
	for h in "${!ADDR[@]}"; do ip netns del "$PREFIX-$h" 2>/dev/null; done
	ip link del "$PREFIX-br" 2>/dev/null
	if [[ "${KEEP:-}" == "" ]]; then rm -rf "$WORK"; else echo "kept $WORK"; fi
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	for f in "$WORK"/*.log; do echo "--- $f" >&2; tail -20 "$f" >&2; done
	exit 1
}

sql() { PGOPTIONS='-c client_min_messages=warning' psql "$DSN" -v ON_ERROR_STOP=1 -AXqt -F ' ' -c "$1"; }

# Network: a bridge in the root namespace and one namespace per host.
ip link add "$PREFIX-br" type bridge
ip addr add $NET.1/24 dev "$PREFIX-br"
ip link set "$PREFIX-br" up
for h in "${!ADDR[@]}"; do
	ns="$PREFIX-$h"
	ip netns add "$ns"
	ip link add "$PREFIX-$h" type veth peer name eth0 netns "$ns"
	ip link set "$PREFIX-$h" master "$PREFIX-br" up
	ip -n "$ns" addr add "${ADDR[$h]}/24" dev eth0
	ip -n "$ns" link set eth0 up
	ip -n "$ns" link set lo up
done

# Services run as differently named executables so that their command
# names and service names differ.
for name in haproxy puma postgres redis-server client; do
	cp "$(command -v python3)" "$WORK/$name"
done
svc() { # host name args...
	local h="$1" name="$2"
	shift 2
	ip netns exec "$PREFIX-$h" "$WORK/$name" "$HERE/service.py" "$@" >"$WORK/$h-$name.log" 2>&1 &
	PIDS+=($!)
}

svc db postgres --listen 5432 --listen 5433
svc db postgres --listen 9187 --bind ${ADDR[db]}
svc app redis-server --listen 6379 --bind 127.0.0.1
sleep 1
# A long-lived connection established before any agent starts.
svc app puma --listen 8080 --upstream ${ADDR[db]}:5432 --upstream 127.0.0.1:6379 --persist ${ADDR[db]}:5433
svc lb haproxy --listen 80 --upstream ${ADDR[app]}:8080
sleep 2

# The collector listens on the bridge, where the agents reach it.
sql "DROP SCHEMA IF EXISTS shawk_v1 CASCADE; DROP SCHEMA IF EXISTS shawk CASCADE" >/dev/null
echo "$DSN" >"$WORK/dsn"
cat >"$WORK/collector.yaml" <<EOF
receivers:
  otlp/shawk:
    protocols:
      grpc: { endpoint: "$NET.1:4327" }
connectors:
  shawk:
    postgres: { dsn_file: "$WORK/dsn", migrate: true }
    write_interval: 2s
exporters:
  debug: { verbosity: detailed }
service:
  telemetry: { metrics: { level: none } }
  pipelines:
    metrics/in: { receivers: [otlp/shawk], exporters: [shawk] }
    metrics/out: { receivers: [shawk], exporters: [debug] }
EOF
"$COLLECTOR" --config "$WORK/collector.yaml" >"$WORK/collector.log" 2>&1 &
PIDS+=($!)

for h in lb app db; do
	# A UTS namespace gives each simulated host its own host name. The hosts
	# share the machine id, like cloned VMs.
	ip netns exec "$PREFIX-$h" unshare --uts sh -c "hostname $h-01 && exec \"$SHAWK\" agent -netns self -interval 1s -otlp-endpoint http://$NET.1:4327" >"$WORK/$h-agent.log" 2>&1 &
	PIDS+=($!)
done
for _ in $(seq 60); do
	[[ "$(sql "SELECT count(*) FROM shawk_v1.agents WHERE alive" 2>/dev/null)" == 3 ]] && break
	sleep 0.5
done
[[ "$(sql "SELECT count(*) FROM shawk_v1.agents WHERE alive")" == 3 ]] || fail "the agents did not report"

svc ext client --client ${ADDR[lb]}:80
sleep 8

check() { # description, SQL, expected output
	local got
	got="$(sql "$2")"
	echo "\$ $1"
	echo "$got"
	echo
	[[ "$got" == "$3" ]] || fail "$1: got '$got', want '$3'"
}

check "dependencies" "
SELECT coalesce(client_host, host(client_addr)), coalesce(client_service, '-'), coalesce(server_host, '-'),
       coalesce(server_service, '-'), port, observed_by
FROM shawk_v1.dependencies
WHERE port IN (80, 8080, 5432, 5433, 6379)
ORDER BY port, 1" \
"10.231.0.50 - lb-01 haproxy 80 server
app-01 puma db-01 postgres 5432 both
app-01 puma db-01 postgres 5433 both
app-01 puma app-01 redis-server 6379 both
lb-01 haproxy app-01 puma 8080 both"

check "unused listeners" "
SELECT s.host, s.port, s.service
FROM shawk_v1.service_endpoints s
WHERE NOT EXISTS (SELECT FROM shawk_v1.dependencies d WHERE d.server_host = s.host AND d.port = s.port)
  AND s.port IN (5432, 5433, 9187) AND NOT s.addr << '127.0.0.0/8'
ORDER BY 1, 2" \
"db-01 9187 postgres"

check "agents" "SELECT host, alive, netns_scope <> 'all' FROM shawk_v1.agents ORDER BY host" \
"app-01 t t
db-01 t t
lb-01 t t"

check "host ids of hosts sharing a machine id" \
"SELECT count(DISTINCT id), count(DISTINCT machine_id) FROM shawk.hosts" "3 1"

check "dependency map" \
"SELECT source, target FROM shawk_v1.graph_edges WHERE mainstat ~ '^(80|8080|5432)/' ORDER BY 1, 2" \
"10.231.0.50 haproxy
haproxy puma
puma postgres"

# The forwarded metrics name the peers and carry no addresses.
grep -q 'service.peer.name: Str(postgres)' "$WORK/collector.log" || fail "no series of puma to postgres"
grep -q 'service.peer.name: Str(~agent)' "$WORK/collector.log" || fail "no server side series of a client with an agent"
grep -q 'service.peer.name: Str(~unresolved)' "$WORK/collector.log" || fail "no series of the client without an agent"
if grep -q 'network.peer.address' "$WORK/collector.log"; then fail "peer addresses forwarded"; fi

echo "PASS"
