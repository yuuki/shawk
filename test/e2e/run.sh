#!/usr/bin/env bash
# End-to-end test: simulates hosts with network namespaces on a bridge, runs
# an agent in each of them, sends to a collector with the shawk connector
# and checks the dependencies it wrote to PostgreSQL and the metrics it
# forwarded.
#
#   ext (no agent) --> lb:80 haproxy --> app:8080 puma --> db:5432 postgres
#                                        app puma ------> 127.0.0.1:6379 redis-server (on app)
#                                        app puma ==persistent==> db:5433 postgres
#                                        app puma --IPv6--> db:5434 postgres
#                                        app puma --UDP---> db:5353 named
#                                                         db:9187 exporter (unused)
#
# Every service runs in a cgroup of its own, like a systemd unit, and the
# agents enter the namespaces with nsenter, which keeps /sys and thus the
# cgroups visible: the units of both sides are checked.
#
# Then the agents stop, and one agent traces all the namespaces with the
# default -netns all, as on a host whose services run in containers: every
# dependency, including that of ext, is then observed on both sides by it.
#
# Requires root, cgroup v2, iproute2 (ip, ss), python3, psql, nsenter and
# unshare (util-linux). Every wait has a deadline.
# SHAWK_E2E_POSTGRES_DSN is a database dedicated to the test: its schemas
# shawk and shawk_v1 are dropped and recreated. The agents must trace UDP
# (BPF trampolines): without them, the UDP dependency is not checked unless
# SHAWK_TEST_STRICT=1.
# Usage: test/e2e/run.sh path/to/shawk path/to/shawk-collector
set -euo pipefail

SHAWK="$(realpath "${1:?usage: run.sh path/to/shawk path/to/shawk-collector}")"
COLLECTOR="$(realpath "${2:?usage: run.sh path/to/shawk path/to/shawk-collector}")"
DSN="${SHAWK_E2E_POSTGRES_DSN:?set SHAWK_E2E_POSTGRES_DSN to a database dedicated to the test}"
# The same values as strconv.ParseBool, which the Go tests use.
case "${SHAWK_TEST_STRICT:-}" in
1 | t | T | true | TRUE | True) STRICT=1 ;;
*) STRICT=0 ;;
esac
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="shawke2e"
NET=10.231.0
NET6=fd00:231:
PIDS=()
AGENTS=()

declare -A ADDR=([lb]=$NET.5 [app]=$NET.11 [db]=$NET.10 [ext]=$NET.50)
declare -A ADDR6=([lb]=${NET6}:5 [app]=${NET6}:11 [db]=${NET6}:10 [ext]=${NET6}:50)

# The cgroup v2 hierarchy, as the agent finds it.
CGROOT="$(awk '$0 ~ / - cgroup2 / { print $5; exit }' /proc/self/mountinfo)"
[[ -n "$CGROOT" ]] || {
	echo "cgroup v2 is not mounted" >&2
	exit 1
}
CGROUPS="$CGROOT/$PREFIX.slice"

# stop PIDS...: stops processes, killing those that did not exit within 10
# seconds of SIGTERM.
stop() {
	local pid deadline=$((SECONDS + 10))
	(($# > 0)) || return 0
	kill "$@" 2>/dev/null || true
	for pid in "$@"; do
		while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.2; done
		kill -KILL "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
}

WORK="$(mktemp -d)"
cleanup() {
	set +e
	stop "${PIDS[@]}" "${AGENTS[@]}"
	for h in "${!ADDR[@]}"; do ip netns del "$PREFIX-$h" 2>/dev/null; done
	ip link del "$PREFIX-br" 2>/dev/null
	for cg in "$CGROUPS"/*/; do rmdir "$cg" 2>/dev/null; done
	rmdir "$CGROUPS" 2>/dev/null
	if [[ "${KEEP:-}" == "" ]]; then rm -rf "$WORK"; else echo "kept $WORK"; fi
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	for f in "$WORK"/*.log; do echo "--- $f" >&2; tail -20 "$f" >&2; done
	exit 1
}

sql() { PGOPTIONS='-c client_min_messages=warning' psql "$DSN" -v ON_ERROR_STOP=1 -AXqt -F ' ' -c "$1"; }

# poll SECONDS COMMAND...: runs COMMAND until it succeeds; returns 1 when
# it has not after SECONDS.
poll() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		((SECONDS < deadline)) || return 1
		sleep 0.2
	done
}

# wait_for SECONDS DESCRIPTION COMMAND...: polls COMMAND or fails.
wait_for() { poll "$1" "${@:3}" || fail "timed out waiting for $2"; }

# listening HOST PORT [-u]: whether a TCP (or UDP with -u) socket listens on
# PORT in the namespace of HOST.
listening() {
	local proto=t
	[[ "${3:-}" == -u ]] && proto=u
	[[ -n "$(ip netns exec "$PREFIX-$1" ss -Hl${proto}n "sport = :$2")" ]]
}

# connected HOST ADDR:PORT: whether HOST has a TCP connection to ADDR:PORT.
connected() { [[ -n "$(ip netns exec "$PREFIX-$1" ss -Htn state established "dst $2")" ]]; }

# Network: a bridge in the root namespace and one namespace per host, with
# IPv4 and IPv6 addresses.
ip link add "$PREFIX-br" type bridge
ip addr add $NET.1/24 dev "$PREFIX-br"
ip link set "$PREFIX-br" up
for h in "${!ADDR[@]}"; do
	ns="$PREFIX-$h"
	ip netns add "$ns"
	ip link add "$PREFIX-$h" type veth peer name eth0 netns "$ns"
	ip link set "$PREFIX-$h" master "$PREFIX-br" up
	ip -n "$ns" addr add "${ADDR[$h]}/24" dev eth0
	ip -n "$ns" -6 addr add "${ADDR6[$h]}/64" dev eth0 nodad
	ip -n "$ns" link set eth0 up
	ip -n "$ns" link set lo up
done

# Services run as differently named executables so that their command
# names and service names differ, each in the cgroup of a unit of its own.
for name in haproxy puma postgres redis-server named client; do
	cp "$(command -v python3)" "$WORK/$name"
done
mkdir -p "$CGROUPS"
svc() { # host name args...
	local h="$1" name="$2" cg="$CGROUPS/$PREFIX-$1-$2.service"
	shift 2
	mkdir -p "$cg"
	sh -c 'echo $$ >"$1/cgroup.procs" && shift && exec "$@"' sh "$cg" \
		ip netns exec "$PREFIX-$h" "$WORK/$name" "$HERE/service.py" "$@" >>"$WORK/$h-$name.log" 2>&1 &
	PIDS+=($!)
}

svc db postgres --listen 5432 --listen 5433
svc db postgres --listen 5434 --bind ::
svc db postgres --listen 9187 --bind "${ADDR[db]}"
svc db named --udp-listen 5353
svc app redis-server --listen 6379 --bind 127.0.0.1
for p in 5432 5433 5434 9187; do wait_for 10 "postgres to listen on $p" listening db $p; done
wait_for 10 "named to listen" listening db 5353 -u
wait_for 10 "redis-server to listen" listening app 6379
# A long-lived connection established before any agent starts.
svc app puma --listen 8080 --upstream "${ADDR[db]}:5432" --upstream 127.0.0.1:6379 \
	--upstream "[${ADDR6[db]}]:5434" --udp-upstream "${ADDR[db]}:5353" --persist "${ADDR[db]}:5433"
svc lb haproxy --listen 80 --upstream "${ADDR[app]}:8080"
wait_for 10 "puma to listen" listening app 8080
wait_for 10 "haproxy to listen" listening lb 80
wait_for 10 "the persistent connection of puma" connected app "${ADDR[db]}:5433"

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
wait_for 30 "the collector to listen" sh -c "ss -Hltn 'src $NET.1:4327' | grep -q ."

# agent NAME NETNS [FLAGS...]: runs an agent whose host is named NAME in the
# network namespace NETNS, or in the root namespace for "-". nsenter, unlike
# ip netns exec, does not remount /sys, so the agent sees the cgroups. A UTS
# namespace gives the agent its own host name. All hosts share the machine
# id, like cloned VMs. Three series per request make every interval span
# several requests.
agent() {
	local name="$1" ns="$2" enter=()
	shift 2
	[[ "$ns" == - ]] || enter=(nsenter "--net=/run/netns/$ns")
	"${enter[@]}" unshare --uts sh -c "hostname $name && exec \"\$@\"" sh \
		"$SHAWK" agent -interval 1s -max-series-per-request 3 -otlp-endpoint "http://$NET.1:4327" "$@" \
		>"$WORK/$name-agent.log" 2>&1 &
	AGENTS+=($!)
}
for h in lb app db; do agent "$h-01" "$PREFIX-$h" -netns self; done
agents_alive() { [[ "$(sql "SELECT count(*) FROM shawk_v1.agents WHERE alive" 2>/dev/null)" == "$1" ]]; }
wait_for 30 "the agents to report" agents_alive 3

# The agents must trace UDP, unless the kernel cannot and the run is not
# strict.
UDP=true
udp_traced="$(sql "SELECT bool_and(udp_traced) FROM shawk_v1.agents WHERE alive")" || fail "reading the agents"
if [[ "$udp_traced" != t ]]; then
	[[ "$STRICT" == 1 ]] && fail "the agents do not trace UDP"
	echo "WARNING: the agents do not trace UDP; the UDP dependency is not checked" >&2
	UDP=false
fi

svc ext client --client "${ADDR[lb]}:80"

check() { # description, SQL, expected output
	local got
	got="$(sql "$2")"
	echo "\$ $1"
	echo "$got"
	echo
	[[ "$got" == "$3" ]] || fail "$1: got '$got', want '$3'"
}

# deps_sql CONDITION: the dependencies between the services of the test,
# with the units of both sides and the family of the server address. They
# are those to the addresses of the test (and to redis on the loopback),
# whatever processes they are attributed to; other servers on these ports,
# e.g. a PostgreSQL the collector writes to, are left out.
deps_sql() {
	echo "
SELECT coalesce(client_host, host(client_addr)), coalesce(client_service, '-'), coalesce(client_unit, '-'),
       coalesce(server_host, '-'), coalesce(server_service, '-'), coalesce(server_unit, '-'),
       proto, port, family(server_addr), observed_by
FROM shawk_v1.dependencies
WHERE port IN (80, 5353, 5432, 5433, 5434, 6379, 8080)
  AND (server_addr << '$NET.0/24' OR server_addr << '${NET6}:/64' OR (port = 6379 AND server_addr << '127.0.0.0/8'))
  AND ($1)
ORDER BY port, 1"
}
# want_deps EXT LB APP DB: the expected rows, with the hosts of the services;
# EXT is the address of ext when it has no agent.
want_deps() {
	local ext="$1" lb="$2" app="$3" db="$4" u="$PREFIX"
	if [[ "$ext" == "${ADDR[ext]}" ]]; then
		echo "$ext - - $lb haproxy $u-lb-haproxy.service tcp 80 4 server"
	else
		echo "$ext client $u-ext-client.service $lb haproxy $u-lb-haproxy.service tcp 80 4 both"
	fi
	if $UDP; then
		echo "$app puma $u-app-puma.service $db named $u-db-named.service udp 5353 4 both"
	fi
	echo "$app puma $u-app-puma.service $db postgres $u-db-postgres.service tcp 5432 4 both
$app puma $u-app-puma.service $db postgres $u-db-postgres.service tcp 5433 4 both
$app puma $u-app-puma.service $db postgres $u-db-postgres.service tcp 5434 6 both
$app puma $u-app-puma.service $app redis-server $u-app-redis-server.service tcp 6379 4 both
$lb haproxy $u-lb-haproxy.service $app puma $u-app-puma.service tcp 8080 4 both"
}

# Wait until the connector has written every dependency and forwarded the
# metrics that name the peers; the checks below report what is missing.
deps_want="$(want_deps "${ADDR[ext]}" lb-01 app-01 db-01)"
deps_written() { [[ "$(sql "$(deps_sql "true")" 2>/dev/null)" == "$deps_want" ]]; }
peers_named() {
	local peer
	for peer in postgres haproxy '~unresolved'; do
		grep -qF "service.peer.name: Str($peer)" "$WORK/collector.log" || return 1
	done
}
poll 60 deps_written || true
poll 30 peers_named || true

check "dependencies" "$(deps_sql true)" "$deps_want"

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

# The client without an agent is named like in Prometheus.
check "dependency map" \
"SELECT source, target FROM shawk_v1.graph_edges WHERE mainstat ~ '^(80|8080|5432)/' ORDER BY 1, 2" \
"haproxy puma
puma postgres
~unresolved haproxy"

# The forwarded metrics name the peers and carry no addresses.
grep -q 'service.peer.name: Str(postgres)' "$WORK/collector.log" || fail "no series of puma to postgres"
grep -q 'service.peer.name: Str(haproxy)' "$WORK/collector.log" || fail "no series of puma's server side"
grep -q 'shawk.peer.agent: Bool(true)' "$WORK/collector.log" || fail "no series of a peer with an agent"
grep -q 'service.peer.name: Str(~unresolved)' "$WORK/collector.log" || fail "no series of the client without an agent"
if grep -q 'network.peer.address' "$WORK/collector.log"; then fail "peer addresses forwarded"; fi

# One agent traces every namespace, as on a host with containers. The
# addresses of the namespaces move from the hosts above to node-01, and
# dependencies, which are matched by address over all time, also pair
# node-01 with them: only the dependencies node-01 observed on both sides
# are checked.
stop "${AGENTS[@]}"
AGENTS=()
agent node-01 -
node_alive() { [[ "$(sql "SELECT netns_scope FROM shawk_v1.agents WHERE host = 'node-01' AND alive" 2>/dev/null)" == all ]]; }
wait_for 30 "the agent of all namespaces to report" node_alive
node_sql="$(deps_sql "client_host = 'node-01' AND server_host = 'node-01'")"
node_want="$(want_deps node-01 node-01 node-01 node-01)"
node_written() { [[ "$(sql "$node_sql" 2>/dev/null)" == "$node_want" ]]; }
poll 60 node_written || true
check "dependencies on a host whose namespaces are all traced" "$node_sql" "$node_want"

echo "PASS"
