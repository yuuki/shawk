#!/usr/bin/env bash
# End-to-end test: simulates hosts with network namespaces on a bridge, runs
# an agent in each of them and queries dependencies across the agents.
#
#   ext (no agent) --> lb:80 haproxy --> app:8080 puma --> db:5432 postgres
#                                        app puma ------> 127.0.0.1:6379 redis-server (on app)
#                                        app puma ==persistent==> db:5433 postgres
#                                                         db:9187 exporter (unused)
#
# Requires root, iproute2 and python3. Usage: test/e2e/run.sh path/to/shawk
set -euo pipefail

SHAWK="$(realpath "${1:?usage: run.sh path/to/shawk}")"
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
# names differ.
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

for h in lb app db; do
	# A UTS namespace gives each simulated host its own host name.
	ip netns exec "$PREFIX-$h" unshare --uts sh -c "hostname $h-01 && exec \"$SHAWK\" agent -netns self -interval 1s -db \"$WORK/$h.db\"" >"$WORK/$h-agent.log" 2>&1 &
	PIDS+=($!)
done
for h in lb app db; do
	for _ in $(seq 50); do
		curl -sf "http://${ADDR[$h]}:7464/healthz" >/dev/null 2>&1 && break
		sleep 0.2
	done
	curl -sf "http://${ADDR[$h]}:7464/healthz" >/dev/null || fail "agent on $h is not up"
done

svc ext client --client ${ADDR[lb]}:80
sleep 6

run() {
	echo "\$ shawk $*"
	"$SHAWK" "$@" | tee "$WORK/out"
	local rc=${PIPESTATUS[0]}
	echo
	return "$rc"
}
expect() { grep -qE -- "$1" "$WORK/out" || fail "expected /$1/"; }

run who-uses ${ADDR[db]}:5432 -depth 3
expect '^db-01:5432/tcp \(10\.231\.0\.10\) +postgres'
expect '── app-01 \(10\.231\.0\.11\) +puma'
expect '── app-01:8080/tcp \(10\.231\.0\.11\) +puma'
expect '── lb-01 \(10\.231\.0\.5\) +haproxy'
expect '── 10\.231\.0\.50 +\(no agent\)'

run who-uses ${ADDR[db]}:5433
expect 'puma'

run deps ${ADDR[lb]} -depth 3
expect 'haproxy'
expect 'app-01:8080/tcp.* puma'
expect 'db-01:5432/tcp.* postgres'
expect 'app-01:6379/tcp.* redis-server'

run unused ${ADDR[db]}
expect '9187 +postgres'

set +e
run can-i-remove ${ADDR[db]}
code=$?
set -e
[[ $code == 1 ]] || fail "can-i-remove exited with $code, want 1"
expect '^NO:'

run can-i-remove ${ADDR[app]}:6379
expect '^OK:'

run graph ${ADDR[app]} -depth 3
expect 'n[0-9]+ -->\|tcp/8080\| n[0-9]+'

run graph ${ADDR[app]} -depth 3 -format dot
expect '"10\.231\.0\.5/[^"]*/haproxy" -> "10\.231\.0\.11/[^"]*/puma" \[label="tcp/8080"\]'
expect '"10\.231\.0\.11/[^"]*/puma" -> "10\.231\.0\.10/[^"]*/postgres" \[label="tcp/5432"\]'
expect '"10\.231\.0\.50" -> "10\.231\.0\.5/[^"]*/haproxy" \[label="tcp/80"\]'

run diff ${ADDR[app]} -since 1h
expect '^\+ +puma'

run status ${ADDR[db]}
expect 'ledger since'

echo "PASS"
