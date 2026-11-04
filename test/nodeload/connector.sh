#!/usr/bin/env bash
# Runs the measurements of the connector of
# docs/research/hpc-compute-nodes/compute_nodes.md, as root, appending JSON
# lines to OUT (default connector.jsonl):
#
#   make collector && go build -o nodeload ./test/nodeload
#   sudo NODELOAD=./nodeload COLLECTOR=collector/_build/shawk-collector test/nodeload/connector.sh [OUT]
#
# A collector with the shawk connector writes to a local PostgreSQL 14 or
# later (the service postgresql, initialized; the statements of the role
# nodeload are logged with their durations to log/nodeload.log) and forwards to a sink, which counts the
# output series. fleet sends the series of the agents of a cluster of 190
# compute nodes and 10 other hosts (fleet), for each scenario of SCENARIOS:
#
#   star  the traffic of §1.6 of docs/proposals/slurm-hpc-clusters.md
#   mpiN  that, and ranks of every compute node talking over TCP to 8 other
#         compute nodes over N connections each, on random ports that change
#         with every job of 5 minutes (MPI over TCP at its worst); mpi64
#         grew the collector beyond the 12 GiB of the VM
#
# for MINUTES (default 25) each. watch samples the collector per write
# interval (1 minute). In the scenario star, PostgreSQL stops for 5 minutes
# from minute 15 and the collector for 5 minutes from minute 25, so it runs
# for 35 minutes. The database nodeload is dropped and recreated.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NL=$(realpath "${NODELOAD:-nodeload}")
COL=$(realpath "${COLLECTOR:-shawk-collector}")
OUT=$(realpath -m "${1:-connector.jsonl}")
MINUTES=${MINUTES:-25}
SCENARIOS=${SCENARIOS:-"star mpi16"}
WORK=$(mktemp -d)
PIDS=()
cleanup() {
	kill "${PIDS[@]}" 2>/dev/null || true
	wait 2>/dev/null || true
	systemctl start postgresql
	rm -rf "$WORK"
}
trap cleanup EXIT

pg() { runuser -u postgres -- psql -v ON_ERROR_STOP=1 -AXqt "$@"; }
pglog() { runuser -u postgres -- psql -AXqt -c "SELECT current_setting('data_directory') || '/' || pg_current_logfile()"; }

# One log file that is not rotated, whose prefix starts with the time.
pg -c "ALTER SYSTEM SET logging_collector = on" -c "ALTER SYSTEM SET log_filename = 'nodeload.log'" \
	-c "ALTER SYSTEM SET log_rotation_age = 0" -c "ALTER SYSTEM SET log_rotation_size = 0" \
	-c "ALTER SYSTEM SET log_line_prefix = '%m [%p] '"
systemctl restart postgresql

pg -c "DROP DATABASE IF EXISTS nodeload" -c "DROP ROLE IF EXISTS nodeload" \
	-c "CREATE ROLE nodeload LOGIN PASSWORD 'nodeload'" -c "CREATE DATABASE nodeload OWNER nodeload" \
	-c "ALTER ROLE nodeload SET log_min_duration_statement = 0"
echo "postgres://nodeload:nodeload@127.0.0.1/nodeload?sslmode=disable" >"$WORK/dsn"

cat >"$WORK/collector.yaml" <<EOF
receivers:
  otlp/shawk:
    protocols:
      grpc: { endpoint: "127.0.0.1:4327", max_recv_msg_size_mib: 16 }
connectors:
  shawk:
    postgres: { dsn_file: "$WORK/dsn", migrate: true }
exporters:
  otlp_grpc/sink:
    endpoint: 127.0.0.1:4329
    tls: { insecure: true }
service:
  telemetry: { metrics: { level: none } }
  pipelines:
    metrics/in: { receivers: [otlp/shawk], exporters: [shawk] }
    metrics/out: { receivers: [shawk], exporters: [otlp_grpc/sink] }
EOF

# collector LABEL: starts the collector with a log of its own, waits until
# it is ready, and watches it for the minutes left of the scenario.
starts=0
collector() {
	starts=$((starts + 1))
	COLLOG=$WORK/collector-$starts.log
	"$COL" --config "$WORK/collector.yaml" >"$COLLOG" 2>&1 &
	COLPID=$!
	PIDS+=($COLPID)
	local deadline=$((SECONDS + 60))
	until grep -q "Everything is ready" "$COLLOG"; do
		kill -0 "$COLPID" 2>/dev/null && ((SECONDS < deadline)) || { cat "$COLLOG" >&2; exit 1; }
		sleep 0.5
	done
	local left=$(((END - SECONDS + 59) / 60))
	"$NL" watch -pid "$COLPID" -every 10ms -window 1m -gap 1s -count "$left" -label "$1" >>"$OUT" &
	WATCH=$!
	PIDS+=($WATCH)
}

# writes LABEL FROM: the durations of the statements of the connector in
# the log of PostgreSQL from byte FROM on, grouped into write intervals:
# their sum, and the time from the first to the last. The extended protocol
# logs the parse, bind and execute of a statement on lines of their own.
writes() {
	tail -c +"$2" "$(pglog)" | python3 -c '
import json, re, sys
from datetime import datetime
label, rows, last = sys.argv[1], [], None
for line in sys.stdin:
    m = re.match(r"(\S+ \S+) \S+ \[\d+\] .*duration: ([\d.]+) ms", line)
    if not m:
        continue
    t = datetime.strptime(m.group(1)[:23], "%Y-%m-%d %H:%M:%S.%f").timestamp()
    d = float(m.group(2))
    if last is None or t - last > 20:
        rows.append({"label": label, "kind": "write", "lines": 0, "sum_ms": 0.0, "start": t, "end": t})
    r = rows[-1]
    r["lines"] += 1
    r["sum_ms"] += d
    r["end"] = t
    last = t
for r in rows:
    r["span_ms"] = round((r["end"] - r["start"]) * 1000, 1)
    r["sum_ms"] = round(r["sum_ms"], 1)
    del r["start"], r["end"]
    print(json.dumps(r))
' "$1" >>"$OUT"
}

"$NL" sink -listen 127.0.0.1:4329 -label connector-out -gap 5s >>"$WORK/out.jsonl" 2>>"$WORK/log" &
PIDS+=($!)
for s in $SCENARIOS; do
	mins=$MINUTES
	[[ $s == star ]] && mins=35
	args=()
	[[ $s == mpi* ]] && args=(-mpi-peers 8 -mpi-ranks "${s#mpi}" -job 5m)
	END=$((SECONDS + mins * 60))
	logpos=$(($(stat -c %s "$(pglog)") + 1))
	collector "$s"
	"$NL" fleet -duration "${mins}m" "${args[@]}" 2>>"$WORK/fleet-$s.log" &
	fleet=$!
	if [[ $s == star ]]; then
		sleep 900
		echo "$s: PostgreSQL stops" >&2
		systemctl stop postgresql
		sleep 300
		systemctl start postgresql
		echo "$s: PostgreSQL starts" >&2
		sleep 300
		echo "$s: the collector stops" >&2
		kill "$COLPID"
		wait "$COLPID" || true
		sleep 300
		collector "$s-restarted"
		echo "$s: the collector starts" >&2
	fi
	wait "$fleet" || true
	# The watch writes to OUT until the collector stops.
	kill "$COLPID"
	wait "$COLPID" 2>/dev/null || true
	wait "$WATCH" 2>/dev/null || true
	writes "$s" "$logpos"
	pg -d nodeload -c "SELECT json_build_object('label', '$s', 'kind', 'tables',
		'hosts', (SELECT count(*) FROM shawk.hosts),
		'edges', (SELECT count(*) FROM shawk.edges),
		'bytes', pg_database_size('nodeload'))" >>"$OUT"
	jq -c --arg s "$s" 'select(.label == "connector-out") | .label = $s | .kind = "out"' "$WORK/out.jsonl" >>"$OUT"
	: >"$WORK/out.jsonl"
	cat "$WORK"/collector-*.log | grep -iE 'warn|error' | tail -20 >&2 || true
	rm -f "$WORK"/collector-*.log
	pg -d nodeload -c "DROP SCHEMA IF EXISTS shawk_v1 CASCADE" -c "DROP SCHEMA IF EXISTS shawk CASCADE" >/dev/null
done
