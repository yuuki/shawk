#!/usr/bin/env bash
# Runs the measurements of the flow table and of the agent of
# docs/research/hpc-compute-nodes/compute_nodes.md on the running kernel,
# as root, appending JSON lines to OUT (default flows-$(uname -r).jsonl):
#
#   go build -o nodeload ./test/nodeload && go build -o shawk ./cmd/shawk
#   sudo NODELOAD=./nodeload SHAWK=./shawk test/nodeload/flows.sh [OUT]
#   ./nodeload flows OUT
#
# For each workload, the ranks of mesh run in the namespace "node" of
# setup.sh with the peer nodes in "peers": RANKS ranks, each connecting to
# PORTS ranks of each of PEERS peer nodes, and with IN every peer node
# connecting to every rank too. probe then collects the flows of "node"
# for COUNT intervals of 15 s with each -max-flows of MAXFLOWS. Last, the
# agent itself runs with AGENT_MAXFLOWS against the sink, watched by watch.
# ONLY runs the workload of that label only; an empty MAXFLOWS skips probe.
# The cgroups of the ranks are under nodeload.slice. Run it on a disposable
# host: it changes sysctls and makes namespaces.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NL=$(realpath "${NODELOAD:-nodeload}")
SHAWK=$(realpath "${SHAWK:-shawk}")
OUT=$(realpath -m "${1:-flows-$(uname -r).jsonl}")
COUNT=${COUNT:-6}
MAXFLOWS=${MAXFLOWS-"16384 32768 65536 131072"}
AGENT_MAXFLOWS=${AGENT_MAXFLOWS:-131072}
CG=/sys/fs/cgroup/nodeload.slice
WORK=$(mktemp -d)
PIDS=()
cleanup() {
	kill "${PIDS[@]}" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# workload LABEL RANKS PEERS PORTS IN [MESH FLAGS...]: starts the ranks
# and the peer nodes, and waits until they are connected.
workload() {
	local label=$1 ranks=$2 peers=$3 ports=$4 in=$5 inflag=() inranks=0
	shift 5
	if [[ $in == 1 ]]; then inflag=(-in) inranks=$ranks; fi
	bash "$HERE/setup.sh" "$peers"
	rm -f "$WORK"/*.ready*
	nsenter --net=/run/netns/peers "$NL" peer -peer-ranks "$ranks" -peers "$peers" -in-ranks "$inranks" \
		-ready "$WORK/peer.ready" 2>>"$WORK/log" &
	PIDS+=($!)
	until [[ -e $WORK/peer.ready ]]; do sleep 0.2; done
	nsenter --net=/run/netns/node "$NL" mesh -ranks "$ranks" -peers "$peers" -ports "$ports" -peer-ranks "$ranks" \
		"${inflag[@]}" -cgroup "$CG" -ready "$WORK/mesh.ready" "$@" 2>>"$WORK/log" &
	PIDS+=($!)
	local deadline=$((SECONDS + 600)) pid
	until [[ -e $WORK/mesh.ready ]] && { [[ $in == 0 ]] || [[ -e $WORK/peer.ready.in ]]; }; do
		for pid in "${PIDS[@]}"; do
			kill -0 "$pid" 2>/dev/null || { echo "$label: the workload exited" >&2; cat "$WORK/log" >&2; exit 1; }
		done
		((SECONDS < deadline)) || { echo "$label: the workload did not connect" >&2; cat "$WORK/log" >&2; exit 1; }
		sleep 1
	done
	EXPECT=$((ranks * peers * ports + (in == 1 ? ranks * peers : 0)))
	# The flows of short jobs come and go: no coverage.
	[[ " $* " == *" -short-rate "* ]] && EXPECT=0
	LABEL=$label
	echo "$label: $(nsenter --net=/run/netns/node ss -Htn state established | wc -l) connections, $EXPECT flows expected (0: not counted)" >&2
}

stop_workload() {
	kill "${PIDS[@]}" 2>/dev/null || true
	wait "${PIDS[@]}" 2>/dev/null || true
	PIDS=()
}

probe() {
	for mf in $MAXFLOWS; do
		"$NL" probe -netns /run/netns/node -max-flows "$mf" -count "$COUNT" -expect "$EXPECT" -label "$LABEL" >>"$OUT"
	done
}

# agent: the agent of shawk on the namespace "node", sending to the sink,
# with its CPU time and memory watched; its log is kept next to OUT.
agent() {
	local ino
	ino=$(stat -L -c %i /run/netns/node)
	"$NL" sink -listen 127.0.0.1:4327 -label "$LABEL" >>"$OUT" 2>>"$WORK/log" &
	local sink=$!
	"$SHAWK" agent -netns "$ino" -max-flows "$AGENT_MAXFLOWS" -otlp-endpoint http://127.0.0.1:4327 \
		2>>"${OUT%.jsonl}-$LABEL-agent.log" &
	local agent=$!
	"$NL" watch -pid "$agent" -count "$((COUNT + 2))" -label "$LABEL" >>"$OUT"
	# The agent sends its last interval when it stops; the sink prints it.
	kill "$agent"
	wait "$agent" 2>/dev/null || true
	kill "$sink"
	wait "$sink" 2>/dev/null || true
}

# run LABEL RANKS PEERS PORTS IN [MESH FLAGS...]; ONLY selects one label.
run() {
	[[ -z ${ONLY:-} || $1 == "$ONLY" ]] || return 0
	workload "$@"
	probe
	agent
	stop_workload
}

# The flows of a rank talking to the same rank of every other node, as
# the issue assumes, below, at and above the default -max-flows; with
# both sides connecting; and a rank talking to several ranks of each node.
run neighbor-64 128 64 1 0
run neighbor-128 128 128 1 0
run neighbor-189 128 189 1 0
run neighbor-189-both 128 189 1 1
run ranks4-189 128 189 4 0
# Four concurrent jobs, and short jobs of 4 ranks with 8 peer nodes each,
# 30 a minute, over the 128 ranks of the neighbor pattern.
run churn-189 128 189 1 0 -jobs 4 -short-rate 30 -short-ranks 4 -short-peers 8 -short-secs 10s
# Ten short jobs a second, as a burst of jobs of a job array.
run churn-fast-189 128 189 1 0 -jobs 4 -short-rate 600 -short-ranks 4 -short-peers 8 -short-secs 5s

# Which flows the table keeps when it is full: among the ranks of
# neighbor-189 and the default -max-flows, the persistent connections of a
# client of a file system to 4 servers (nfsclient) and a short connection
# every 5 s (slurmd), each command in a cgroup of its own.
priority() {
	[[ -z ${ONLY:-} || $ONLY == priority ]] || return 0
	workload priority-189 128 189 1 0
	local name
	for name in nfsclient slurmd; do
		cp "$NL" "$WORK/$name"
		mkdir -p "$CG/$name.service"
	done
	nsenter --net=/run/netns/node sh -c 'echo $$ >"$1/cgroup.procs" && shift && exec "$@"' sh "$CG/nfsclient.service" \
		"$WORK/nfsclient" rank -id 0 -peers 4 -ports 1 -peer-ranks 128 >/dev/null &
	PIDS+=($!)
	nsenter --net=/run/netns/node sh -c 'echo $$ >"$1/cgroup.procs" && shift && exec "$@"' sh "$CG/slurmd.service" \
		"$WORK/slurmd" rank -id 1 -peer-first 10.98.0.5 -peers 1 -ports 1 -peer-ranks 128 -short >/dev/null &
	PIDS+=($!)
	sleep 5
	"$NL" probe -netns /run/netns/node -comm nfsclient -count "$COUNT" -expect 4 -label priority-nfsclient >>"$OUT"
	"$NL" probe -netns /run/netns/node -comm slurmd -count "$COUNT" -expect 1 -label priority-slurmd >>"$OUT"
	stop_workload
	rmdir "$CG/nfsclient.service" "$CG/slurmd.service"
}
priority
