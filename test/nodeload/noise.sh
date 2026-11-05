#!/usr/bin/env bash
# Runs the measurements of the effect of the agent on jobs of
# docs/research/hpc-compute-nodes/compute_nodes.md, as root, appending JSON
# lines to OUT (default noise-$(uname -r).jsonl):
#
#   mpicc -O2 -o noise test/nodeload/mpi/noise.c
#   sudo NODELOAD=./nodeload NOISE=./noise ENDPOINT=http://collector:4327 test/nodeload/noise.sh [OUT]
#
# The host is a Slurm cluster of its own (slurm.sh). The ranks of mesh hold
# the connections of 128 ranks to 94 peer nodes in the namespace "node",
# idle; the agent traces all namespaces, those of the peer nodes too, so
# that every collection walks the 24064 sides of 12032 connections, about
# the 24192 flows of a compute node of the issue, which -max-flows 32768
# holds. A job of noise (an MPI_Allreduce of 8
# bytes over TCP, -n ITER) then runs on all the CPUs Slurm gives it, in
# these configurations, each REPS times, interleaved:
#
#   all-none             no CPU reserved, no agent: all CPUs run ranks
#   all-agent            no CPU reserved, the agent as packaged
#   spec-none            CpuSpecList=SPEC, no agent: the job runs on the others
#   spec-agent           CpuSpecList=SPEC, the agent as packaged
#   spec-agent-confined  CpuSpecList=SPEC, the agent with AllowedCPUs=SPEC
#                        (packaging/systemd/shawk-agent-reserved-cpus.conf)
#
# The effect of the agent is the difference to the configuration without it
# with the same CPUs reserved: the spec-* jobs have as many ranks fewer as
# SPEC has CPUs. SPEC is a comma-separated list of CPUs, the same ids for
# Slurm (CpuSpecList) and the kernel (AllowedCPUs): check that they are on
# the host (slurmd runs on them, which the log shows).
#
# The agent is the unit of packaging/systemd with /usr/bin/shawk, sending to
# ENDPOINT (an OTLP receiver on another host, e.g. nodeload sink, so that
# receiving costs this host nothing) with -max-flows 32768. MPI uses TCP
# (btl self,tcp), not shared memory. Run it on a disposable host.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NL=$(realpath "${NODELOAD:-nodeload}")
NOISE=$(realpath "${NOISE:-noise}")
OUT=$(realpath -m "${1:-noise-$(uname -r).jsonl}")
ENDPOINT=${ENDPOINT:?set ENDPOINT to an OTLP receiver on another host}
REPS=${REPS:-5}
ITER=${ITER:-500000}
SPEC=${SPEC:-0}
CONFIGS=${CONFIGS:-"all-none all-agent spec-none spec-agent spec-agent-confined"}
CG=/sys/fs/cgroup/nodeload.slice
WORK=$(mktemp -d)
PIDS=()
cleanup() {
	systemctl stop shawk-agent 2>/dev/null || true
	kill "${PIDS[@]}" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# The connections of the compute node, idle.
[[ $SPEC =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "SPEC must be a comma-separated list of CPUs" >&2; exit 2; }
bash "$HERE/setup.sh" 94
nsenter --net=/run/netns/peers "$NL" peer -peer-ranks 128 -peers 94 -ready "$WORK/peer.ready" -traffic 0 2>>"$WORK/log" &
PIDS+=($!)
until [[ -e $WORK/peer.ready ]]; do sleep 0.2; done
nsenter --net=/run/netns/node "$NL" mesh -ranks 128 -peers 94 -ports 1 -peer-ranks 128 -traffic 0 \
	-cgroup "$CG" -ready "$WORK/mesh.ready" 2>>"$WORK/log" &
PIDS+=($!)
until [[ -e $WORK/mesh.ready ]]; do sleep 1; done

install -m 0755 "${SHAWK:-$ROOT/shawk}" /usr/bin/shawk
install -m 0644 "$ROOT/packaging/systemd/shawk-agent.service" /etc/systemd/system/
mkdir -p /etc/shawk /etc/systemd/system/shawk-agent.service.d
echo "SHAWK_AGENT_OPTS=-otlp-endpoint $ENDPOINT -max-flows 32768" >/etc/shawk/agent.env

spec_now=unset
# config NAME: reconfigures Slurm and the agent, and sets CPUS to the CPUs
# of the node. It runs in this shell, so that spec_now is kept.
config() {
	local spec="" agent=none
	case $1 in
	spec-*) spec=$SPEC ;;
	esac
	case $1 in
	*-agent) agent=packaged ;;
	*-agent-confined) agent=confined ;;
	esac
	if [[ $spec != "$spec_now" ]]; then
		bash "$HERE/slurm.sh" $spec >&2
		spec_now=$spec
		echo "$1: slurmd on CPUs $(cat /sys/fs/cgroup/system.slice/slurmd.service/cpuset.cpus.effective)," \
			"slurmstepd on $(cat /sys/fs/cgroup/system.slice/slurmstepd.scope/cpuset.cpus.effective 2>/dev/null)" >&2
	fi
	systemctl stop shawk-agent 2>/dev/null || true
	rm -f /etc/systemd/system/shawk-agent.service.d/*.conf
	if [[ $agent == confined ]]; then
		sed "s/^AllowedCPUs=.*/AllowedCPUs=$SPEC/" "$ROOT/packaging/systemd/shawk-agent-reserved-cpus.conf" \
			>/etc/systemd/system/shawk-agent.service.d/reserved-cpus.conf
	fi
	systemctl daemon-reload
	if [[ $agent != none ]]; then
		systemctl start shawk-agent
		# Past the adoption of the connections at start.
		sleep 20
		systemctl is-active -q shawk-agent || { journalctl -u shawk-agent -n 20 >&2; exit 1; }
		echo "$1: agent on CPUs $(cat /sys/fs/cgroup/system.slice/shawk-agent.service/cpuset.cpus.effective)" >&2
	fi
	CPUS=$(sinfo -h -N -o %c)
}

for rep in $(seq "$REPS"); do
	order=$CONFIGS
	# Every other repetition in the reverse order, so that a drift of the
	# host spreads over the configurations.
	((rep % 2 == 0)) && order=$(echo "$CONFIGS" | tr ' ' '\n' | tac | tr '\n' ' ')
	for c in $order; do
		config "$c"
		ranks=$CPUS
		[[ $c == spec-* ]] && ranks=$((CPUS - $(echo "$SPEC" | tr ',' '\n' | wc -l)))
		echo "rep $rep: $c, $ranks ranks" >&2
		OMPI_MCA_btl=self,tcp OMPI_MCA_pml=ob1 srun -n "$ranks" --cpu-bind=cores "$NOISE" "$ITER" "$c" >>"$OUT"
	done
done
