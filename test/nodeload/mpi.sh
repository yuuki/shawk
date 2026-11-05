#!/usr/bin/env bash
# Counts the flows of real MPI over TCP (Open MPI, btl tcp) for
# docs/research/hpc-compute-nodes/compute_nodes.md, as root, appending JSON
# lines of probe to OUT (default mpi-$(uname -r).jsonl), each with the
# number of flows keys.py predicts from the connections (-expect):
#
#   mpicc -O2 -o alltoall test/nodeload/mpi/alltoall.c
#   sudo NODELOAD=./nodeload ALLTOALL=./alltoall test/nodeload/mpi.sh [OUT]
#
# 1. A job of RANKS ranks of alltoall on the Slurm cluster of this host
#    (slurm.sh), launched by srun with PMIx, with jobacct_gather/cgroup,
#    without and with ConstrainRAMSpace.
# 2. Three nodes as network namespaces m1, m2, m3 on a bridge (10.96.0.1 to
#    .3), and RANKS ranks on each, launched by mpirun from m1 with an rsh
#    agent that enters the namespaces: the ranks of a node share a cgroup.
#    The flows of m1 are counted. The daemons of the nodes share the host:
#    the topology that rtc/hwloc writes to shared memory crashed them
#    (Open MPI 4.1.1, hwloc 2.4.1), so it is left out.
#
# MPI uses TCP between all ranks, also of one node (btl self,tcp).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NL=$(realpath "${NODELOAD:-nodeload}")
A2A=$(realpath "${ALLTOALL:-alltoall}")
OUT=$(realpath -m "${1:-mpi-$(uname -r).jsonl}")
MPIBIN=${MPIBIN:-/usr/lib64/openmpi/bin}
export OMPI_MCA_btl=self,tcp OMPI_MCA_pml=ob1
WORK=$(mktemp -d)
cleanup() {
	set +e
	kill $(jobs -p) 2>/dev/null
	wait 2>/dev/null
	for n in m1 m2 m3; do ip netns del $n 2>/dev/null; done
	ip link del mbr 2>/dev/null
	sed -i '/ # nodeload$/d' /etc/hosts
	rm -rf "$WORK"
}
trap cleanup EXIT

# count LABEL NETNS: probes the flows of alltoall while it runs, with the
# flows its connections make by keys.py.
count() {
	local label=$1 ns=$2 expect enter=()
	[[ $ns == - ]] || enter=(nsenter --net=/run/netns/$ns)
	sleep 15
	expect=$({ "${enter[@]}" ss -Htnp state established; echo --; "${enter[@]}" ss -Htlnp; } | python3 "$HERE/keys.py" alltoall)
	echo "$label: flows predicted (all, out, in): $expect" >&2
	local args=(-comm alltoall -count 3 -expect "${expect%% *}" -label "$label")
	[[ $ns == - ]] || args+=(-netns /run/netns/$ns)
	"$NL" probe "${args[@]}" >>"$OUT"
}

# 1. Slurm with jobacct_gather/cgroup, without ConstrainRAMSpace (the
# tasks of a step share task_special up to Slurm 24.11.2) and with it (a
# cgroup per task); the cgroups the ranks are in are logged.
for ram in no yes; do
	acct=ram-$ram
	ACCT=cgroup RAM=$ram bash "$HERE/slurm.sh"
	for ranks in 4 8 16; do
		srun -n $ranks --overcommit "$A2A" 100 &
		sleep 5
		echo "slurm-srun-$acct-$ranks: cgroups of the ranks:" \
			$(for p in $(pgrep -x alltoall); do cut -d: -f3 /proc/$p/cgroup; done | sort | uniq -c | sed 's|/system.slice/slurmstepd.scope/||') >&2
		count "slurm-srun-$acct-$ranks" -
		wait
	done
done

# 2. Three nodes.
ip link add mbr type bridge
ip link set mbr up
for i in 1 2 3; do
	n=m$i
	ip netns add $n
	ip link add $n type veth peer name eth0 netns $n
	ip link set $n master mbr up
	nsenter --net=/run/netns/$n ip addr add 10.96.0.$i/24 dev eth0
	nsenter --net=/run/netns/$n ip link set eth0 up
	nsenter --net=/run/netns/$n ip link set lo up
	echo "10.96.0.$i $n # nodeload" >>/etc/hosts
done
cat >"$WORK/nsrsh" <<'EOF'
#!/bin/sh
# An rsh agent of Open MPI: runs the command on a node, its namespace.
host=$1
shift
exec nsenter --net=/run/netns/"$host" /bin/sh -c "$*"
EOF
chmod +x "$WORK/nsrsh"
for ranks in 4 8 16; do
	nsenter --net=/run/netns/m1 "$MPIBIN/mpirun" --prefix "$(dirname "$MPIBIN")" --allow-run-as-root --oversubscribe -np $((3 * ranks)) \
		--host m1:$ranks,m2:$ranks,m3:$ranks --mca plm_rsh_agent "$WORK/nsrsh" \
		--mca btl_tcp_if_include 10.96.0.0/24 --mca oob_tcp_if_include 10.96.0.0/24 \
		--mca rtc ^hwloc \
		"$A2A" 100 &
	count "mpirun-3nodes-$ranks" m1
	wait
done
