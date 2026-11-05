#!/usr/bin/env bash
# Configures and (re)starts a Slurm cluster of this host alone, as root,
# for noise.sh and mpi.sh: slurmctld and slurmd on this host, cgroup v2,
# task/cgroup with ConstrainCores, PMIx for MPI. With SPEC, the CPUs
# of SPEC are reserved for the system (CpuSpecList, abstract ids of Slurm,
# here those of the kernel): jobs do not get them, and slurmd runs there
# (slurmstepd runs in the cgroups of the job with cgroup v2).
#
#   sudo ACCT=cgroup RAM=no ./slurm.sh [SPEC]
#
# ACCT is the plugin of JobAcctGatherType without its prefix, cgroup by
# default, and RAM ConstrainRAMSpace, no by default. They decide the cgroups
# of the tasks with cgroup v2: up to Slurm 24.11.2, task/cgroup moves the
# processes of the tasks to the cgroup of the step (task_special) for
# ConstrainCores after jobacct_gather/cgroup moved them to their task_<n>,
# and memory moves them back to task_<n> after it. So the tasks of a step
# share task_special with ConstrainCores and without RAM, and have a cgroup
# each with RAM=yes (Slurm commit 91f1fc540b, 24.11.3, fixed the cpuset).
#
# Requires the packages slurm, slurm-slurmctld, slurm-slurmd and munge
# (EPEL on Rocky Linux 9), and nothing else of Slurm on the host.
set -euo pipefail
SPEC=${1:-}
ACCT=${ACCT:-cgroup}
RAM=${RAM:-no}
node=$(hostname -s)

if [[ ! -s /etc/munge/munge.key ]]; then
	dd if=/dev/urandom of=/etc/munge/munge.key bs=1024 count=1 status=none
	chown munge:munge /etc/munge/munge.key
	chmod 0400 /etc/munge/munge.key
fi
systemctl enable --now munge

hw=$(slurmd -C | head -1 | sed "s/^NodeName=[^ ]* //")
spec=""
[[ -n $SPEC ]] && spec="CpuSpecList=$SPEC"
# The packages of EPEL do not make the user of slurmctld.
id slurm >/dev/null 2>&1 || useradd -r -M -d /var/lib/slurm -s /sbin/nologin slurm
mkdir -p /var/spool/slurm/ctld /var/spool/slurm/d /var/log/slurm
chown slurm:slurm /var/spool/slurm/ctld /var/log/slurm
cat >/etc/slurm/slurm.conf <<EOF
ClusterName=nodeload
SlurmctldHost=$node
SlurmUser=slurm
StateSaveLocation=/var/spool/slurm/ctld
SlurmdSpoolDir=/var/spool/slurm/d
SlurmctldLogFile=/var/log/slurm/slurmctld.log
SlurmdLogFile=/var/log/slurm/slurmd.log
AuthType=auth/munge
ProctrackType=proctrack/cgroup
JobAcctGatherType=jobacct_gather/$ACCT
TaskPlugin=task/cgroup,task/affinity
MpiDefault=pmix
SelectType=select/cons_tres
SelectTypeParameters=CR_Core
ReturnToService=2
NodeName=$node $hw $spec State=UNKNOWN
PartitionName=batch Nodes=ALL Default=YES MaxTime=INFINITE State=UP
EOF
cat >/etc/slurm/cgroup.conf <<EOF
CgroupPlugin=cgroup/v2
ConstrainCores=yes
ConstrainDevices=no
ConstrainRAMSpace=$RAM
EOF
systemctl restart slurmctld slurmd
for _ in $(seq 60); do
	state=$(sinfo -h -N -o %T 2>/dev/null || true)
	[[ $state == idle ]] && break
	sleep 1
done
[[ $state == idle ]] || { echo "the node is $state" >&2; exit 1; }
scontrol show node "$node" | grep -E 'CPUTot|CoreSpec|CPUSpec' >&2 || true
