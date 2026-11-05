#!/usr/bin/env bash
# Runs jobs on the cluster of test/harness/slurm.sh and checks them, as root
# in its VM (slurm.sh check runs it):
#
#   check.sh UNITS
#
# UNITS is test/harness/units built for the VM. A batch job of the user of
# the VM runs srun with two tasks; while they run:
#
# - every process of the job has the unit the agent gives it
#   (procinfo.Unit) that its step in Slurm calls for (scontrol listpids):
#   slurm/batch for those of the batch step (the script and srun),
#   slurm/step for those of step 0 (the two tasks), and slurmstepd for the
#   slurmstepd of both steps (#173);
# - the directory of the job in the cgroup tree, the same for all of them,
#   is job_<id> before Slurm 26.05 or with CgroupJobIdPaths=yes, and
#   otherwise the SLUID that scontrol shows;
# - the ports srun listens on are printed, and must be in SrunPortRange if
#   it is set (#174).
#
# With MpiDefault=pmix, an MPI program then runs with two ranks through
# srun.
set -euo pipefail
UNITS="${1:?usage: check.sh UNITS}"
WORK="$(mktemp -d)"
JOBS=()
cleanup() {
	((${#JOBS[@]} == 0)) || scancel "${JOBS[@]}" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() { echo "OK: $*"; }
at_least() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
# as_user CMD...: runs CMD as the user of the VM (who ran sudo), so that
# the jobs are those of a user, not of root.
as_user() {
	if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
		runuser -u "$SUDO_USER" -- env "PATH=$PATH" "$@"
	else
		"$@"
	fi
}
chmod 0755 "$WORK"

version="$(scontrol version | cut -d' ' -f2)"
job_id_paths="$(sed -n 's/^CgroupJobIdPaths=//p' /etc/slurm/cgroup.conf)"
port_range="$(sed -n 's/^SrunPortRange=//p' /etc/slurm/slurm.conf)"
echo "Slurm $version, CgroupJobIdPaths=${job_id_paths:-(default)}, SrunPortRange=${port_range:-(none)}"

job="$(cd "$WORK" && as_user sbatch --parsable -n2 -o /dev/null --wrap 'srun -n2 sleep 300')"
job="${job%%;*}"
JOBS+=("$job")
# Wait for the two tasks of step 0.
for ((i = 0; i < 120; i++)); do
	[[ "$(scontrol listpids "$job" 2>/dev/null | awk '$3 == "0"' | wc -l)" -ge 2 ]] && break
	sleep 1
done
scontrol listpids "$job" >"$WORK/pids" 2>&1 || true
[[ "$(awk '$3 == "0"' "$WORK/pids" | wc -l)" -ge 2 ]] || {
	cat "$WORK/pids" >&2
	squeue >&2
	fail "the tasks of job $job did not start"
}
# The processes of the job by their step (PID STEP), and the slurmstepd of
# its steps.
awk 'NR > 1 { print $1, $3 }' "$WORK/pids" >"$WORK/steps"
pids=$({
	awk '{ print $1 }' "$WORK/steps"
	pgrep -f "^slurmstepd: \[$job\." || true
} | sort -nu)
echo "processes of job $job:"
# shellcheck disable=SC2086
"$UNITS" $pids >"$WORK/units" || fail "units failed: a process of job $job is gone"
sed 's/^/  /' "$WORK/units"

# The unit each process must have, from its step in Slurm.
awk 'FNR == NR { step[$1] = $2; next }
	{
		if ($2 == "slurmstepd") want = "slurmstepd"
		else if (step[$1] == "batch") want = "slurm/batch"
		else if (step[$1] == "0") want = "slurm/step"
		else want = "none (step " step[$1] ")"
		if ($3 != want) { printf "  %s %s has the unit %s, not %s\n", $1, $2, $3, want; bad = 1 }
	}
	END { exit bad }' "$WORK/steps" "$WORK/units" >&2 || fail "processes of job $job have other units than their steps call for"
# count COMM UNIT: the processes named COMM with the unit UNIT.
count() { awk -v c="$1" -v u="$2" '$2 == c && $3 == u' "$WORK/units" | wc -l | tr -d ' '; }
[[ "$(count sleep slurm/step)" == 2 ]] || fail "not the two tasks of job $job with the unit slurm/step"
(($(count slurm_script slurm/batch) >= 1)) || fail "no batch script of job $job with the unit slurm/batch"
(($(count srun slurm/batch) >= 1)) || fail "no srun of job $job with the unit slurm/batch"
(($(count slurmstepd slurmstepd) >= 2)) || fail "not the slurmstepd of both steps of job $job with the unit slurmstepd"
ok "the processes of job $job have the units of their steps: slurm/batch, slurm/step, slurmstepd"

# The directory of the job, after the scope of slurmstepd, in the cgroups of
# all its processes.
dirs="$(awk '{ print $4 }' "$WORK/units" | sed -n 's|^.*slurmstepd[^/]*\.scope/\([^/]*\)/.*$|\1|p' | sort -u)"
if ! at_least "$version" 26.05 || [[ "$job_id_paths" == yes ]]; then
	want="job_$job"
else
	# scontrol shows the SLUID with -d.
	want="$(scontrol -d show job "$job" | sed -n 's/.*SLUID=\([^ ]*\).*/\1/p' | head -1)"
	[[ -n "$want" ]] || fail "scontrol -d shows no SLUID of job $job"
fi
[[ "$dirs" == "$want" ]] || fail "the cgroups of job $job are in $(echo $dirs), not $want"
ok "the cgroups of job $job are in $want"

ports="$(ss -Htlnp | awk '/"srun"/ { n = split($4, a, ":"); print a[n] }' | sort -nu | tr '\n' ' ')"
[[ -n "$ports" ]] || fail "srun listens on no port"
if [[ -n "$port_range" ]]; then
	for p in $ports; do
		((p >= ${port_range%-*} && p <= ${port_range#*-})) || fail "srun listens on $p, outside SrunPortRange=$port_range"
	done
fi
ok "srun listens on the ports $ports"
scancel "$job"

if grep -q '^MpiDefault=pmix' /etc/slurm/slurm.conf; then
	cat >"$WORK/hello.c" <<'EOF'
#include <mpi.h>
#include <stdio.h>
int main(int argc, char **argv) {
	int rank, size;
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	MPI_Barrier(MPI_COMM_WORLD);
	printf("rank %d of %d\n", rank, size);
	MPI_Finalize();
	return 0;
}
EOF
	/usr/lib64/openmpi/bin/mpicc -o "$WORK/hello" "$WORK/hello.c"
	# TCP between the ranks, also on one node, as in #172.
	out="$(cd "$WORK" && as_user env OMPI_MCA_btl=self,tcp OMPI_MCA_pml=ob1 timeout 120 srun -n2 "$WORK/hello" 2>&1)" ||
		fail "srun of an MPI program failed: $out"
	[[ "$(grep -c '^rank [01] of 2$' <<<"$out")" == 2 ]] || fail "unexpected output of the MPI program: $out"
	ok "an MPI program ran with 2 ranks through srun (PMIx)"
fi
