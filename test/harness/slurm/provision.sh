#!/usr/bin/env bash
# Provisions the Slurm cluster of one node of test/harness/slurm.sh in its
# VM (Rocky Linux 9), as root, with the settings that slurm.sh passes in the
# environment (see there):
#
#   VERSION TARBALL CACHE GO_TARBALL MPI JOB_ID_PATHS SRUN_PORT_RANGE
#   JOBACCT CONSTRAIN_RAM CPU_SPEC
#
# Running it again reconfigures and restarts the daemons; another version
# replaces Slurm and deletes its state. Slurm is built from TARBALL, the
# verified source, into /opt/slurm once per version, architecture and MPI,
# and kept as a tarball in CACHE/slurm, which the VM shares with the host.
# GO_TARBALL, the verified release of Go of go.mod, is installed in
# /usr/local/go.
#
# Without VERSION, it only reconfigures the Slurm installed, e.g. from a
# script in the VM that changes the settings between measurements:
#
#   JOBACCT=cgroup CONSTRAIN_RAM=yes bash test/harness/slurm/provision.sh
#
# Slurm is configured as in #195 (test/nodeload/slurm.sh): cgroup v2,
# proctrack/cgroup, task/cgroup with ConstrainCores, select/cons_tres. The
# node is the VM, addressed by its address on its first interface.
set -euo pipefail

log() { echo "provision: $*" >&2; }
die() {
	echo "provision: $*" >&2
	exit 1
}

if [[ -n "${VERSION:-}" ]]; then
	: "${TARBALL:?}" "${CACHE:?}" "${GO_TARBALL:?}"
	MPI=${MPI:-yes}
else
	read -r VERSION flavor </opt/slurm/.harness 2>/dev/null || die "no Slurm is installed: run test/harness/slurm.sh up"
	installed_mpi=no
	[[ "$flavor" == *-pmix ]] && installed_mpi=yes
	MPI=${MPI:-$installed_mpi}
	[[ "$MPI" == "$installed_mpi" ]] || die "MPI=$MPI needs another build of Slurm: run test/harness/slurm.sh up with SLURM_MPI=$MPI"
fi
JOB_ID_PATHS=${JOB_ID_PATHS:-}
SRUN_PORT_RANGE=${SRUN_PORT_RANGE:-}
JOBACCT=${JOBACCT:-cgroup}
CONSTRAIN_RAM=${CONSTRAIN_RAM:-no}
CPU_SPEC=${CPU_SPEC:-}

# at_least VERSION MIN: whether VERSION is MIN or later.
at_least() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

[[ "$MPI" =~ ^(yes|no)$ ]] || die "SLURM_MPI must be yes or no"
[[ "$JOB_ID_PATHS" =~ ^(|yes|no)$ ]] || die "SLURM_CGROUP_JOB_ID_PATHS must be yes or no"
[[ "$JOBACCT" =~ ^(cgroup|linux|none)$ ]] || die "SLURM_JOBACCT must be cgroup, linux or none"
[[ "$CONSTRAIN_RAM" =~ ^(yes|no)$ ]] || die "SLURM_CONSTRAIN_RAM must be yes or no"
[[ "$SRUN_PORT_RANGE" =~ ^([0-9]+-[0-9]+)?$ ]] || die "SLURM_SRUN_PORT_RANGE must be like 60001-63000"
[[ "$CPU_SPEC" =~ ^[0-9,-]*$ ]] || die "SLURM_CPU_SPEC must be a list of CPUs like 0 or 0,1"
if [[ -n "$JOB_ID_PATHS" ]] && ! at_least "$VERSION" 26.05; then
	# Before 26.05 the directories of jobs are job_<id>, and cgroup.conf has
	# no CgroupJobIdPaths.
	[[ "$JOB_ID_PATHS" == yes ]] || die "Slurm $VERSION names the cgroups of jobs job_<id>; SLUIDs need 26.05 or later"
	JOB_ID_PATHS=""
fi

# Packages: to build Slurm (cgroup/v2 needs D-Bus, the devices of cgroup v2
# the headers of BPF), munge, the tools of the tests (those of make e2e
# among them: psql, iproute, iptables, nsenter), and Open MPI with PMIx.
# From the BaseOS, AppStream and CRB repositories of Rocky Linux, whose
# signatures dnf checks.
pkgs=(gcc make bzip2 tar perl python3 munge munge-devel pam-devel readline-devel dbus-devel
	hwloc-devel json-c-devel kernel-headers iproute procps-ng util-linux jq nftables iptables-nft
	postgresql)
[[ "$MPI" == yes ]] && pkgs+=(pmix pmix-devel openmpi openmpi-devel)
if ! rpm -q "${pkgs[@]}" >/dev/null 2>&1; then
	log "installing ${pkgs[*]}"
	dnf -y --enablerepo=crb install "${pkgs[@]}" >/var/log/harness-dnf.log 2>&1 ||
		{ tail -30 /var/log/harness-dnf.log >&2; die "dnf failed (log: /var/log/harness-dnf.log)"; }
fi

# Go of go.mod, and none other (GOTOOLCHAIN=local in slurm.sh).
if [[ -n "${GO_TARBALL:-}" ]]; then
	go_version="$(basename "$GO_TARBALL" | sed 's/\.linux-.*//')"
	if [[ "$(head -1 /usr/local/go/VERSION 2>/dev/null)" != "$go_version" ]]; then
		log "installing $go_version in /usr/local/go"
		rm -rf /usr/local/go
		tar -xzf "$GO_TARBALL" -C /usr/local
	fi
fi
cat >/etc/profile.d/harness.sh <<'EOF'
# Written by test/harness/slurm/provision.sh: as slurm.sh run and shell.
PATH=/opt/slurm/bin:/opt/slurm/sbin:/usr/local/go/bin:$PATH:/usr/lib64/openmpi/bin
export GOTOOLCHAIN=local GOFLAGS=-buildvcs=false SHAWK_HARNESS_STATE=/var/tmp/shawk-harness
EOF

flavor="el9-$(uname -m)"
[[ "$MPI" == yes ]] && flavor+=-pmix
pkg="${CACHE:-}/slurm/slurm-$VERSION-$flavor.tar.gz"
if [[ -n "${TARBALL:-}" && ! -f "$pkg" ]]; then
	log "building Slurm $VERSION ($flavor), which takes a few minutes, into $pkg"
	src=/var/tmp/shawk-slurm-build
	rm -rf "$src"
	mkdir -p "$src/source" "$src/dest"
	tar -xjf "$TARBALL" -C "$src/source" --strip-components=1
	opts=(--prefix=/opt/slurm --sysconfdir=/etc/slurm --disable-dependency-tracking --disable-static)
	[[ "$MPI" == yes ]] && opts+=(--with-pmix=/usr)
	(
		cd "$src/source"
		./configure "${opts[@]}" >"$src/configure.log" 2>&1 || { tail -30 "$src/configure.log"; exit 1; }
		make -j"$(nproc)" >"$src/make.log" 2>&1 || { tail -30 "$src/make.log"; exit 1; }
		make install-strip DESTDIR="$src/dest" >>"$src/make.log" 2>&1 || { tail -30 "$src/make.log"; exit 1; }
		mkdir -p "$src/dest/opt/slurm/systemd"
		cp etc/slurmctld.service etc/slurmd.service "$src/dest/opt/slurm/systemd/"
	) || die "building Slurm $VERSION failed (logs in $src)"
	# The plugins the cluster needs, which configure leaves out silently
	# when their libraries are missing.
	need=(cgroup_v2 auth_munge proctrack_cgroup task_cgroup)
	[[ "$MPI" == yes ]] && need+=(mpi_pmix)
	for p in "${need[@]}"; do
		[[ -f "$src/dest/opt/slurm/lib/slurm/$p.so" ]] || die "Slurm $VERSION was built without $p (logs in $src)"
	done
	# Written aside and renamed, so that VMs sharing the cache never see a
	# partial file.
	mkdir -p "$CACHE/slurm"
	part="$(mktemp "$CACHE/slurm/.part.XXXXXX")"
	tar -C "$src/dest" -czf "$part" opt
	chmod 0644 "$part"
	mv -f "$part" "$pkg"
	rm -rf "$src"
fi

if [[ "$(cat /opt/slurm/.harness 2>/dev/null)" != "$VERSION $flavor" ]]; then
	log "installing Slurm $VERSION ($flavor) in /opt/slurm"
	systemctl stop slurmd slurmctld 2>/dev/null || true
	# Another version may not read the state of this one.
	rm -rf /opt/slurm /var/spool/slurm
	if ! tar -xzf "$pkg" -C /; then
		rm -rf /opt/slurm "$pkg"
		die "the build of Slurm in the cache was damaged and is deleted: run test/harness/slurm.sh up again"
	fi
	# The binaries are labeled like those of /usr/bin, which systemd starts.
	command -v chcon >/dev/null && chcon -R -t bin_t /opt/slurm/bin /opt/slurm/sbin 2>/dev/null || true
	# Written last: an interrupted installation is done again.
	echo "$VERSION $flavor" >/opt/slurm/.harness
fi
# The units of the Slurm installed, at every run, so that they are those of
# its version whatever an earlier run left.
for unit in slurmctld.service slurmd.service; do
	if ! cmp -s "/opt/slurm/systemd/$unit" "/etc/systemd/system/$unit"; then
		install -m 0644 "/opt/slurm/systemd/$unit" /etc/systemd/system/
		systemctl daemon-reload
	fi
done

# The user of slurmctld, which the build does not make.
id slurm >/dev/null 2>&1 || useradd -r -M -d /var/spool/slurm -s /sbin/nologin slurm
install -d -o slurm -g slurm /var/spool/slurm /var/spool/slurm/ctld /var/log/slurm
install -d /var/spool/slurm/d

# The key of munge, made here and never leaving the VM.
if [[ ! -s /etc/munge/munge.key ]]; then
	dd if=/dev/urandom of=/etc/munge/munge.key bs=1024 count=1 status=none
	chown munge:munge /etc/munge/munge.key
	chmod 0400 /etc/munge/munge.key
fi
# The unit of munge of Rocky Linux has its PID file in /var/run, which
# systemd-analyze verify warns about for every unit, those of shawk too,
# which fails TestUnitsVerify of make test (#196). The same unit with
# /run, which /var/run links to, replaces it.
if [[ ! -f /etc/systemd/system/munge.service ]]; then
	sed 's|^PIDFile=/var/run/|PIDFile=/run/|' /usr/lib/systemd/system/munge.service >/etc/systemd/system/munge.service
	systemctl daemon-reload
fi
systemctl enable --now munge

node="$(hostname -s)"
addr="$(ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
[[ -n "$addr" ]] || die "no IPv4 address"
hw="$(/opt/slurm/sbin/slurmd -C | head -1 | sed 's/^NodeName=[^ ]* //')"
mkdir -p /etc/slurm
{
	echo "# Written by test/harness/slurm/provision.sh."
	echo "ClusterName=shawk"
	echo "SlurmctldHost=$node($addr)"
	echo "SlurmUser=slurm"
	echo "AuthType=auth/munge"
	echo "StateSaveLocation=/var/spool/slurm/ctld"
	echo "SlurmdSpoolDir=/var/spool/slurm/d"
	echo "SlurmctldLogFile=/var/log/slurm/slurmctld.log"
	echo "SlurmdLogFile=/var/log/slurm/slurmd.log"
	echo "ProctrackType=proctrack/cgroup"
	echo "TaskPlugin=task/cgroup,task/affinity"
	# Without a plugin, Slurm gathers nothing (jobacct_gather/none is gone in
	# later versions).
	[[ "$JOBACCT" == none ]] || echo "JobAcctGatherType=jobacct_gather/$JOBACCT"
	[[ "$MPI" == yes ]] && echo "MpiDefault=pmix"
	echo "SelectType=select/cons_tres"
	echo "SelectTypeParameters=CR_Core"
	echo "ReturnToService=2"
	[[ -n "$SRUN_PORT_RANGE" ]] && echo "SrunPortRange=$SRUN_PORT_RANGE"
	echo "NodeName=$node NodeAddr=$addr $hw${CPU_SPEC:+ CpuSpecList=$CPU_SPEC} State=UNKNOWN"
	echo "PartitionName=debug Nodes=ALL Default=YES MaxTime=INFINITE State=UP"
} >/etc/slurm/slurm.conf.new
{
	echo "# Written by test/harness/slurm/provision.sh."
	echo "CgroupPlugin=cgroup/v2"
	echo "ConstrainCores=yes"
	echo "ConstrainDevices=no"
	echo "ConstrainRAMSpace=$CONSTRAIN_RAM"
	if [[ -n "$JOB_ID_PATHS" ]]; then echo "CgroupJobIdPaths=$JOB_ID_PATHS"; fi
} >/etc/slurm/cgroup.conf.new
mv /etc/slurm/slurm.conf.new /etc/slurm/slurm.conf
mv /etc/slurm/cgroup.conf.new /etc/slurm/cgroup.conf

systemctl enable slurmctld slurmd >/dev/null 2>&1
systemctl restart slurmctld
systemctl restart slurmd
state=""
for _ in $(seq 60); do
	state="$(/opt/slurm/bin/sinfo -h -N -o %T 2>/dev/null || true)"
	[[ "$state" == idle ]] && break
	sleep 1
done
if [[ "$state" != idle ]]; then
	/opt/slurm/bin/scontrol show node "$node" >&2 || true
	tail -20 /var/log/slurm/slurmctld.log /var/log/slurm/slurmd.log >&2 || true
	die "the node is ${state:-not known to slurmctld}"
fi
log "Slurm $(/opt/slurm/bin/scontrol version | cut -d' ' -f2) is up: node $node ($addr), $(grep -h '^\(SrunPortRange\|CgroupJobIdPaths\|MpiDefault\|JobAcctGatherType\)=' /etc/slurm/slurm.conf /etc/slurm/cgroup.conf | tr '\n' ' ')"
