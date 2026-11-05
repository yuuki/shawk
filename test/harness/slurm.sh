#!/usr/bin/env bash
# A Slurm cluster of one node in a virtual machine of Lima: slurmctld,
# slurmd and munge on Rocky Linux 9 with cgroup v2, a version of Slurm built
# from its source, and optionally MPI (Open MPI with PMIx):
#
#   test/harness/slurm.sh up           create or start the VM, build and
#                                      (re)configure Slurm (idempotent)
#   test/harness/slurm.sh check        run jobs and check the units of their
#                                      processes (see slurm/check.sh)
#   test/harness/slurm.sh run CMD...   run CMD as root in the VM, e.g.
#                                      run srun -n2 hostname
#   test/harness/slurm.sh shell [CMD...]
#                                      a shell in the VM, or CMD, as the user
#   test/harness/slurm.sh status
#   test/harness/slurm.sh stop         stop the VM, keeping it
#   test/harness/slurm.sh down         delete the VM
#
# up takes its settings from the environment; running it again with others
# reconfigures the cluster, and another SLURM_VERSION replaces Slurm (the
# state of slurmctld is deleted then):
#
#   SLURM_VERSION              a version of the table below (default 26.05.5)
#   SLURM_CGROUP_JOB_ID_PATHS  CgroupJobIdPaths of cgroup.conf, 26.05 and
#                              later: no (the default of Slurm) names the
#                              cgroup of a job after its SLUID, yes job_<id>
#                              as the versions before 26.05 do
#   SLURM_SRUN_PORT_RANGE      SrunPortRange, e.g. 60001-63000 (default none:
#                              srun listens on a random port at every run)
#   SLURM_MPI                  yes (default) builds Slurm with PMIx and
#                              installs Open MPI, MpiDefault=pmix; no skips both
#   SLURM_JOBACCT              JobAcctGatherType without its prefix: cgroup
#                              (default), linux or none
#   SLURM_CONSTRAIN_RAM        ConstrainRAMSpace, no (default) or yes
#   SLURM_CPU_SPEC             CpuSpecList, CPUs reserved for the system
#   SHAWK_VM_CPUS, SHAWK_VM_MEMORY, SHAWK_VM_DISK
#                              the size of a new VM (default 4, 6GiB, 30GiB)
#
# The VM is named shawk-slurm-<workspace> (lib.sh), or SHAWK_SLURM_VM,
# mounts the workspace at the same path, writable, so that binaries built
# on the host for Linux and make run in it, and forwards no port to the
# host, so that the VMs of several workspaces do not clash. Its image is
# Rocky Linux 9.8 GenericCloud, pinned by its SHA-256. The source of Slurm
# and the release of Go of go.mod are downloaded on the host and checked
# against their SHA-256 (those SchedMD and go.dev publish); Slurm is built
# in the VM once and kept in the cache (SHAWK_CACHE_DIR) for the next VMs.
# The packages of Rocky Linux (BaseOS, AppStream, CRB) are installed with
# dnf, which checks their signatures. The munge key is made in the VM.
#
# Requires limactl: on macOS, Lima from Homebrew (vz); on Linux, the pinned
# release of Lima is downloaded to the cache if limactl is not installed,
# and QEMU (qemu-system-*, qemu-utils, the UEFI firmware: ovmf or
# qemu-efi-aarch64) with KVM is needed. Lima does not work in the sandbox
# of an agent such as Claude Code (it reads sysctls and writes ~/.lima):
# run it outside.
# Commands run as root in the VM through sudo inside it.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

VM="${SHAWK_SLURM_VM:-shawk-slurm-$WS_ID}"
DIR="$STATE/slurm"
SLURM_VERSION="${SLURM_VERSION:-26.05.5}"
# The environment of the commands in the VM: Slurm and Go in PATH, Go as
# installed (no other toolchain; the VM has not the git metadata of a
# worktree), and the state of test/harness in the VM.
ENV_IN_VM=(PATH=/opt/slurm/bin:/opt/slurm/sbin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
	GOTOOLCHAIN=local GOFLAGS=-buildvcs=false SHAWK_HARNESS_STATE=/var/tmp/shawk-harness)

# go_tarball: the release of Go of go.mod for Linux on the architecture of
# the VM (that of the host), from go.dev, pinned by its SHA-256.
go_tarball() {
	local version arch sum
	version="$(sed -n 's/^go //p' "$ROOT/go.mod")"
	arch="$(platform)"
	arch="${arch#*-}"
	case "$version-$arch" in
	1.27.3-amd64) sum=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
	1.27.3-arm64) sum=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
	*) die "Go $version of go.mod is not in the table of slurm.sh: add its SHA-256 from https://go.dev/dl/?mode=json" ;;
	esac
	fetch "https://go.dev/dl/go$version.linux-$arch.tar.gz" "$sum"
}

# The SHA-256 of the source of Slurm, from https://download.schedmd.com/slurm/SHA256.
slurm_sha256() {
	case "$1" in
	22.05.11) echo cb860cabfc39e0a0f71759b28aa0e0a2fed1059269a5cb83686aa6e10c9078a6 ;;
	23.02.8) echo 74a706e62d342a43e677991c92b1a30435148e44cf5d2e2a7bac8471f1a2006e ;;
	23.11.11) echo 4a1713dceb5bfad74d3f43c9bfedf23603933f0d7148cdad7feedea57da4e45d ;;
	24.05.8) echo 59c33ee924bdf105fe288b65798d6db0fca12244aec8bcb4b346a89ccddd39d0 ;;
	24.11.7) echo 8bcbaae09f4962b72fb322b6ef97b77cc2633f59fda151e90338cf5d9187b9cf ;;
	25.05.9) echo 7be633820df896df819ac2e9f2ebd0824de509515e5fb78ba1c19da2453b39ed ;;
	25.11.8) echo 34ace13f81011add6094569d13bfc4006ad8868201c2236e2905443c7e526393 ;;
	26.05.5) echo 4680cafc82b0689865c885eb703441e7ebf764896c40fd03a50f2fcb60664f68 ;;
	*) die "Slurm $1 is not in the table of slurm.sh: one of 22.05.11 23.02.8 23.11.11 24.05.8 24.11.7 25.05.9 25.11.8 26.05.5" ;;
	esac
}

# find_limactl sets LIMACTL to Lima of the host, or on Linux to its pinned
# release, downloaded to the cache. It runs before the commands, not in a
# command substitution, so that its errors stop the script and are seen.
LIMA_VERSION=2.2.1
find_limactl() {
	local lima tmp
	if LIMACTL="$(type -P limactl)"; then
		return
	fi
	case "$(platform)" in
	linux-amd64) lima=$(fetch "https://github.com/lima-vm/lima/releases/download/v$LIMA_VERSION/lima-$LIMA_VERSION-Linux-x86_64.tar.gz" \
		b391ac7fcac2b2a5a1628107756463188ded4d18d3104a40a66a8bb6fec01bcb) ;;
	linux-arm64) lima=$(fetch "https://github.com/lima-vm/lima/releases/download/v$LIMA_VERSION/lima-$LIMA_VERSION-Linux-aarch64.tar.gz" \
		fbcf4d127936666aa2cf6013b663c250431f2a59394757b404070f8d6a160e10) ;;
	*) die "limactl not found: install Lima (brew install lima)" ;;
	esac
	if [[ ! -x "$CACHE/lima/$LIMA_VERSION/bin/limactl" ]]; then
		# Extracted aside and renamed whole, so that an interrupted run or
		# another workspace sharing the cache never sees a partial copy.
		mkdir -p "$CACHE/lima"
		tmp="$(mktemp -d "$CACHE/lima/.extract.XXXXXX")"
		tar -xzf "$lima" -C "$tmp"
		[[ -e "$CACHE/lima/$LIMA_VERSION" ]] || mv "$tmp" "$CACHE/lima/$LIMA_VERSION" 2>/dev/null || true
		rm -rf "$tmp"
	fi
	LIMACTL="$CACHE/lima/$LIMA_VERSION/bin/limactl"
	[[ -x "$LIMACTL" ]] || die "no limactl in $CACHE/lima/$LIMA_VERSION; remove it and try again"
}
limactl() { "$LIMACTL" "$@"; }

# vm_status: the status of the VM (Running, Stopped, ...), or nothing if
# there is none.
vm_status() { limactl list --format '{{.Status}}' "$VM" 2>/dev/null || true; }

# workdir: the current directory if the VM has it (the workspace is
# mounted at the same path), else /.
workdir() {
	if [[ "$PWD" == "$ROOT" || "$PWD" == "$ROOT"/* ]]; then echo "$PWD"; else echo /; fi
}

# as_root CMD...: runs CMD as root in the VM, with ENV_IN_VM.
as_root() { limactl shell --workdir "$(workdir)" "$VM" sudo -n env "${ENV_IN_VM[@]}" "$@"; }

# as_user CMD...: runs CMD as the user of the VM, with ENV_IN_VM.
as_user() { limactl shell --workdir "$(workdir)" "$VM" env "${ENV_IN_VM[@]}" "$@"; }

# config: the Lima configuration of a new VM.
config() {
	local cache_mount=""
	# The cache is mounted too when it is not in the workspace.
	case "$CACHE/" in
	"$ROOT"/*) ;;
	*) cache_mount="- location: \"$CACHE\"
  writable: true" ;;
	esac
	cat <<EOF
# Generated by test/harness/slurm.sh for the workspace $ROOT.
minimumLimaVersion: 2.0.0
# Rocky Linux 9.8, pinned by the SHA-256 of rocky-9.8 CHECKSUM; the vault
# keeps the release once a newer one replaces it in pub.
images:
- location: https://dl.rockylinux.org/pub/rocky/9.8/images/aarch64/Rocky-9-GenericCloud-Base-9.8-20260525.0.aarch64.qcow2
  arch: aarch64
  digest: sha256:24692a444f1f0b8bb95375c38c8b43f8099a115347623691be2c330b40c8a1fe
- location: https://dl.rockylinux.org/vault/rocky/9.8/images/aarch64/Rocky-9-GenericCloud-Base-9.8-20260525.0.aarch64.qcow2
  arch: aarch64
  digest: sha256:24692a444f1f0b8bb95375c38c8b43f8099a115347623691be2c330b40c8a1fe
- location: https://dl.rockylinux.org/pub/rocky/9.8/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2
  arch: x86_64
  digest: sha256:92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8
- location: https://dl.rockylinux.org/vault/rocky/9.8/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2
  arch: x86_64
  digest: sha256:92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8
mountTypesUnsupported: [9p]
cpus: ${SHAWK_VM_CPUS:-4}
memory: ${SHAWK_VM_MEMORY:-6GiB}
disk: ${SHAWK_VM_DISK:-30GiB}
mounts:
- location: "$ROOT"
  writable: true
$cache_mount
containerd:
  system: false
  user: false
ssh:
  loadDotSSHPubKeys: false
# No port of the VM is forwarded to the host.
portForwards:
- guestIP: 0.0.0.0
  guestIPMustBeZero: false
  proto: any
  ignore: true
- guestIP: 127.0.0.1
  proto: any
  ignore: true
EOF
}

up() {
	local status sum tarball go
	# Assignments of their own, so that an unknown version stops here.
	sum="$(slurm_sha256 "$SLURM_VERSION")"
	tarball="$(fetch "https://download.schedmd.com/slurm/slurm-$SLURM_VERSION.tar.bz2" "$sum")"
	go="$(go_tarball)"
	mkdir -p "$DIR" "$CACHE"
	status="$(vm_status)"
	if [[ -z "$status" ]]; then
		config >"$DIR/lima.yaml"
		log "creating the VM $VM"
		limactl create --name="$VM" --tty=false "$DIR/lima.yaml"
		status=Stopped
	fi
	if [[ "$status" != Running ]]; then
		log "starting the VM $VM"
		limactl start --tty=false "$VM"
	fi
	# A VM made with another SHAWK_CACHE_DIR does not mount this one.
	as_root test -r "$tarball" ||
		die "the VM $VM does not see the cache $CACHE (another SHAWK_CACHE_DIR?): make it again with slurm.sh down"
	log "provisioning Slurm $SLURM_VERSION in $VM"
	as_root env "VERSION=$SLURM_VERSION" "TARBALL=$tarball" "CACHE=$CACHE" "GO_TARBALL=$go" \
		"MPI=${SLURM_MPI:-yes}" "JOB_ID_PATHS=${SLURM_CGROUP_JOB_ID_PATHS:-}" \
		"SRUN_PORT_RANGE=${SLURM_SRUN_PORT_RANGE:-}" "JOBACCT=${SLURM_JOBACCT:-cgroup}" \
		"CONSTRAIN_RAM=${SLURM_CONSTRAIN_RAM:-no}" "CPU_SPEC=${SLURM_CPU_SPEC:-}" \
		bash "$HARNESS/slurm/provision.sh"
	log "Slurm $SLURM_VERSION is up in $VM: test/harness/slurm.sh run sinfo"
}

check() {
	local goarch bin
	case "$(as_root uname -m | tr -d '\r')" in
	aarch64) goarch=arm64 ;;
	x86_64) goarch=amd64 ;;
	*) die "unknown architecture of the VM" ;;
	esac
	bin="$DIR/bin/units-linux-$goarch"
	log "building $bin"
	if "${GO:-go}" version >/dev/null 2>&1; then
		(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch "${GO:-go}" build -o "$bin" ./test/harness/units)
	else
		# No Go on the host: that of the VM.
		mkdir -p "$DIR/bin"
		(cd "$ROOT" && as_user env CGO_ENABLED=0 go build -o "$bin" ./test/harness/units)
	fi
	as_root bash "$HARNESS/slurm/check.sh" "$bin"
}

case "${1:-}" in
up | check | run | shell | status | stop | down) find_limactl ;;
esac
case "${1:-}" in
up) up ;;
check) check ;;
run)
	shift
	(($# > 0)) || die "usage: slurm.sh run CMD [ARG...]"
	as_root "$@"
	;;
shell)
	shift
	if (($# > 0)); then as_user "$@"; else limactl shell "$VM"; fi
	;;
status)
	status="$(vm_status)"
	echo "VM $VM: ${status:-none}"
	[[ "$status" == Running ]] && as_root sh -c 'scontrol version 2>/dev/null; sinfo 2>/dev/null' || true
	;;
stop) [[ -z "$(vm_status)" ]] || limactl stop "$VM" ;;
down)
	[[ -z "$(vm_status)" ]] || limactl delete --force "$VM"
	rm -rf "$DIR"
	log "deleted the VM $VM (the cache is kept)"
	;;
*)
	echo "usage: slurm.sh up|check|run CMD...|shell [CMD...]|status|stop|down" >&2
	exit 2
	;;
esac
