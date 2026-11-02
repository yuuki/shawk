#!/usr/bin/env bash
# Runs the tests that load the BPF programs (internal/tracer, internal/agent)
# in a virtual machine with another kernel than the host's:
#
#   test/vm/run.sh KERNEL [ARCH]
#
# KERNEL is one of
#   rocky9   Rocky Linux 9.6 (5.14.0-570), the primary target
#   5.14     upstream 5.14.21: the old layout of sock_cgroup_data, and a TCP
#            iterator that does not lock sockets
#   5.15     upstream 5.15.224, a long-term release: a TCP iterator that does
#            not lock sockets
# or the path of a kernel image. The upstream kernels are the builds of
# Ubuntu's mainline kernel archive. ARCH is x86_64 or aarch64 (5.14 is
# x86_64 only); the default is the architecture of the host.
#
# The kernel package is downloaded once to build/kernel and checked against
# its SHA-256 (scripts/fetch-verified.sh). The initramfs holds the init of
# test/vm/init, the test binaries, and the BPF source that the prototype test
# reads; the tests need no other program. QEMU uses KVM when the host can
# run the guest with it, and emulates the guest otherwise (a few minutes
# for aarch64 on x86_64).
#
# The tests run with SHAWK_TEST_STRICT=1, so that a skip fails, unless the
# environment sets it. On kernels without BPF trampolines (aarch64 before
# 6.0, including Rocky Linux 9), they run with SHAWK_TEST_NO_UDP=1: UDP
# tracing must be reported unavailable. The initramfs holds the modules of
# the NFS client for Rocky Linux 9 (from kernel-modules-core), which init
# loads; the other kernels run with SHAWK_TEST_NO_NFS=1. Further arguments of the test binaries can be given in
# VM_TEST_ARGS, e.g. VM_TEST_ARGS='-test.run=TestUDP'.
#
# Requires go, qemu-system-x86_64 or qemu-system-aarch64, cpio, gzip, curl,
# sha256sum, rpm2cpio and xz (rocky9), and dpkg-deb (5.14, 5.15).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KERNEL="${1:?usage: run.sh KERNEL [ARCH]}"
ARCH="${2:-$(uname -m)}"
ARCH="${ARCH/arm64/aarch64}"
ARCH="${ARCH/amd64/x86_64}"
TIMEOUT="${VM_TIMEOUT:-1800}"

case "$ARCH" in
x86_64) goarch=amd64 qemu=qemu-system-x86_64 console=ttyS0 ;;
aarch64) goarch=arm64 qemu=qemu-system-aarch64 console=ttyAMA0 ;;
*) echo "unsupported architecture $ARCH" >&2 && exit 2 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fetch() { "$ROOT/scripts/fetch-verified.sh" "$@"; }
# The environment may declare a kernel without BPF trampolines, e.g. one
# given by its path.
no_udp="${SHAWK_TEST_NO_UDP:-}"
# The package holding the modules of the NFS client, if any.
modules=""

# Packages signed by the Rocky Linux 9 release key (rpmkeys --checksig, key id
# 350d275d). The mainline builds are pinned by the SHA-256 they had when
# they were added here.
rocky=https://dl.rockylinux.org/vault/rocky/9.6/BaseOS
mainline=https://kernel.ubuntu.com/mainline
case "$KERNEL/$ARCH" in
rocky9/x86_64)
	pkg=$(fetch $rocky/x86_64/os/Packages/k/kernel-core-5.14.0-570.58.1.el9_6.x86_64.rpm \
		e24873a95fc2c4bdc1fbc6e3416064266eeed6005e2b44684f5d1fcfdc7c6c7f)
	modules=$(fetch $rocky/x86_64/os/Packages/k/kernel-modules-core-5.14.0-570.58.1.el9_6.x86_64.rpm \
		af3acc764136bc51035c0ae5ea93d7166cc02818c3032c089c2876c5024135d8) ;;
rocky9/aarch64)
	# arm64 has BPF trampolines since Linux 6.0, and RHEL 9 did not backport
	# them: fentry programs load but do not attach.
	: "${no_udp:=1}"
	pkg=$(fetch $rocky/aarch64/os/Packages/k/kernel-core-5.14.0-570.58.1.el9_6.aarch64.rpm \
		f0eb542737285c1a7fd386a2cbb5f464228b847762d585d8bd47aa013512d7dd)
	modules=$(fetch $rocky/aarch64/os/Packages/k/kernel-modules-core-5.14.0-570.58.1.el9_6.aarch64.rpm \
		decce35b2fad61a7601ae1786411f9e053c89df8b0d3a3c873d4c83525a5fd11) ;;
5.14/x86_64)
	pkg=$(fetch $mainline/v5.14.21/amd64/linux-image-unsigned-5.14.21-051421-generic_5.14.21-051421.202111210831_amd64.deb \
		632912f5bc688328e7f75d0e3b5038146aa8650c46f6d6fdb20f0ceed6a245e0) ;;
5.15/x86_64)
	pkg=$(fetch $mainline/v5.15.224/amd64/linux-image-unsigned-5.15.224-0515224-generic_5.15.224-0515224.202610301525_amd64.deb \
		bce2733d9144d11e31f9680c69cd093a656e68b0fe50b315c364c2544cf5a29e) ;;
5.15/aarch64)
	: "${no_udp:=1}"
	pkg=$(fetch $mainline/v5.15.224/arm64/linux-image-unsigned-5.15.224-0515224-generic_5.15.224-0515224.202610301525_arm64.deb \
		dee11976dee32b5e762a74fa027a17619b9c425135f84fae6be1d0c6bc1fb7bd) ;;
*)
	if [[ ! -f "$KERNEL" ]]; then
		echo "unknown kernel $KERNEL for $ARCH" >&2
		exit 2
	fi
	pkg="" ;;
esac

mkdir -p "$WORK/pkg"
case "$pkg" in
"") image="$(realpath "$KERNEL")" ;;
*.rpm)
	(cd "$WORK/pkg" && rpm2cpio "$pkg" | cpio -idm --quiet './lib/modules/*/vmlinuz')
	image="$(echo "$WORK"/pkg/lib/modules/*/vmlinuz)" ;;
*.deb)
	dpkg-deb --fsys-tarfile "$pkg" | tar -x -C "$WORK/pkg" --wildcards './boot/vmlinuz-*'
	image="$(echo "$WORK"/pkg/boot/vmlinuz-*)" ;;
esac

# The initramfs. The prototype test reads the BPF source at the path the
# test binary was built from.
initrd="$WORK/root"
mkdir -p "$initrd/vm" "$initrd$ROOT/internal/tracer/bpf"
cp "$ROOT/internal/tracer/bpf/shawk.bpf.c" "$initrd$ROOT/internal/tracer/bpf/"

# The NFS client (TestKernelSockets) and the modules it needs, which init
# loads from /vm/modules. They are decompressed, since the kernel loads
# compressed modules only since 6.4.
no_nfs=1
if [[ -n "$modules" ]]; then
	mkdir -p "$WORK/modules" "$initrd/vm/modules"
	(cd "$WORK/modules" && rpm2cpio "$modules" | cpio -idm --quiet \
		'./lib/modules/*/kernel/net/sunrpc/sunrpc.ko.xz' \
		'./lib/modules/*/kernel/net/sunrpc/auth_gss/auth_rpcgss.ko.xz' \
		'./lib/modules/*/kernel/net/dns_resolver/dns_resolver.ko.xz' \
		'./lib/modules/*/kernel/fs/nfs_common/grace.ko.xz' \
		'./lib/modules/*/kernel/fs/lockd/lockd.ko.xz' \
		'./lib/modules/*/kernel/fs/netfs/netfs.ko.xz' \
		'./lib/modules/*/kernel/fs/fscache/fscache.ko.xz' \
		'./lib/modules/*/kernel/fs/nfs/nfs.ko.xz' \
		'./lib/modules/*/kernel/fs/nfs/nfsv4.ko.xz')
	for m in $(find "$WORK/modules" -name '*.ko.xz'); do
		xz -dc "$m" >"$initrd/vm/modules/$(basename "$m" .xz)"
	done
	no_nfs=0
fi
(
	cd "$ROOT"
	export CGO_ENABLED=0 GOOS=linux GOARCH=$goarch
	go build -o "$initrd/init" ./test/vm/init
	go test -c -o "$initrd/vm/tracer.test" ./internal/tracer
	go test -c -o "$initrd/vm/agent.test" ./internal/agent
)
args="-test.v -test.count=1 ${VM_TEST_ARGS:-}"
cat >"$initrd/vm/commands" <<EOF
/vm /vm/tracer.test $args
/vm /vm/agent.test $args
EOF
(cd "$initrd" && find . | cpio -o -H newc --quiet | gzip -1) >"$WORK/initramfs.gz"

# Unknown parameters of the kernel command line are passed to init as
# environment variables.
cmdline="console=$console panic=-1 quiet SHAWK_TEST_STRICT=${SHAWK_TEST_STRICT:-1} SHAWK_TEST_NO_UDP=${no_udp:-0} SHAWK_TEST_NO_NFS=${SHAWK_TEST_NO_NFS:-$no_nfs}"
opts=(-m 2G -smp 2 -nographic -no-reboot -kernel "$image" -initrd "$WORK/initramfs.gz" -append "$cmdline")
host="$(uname -m)"
if [[ "$host" == "$ARCH" && -r /dev/kvm && -w /dev/kvm ]]; then
	opts+=(-accel kvm -cpu host)
else
	opts+=(-accel tcg -cpu max)
fi
[[ "$ARCH" == aarch64 ]] && opts+=(-machine virt)
[[ "$ARCH" == x86_64 ]] && opts+=(-machine q35)

echo "booting $(basename "$image") ($ARCH) with ${opts[*]: -4}" >&2
log="$WORK/console.log"
status=0
timeout "$TIMEOUT" "$qemu" "${opts[@]}" </dev/null 2>&1 | tee "$log" || status=$?
if ((status == 124)); then
	echo "FAIL: the virtual machine did not finish within $TIMEOUT seconds" >&2
	exit 1
fi
exit_line="$(grep -a '^SHAWK-VM-EXIT ' "$log" | tail -1 | tr -d '\r')" || true
if [[ -z "$exit_line" ]]; then
	echo "FAIL: the virtual machine stopped without the status of the tests" >&2
	exit 1
fi
exit "${exit_line#SHAWK-VM-EXIT }"
