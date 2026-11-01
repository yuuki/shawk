#!/usr/bin/env bash
# Extracts the BTF of a Rocky Linux kernel for TestKernelCompatibility.
#
#   scripts/fetch-kernel-btf.sh [kernel-core RPM URL] [output file]
#
# The default is the Rocky Linux 9.6 kernel (5.14.0-570). The RPM is
# downloaded once to build/kernel/ and checked against its SHA-256 before
# every use: the one pinned below, or KERNEL_RPM_SHA256 for another URL.
# Requires curl, sha256sum, rpm2cpio, cpio, python3 and objcopy.
set -euo pipefail

default_url=https://dl.rockylinux.org/vault/rocky/9.6/BaseOS/x86_64/os/Packages/k/kernel-core-5.14.0-570.58.1.el9_6.x86_64.rpm
# The RPM is signed by the Rocky Linux 9 release key (rpmkeys --checksig,
# key id 350d275d).
default_sha256=e24873a95fc2c4bdc1fbc6e3416064266eeed6005e2b44684f5d1fcfdc7c6c7f

url="${1:-$default_url}"
out="${2:-rocky9.btf}"
if [[ "$url" == "$default_url" ]]; then
	sha256="${KERNEL_RPM_SHA256:-$default_sha256}"
else
	sha256="${KERNEL_RPM_SHA256:?set KERNEL_RPM_SHA256 to the SHA-256 of $url}"
fi

cache="$(cd "$(dirname "$0")/.." && pwd)/build/kernel"
rpm="$cache/$(basename "$url")"
verified() { echo "$sha256  $1" | sha256sum --check --status -; }

if [[ -f "$rpm" ]] && ! verified "$rpm"; then
	echo "$rpm does not match its SHA-256; downloading it again" >&2
	rm -f "$rpm"
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ ! -f "$rpm" ]]; then
	mkdir -p "$cache"
	# A download of its own, renamed into the cache once verified, so that
	# concurrent runs neither clash nor see a partial file.
	part="$(mktemp "$cache/.download.XXXXXX")"
	trap 'rm -rf "$work" "$part"' EXIT
	curl -fsSL -o "$part" "$url"
	if ! verified "$part"; then
		echo "$url does not match the SHA-256 $sha256" >&2
		exit 1
	fi
	chmod 0644 "$part"
	mv -f "$part" "$rpm"
fi

(cd "$work" && rpm2cpio "$rpm" | cpio -idm --quiet './lib/modules/*/vmlinuz')

# vmlinuz is a bzImage; find the gzip stream that decompresses to the ELF.
python3 - "$work"/lib/modules/*/vmlinuz "$work/vmlinux" <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
i = data.find(b'\x1f\x8b\x08\x00')
while i != -1:
    try:
        out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data[i:])
        if out[:4] == b'\x7fELF':
            open(sys.argv[2], 'wb').write(out)
            sys.exit(0)
    except zlib.error:
        pass
    i = data.find(b'\x1f\x8b\x08\x00', i + 1)
sys.exit('no gzip-compressed vmlinux found')
PY

objcopy --dump-section .BTF="$out" "$work/vmlinux" /dev/null
echo "wrote $out"
