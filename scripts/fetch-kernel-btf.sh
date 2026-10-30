#!/usr/bin/env bash
# Extracts the BTF of a Rocky Linux kernel for TestKernelCompatibility.
#
#   scripts/fetch-kernel-btf.sh [kernel-core RPM URL] [output file]
#
# The default is the Rocky Linux 9.6 kernel (5.14.0-570). Requires curl,
# rpm2cpio, cpio, python3 and objcopy.
set -euo pipefail

url="${1:-https://dl.rockylinux.org/vault/rocky/9.6/BaseOS/x86_64/os/Packages/k/kernel-core-5.14.0-570.58.1.el9_6.x86_64.rpm}"
out="${2:-rocky9.btf}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL -o "$work/kernel.rpm" "$url"
(cd "$work" && rpm2cpio kernel.rpm | cpio -idm --quiet './lib/modules/*/vmlinuz')

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
