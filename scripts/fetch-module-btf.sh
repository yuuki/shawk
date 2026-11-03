#!/usr/bin/env bash
# Extracts the BTF of a kernel module of Rocky Linux for
# TestKernelCompatibility (SHAWK_TARGET_MODULE_BTF), split on the BTF of
# the kernel that scripts/fetch-kernel-btf.sh extracts.
#
#   scripts/fetch-module-btf.sh MODULE [kernel-modules-core RPM URL] [output file]
#
# MODULE is the path of the module in the RPM below kernel/, without .ko.xz,
# e.g. net/netfilter/nf_conntrack. The default RPM is that of the Rocky Linux
# 9.6 kernel (5.14.0-570), downloaded once to build/kernel/ and checked
# against its SHA-256 (scripts/fetch-verified.sh): the one pinned below, or
# KERNEL_RPM_SHA256 for another URL.
# Requires curl, sha256sum, rpm2cpio, cpio, xz and objcopy.
set -euo pipefail

default_url=https://dl.rockylinux.org/vault/rocky/9.6/BaseOS/x86_64/os/Packages/k/kernel-modules-core-5.14.0-570.58.1.el9_6.x86_64.rpm
# Signed by the Rocky Linux 9 release key (rpmkeys --checksig, key id
# 350d275d); the same package as test/vm/run.sh.
default_sha256=af3acc764136bc51035c0ae5ea93d7166cc02818c3032c089c2876c5024135d8

module="${1:?usage: fetch-module-btf.sh MODULE [RPM URL] [output file]}"
url="${2:-$default_url}"
out="${3:-$(basename "$module").btf}"
if [[ "$url" == "$default_url" ]]; then
	sha256="${KERNEL_RPM_SHA256:-$default_sha256}"
else
	sha256="${KERNEL_RPM_SHA256:?set KERNEL_RPM_SHA256 to the SHA-256 of $url}"
fi

rpm="$("$(dirname "$0")/fetch-verified.sh" "$url" "$sha256")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$work" && rpm2cpio "$rpm" | cpio -idm --quiet "./lib/modules/*/kernel/$module.ko.xz")
ko="$(echo "$work"/lib/modules/*/kernel/"$module".ko.xz)"
xz -dc "$ko" >"$work/module.ko"
objcopy --dump-section .BTF="$out" "$work/module.ko" /dev/null
echo "wrote $out"
