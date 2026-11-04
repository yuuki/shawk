#!/usr/bin/env bash
# Runs the measurements of docs/research/kernel-hooks/kernel_hooks.md on
# the running kernel, appending JSON lines to OUT (default
# hookcost-$(uname -r).jsonl):
#
#   cd test/hookcost && go generate && go build -o hookcost .
#   sudo ./setup.sh              # once per boot, on a disposable host
#   sudo ./run.sh [OUT]          # or HOOKCOST=<binary with capabilities> ./run.sh
#   ./hookcost report OUT...
#
# Each workload runs ROUNDS times (default 5) for SECS seconds (default 4)
# per variant, the variants interleaved so that drifts of the host spread
# over all of them, with one pair of threads (latency) and with two pairs
# per CPU (a busy host). One more round with -stats counts how often the
# programs run. Variants the kernel cannot attach are recorded with the
# error. The failure experiment then compares the reasons shawk gives with
# the errors the application got.
set -euo pipefail
cd "$(dirname "$0")"
HC=${HOOKCOST:-./hookcost}
OUT=${1:-hookcost-$(uname -r).jsonl}
ROUNDS=${ROUNDS:-5}
SECS=${SECS:-4}
busy=$((2 * $(nproc)))

tcp_rr="none shawk tp-empty tcpmsg-kprobe-empty tcpmsg-kprobe tcpmsg-kmulti tcpmsg-fentry-empty tcpmsg-fentry cgskb-empty cgskb"
udp_rr="none shawk udp-kprobe-empty udp-kprobe udp-fentry-empty udp-fentry cgskb-empty cgskb"
tcp_crr="none shawk tp-empty accept-kretprobe-empty accept-kretprobe accept-fexit tcpmsg-kprobe tcpmsg-fentry"

measure() { "$HC" "$@" >>"$OUT"; }

matrix() {
	for pairs in 1 "$busy"; do
		for v in $tcp_rr; do measure -variant "$v" -mode tcp_rr -pairs "$pairs" -secs "$SECS" "$@"; done
		for v in $udp_rr; do measure -variant "$v" -mode udp_rr -pairs "$pairs" -secs "$SECS" "$@"; done
	done
	for v in $tcp_crr; do measure -variant "$v" -mode tcp_crr -pairs "$busy" -secs "$SECS" "$@"; done
}

for round in $(seq "$ROUNDS"); do
	echo "round $round of $ROUNDS" >&2
	matrix
done
echo "statistics" >&2
matrix -stats

echo "failures" >&2
if ip -o addr show | grep -q 10.99.0.1/; then
	# host unreachable, port unreachable, reset
	for wait in poll spin; do
		for port in 9 10 12; do
			measure -variant shawk,errobs -mode fail -target 10.99.0.2:$port -wait $wait -pairs "$(nproc)" -secs 10
		done
	done
	# timeouts, of 3 s each
	measure -variant shawk,errobs -mode fail -target 10.99.0.2:11 -pairs 64 -secs 10
else
	echo "no 10.99.0.1: run setup.sh for the failure experiment" >&2
fi
