#!/usr/bin/env bash
# Prepares a disposable host or VM for run.sh, as root:
#
# - sysctls for the workloads of many short connections;
# - a network namespace hcpeer behind a veth pair, 10.99.0.1 on the host
#   and 10.99.0.2 in the namespace, whose firewall fails the connects of
#   the failure experiment: port 9 with ICMP host unreachable, port 10
#   with ICMP port unreachable, port 11 by dropping the SYN, and port 12
#   with a reset (nothing listens). The SYNs leave the host with 1 ms of
#   delay (netem), so that the answer arrives after connect(2) returned,
#   in a softirq, as from another host: on loopback it would arrive within
#   connect(2), while the task holds the socket.
#
# Requires ip, tc, nft, nsenter and the module sch_netem. The namespace is
# entered with nsenter rather than ip -n, which mounts /sys and which SELinux
# denies to the boot scripts of cloud-init.
set -euo pipefail

sysctl -qw net.ipv4.ip_local_port_range="10000 65000"
sysctl -qw net.ipv4.tcp_tw_reuse=1

if ip link show hc0 >/dev/null 2>&1; then
	exit 0
fi
modprobe sch_netem
ip netns list | grep -qw hcpeer || ip netns add hcpeer
peer() { nsenter --net=/run/netns/hcpeer "$@"; }
ip link add hc0 type veth peer name hc1 netns hcpeer
ip addr add 10.99.0.1/24 dev hc0
ip link set hc0 up
peer ip addr add 10.99.0.2/24 dev hc1
peer ip link set hc1 up
peer ip link set lo up
tc qdisc add dev hc0 root netem delay 1ms limit 100000
# ICMP errors are rate limited per destination by default.
peer sysctl -qw net.ipv4.icmp_ratelimit=0
# Per namespace since Linux 6.2, global before.
peer sysctl -qw net.ipv4.icmp_msgs_per_sec=1000000 net.ipv4.icmp_msgs_burst=1000000 2>/dev/null || true
sysctl -qw net.ipv4.icmp_msgs_per_sec=1000000
sysctl -qw net.ipv4.icmp_msgs_burst=1000000
peer nft -f - <<'EOF'
table inet hookcost {
	chain input {
		type filter hook input priority 0;
		tcp dport 9 reject with icmp type host-unreachable
		tcp dport 10 reject with icmp type port-unreachable
		tcp dport 11 drop
	}
}
EOF
