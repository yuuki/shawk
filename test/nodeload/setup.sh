#!/usr/bin/env bash
# Prepares a disposable host or VM for flows.sh, as root: a network
# namespace "node", the compute node whose agent is measured, at 10.97.0.1,
# and a namespace "peers" holding the addresses of PEERS peer nodes from
# 10.98.0.1 on (default 189), joined by a veth pair; the sysctls of both
# for many connections. Run it again with another PEERS to change them.
#
#   sudo ./setup.sh [PEERS]
#
# Requires ip (iproute2) and nsenter.
set -euo pipefail
PEERS=${1:-189}

ip netns list | grep -qw node || ip netns add node
ip netns list | grep -qw peers || ip netns add peers
inns() { nsenter --net=/run/netns/"$1" "${@:2}"; }
if ! inns node ip link show nl0 >/dev/null 2>&1; then
	ip link add nl0 netns node type veth peer name nl1 netns peers
fi
inns node ip addr replace 10.97.0.1/24 dev nl0
inns node ip link set lo up
inns node ip link set nl0 up
inns node ip route replace 10.98.0.0/16 dev nl0
inns peers ip addr flush dev nl1
inns peers ip link set lo up
inns peers ip link set nl1 up
inns peers ip route replace 10.97.0.0/24 dev nl1
# 10.98.0.1 and on, as /32 on the link of the route: none is special.
python3 - "$PEERS" <<'EOF' | inns peers ip -batch -
import ipaddress, sys
first = ipaddress.IPv4Address("10.98.0.1")
for i in range(int(sys.argv[1])):
    print(f"addr add {first + i}/32 dev nl1")
EOF
for ns in node peers; do
	# The ports of the ranks (nodeload mesh and peer) are not ephemeral:
	# a rank connecting first would take the port of one not listening yet.
	inns $ns sysctl -qw net.ipv4.ip_local_port_range="10000 65000" net.ipv4.ip_local_reserved_ports=20000-20999,30000-30999 \
		net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
done
