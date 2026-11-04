#!/usr/bin/env python3
"""Predicts the flows of the agent from the TCP connections of a command.

Reads `ss -Htnp state established` and `ss -Htlnp` of a network namespace
on stdin, separated by a line "--", and prints the number of distinct keys
of struct shawk_flow_key the established connections of COMM make: an
outgoing connection is keyed by the cgroup of its process, the local and
remote addresses and the remote (service) port; an incoming one, accepted
by a listener of COMM, by the listener's port and both addresses, and
belongs to the cgroup of the listener's owner. The client port is dropped.

    (ss -Htnp state established; echo --; ss -Htlnp) | keys.py COMM
"""
import re
import sys

comm = sys.argv[1][:15]
users = re.compile(r'\("([^"]*)",pid=(\d+),')


def split(addr):
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def cgroup(pid):
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            return f.read().strip()
    except OSError:
        return "?"


est, listen, part = [], [], 0
for line in sys.stdin:
    if line.strip() == "--":
        part = 1
        continue
    (listen if part else est).append(line.split())

owners = {}  # listening port -> cgroup of its owner, for COMM
for f in listen:
    m = users.findall(" ".join(f))
    if m and m[0][0] == comm:
        owners[split(f[3])[1]] = cgroup(m[0][1])

out, inc = set(), set()
for f in est:
    m = users.findall(" ".join(f))
    if not m or m[0][0] != comm:
        continue
    (laddr, lport), (raddr, rport) = split(f[2]), split(f[3])
    if lport in owners:
        inc.add((owners[lport], laddr, raddr, lport))
    else:
        out.add((cgroup(m[0][1]), laddr, raddr, rport))
print(f"{len(out) + len(inc)} {len(out)} {len(inc)}")
