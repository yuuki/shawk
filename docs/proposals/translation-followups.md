# Dependencies through translations of addresses: what remains

Status: proposed, not implemented. Translations of addresses are
implemented from two sources (issue #107): static ones in the
configuration of the connector (`translations`), for relays without an
agent, and translations that the agents of the hosts that make them learn
from conntrack (DNAT, SNAT, masquerade, REDIRECT, IPVS with
`net.ipv4.vs.conntrack=1`). `docs/design.md` describes them: the kernel in
§3.7, the OTLP in §4.2, the matching and the names of peers in §5.4, the
tables in §6, the counting in §7 and the limitations in §10. This proposal
covers the connections they still leave unmatched: through docker-proxy
(§1), translated on two hosts (§2), through IPVS without conntrack (§3), and
the clients that a host forwards with SNAT (§4).

## 1. docker-proxy

**Problem.** A connection to a published port of Docker on loopback, or
hairpinned to an address of the host, goes through the userland proxy of
Docker rather than through DNAT. docker-proxy shows up as a service of the
host, with a server edge from the client (127.0.0.1 → 127.0.0.1:8080) and a
client edge to the container (172.17.0.1 → 172.17.0.2:80), so the client
depends on docker-proxy instead of the service of the container. The
connector names a client edge after a service at the virtual address only
if it saw that service's server edge from this client (§5.4 of the
design), so that the clients of other hosts, which the host DNATs to the
container, are named after the container; the containers of the host that
reach the port at an address of the host are named after docker-proxy.

**Proposal.**

- Which published port goes to which container and port is on the command
  line of docker-proxy (`-host-port`, `-container-ip`, `-container-port`)
  and in the state of Docker (`NetworkSettings.Ports` of `config.v2.json`),
  which the agent already reads to name containers (§4.1 of the design).
- The agent would send it as a translation, by the path of the learned
  translations (`shawk.translation.*`, §4.2 of the design).
- The views would treat the edges of docker-proxy as those of a relay: out
  of the matching by address, matched through the translation, so that the
  client is linked to the service of the container.

## 2. Connections translated on two hosts

A connection translated on two hosts, such as a container behind the
masquerade of its host to a published port of another host, is matched for
neither hop: the agent of each host learns its own translation, and the
client edge and the server edge share no address with the same row.

The cheap next step for hosts with containers: join a pure SNAT row, whose
virtual address is its backend, with the DNAT row of the next host by the
source, the virtual address and the port.

## 3. IPVS without conntrack

An LVS director configured by hand without `net.ipv4.vs.conntrack=1` makes
no conntrack entry, so nothing is learned; kube-proxy sets the sysctl.
Learning those connections would need a kprobe on `ip_vs_conn_new` of the
module ip_vs (#139). Until then, such a director is written as a static
translation.

## 4. Clients forwarded with SNAT

A server edge behind a learned SNAT keeps its name and `shawk.peer.agent`
of the host of the source (§5.4 of the design): it bundles every client the
source forwards or masquerades, and the containers of that host that leave
with its address are counted by their own client edges. The clients that
the host forwards from other hosts, such as those of a NodePort of
kube-proxy with `externalTrafficPolicy: Cluster`, are counted on neither
side in Prometheus when they run no agent; they keep their rows in
PostgreSQL. The learned rows of the host tell those clients apart, which
the names of peers could use.

## 5. Not covered, without a proposal

- Datapaths without netfilter conntrack: the kube-proxy replacement of
  Cilium, eBPF load balancers.
- A table of translations that users or other tools write, besides the
  configuration of the connector: the tables of `shawk` are internal and
  may change in a migration.
