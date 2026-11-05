# Static HPC clusters managed by Slurm: design proposal

Status: implemented, except the parts noted below. Tracked by
#170; each part has a sub-issue, named in its section. Revised after an
adversarial review. What was built, and where it departs from this
proposal, is in [docs/design.md](../design.md):

| part | sub-issue | pull request | design |
|---|---|---|---|
| §0.1, §7 scope and RDMA | #171 | #192 | §1, §4.2, §8, §10 |
| §1 metrics per peer host | #176 | #188 | §5.2, §5.3, §7, §8 |
| §2.1 to §2.3 processes of jobs | #173 | #185 | §4.1, §5.3 |
| §2.4 users | #181 | #193 | §4.1, §6.1, §6.2 |
| §3 dynamic ports | #174 | #187 | §5.3, §6.1, §6.2 |
| §4 load on compute nodes | #172 | #195 | |
| §5.1 inventory | #175 | #184 | §5.6 |
| §5.2 node states | #177 | #191 | §5.7, §8 |
| §6.1 host identity | #178 | #189 | §4.1, §6.2, §10 |
| §6.2 start order | #179 | #183 | §4.3 |
| §8 kernel sockets | #180 | #190 | §3.2, §4.1, §10 |

§4 changed neither the agent nor the connector. Its measurements in a VM,
and the guidance from them, are in
[docs/research/hpc-compute-nodes/compute_nodes.md](../research/hpc-compute-nodes/compute_nodes.md);
measuring on a real cluster is #206. Not implemented: the named networks
of §1.5 (#204), and the automatic detection of ports chosen by the kernel
of §3.2 (#205). The operating guidance is in
[packaging/README.md](../../packaging/README.md#hpc-clusters).

The target is a traditional HPC cluster: bare-metal hosts that are not added
or removed dynamically, up to about 200 nodes, managed by Slurm. Most of
shawk applies as it is. This proposal covers what does not: metrics per
peer host (§1), the processes of jobs (§2), dynamic ports (§3), the load on
compute nodes (§4), an inventory and node states (§5), host identity and
start order (§6), RDMA (§7) and the names of kernel sockets (§8).

## 0. Scope and assumptions

### 0.1 What is observed (#171)

- shawk observes TCP and UDP sockets. The verbs of RDMA (InfiniBand, RoCE)
  bypass them, so MPI over UCX, NCCL, Lustre o2ib, GPFS verbs and NFS over
  RDMA are not seen; TCP over IPoIB is. In HPC clusters the main data paths
  use RDMA, so "observed and not used" holds for TCP and UDP only, and the
  documents and dashboards say so from the start (§7).
- The sockets of kernel clients (NFS, Lustre over TCP) belong to cgroup 0
  and are named `~kernel:*` (design §3.2, §4.1). shawk tells which hosts use
  a file system, not which users or jobs.

### 0.2 Slurm

- Cgroup v2, the default of RHEL 9. Cgroup v1 is out of scope; hierarchies
  that are not recognized keep the current behavior.
- Jobs run in `system.slice/slurmstepd.scope/<job>/<step>/...`. `<job>` is
  `job_<id>` before Slurm 26.05, and a SLUID since 26.05 unless
  `CgroupJobIdPaths=yes`.
- `pam_slurm_adopt` needs `PrologFlags=contain` among other settings and may
  not be in use.
- The agent does not depend on Slurm (not every host runs slurmd). What
  comes from Slurm is taken by the connector.

## 1. Metrics per peer host (#176)

### 1.1 Problem

- The outputs to Prometheus reduce a peer to `service.peer.name` (design
  §5.3), which treats the peers of one service as interchangeable.
- In an HPC cluster the hosts of one service usually have different roles:
  nfs01 exports /home and nfs02 /scratch, each OSS serves its own OSTs, and
  the `slurmd` of 190 compute nodes are one `slurmd`.
- The traffic and failures per peer host are lost. Failures, handshakes and
  SYN retransmissions exist on the client side only, so which nodes
  slurmctld fails to reach, and why, cannot be told from Prometheus.
  `shawk_v1.dependencies` has the hosts of each dependency but no
  quantities.

### 1.2 A separate family

Adding a label to the existing metrics would split each series and change
direct references and vector matching, which is a change of the contract
(design §2). The existing outputs stay as they are, and the outputs per
host are a separate, opt-in family (`peer_hosts: true`):

| output | sides |
|---|---|
| `shawk_host_connection_opened_total` | client, server |
| `shawk_host_connection_failed_by_reason_total` | client, reasons that occurred |
| `shawk_host_tcp_handshake_seconds_sum`, `_count` | client |
| `shawk_host_tcp_syn_retransmits_total` | client |
| `shawk_host_network_io_bytes_total` | client, server, with `network_io_direction` |
| `shawk_host_tcp_retransmits_total` | client, server |

Their labels are those of the existing outputs plus `shawk_peer_host`.
`max_peer_hosts` bounds the peer hosts per host, local service, role and
peer service as a safety net, and an allowlist may restrict the local
services.

### 1.3 The peer host

Identifying a host takes stronger evidence than naming a service, so an
ambiguous peer has no host. `shawk.peer.host` is, in order:

1. the host the inventory (§5.1) maps the address to, if one;
2. the host whose live agent alone holds the address (`holders()` in
   `peers.go`);
3. the latest host that held the address, within a limit (e.g. 30 days, as
   `service_endpoints`), if no other host held it meanwhile, so that
   failures towards a dead node are named;
4. otherwise `~unknown` for an internal address and `~external` for a public
   or folded one. Names of `peer_cidrs` are ranges, not hosts, and are not
   used; names of appliances in the inventory are.

- **Translations.** A backend is the peer host only when it is the only
  one. `pickBackend()` chooses a representative for naming, not the backend
  a connection reached, so a virtual address with several backends has host
  `~unknown`. The names of services do not change.
- **`shawk.peer.agent`** keeps its meaning: knowing the host of a peer does
  not mean that its agent records the other side.

### 1.4 Recording rules

`shawk:host_dependency_*{src_host, src, dst_host, dst, server_port,
network_transport}` count each dependency once as §7 of the design does,
per metric:

| metric | from |
|---|---|
| connections, bytes | the client side (`src_host` its `host_name`, `dst_host` its `shawk_peer_host`), and the server side when the client has no agent (the other way round) |
| failures, handshakes, SYN retransmissions | the client side |
| retransmissions | both sides; `shawk_role` is the sender |

The exception of §7 remains: behind a translation with sources the server
side also counts the clients that run an agent.

### 1.5 Addresses and networks

- Raw addresses are not labels by default: a multi-homed node
  (management, IPoIB or fast Ethernet, storage network, BMC) would split
  into several values. `keep_peer_address` stays for diagnosis, possibly
  limited to internal ranges.
- Optionally, named ranges classify the local and the peer address of an
  edge: `networks: {ib: 10.10.0.0/16, mgmt: 10.0.0.0/16}` gives
  `shawk_local_network` and `shawk_peer_network`. This classifies endpoints;
  it does not measure the path or the interface, and does not tell NICs of
  one subnet or a bond apart. It shares the matching of ranges with the
  zones of [path-quality-zones.md](path-quality-zones.md). Not implemented
  yet (#204).

### 1.6 Series

Assume 190 compute nodes and 10 infrastructure hosts. Every compute node is
a TCP client of 7 hosts (slurmctld, 4 storage servers, 2 LDAP servers) and
a UDP client of 4 (2 DNS, 2 NTP servers); Prometheus scrapes 200 hosts and
slurmctld talks to 190 `slurmd`. The family has 8 series per TCP client
edge, 4 per TCP server edge and 2 per side of a UDP edge, plus failure
reasons that occurred.

| | | series |
|---|---|---|
| existing outputs, same assumptions | | about 15 000 |
| compute nodes (client) | 190 × (7 × 8 + 4 × 2) | 12 160 |
| infrastructure (server) | 190 × (7 × 4 + 4 × 2) | 6 840 |
| Prometheus to 200 hosts | 200 × (8 + 4) | 2 400 |
| slurmctld to 190 `slurmd` | 190 × (8 + 4) | 2 280 |
| **the family, star traffic** | | **about 24 000** (about 1 600 samples/s at 15 s) |
| all to all between compute nodes, per service and port | 190 × 189 × (8 + 4) | about 430 000; up to 650 000 with every failure reason (about 29 000 samples/s) |

- With the 13 and 8 series of the existing outputs, the star traffic alone
  would take about 42 000.
- A series lives until both idle TTLs pass after its last activity: the
  agent sends it for `-idle-ttl` (15 minutes) and the connector keeps the
  output for its `idle_ttl` (15 minutes).
- Traffic between compute nodes (the tree of `slurmd`, srun, MPI over TCP)
  multiplies with services, ports and networks. `max_peer_hosts` does not
  bound the total, so the allowlist and measurements of the real label
  combinations come before enabling the family widely.

## 2. Processes of jobs

### 2.1 Units (#173)

Implemented (#185, design §4.1 and §5.3); see there for what differs from
this section, such as the names of peers.

- `Unit()` (`internal/procinfo/cgroup.go`) does not know the cgroups of
  Slurm, so the processes of jobs get the last element of the path:
  `task_0`, `task_1`, …, and slurmstepd `slurm`.
- The tree under `slurmstepd.scope` is recognized by its structure, not by
  the name of the job directory (`job_<id>` or a SLUID):
  - the directory of slurmstepd in a step (`slurm`, or as newer releases
    name it) → `slurmstepd`;
  - `user/task_*` → `slurm/batch`, `slurm/step`, `slurm/extern`,
    `slurm/interactive` by the kind of step;
  - anything else keeps the current behavior.
- The series from the agent are also keyed by the path of the executable
  (`otlp.Process`), so they still grow with the executables of jobs,
  bounded by the idle TTL.

### 2.2 Names (#173)

- **`OTEL_` variables** are not trusted in the cgroups of jobs: any user
  could name a job `slurmctld`. The name comes from the executable onwards
  (design §4.1).
- **PostgreSQL keeps the names as they are.** `shawk.processes` is unique by
  host, unit, comm and service, and keeps the latest `exe`; collapsing the
  services of jobs there would make jobs of different users share rows.
- **Prometheus only.** The connector forwards processes whose unit starts
  with `slurm/` under `job="slurm-job"`, so that every executable of every
  job does not become a `job`. `max_services` does not evict services
  already registered, but services that appear after it is full, or that
  expired while idle, would fold into `~other`.

### 2.3 Identity cache (#173)

A process that exited is given the latest identity seen for its unit and
comm (`resolve()` in `internal/agent/identity.go`). With `task_0` as the
unit, jobs of different users already share it. For processes of jobs the
cache is also keyed by the cgroup id, so an identity is filled in only
within the same step.

### 2.4 Users, opt-in (#181)

- The uid of a process of a job (`process.user.id`) becomes part of its
  identity in PostgreSQL; rows grow with users, not jobs. A uid that could
  not be read is unknown, never taken from the cache.
- Job ids are not kept: edges have only their first and last times, so
  joining them with slurmdbd later cannot split them by job. If needed, a
  separate table of dependencies per job with a short retention, at a cost
  proportional to jobs times their dependencies.
- `packaging/postgres/grants.sql` lets Grafana read all of `shawk_v1`. Uids
  with executables, peers and times identify the activity of other users'
  jobs, so the first version is for administrators only.
- Connections opened by processes that `pam_slurm_adopt` moved into a job
  belong to the job. An SSH connection accepted before stays with the owner
  of its listener (`chooseOwner()` in `internal/tracer/owner.go`).

## 3. Dynamic ports (#174)

### 3.1 Problem

- Without `SrunPortRange`, srun and salloc listen on a random port at every
  run, and slurmctld and slurmstepd connect to it. An srun inside a batch
  job runs on the first node of the job, so this happens between compute
  nodes too. The PMIx plugin and MPI over TCP may behave alike.
- `known_dependencies` and `dependency_changes` are per service and port,
  so such runs tend to appear as new dependencies, and `server_port`
  churns in Prometheus.

### 3.2 Keep ports, aggregate by rules

- **`shawk.edges` keeps the real port.** The direct match of
  `shawk_v1.dependencies` joins on both addresses, port, protocol and
  scope, without overlap of periods. Between two hosts the port is what
  tells the connections of different processes apart; normalizing it
  before storing would join connections that never happened.
- **Explicit rules for aggregation:**
  - `port_agnostic_services` (e.g. `[srun, salloc, slurm-job]`):
    dependencies on these services ignore the port in new and disappeared
    dependencies and in the outputs to Prometheus;
  - `dynamic_ports`: ranges by host and protocol, e.g. the `SrunPortRange`
    of the cluster, which the operating guidance recommends (it is common
    for firewalls anyway).
- **Automatic detection is a hint only.** A listener without
  `SOCK_BINDPORT_LOCK` got its port from the kernel (`port_bound()` in
  shawk.bpf.c), but listeners are listed by the iterator, so short-lived
  ones are missed, and a port chosen by the kernel does not make the
  services on it one. Without evidence the port is kept. Not implemented
  yet (#205).
- The rows of `shawk.edges` still grow with runs of srun. If they turn out
  to matter, matched dependencies may be kept in a separate table.

## 4. Load on compute nodes (#172)

- **Flow table.** The key of a flow has the cgroup, comm, addresses and port
  (`struct shawk_flow_key` in shawk.h), and `-max-flows` defaults to 16 384.
  A host whose 128 ranks each connect to 189 peer nodes, a port per rank,
  needs 24 192 flows in an interval. Slurm makes a cgroup per task, so
  units normalized in user space do not reduce them. To do:
  - guidance on `-max-flows`;
  - alerts on `partly_observed()`;
  - measurements with ranks per node, concurrent jobs and the rate of short
    jobs as parameters: drops, collection and export times, memory.
- **OS noise.** `AllowedCPUs=` can move the user-space work of the agent to
  the cores Slurm reserves (`CpuSpecList`, `CoreSpecCount`); the BPF
  programs run in the context of the applications. The effect on jobs is
  measured and documented.
- **Connector.** One active connector is the natural setup (#128 does not
  apply); its capacity and the downtime it can take are measured.
- **Measured** in a VM in
  [../research/hpc-compute-nodes/compute_nodes.md](../research/hpc-compute-nodes/compute_nodes.md),
  with the guidance on `-max-flows`, the alert and the drop-in; not yet on
  a cluster (#206). Slurm makes a cgroup per task only in some
  configurations: 22.05.9 with cgroup v2, `ConstrainCores` and without
  `ConstrainRAMSpace` leaves the tasks of a step in one cgroup
  (`task_special`), and their ranks then share flows; 24.11.7 and 25.11.4
  make one per task (fixed in 24.11.3). The agent has 10 s
  for an interval in all rather than per request (#194).

## 5. Inventory and node states

### 5.1 Static inventory (#175)

- **Contents.** Host names, all their addresses, roles, and the Slurm
  `NodeName` of each node. Hosts without an agent are included: storage
  appliances, switches, BMCs.
- **Addresses from provisioning** (Warewulf, xCAT, …). Slurm's `NodeAddr`
  may be a name and is one address, not the IPoIB and storage addresses.
- **Mapping to Slurm.** `NodeName` may be any alias, so the mapping is
  written, not derived by trimming host names.
- **Loading.** The connector reads `inventory_file` every write interval
  and writes it to PostgreSQL like `peer_cidrs`. When the file cannot be
  read or is invalid, the last valid contents stay, with the time they
  were read. The connector does not talk to Slurm; a cron job may generate
  the file from `scontrol show nodes --json` and the provisioning database.
- **Uses:**
  - a new function that reports the expected hosts never observed;
  - the peer hosts of §1.3.
- **Order.** The inventory comes before the family of §1, or with it.

### 5.2 Node states (#177)

- **Transitions with times.** Node states and maintenance windows are
  stored as time-stamped transitions, apart from the inventory. Attaching
  today's state or reason to past gaps would show past failures as planned.
- **Suppressed alerts.** Only planned stops suppress the alerts of stopped
  agents:
  - power saving (`POWERED_DOWN`, `POWERING_DOWN`);
  - maintenance windows registered explicitly.
- **Not suppressed.** `DOWN` and `DRAIN` never suppress: `DOWN` also
  follows failed boots and a `ResumeTimeout`, and jobs keep running on a
  `DRAIN` node. A stale state suppresses nothing, and every suppression has
  an end.
- **Gaps stay recorded.** Their reasons come from a new view or function;
  `unobserved()` does not change.
- **Prometheus.** `ShawkAgentDown` is suppressed under the same conditions
  by joining the node states of a Slurm exporter on the host name.
- **Not in shawk's metrics.** Slurm partitions and states are not labels.

## 6. Host identity and start order

### 6.1 Machine id (#178)

- **Problem.**
  - PostgreSQL keys a host by the hash of its machine id and host name
    (`hostKey()`), and the connector sends the machine id as `host_id` to
    Prometheus.
  - On stateless nodes whose machine id changes at every boot, every boot
    makes a new host. Whether it changes depends on the node: systemd first
    takes `systemd.machine_id=` and other sources.
  - `unobserved()` is computed per host id and returns the host name, so the
    old ids report false gaps for a host that was observed throughout.
    Power saving boots nodes often.
- **Provisioning first.** Every node gets a stable machine id
  (`systemd.machine_id=` on the kernel command line, or a file per node in
  the overlay), which also stabilizes `host_id` and OBI's `host.id`.
- **In shawk.** A function computes the gaps over the sessions of all host
  ids with the same host name.
- **Implemented:** `shawk_v1.unobserved_by_name()`, and the
  guidance in `packaging/README.md`. The annotations of the dashboards
  keep `unobserved()`; the table of gaps of the fleet dashboard is per
  host name, through `unobserved_reasons()` of §5.2.
- **Not proposed.**
  - Changing the host key: it would need a migration of hosts, sessions and
    processes, and it affects Prometheus, OBI and `host_identity:
    certificate`, which matches `host.name`.
  - Rewriting host names, e.g. dropping the domain: names may collide and
    certificates stop matching. The mapping to Slurm is in the inventory.

### 6.2 Start order (#179)

`Before=slurmd.service` alone does not make tracing start first: the unit
is `Type=simple`, so systemd does not wait for the BPF programs. The agent
becomes `Type=notify` and reports ready once they are attached, and a
drop-in for Slurm nodes orders it before slurmd. Until then the drop-in
only narrows the race, and the time before the programs are attached is
not observed.

## 7. RDMA (#171)

- The scope of §0.1 is stated in the first step of HPC support.
- **Port counters as a hint.** Optionally, the agent reports whether the
  RDMA ports of the host carried traffic. The counters of a port cover all
  its virtual lanes, IPoIB included, so they are not a coverage guarantee
  like `udp_traced`: no increase does not prove that no RDMA dependency was
  missed, and an increase does not tell which hosts or jobs used RDMA.
- **Usage by job** of file systems is left to them, e.g. Lustre jobstats
  with `jobid_var=SLURM_JOB_ID`.
- **Research.** Kernel upper-layer protocols (Lustre o2iblnd, NFS/RDMA,
  iSER, NVMe/RDMA) connect through rdma_cm, whose tracepoints might record
  their connections as TCP state changes are recorded. User-space verbs
  (UCX, NCCL) would need another hook.

## 8. Names of kernel sockets (#180)

- **Lustre.** LNet over TCP (socklnd) connects from the kernel to port 988,
  from either side, and `kernelPorts` does not list it, so these sockets
  are `~kernel`. Port 988 becomes `~kernel:lnet`, one name for both sides
  as for DRBD and OCFS2.
- **BeeGFS.** Its client is a kernel module that creates its sockets with
  `sock_create_kern()` (`StandardSocket.c`), so they are the kernel's:
  `~kernel:beegfs` for the ports of the daemons (8003 storage, 8005
  metadata, 8008 management) and the client's UDP port (8004). The daemons
  are processes and keep their names.

## What does not change

- **Fixed ports.** slurmctld (6817), slurmd (6818), slurmdbd (6819) and the
  database behind it are recorded as they are. munge uses a Unix socket,
  out of scope.
- **PostgreSQL** already has both hosts and the period of each dependency.
- **Existing outputs.** The outputs to Prometheus and the recording rules
  (`src`, `dst`, `server_port`, `network_transport`) do not change.

## Order

PostgreSQL keeps names for its retention (3 years), so what it would keep
wrong comes first, together with measurements:

0. Measurements on compute nodes (§4, #172), and operating guidance: a
   stable machine id, `SrunPortRange`, the scope (§0.1, #171).
1. The processes of jobs (§2.1 to §2.3, #173).
2. Dynamic ports (§3, #174).
3. The inventory (§5.1, #175).
4. Metrics per peer host, rules and a dashboard (§1, #176).
5. Node states (§5.2, #177), readiness (§6.2, #179), names of kernel
   sockets (§8, #180).
6. Optional: users of job processes (§2.4, #181), gaps per host name (§6.1,
   #178).
