# The agent on the compute nodes of a Slurm cluster

Written 2026-11-05 for #172, part of #170
([../../proposals/slurm-hpc-clusters.md](../../proposals/slurm-hpc-clusters.md)
§4). It measures what the agent costs a compute node and what one
connector takes for a cluster of 200 hosts, in a VM that runs Slurm and MPI
over TCP, and gives the guidance that follows. What a VM cannot show is in
§8, with the procedure to measure it on a cluster: **it has not been
measured on a cluster yet.**

## Summary

- **MPI over TCP makes a flow per local rank (or per node) and remote rank
  port, every interval its connections are open.** Open MPI gives every
  rank a listening port of its own (from 1024 up), and the key of a flow
  drops the client port only, so the 128 ranks of a node that each talk to
  the same rank of 189 other nodes make 24 192 flows, as the issue
  assumed. The agent counted exactly the flows that the connections
  predict, under Slurm (srun, PMIx) and across three nodes (mpirun).
- **Whether Slurm makes a cgroup per task depends on its version and
  `cgroup.conf`.** Of the versions shawk targets, 22.05.9 (like 22.05.11,
  measured) leaves the tasks of a step in one cgroup (`task_special`) with
  `ConstrainCores=yes` and without `ConstrainRAMSpace`: `task/cgroup`
  moves every task back to the step for its cpuset after
  `jobacct_gather/cgroup` moved it to `task_<n>`. 24.11.7 and 25.11.4 give
  every task a cgroup of its own whenever `jobacct_gather/cgroup` or a
  constraint of `task/cgroup` is on (Slurm commit 91f1fc540b, 24.11.3;
  read from their sources, not measured). With one cgroup per step, an
  all-to-all of R ranks per node over N nodes makes at most about
  2 R (N − 1) flows on a node (48 384 for 128 ranks and 190 nodes); with a
  cgroup per task, as the issue assumes, up to about R² (N − 1) / 2
  (1.5 million), which no flow table holds. On one node, 16 ranks of
  `MPI_Alltoall` made 33 flows with one cgroup and 88 with a cgroup per
  task.
- **A full table drops the same flows in every interval, the dependencies
  of the infrastructure among them.** With 24 192 flows and the default
  `-max-flows` of 16 384, the same 16 384 were collected for 6 intervals
  and the other 7 808 never; a client of a file system with persistent
  connections to 4 servers was seen to 2 of them only. Short connections
  (slurmd) were always seen: they enter the table at their state changes,
  before the walk at the end of the interval fills it.
- **`-max-flows` costs about 2.7 KiB of kernel memory per flow** (51 MiB of
  BPF maps at 16 384, 102 at 32 768, 203 at 65 536, 355 at 131 072), and the
  agent 10 to 15 KiB of resident memory per edge it sends (up to 270 MiB
  at 24 192 edges, 0.7 to 0.9 GiB at 96 768). A collection takes 0.1 to 0.5 s, and an
  interval of the agent with 24 192 edges 0.57 s of CPU and 1.2 s of wall
  time, 38 requests of 107 MB before compression; 96 768 edges take 3.2 s
  of CPU and 5.9 s.
- **The agent has 10 s for an interval in all, not per request**
  (`exportTimeout()`, 2/3 of `-interval`, bounds the context of the whole
  `tick()`, from which each request derives its deadline; the comment in
  `tick()` says each request has its own). A host whose collection and
  export take longer never sends the last request of an interval, which
  carries the metrics of the agent. It happened in every interval with
  48 384 and 96 768 edges when the host was busy, and not once when it was
  not; it is a bug of the agent, #194, fixed since: each request has a
  deadline of its own, and the requests of an interval together 4
  intervals.
- **Jobs on all CPUs are slowed by the agent; jobs off a reserved CPU are
  not, measurably.** An `MPI_Allreduce` loop over TCP on all 8 CPUs ran
  3.7 % longer (median of 5) with the agent and had 184 instead of 38
  iterations over 10 ms. With one CPU reserved by Slurm (`CpuSpecList`)
  the job ran 0.5 % longer with the agent (within the spread), with 33
  instead of 25 iterations over 10 ms. Confining the agent to the reserved
  CPU with `AllowedCPUs=` made no further difference: an idle reserved CPU
  takes the agent anyway. The drop-in makes that so whatever else runs.
- **One connector takes the star traffic of 200 hosts with 5 % of a CPU
  and 160 MiB**, a write of 0.2 s a minute, and 5 minutes without
  PostgreSQL or without itself. **The edges of jobs decide its size**:
  with 48 640 new edges every 5 minutes (MPI over TCP on random ports), it
  grew for 30 minutes, the two idle TTLs, to 1.5 CPUs and 6.9 GiB; four
  times that ran out of the 12 GiB of the VM in 8 minutes.

## 1. How it was measured

**Host.** One VM of Lima (Apple Virtualization.framework) on a Mac with
Apple silicon (12 cores, 32 GiB), with 8 vCPUs and 12 GiB: Rocky Linux 9.8,
kernel 5.14.0-687.10.1.el9_8 (aarch64), Slurm 22.05.11 and PMIx 3.2.3 from
EPEL, Open MPI 4.1.1 (btl `self,tcp`, so ranks on one node use TCP too),
PostgreSQL 16.15, shawk at 93c1584 (v0.8.1 and the proposal), before the
parts of #170 that followed (the names of the processes of jobs, #173,
among them). Other work ran on the Mac
at the same time; timings on a VM are noisier than on bare metal, and the
benchmark of §5 has iterations over 10 ms without the agent too.

**Nodes.** One VM cannot hold 190 compute nodes, so the measured node is a
network namespace, `node` (10.97.0.1), and its peer nodes are up to 189
addresses of a second namespace, `peers`, joined by a veth pair
([setup.sh](../../../test/nodeload/setup.sh)). Slurm runs on the VM
itself, a cluster of one node with cgroup v2, `task/cgroup` with
`ConstrainCores`, and PMIx ([slurm.sh](../../../test/nodeload/slurm.sh)).

**Harness.** [test/nodeload](../../../test/nodeload):

- `nodeload mesh` runs the ranks of the node as processes, each in a
  cgroup of its own laid out as Slurm lays out tasks
  (`job_<id>/step_0/user/task_<n>`), each listening on a port of its own
  and connecting to ports of ranks of the peer nodes, which `nodeload peer`
  serves; every connection carries 8 bytes every 5 s. With `-in`, every
  peer node also connects to every rank. Concurrent jobs split the ranks;
  short jobs start at a rate, connect, and exit after a few seconds.
- `nodeload probe` loads the tracer of shawk with the options of the agent
  and collects it every 15 s as the agent does, without exporting: flows,
  drops, the distinct flows seen so far, the time of `Collect()`, and the
  memory the kernel charges for the BPF maps. The first interval, which
  adopts the open connections, is left out.
- `nodeload sink` receives OTLP and groups the requests of an agent per
  interval; it tells whether the last request, which carries the metrics
  of the agent, arrived. `nodeload watch` samples a process every 5 ms: its
  CPU time, its bursts of activity, and its resident memory.
- [mpi/alltoall.c](../../../test/nodeload/mpi/alltoall.c) runs
  `MPI_Alltoall` in a loop; [keys.py](../../../test/nodeload/keys.py)
  predicts the flows of the agent from the connections `ss` lists;
  [mpi/noise.c](../../../test/nodeload/mpi/noise.c) times every iteration
  of an `MPI_Allreduce` of 8 bytes, which all ranks delay.
- `nodeload fleet` sends the series of the agents of a cluster to a
  connector, built as the agent builds them (`internal/otlp`).

`flows.sh`, `mpi.sh`, `noise.sh` and `connector.sh` run §2 to §6 and append
JSON lines, which are in [data](data); `nodeload flows` makes the table of
§3 from them. They need root on a disposable host.

## 2. Flows of MPI over TCP

The key of a flow (`struct shawk_flow_key`) is the local and remote
address, the cgroup and command of the local process, the network
namespace, the service port and the direction; the client port is dropped.
An outgoing connection is keyed by the port it connects to, and an incoming
one by its listening port and the address of the client, and belongs to
the owner of the listener. Every open connection updates its flow at every
walk, so a flow takes a slot in every interval in which one of its
connections is open.

Open MPI 4.1 (btl `tcp`) gives every rank a listening port of its own
(here consecutive ports from 1026, after `btl_tcp_port_min_v4`, 1024) and connects
the ranks that talk to each other, a connection per pair or about. On a
node with R ranks of a job over N nodes:

- outgoing flows: per local cgroup, the distinct remote rank ports
  connected to: with a cgroup per task up to R × R (N − 1), with one cgroup
  for the ranks of the node up to R (N − 1);
- incoming flows: per local rank, the distinct nodes that connected to it,
  up to R (N − 1).

| pattern, R = 128, N = 190 | a cgroup per task | one cgroup per step |
|---|---|---|
| a rank talks to the same rank of every node (the issue) | 24 192 | 24 192 |
| all to all | about 1.5 million (R² (N − 1) / 2 + R (N − 1)) | at most 48 384 (2 R (N − 1)) |

The agent counted what the connections predict, in every run
([mpi-rocky9.8-aarch64.jsonl](data/mpi-rocky9.8-aarch64.jsonl)):

| job | flows measured | predicted from `ss` | outgoing | ends of connections on the node |
|---|---|---|---|---|
| srun, one node, 4 / 8 / 16 ranks, one cgroup per step | 7 / 15 / 33 | 7 / 15 / 33 | 4 / 8 / 17 | 16 / 64 / 128 |
| srun, one node, 4 / 8 / 16 ranks, a cgroup per task | 13 / 43 / 88 | 13 / 43 / 88 | 10 / 36 / 72 | 16 / 64 / 128 |
| mpirun, 3 nodes, 4 / 8 / 16 ranks each, on one node | 15 / 33 / 71 | 15 / 33 / 71 | 12 / 18 / 40 | 48 / 76 / 184 |

A connection between two ranks of the node has both ends on it. Open MPI
connects the pairs that exchange data, when they first do, so the flows
differ a little between runs (15 / 32 / 64 for mpirun in another run,
[mpi-acct-rocky9.8-aarch64.jsonl](data/mpi-acct-rocky9.8-aarch64.jsonl),
with `jobacct_gather/cgroup` and `jobacct_gather/none` alike for srun).
The ranks of mpirun are children of `orted` and share its cgroup.

**The cgroups of the tasks.** Slurm 22.05.11 with cgroup v2 adds the
processes of a step to `step_0/user/task_special` (`cgroup_p_step_addto()`)
and a task to `task_<n>` when a plugin adds it with its id
(`cgroup_p_task_addto()`). slurmstepd adds every task to proctrack
(`task_special`), then to `jobacct_gather/cgroup` (`task_<n>`), then to
`task/cgroup` before setting its affinity: its cpuset, for
`ConstrainCores=yes`, adds the process to the step (`task_special`) and
its memory, for `ConstrainRAMSpace=yes`, to the task (`task_<n>`). In one
hierarchy (cgroup v2) the last move wins
([slurm-task-cgroups-rocky9.8-aarch64.txt](data/slurm-task-cgroups-rocky9.8-aarch64.txt),
`srun -n 2 sleep 8`, and the log of slurmd with `DebugFlags=CGroup`):

| `JobAcctGatherType` | `ConstrainCores` | `ConstrainRAMSpace` | the tasks are in |
|---|---|---|---|
| `jobacct_gather/cgroup` | yes | no | `task_special` |
| `jobacct_gather/cgroup` | yes | yes | `task_0`, `task_1` |
| `jobacct_gather/cgroup` | no | no | `task_0`, `task_1` |
| `jobacct_gather/none` | no | no | `task_special` |
| `jobacct_gather/none` | yes | yes | `task_0`, `task_1` |

Slurm 24.11.3 made the cpuset work per task (commit 91f1fc540b, "There was
a race when jobacctgather/cgroup moved a pid to task_x directory ... Then
task/cgroup was removing it and putting again the pid in the step_0
superior directory"). For the versions shawk targets, from their sources
(`_fork_all_tasks()` of `slurmstepd/mgr.c`, `task_cgroup_cpuset.c`,
`cgroup_v2.c`; only 22.05.11 was run):

| Slurm | the order of the plugins for a task | the tasks of a step are in |
|---|---|---|
| 22.05.9 | proctrack, `jobacct_gather`, `task/cgroup` (cpuset to the step, memory to the task) | as measured with 22.05.11 above |
| 24.11.7, 25.11.4 | proctrack, `jobacct_gather`, `task/cgroup` (cpuset and memory to the task) | `task_<n>` with `jobacct_gather/cgroup` or a constraint of `task/cgroup`; `task_special` without either |

The directories are the same in all three (`job_<id>/step_<n>/user/` with
`task_<n>` and `task_special`). With one cgroup per step the ranks of a
node share the key of a remote port: 17 outgoing flows for 16 ranks,
against 72 with a cgroup per task. What `/proc/<rank>/cgroup` shows on a
cluster decides between the two columns of the first table.
Since the ports of the ranks are numbered from 1024 on every node, the
ports of a job repeat on the next job of the same shape; MPI libraries
other than Open MPI, and UCX, were not measured.

## 3. The flow table

`flows.sh` with the ranks of `nodeload mesh` (a cgroup per task, each rank
connecting to `ports` ranks of each peer node), each `-max-flows` for 6
intervals of 15 s ([flows-rocky9.8-aarch64.jsonl](data/flows-rocky9.8-aarch64.jsonl),
[churn-priority-rocky9.8-aarch64.jsonl](data/churn-priority-rocky9.8-aarch64.jsonl)):

| workload | flows | `-max-flows` | drops per interval | flows seen in 6 intervals | collection, ms (median, max) | BPF maps, MiB |
|---|---|---|---|---|---|---|
| 128 ranks × 64 peers | 8 192 | 16 384 | 0 | all | 114, 130 | 51 |
| 128 × 128 | 16 384 | 16 384 | 0 | all | 133, 140 | 51 |
| 128 × 189 (the issue) | 24 192 | 16 384 | 7 808 | 16 384 (68 %) | 109, 151 | 51 |
| | | 32 768 | 0 | all | 145, 161 | 102 |
| 128 × 189, both sides connect | 48 384 | 16 384 | 32 000 | 34 % | 155, 167 | 51 |
| | | 32 768 | 15 616 | 68 % | 134, 158 | 102 |
| | | 65 536 | 0 | all | 207, 254 | 203 |
| 128 × 189, 4 ranks of each | 96 768 | 65 536 | 31 232 | 68 % | 386, 512 | 203 |
| | | 131 072 | 0 | all | 392, 481 | 355 |
| 128 × 189 in 4 jobs, 30 short jobs a minute | about 24 600 | 16 384 | 8 200 | — | 121, 139 | 51 |
| | | 32 768 | 0 | — | 157, 171 | 102 |
| the same, 10 short jobs a second (40 tasks) | about 30 400 | 16 384 | 14 032 | — | 124, 158 | 51 |
| | | 32 768 | 0 | — | 186, 209 | 102 |

- The flows that did not fit stayed out in every interval: which
  connections the walk reaches first does not change while they are open.
  The seen fraction of the runs with short jobs is not given, since their
  flows come and go.
- Beside the ranks of the issue's workload, with the default
  `-max-flows`, a process `nfsclient` holding connections to 4 servers had
  2 of its 4 flows in all 6 intervals and the other 2 in none; a process
  `slurmd` connecting every 5 s had its flow in all. A dependency of
  persistent connections can be missing from PostgreSQL for as long as a
  job too large for the table runs.
- No event of a new cgroup was dropped, also at 10 short jobs a second
  (about 70 cgroups a second).
- The memory of the BPF maps grows by 2.7 KiB per slot of `-max-flows`
  (two flow tables, translations, live conntrack entries, and the tables
  of listening ports from 8 192 to 65 536 slots), and is charged whether
  used or not.
- With 96 768 connections, the TCP iterator of the kernel skipped some, and
  the tracer walked the processes in every interval instead (it warns);
  the collections of that row include it.

## 4. Collection, export and memory of the agent

The agent itself (`-max-flows 131072`) on the same workloads, sending to
`nodeload sink` in the VM, with `nodeload watch`, medians of 6 to 8
intervals ([agent-rocky9.8-aarch64.jsonl](data/agent-rocky9.8-aarch64.jsonl)
and the agent rows of the flows file):

| edges sent | requests | bytes before compression | export | CPU per interval | busy per interval | resident memory |
|---|---|---|---|---|---|---|
| 8 192 | 13 | 36 MB | 0.32 s | 0.27 s | 0.53 s | 73 to 113 MiB |
| 16 384 | 26 | 73 MB | 0.67 s | 0.47 s | 0.93 s | 131 to 219 MiB |
| 24 192 | 38 | 107 MB | 0.95 s | 0.57 s | 1.17 s | 192 to 270 MiB |
| 48 384 | 64 | 183 MB | 1.80 s | 1.24 s | 2.23 s | 427 to 732 MiB |
| 96 768 | 149 | 429 MB | 4.72 s | 3.21 s | 5.86 s | 669 to 926 MiB |

- CPU per interval is that of the agent's process (clock ticks of 10 ms);
  busy is the wall time of its bursts of activity, collection to the end of
  the export. The CPU of the kernel walking sockets for the agent is in it.
- The edges are the flows after the names of user space: the short jobs of
  §3 added 6 000 flows per interval but 33 edges, since their tasks were
  named `task_0` to `task_3` in every job (`nodeload mesh` makes its
  cgroups outside `slurmstepd.scope`; #173 names the processes of real
  jobs since).
- With 10 short jobs a second the agent never paused for 100 ms: it woke
  for the events of new cgroups and the reads of new processes between
  intervals, with 0.85 s of CPU per interval.
- **The deadline of an interval.** In a first run, while other work ran on
  the Mac, the export of 48 384 and 96 768 edges took 9 s and stopped in
  every interval after 34 to 40 requests: the last request, with the
  metrics of the agent (`shawk.agent.flows.dropped` among them), never
  arrived, and the connector would not see the interval as observed. The
  agent gives the whole `tick()`, collection included, a context of
  `exportTimeout()` (2/3 of the interval, 10 s), and each request's
  deadline derives from it; the comment of `tick()` says each request has a
  deadline of its own "so that a host with many requests delivers them
  all", which the code does not do (#194). In the second run all requests
  arrived, in 1.8 and 4.7 s.

## 5. The effect on jobs

`noise.sh`: 4 million iterations of an `MPI_Allreduce` of 8 bytes over TCP
(about 55 s, four intervals of the agent) on all CPUs Slurm gives the job,
5 times per configuration, interleaved. The agent traces all namespaces
with the connections of 128 ranks to 94 peer nodes held idle (24 064 flows,
`-max-flows 32768`), exports to a sink on the Mac (93 MB an interval, all
requests delivered), and runs as the unit of packaging, with or without
[shawk-agent-reserved-cpus.conf](../../../packaging/systemd/shawk-agent-reserved-cpus.conf)
([noise-rocky9.8-aarch64.jsonl](data/noise-rocky9.8-aarch64.jsonl)):

| configuration | ranks | run time, median (range) | p99.99 | iterations over 1 ms | over 10 ms (each run) |
|---|---|---|---|---|---|
| all CPUs, no agent | 8 | 55.9 s (55.3–58.9) | 483 µs | 249 | 38 (34, 42, 59, 29, 38) |
| all CPUs, agent | 8 | 58.0 s (57.5–64.0), +3.7 % | 1 199 µs | 437 | 184 (182, 181, 224, 191, 184) |
| CPU 0 reserved, no agent | 7 | 51.3 s (50.4–52.6) | 180 µs | 127 | 25 (22, 25, 25, 19, 28) |
| CPU 0 reserved, agent | 7 | 51.5 s (51.0–51.8), +0.5 % | 208 µs | 139 | 33 (32, 34, 35, 33, 31) |
| CPU 0 reserved, agent on CPU 0 (`AllowedCPUs=0`) | 7 | 52.0 s (50.6–53.8), +1.5 % | 360 µs | 221 | 36 (27, 36, 21, 38, 43) |

- With all CPUs running ranks, the work of the agent (about 1 s of CPU an
  interval at this load) runs on CPUs of ranks, and a collective waits for
  the slowest rank.
- With a CPU reserved (`CpuSpecList=0`, which confines slurmd there; the
  scope of slurmstepd keeps all CPUs), the scheduler ran the agent on the
  idle reserved CPU also without `AllowedCPUs=`; confining it changed
  nothing measurable, and its p99.99 was if anything higher. The drop-in
  guarantees what an idle reserved CPU gives here: that the agent does not
  run on the CPUs of jobs when the reserved ones are busy.
- 8 to 11 more iterations over 10 ms per run remained with the agent, with
  or without the drop-in. They were not explained: candidates are the
  interrupts of the export (on any CPU), the BPF programs and the walk of
  the sockets of the job, and the grace periods the collection waits for.
  The BPF programs of TCP run per state change, not per message, and the
  connections of MPI stay open.

## 6. The connector

`connector.sh`: a collector with the shawk connector (`write_interval`
1 m, `idle_ttl` 15 m, the defaults) writing to PostgreSQL 16 in the same
VM, with its defaults, and forwarding to `nodeload sink`; `nodeload fleet`
sends the series of 190 compute nodes and 10 other hosts, each at its own
phase, as the agent builds them
([connector-rocky9.8-aarch64.jsonl](data/connector-rocky9.8-aarch64.jsonl);
the output of the connector is summarized per minute there):

- **star**: the traffic of §1.6 of the proposal: every compute node a TCP
  client of slurmctld, 4 storage servers and 2 LDAP servers and a UDP
  client of 2 DNS and 2 NTP servers, slurmctld a client of every slurmd,
  Prometheus of every host; 4 960 edges in all.
- **mpi16**: that, and on every compute node ranks talking over TCP to 8
  other compute nodes over 16 connections each, on random ports that change
  with every job of 5 minutes: 48 640 new edges every 5 minutes, the worst
  case for MPI over TCP (Open MPI repeats the ports of a node, §2).

| scenario | CPU per minute | resident memory | a write (sum of the statements, from first to last) | output points per host and interval | after 40 minutes in PostgreSQL |
|---|---|---|---|---|---|
| star | 3.0 to 3.3 s | 145 to 163 MiB | 123 to 181 ms, 188 to 260 ms | 72 (max 102) | 4 960 edges, 13 MB |
| mpi16 | 10 s, growing to 83 to 94 s after 30 minutes | 1.1 GiB, growing to 6.5 to 6.9 GiB after 30 minutes | 0.7 to 2.4 s, 0.8 to 2.9 s | 11 035 (max 19 147) | 394 062 edges, 197 MB |
| mpi64 (first run) | 36 s, growing to 194 s at 8 minutes | 3.8 GiB, 8.9 GiB at 8 minutes, then killed by the kernel (out of memory, 12 GiB) | — | — | — |

- A series of a job lives until both idle TTLs pass after its last
  activity: 15 minutes in the agent, then 15 in the connector. With jobs of
  5 minutes on new ports, 7 generations are alive, about 340 000 series in
  mpi16, and the connector held about 20 KB and 0.25 ms of CPU a minute
  per series. It forwards about 11 000 points per host and interval, about
  150 000 samples a second for 200 hosts, to Prometheus.
- The star traffic of a cluster of 200 hosts costs one connector 5 % of a
  CPU. The edges of jobs that talk over TCP decide its size, by the edges
  per job and how often their ports change: mpi64 (4 times mpi16) did not
  fit 12 GiB.
- **Downtime.** PostgreSQL stopped for 5 minutes: the connector kept the
  changes (6 933 pending rows for 200 hosts, of `max_pending_rows`
  10 000 000) and wrote them in the first write after, in 608 ms. The
  collector stopped for 5 minutes: the agents' requests failed meanwhile,
  and the writes were back to their size 3 minutes after it started
  (1 733, 3 051, then 3 609 log lines), since the agents send cumulative
  series again. Whether PostgreSQL lost a period of a dependency across
  the outages was not checked. At the star traffic, `max_pending_rows` holds about 120 hours of
  changes; with mpi16 the changes per write are larger, which was not
  measured.

## 7. Guidance

**`-max-flows` of compute nodes.** Size it for the flows of the busiest
interval, with a quarter of margin:

    flows ≈ services of the node (tens to hundreds)
          + per job on the node, if its ranks talk over TCP:
              outgoing: ranks × remote rank ports each connects to   (a cgroup per task)
                        remote rank ports the node connects to       (one cgroup per step)
              incoming: ranks × nodes that connect to each

- The ranks of a node talking to one rank of every other node of 190
  nodes: 24 192 flows, `-max-flows 32768` (102 MiB of BPF maps).
- All to all over 190 nodes, 128 ranks a node, one cgroup per step
  (22.05.9 with `ConstrainCores` and without `ConstrainRAMSpace`): up to
  48 384, `-max-flows 65536` (203 MiB).
- All to all with a cgroup per task (24.11.7 and 25.11.4 with the usual
  `cgroup.conf`), or MPI over TCP between thousands of ranks: no table
  holds it. Keep the default and accept that such jobs are
  partly observed, or exclude them by not running MPI over TCP.
- Check what the tasks are in (`cat /proc/<rank>/cgroup`: `task_<n>` or
  `task_special`), which the version and `cgroup.conf` decide (§2), and count the
  flows of a real job with `nodeload probe -comm <executable>` or
  `keys.py` before choosing.

Every slot costs 2.7 KiB of kernel memory, and every edge the agent sends
10 to 15 KiB of its memory, 4.4 KB of every request and CPU of the
connector. Above about 50 000 edges, the 10 s an interval has (§4) is
within reach of a busy host.

**The connector.** One connector serves a cluster of 200 hosts whose
compute nodes talk to the infrastructure (5 % of a CPU, 160 MiB). Jobs
whose ranks talk over TCP add their edges for 30 minutes after they end
(the two idle TTLs), about 20 KB of memory and 0.25 ms of CPU a minute
each in the connector, and their points to Prometheus. Ports that repeat
from job to job keep that bounded: Open MPI numbers the ports of its
ranks from `btl_tcp_port_min_v4`; give other MPI libraries a fixed range
where they can take one (not measured), and srun `SrunPortRange` (#174).

**Alerts.** A job too large for the table makes all its nodes partly
observed at once. The opt-in rule
[shawk-compute-nodes.yaml.example](../../../packaging/grafana/provisioning/alerting/shawk-compute-nodes.yaml.example)
fires once with the number of compute nodes that dropped flows in the last
30 minutes, from `shawk_v1.partly_observed()`, instead of one alert per
node; the Prometheus rule `ShawkFlowsDropped` can then exclude the compute
nodes in a copy of the rules.

**Reserved CPUs.** Reserve CPUs for the system in Slurm (`CpuSpecList` or
`CoreSpecCount`, with `task/cgroup`), which keeps jobs and slurmd apart,
and confine the agent there with the drop-in
[shawk-agent-reserved-cpus.conf](../../../packaging/systemd/shawk-agent-reserved-cpus.conf),
whose `AllowedCPUs=` takes the CPU ids of the kernel. Measured here, the
reservation removes the effect of the agent on the run time (0.5 %,
within the spread, against 3.7 % with jobs on all CPUs); the drop-in keeps
it so when the reserved CPUs are busy. Steering the interrupts of the
interface the agent exports through to the reserved CPUs was not tried.

## 8. Not measured yet, and how to measure it on a cluster

What the VM could not show:

- bare-metal compute nodes of 64 to 128 cores and x86_64, a real interface
  and its interrupts, IPoIB, and jobs over many nodes at once;
- MPI over TCP across real nodes at the scale of the issue, other MPI
  libraries (MPICH, Intel MPI, UCX over TCP), and the Slurm versions shawk
  targets (22.05.9, 24.11.7, 25.11.4) rather than 22.05.11 of EPEL;
- the effect on jobs spanning nodes, whose collective operations wait for
  the slowest node, with the agents of all nodes collecting at the same
  time or not;
- the connector with the series of real jobs.

**Procedure.** On a test partition of a few nodes, as root, with the agent
and `nodeload` built from the same commit (`go build ./cmd/shawk
./test/nodeload`, `mpicc` for `mpi/*.c`):

1. *Flows of real jobs.* While a representative job runs, on one of its
   nodes, for each Slurm version in use: `cat /proc/<rank>/cgroup` for a
   few ranks, with `cgroup.conf` and `JobAcctGatherType`; `nodeload probe -comm
   <executable> -count 4` (with `-max-flows` above the expected flows) and
   `(ss -Htnp state established; echo --; ss -Htlnp) | keys.py
   <executable>`; record ranks per node, nodes, the MPI library and its
   transport. Compare with the formula of §7.
2. *The agent at that load.* Run the agent with the planned `-max-flows`
   and watch it with `nodeload watch -pid $(pidof shawk)`; check
   `shawk_agent_flows_dropped_total`, and that every interval of the host
   arrives (`shawk_v1.agents`, no gaps in `shawk_v1.unobserved()`).
3. *The effect on jobs.* On N exclusive nodes, interleave runs of
   `srun -N N --ntasks-per-node=<cores> noise <iterations>` (about a minute
   each, at least 5 per configuration) without the agent, with it as
   packaged, and with the drop-in, on nodes with and without `CpuSpecList`
   or `CoreSpecCount`; start and stop the agent on all nodes between runs
   (pdsh). Compare run times and the iterations over 1 and 10 ms of the same
   rank counts.
4. *The connector.* `nodeload watch -pid $(pidof shawk-collector) -window
   1m -gap 1s`, the durations of its statements (`ALTER ROLE <connector
   role> SET log_min_duration_statement = 0` for a while, or
   `pg_stat_statements`), and the series per host
   (`count by (host_name) ({__name__=~"shawk_.*"})` in Prometheus).

Record the results next to these, with the date and versions.
