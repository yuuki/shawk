# Kernel hooks for TCP and UDP, re-evaluated on the targets

Written 2026-11-04 for #165. Most of shawk up to v0.8.0 was written in a
sandbox whose kernel (Linux 6.18 on Firecracker) loaded tracepoints and
iterators but neither kprobes nor fentry, so the choices of hooks were
made without measuring the alternatives. This note measures them on kernels
of the targets and answers the questions of the issue. What shawk does is
in [../../design.md](../../design.md) §3.

## Summary

- **TCP stays on the state change tracepoint and the iterators (option a).**
  It costs 0.11 to 0.16 µs of CPU per state change, 1.1 to 1.6 µs per
  connection, and nothing per message. Bundling every message as the paper
  did (option c) costs 0.11 µs per message with fentry and 0.30 to 0.34 µs
  with kprobes, 11 % and 27 % of a saturated loopback request-response,
  to add message counts.
- **A hook on accept (option b) is not worth it.** It costs at most 0.5 µs
  per connection, within the noise, but removes none of the rules of
  `owner.go`: they stay for `Accept=yes` and inetd, for connections never
  accepted or accepted before the agent started, and for listeners of the
  kernel.
- **The failure reasons race with user space on every kernel**, also with
  `tcp_done_with_error()`: 0.01 to 0.05 % of connects that an ICMP error
  failed are counted as `timeout` when the client waits in poll(2), and 5 to
  59 % of all failures, resets included, when it busy-polls the socket.
  Hooks that see the error as a value before user space can take it, the
  tracepoint `tcp_receive_reset` and kprobes on `ip_icmp_error()` and
  `ipv6_icmp_error()`, saw it for every failure. They run only on failed
  connects, and the kprobes read only the first three parameters, which
  both kernels share: a change of design, #166.
- **UDP stays on fentry, with kprobes as the fallback rather than the
  primary hook (#118).** On arm64 a kprobe doubles the cost per datagram
  (0.29 instead of 0.15 µs). cgroup_skb is cheaper (0.06 µs) but sees no
  process and runs on every TCP packet. RHEL 9 attaches fentry on aarch64
  from kernel 5.14.0-621 (Rocky Linux 9.8 does, 9.6 does not), upstream
  arm64 from 6.0.
- **`perf_event_open` stays allowed** in the agent's unit, as the conntrack
  kprobes already need; any kprobe above needs nothing more.

## 1. How it was measured

**Hosts.** Two VMs of Lima (Apple Virtualization.framework) on a Mac mini
with Apple silicon, 4 vCPUs and 6 GiB each, aarch64 with hardware
virtualization:

| kernel | trampolines (fentry) | kprobes | kprobe_multi | `tcp_done_with_error()` | `inet_csk_accept()` |
|---|---|---|---|---|---|
| Rocky Linux 9.8, 5.14.0-687.10.1.el9_8 | yes | yes | no (`CONFIG_FPROBE` unset) | no | with `struct proto_accept_arg` (6.10, backported) |
| Ubuntu 24.04, 6.8.0-142-generic | yes | yes | no (`CONFIG_FPROBE` unset) | yes (backported) | before 6.10 |

**Harness.** [test/hookcost](../../../test/hookcost) attaches one *variant*,
runs a loopback workload in a process of its own, and reads the CPU time of
the whole VM from `/proc/stat` around it, so that what a hook costs shows
as CPU time per transaction whichever task or softirq pays it. A variant is
one of:

- the tracer of shawk v0.8.0 itself (`shawk`), loaded as the agent loads it;
- a program of [hookcost.bpf.c](../../../test/hookcost/bpf/hookcost.bpf.c)
  that does what its hook would do in shawk (find the state of the socket
  and the bundled flow, add to it), or the same hook with an empty program
  (`*-empty`), which tells the cost of a hook from the cost of the work.

The workloads use blocking sockets with raw system calls, each thread on an
OS thread of its own:

| workload | a transaction | events per transaction |
|---|---|---|
| `tcp_rr` | write 64 bytes on a persistent connection, read them back | 2 `tcp_sendmsg()`, 2 reads, which call `tcp_cleanup_rbuf()` twice each |
| `tcp_crr` | connect, write 64 bytes, read them back, close | 1 connection: 10 state changes, 1 accept |
| `udp_rr` | send a datagram of 64 bytes, receive the echo | 2 datagrams sent, 2 received |

Each runs with 1 pair of client and server threads (the latency of a
transaction) and with 8 pairs on the 4 vCPUs, which keeps the VM at 100 %
CPU (a busy host): 5 rounds of 4 s per variant, the variants interleaved so
that drifts of the host spread over all. The tables give the median. One
more round with `kernel.bpf_stats_enabled` counts how often each program
ran and how long a run took. The cost of an event is the difference of CPU
time per transaction to the runs without hooks, divided by the runs per
transaction. Differences of a tenth of a µs per transaction are within the
spread of the rounds, given as a range where it matters, and for `tcp_crr`
differences of 0.4 µs: hooks that do nothing land between −0.36 and
+0.09 µs there. `run.sh` runs all of it, `setup.sh` prepares the host, and
`hookcost report` summarizes the raw results in [data](data).

## 2. TCP: per state change or per message (options a and c)

CPU time per transaction of `tcp_rr` on the busy host, against 3.20 µs
(Rocky Linux 9.8) and 3.86 µs (Linux 6.8) without hooks:

| variant | Rocky 9.8: Δ per transaction | per run | throughput | Linux 6.8: Δ per transaction | per run | throughput |
|---|---|---|---|---|---|---|
| shawk v0.8.0 | 0 (−0.07…+0.35 µs) | — | ±0 % | +0.07 µs (−0.02…+0.11) | — | −3 % (noise) |
| kprobes per message | +1.18 µs | 0.20 µs | −27 % | +1.37 µs | 0.23 µs | −27 % |
| kprobes, empty | +0.80 µs | 0.13 µs | −20 % | +0.94 µs | 0.16 µs | −20 % |
| fentry per message | +0.44 µs | 0.07 µs | −12 % | +0.44 µs | 0.08 µs | −11 % |
| fentry, empty | +0.16 µs | 0.03 µs | −5 % | +0.25 µs | 0.04 µs | −7 % |
| cgroup_skb, UDP only | +0.10 µs | 0.02 µs per packet | −3 % | +0.12 µs | 0.03 µs | −4 % |

A run is a call of `tcp_sendmsg()` or `tcp_cleanup_rbuf()`. `tcp_recvmsg()`
also calls `tcp_cleanup_rbuf()` with nothing copied before it waits, so a
hook there runs twice per read: per message (a write or a read), the per
message variants cost 0.30 µs (Rocky) and 0.34 µs (6.8) with kprobes, and
0.11 µs with fentry. On arm64 a kprobe is a breakpoint and a single step,
0.13 to 0.16 µs before the program does anything; on x86_64 a kprobe at the
entry of a function goes through ftrace instead. The same programs as
fentry cost a fifth of that. Per round trip of one pair (latency), kprobes
add 1.6 to 2.1 µs to 15 to 16 µs, fentry 0.6 to 0.8 µs.

shawk pays per connection instead, `tcp_crr` on the busy host, against
19.0 µs and 18.8 µs per connection without hooks:

| variant | Rocky 9.8 | per run | Linux 6.8 | per run |
|---|---|---|---|---|
| shawk v0.8.0 | +1.63 µs (−7.6 % connections/s) | 0.16 µs per state change | +1.09 µs (−5.3 %) | 0.11 µs |
| kprobes per message | +1.20 µs | 0.23 µs | +0.89 µs | 0.17 µs |
| fentry per message | +1.24 µs | 0.24 µs | +0.92 µs | 0.18 µs |

Per message hooks run 5.2 times per connection here (one write and one read
on each side) and cost about as much as shawk's 10 state changes; with more
messages per connection they cost more, while shawk's cost stays per
connection, plus the walks, which cost nothing per message. The sandbox
had measured about 0.56 µs per state change; these VMs give 0.11 to
0.16 µs (bpf_stats: 133 to 140 ns per run).

**What option c would give.** Message counts, the edge weight the design
lacks (§3.1), and the traffic and RTT of every message rather than at the
walks. Its cost grows with the rate of messages: 100 000 messages a second
take 1.1 % of a CPU with fentry and 3 to 3.4 % with kprobes, a million take
11 % and 30 to 34 %. The paper kept its CPU overhead under 2.2 % at the
rates of its evaluation; on a host whose network service passes a million
small messages a second, the hook would cost a third of a CPU on arm64
without trampolines. A kprobe has no socket local storage either
(`bpf_sk_storage_get()` is given to tracing programs only), so the state of
a connection goes into a hash keyed by the address of the socket, which
must be deleted at close.

## 3. UDP: fentry, kprobes or cgroup_skb (item 2)

UDP is bundled per datagram in every design. CPU time per transaction of
`udp_rr` (4 datagram events) on the busy host, against 2.83 µs (Rocky) and
3.32 µs (6.8) without hooks:

| variant | Rocky 9.8: per datagram | throughput | Linux 6.8: per datagram | throughput |
|---|---|---|---|---|
| shawk v0.8.0 (fentry) | 0.16 µs | −18 % | 0.16 µs | −16 % |
| fentry, as shawk | 0.15 µs | −18 % | 0.16 µs | −16 % |
| fentry, empty | 0.01 µs | −3 % | 0.01 µs | −1 % |
| kprobes, as shawk | 0.29 µs | −29 % | 0.29 µs | −26 % |
| kprobes, empty | 0.13 µs | −16 % | 0.13 µs | −13 % |
| cgroup_skb | 0.06 µs | −8 % | 0.07 µs | −8 % |
| cgroup_skb, empty | 0.02 µs | −3 % | 0.01 µs | −2 % |

- **kprobes** do the same work at twice the cost on arm64, all of the
  difference being the breakpoint. They keep the direction of a socket in
  an LRU hash instead of socket local storage, which costs about as much
  (bpf_stats: 146 to 149 ns per run, against 128 to 139 ns with fentry).
  They need `CONFIG_KPROBES` (RHEL 9 and Ubuntu have it) and
  `perf_event_open`, as the conntrack kprobes do.
- **cgroup_skb** on the root cgroup is the cheapest: it reads the headers
  with `bpf_skb_load_bytes()` and has socket local storage. But it runs in
  the cgroup of the socket rather than in the task: the command and the
  process of a flow would be resolved from the cgroup in user space, which
  cannot tell apart the processes of one cgroup. It runs on every packet,
  TCP included (0.02 to 0.03 µs each, §2), counts a received datagram when
  it is delivered to the socket rather than when it is read, and sees a
  GSO or GRO packet once.

**Where fentry cannot attach.** Rocky Linux 9.8 attaches fentry on aarch64
and shawk v0.8.0 traces UDP there: the kernel changelog adds arm64 ftrace
direct calls in 5.14.0-621.el9 (RHEL-101598), a build of the 9.8 stream.
CI's 9.6 (5.14.0-570) cannot, nor can upstream arm64 before 6.0. On those
kprobes are the only hook of the three that keeps the process of a flow. A
fallback to kprobes costs nothing where fentry attaches; making them the
primary hook would double the cost everywhere on arm64.

## 4. The owner of accepted connections with a hook on accept (option b)

An accept hook sees the task that accepts a connection: its process,
command and cgroup. What `internal/tracer/owner.go` infers instead, rule by
rule:

| rule of owner.go | with a hook on `inet_csk_accept()` |
|---|---|
| holders of the listener, from owner scans | exact for the connections a process accepts after the agent started |
| programs sharing a port with `SO_REUSEPORT` are told apart by the cgroup of the accepted socket | exact, also within one cgroup (hot restarts of a proxy); the old and the new process usually have the same name anyway |
| socket activation: the service rather than systemd (PID 1) | exact with `Accept=no`; with `Accept=yes`, inetd and xinetd, the accepting task is systemd or inetd, which hands the connection to a process it starts: the rule stays |
| the parent rather than its workers | the worker that accepted (nginx, Apache, gunicorn, PHP-FPM): same command, cgroup and environment, so the same service |
| a replaced listener requests an owner scan | not needed for the connections accepted after the change |
| listeners of the kernel (nfsd, iSCSI targets) | a kernel thread of the subsystem; the test for sockets of the kernel stays, since they are named after their port (design §4.1) |

The hook does not see connections that are never accepted (closed in the
accept queue, or whose listener exits first, including Fast Open children
closed before accept), nor those accepted before the agent started: owner
scans and every rule above stay for them. The passive open is counted in
softirq at SYN_RECV→ESTABLISHED, before the accept, so the owner would also
arrive after the key was built: the connection would have to be counted at
accept (and at close for those never accepted) or its key rewritten.

A kretprobe reads only the return value, which the 6.10 change of the
parameters did not touch; but it has no socket local storage, so the owner
goes into a hash keyed by the address of the socket, which the state change
tracepoint looks up and deletes. fexit has socket local storage but must
declare the parameters: Rocky Linux 9.8 has those of 6.10 on its 5.14
kernel, so neither the version of the kernel nor the distribution predicts
them (`make compat` and `TestProgramPrototypes` would catch it).

Cost per connection of `tcp_crr` on the busy host: kretprobe +0.27 µs
(Rocky) and +0.02 µs (6.8), fexit +0.52 µs and +0.27 µs, within the noise
of 0.5 µs (bpf_stats: 160 to 231 ns per run).

## 5. Failure reasons (option b)

`fail_reason()` reads the error of a failed active open from `sk_err` at
SYN_SENT→CLOSE. A task that reads `SO_ERROR` takes the error from `sk_err`
without the socket lock. On kernels without `tcp_done_with_error()`, the
ICMP errors and timeouts report the error, which wakes the task, before
`tcp_done()`; with it, the error is still set before `tcp_done()`, and a
task that polls the socket meanwhile sees `POLLERR`. Resets set `sk_err`
before `tcp_done()` on every kernel. When the task wins, the fallback of
`fail_reason()` gives `timeout`.

The experiment ([setup.sh](../../../test/hookcost/setup.sh)) connects to a
network namespace behind a veth whose firewall answers port 9 with ICMP host
unreachable, port 10 with ICMP port unreachable, and port 12 with a reset;
the SYNs are delayed by 1 ms (netem), so that the answers arrive after
`connect(2)` returned, as from another host. Four threads connect over and
over for 10 s, about 30 000 to 39 000 attempts, waiting for each in poll(2)
asleep (as an event loop does) or spinning with a zero timeout (a client
that busy-polls). The port tells the true reason. Failures counted as
`timeout` by shawk v0.8.0, in two runs:

| | Rocky 9.8, poll | Rocky 9.8, spin | Linux 6.8, poll | Linux 6.8, spin |
|---|---|---|---|---|
| host unreachable | 0.03–0.04 % | 30–57 % | 0.01–0.02 % | 5–18 % |
| port unreachable | 0.03–0.05 % | 32–59 % | 0.02–0.03 % | 5–19 % |
| reset | 0 | 42–44 % | 0 | 50–52 % |

Connects that time out (port 11 dropped, 256 per kernel) were all counted
as `timeout`. Where other hooks saw the error, in the second run:

| hook | Rocky 9.8, spin | Linux 6.8, spin | poll, both |
|---|---|---|---|
| `sk_err` at SYN_SENT→CLOSE (shawk) | 40–50 % | 45–82 % | > 99.9 % |
| tracepoint `inet_sk_error_report` (after the wakeup; on 6.8 after the close) | 61–63 % of ICMP errors | — | |
| kprobe on `sk_error_report()` (before the wakeup) | 94 % of ICMP errors | — | |
| kprobe on `tcp_done_with_error()` (the error as a parameter) | — | 100 % | 100 % (6.8) |
| tracepoint `tcp_receive_reset`, kprobes on `ip_icmp_error()` and `ipv6_icmp_error()` | 100 % | 100 % | 100 % |

`tcp_reset()` fires `tcp_receive_reset` before it sets `sk_err`, and
`tcp_v4_err()`/`tcp_v6_err()` call `ip_icmp_error()`/`ipv6_icmp_error()`
with the error in SYN_SENT before they set it, also while the task holds
the socket (where the error goes to `sk_err_soft`). Those three hooks give
the reason exactly on every kernel; timeouts need none. They run on failed
connects only, so their cost does not matter. The tracepoint assumes no
signature; the kprobes read only the first three parameters (`sk`, `skb`,
`err`), which both kernels share (`make compat` and `TestProgramPrototypes`
would check them), and need no trampolines. Without socket local storage,
the kprobes keep the error in an LRU hash keyed by the socket, which the
state change tracepoint reads and deletes.

## 6. Questions of the issue

**What does (c) cost on a busy host compared with the in-kernel bundling
of the paper?** Option c is the bundling of the paper. On arm64 it costs
0.11 µs of CPU per message with fentry and 0.30 to 0.34 µs with kprobes:
11 to 12 % and 27 % of a saturated loopback request-response, against
nothing per message for option a, which pays 1.1 to 1.6 µs per connection
(§2). The cost grows with the message rate, where the paper's grew with the
number of services: a third of a CPU at a million messages a second with
kprobes.

**Does (b) remove enough of the owner rules and of the races in
`fail_reason()` to be worth depending on function signatures?** For owners,
no: every rule stays (§4). For failure reasons, the race is rare for
clients that sleep in poll(2) or epoll (0.01 to 0.05 % of ICMP failures)
but large for busy-polling ones, and exists on every kernel (§5). Hooks
that remove it exist with little dependence on signatures: a tracepoint and
two kprobes that read their first three parameters. That change is #166.

**With hooks on connect and accept, would iterators still be needed for
anything other than adopting connections that predate the agent and
reporting listeners?** Yes. Without hooks on messages, the walks are what
accounts the traffic, RTT and open connections of every connection between
its state changes, and `iter/task_file` finds the owners of adopted
connections, of MPTCP connections and of listeners. With hooks on messages
too, traffic and RTT could be taken per message, and open connections
counted in a map of live connections (as `xlat_conns` counts translations):
`iter/tcp` would then adopt and list listeners only, and its skips would
only delay adoption until a connection's next message. That is the design
option c rejects for its cost.

**Smaller items.**

- `perf_event_open` is allowed in `packaging/systemd/shawk-agent.service`
  since the conntrack kprobes (54de23f); a kprobe fallback for UDP or the
  hooks of §5 need nothing more. It stays.
- The conntrack kprobes need no change, as the issue says.
- Development environment: the VMs of this note (Lima on Apple silicon)
  run Rocky Linux 9 and Ubuntu on aarch64 with hardware virtualization,
  kprobes and trampolines. `setup.sh` and `run.sh` need root in the VM,
  or a binary with capabilities (see the comment of `main.go`).

## 7. What this does not cover

- **x86_64.** Only emulated x86_64 VMs (TCG) were available on this host,
  whose timings mean nothing. On x86_64 a kprobe at the entry of a function
  goes through ftrace (`CONFIG_KPROBES_ON_FTRACE`), so the gap between
  kprobes and fentry measured here on arm64 is expected to be smaller
  there; the order of the variants is not expected to change. The GitHub
  runners have KVM, where `run.sh` could run in a Rocky Linux 9 x86_64 VM.
- **RHEL 9.7 on aarch64**, between 9.6 without trampolines and 9.8 with
  them, was not checked.
- **Loopback.** Every packet is local, so the costs of both ends add up in
  one VM. On a network the same events happen, split between two hosts.
- **The client of the failure experiment** sometimes saw `POLLERR` and then
  no error in `SO_ERROR`, with the socket still in SYN_SENT; the port, not
  what the client read, tells the true reason.
