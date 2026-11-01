// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2026 Yuuki Tsubouchi */

/*
 * In-kernel flow bundling for discovering network service dependencies.
 *
 * TCP (tracepoint and iterators only; no hook on the data path)
 *   - tp_btf/inet_sock_set_state
 *       CLOSE -> SYN_SENT       active open. It runs inside connect(2), so the
 *                               current task is the client process. The
 *                               bundled flow key and the owner are kept in the
 *                               socket local storage.
 *       SYN_SENT -> ESTABLISHED counts an established outgoing connection.
 *       SYN_SENT -> CLOSE       counts a failed outgoing connection.
 *       SYN_RECV -> *           passive open; counts an incoming connection.
 *                               Its owner is the owner of the listening
 *                               socket, which user space resolves. On a
 *                               socket that went through SYN_SENT, it ends a
 *                               simultaneous open instead, e.g. of a socket
 *                               connected to itself.
 *       * -> CLOSE              accounts the remaining bytes.
 *   - iter/tcp periodically walks all TCP sockets. It accounts the byte
 *     deltas of long-lived connections from the cumulative counters kept in
 *     struct tcp_sock and adopts connections established before the tracer
 *     started.
 *   - iter/task_file resolves the owners of adopted connections and of
 *     listening sockets.
 *
 * UDP
 *   - fentry/ip_send_skb, fentry/ip6_send_skb and fentry/skb_consume_udp
 *     bundle datagrams in process context. The direction of a socket is
 *     decided by its first datagram (see udp_direction()).
 *
 * Bundled flows are written into one of two hash maps. User space flips the
 * active map at every interval and drains the inactive one, so that no
 * update is lost while reading.
 */

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

#include "shawk.h"

/*
 * The kernel rejects programs without a GPL-compatible license when they use
 * GPL-only helpers such as bpf_probe_read_kernel() and bpf_seq_write(), or
 * kernel types such as struct bpf_iter_meta. This file is dual-licensed so
 * that its object can also be distributed with the Apache-2.0 user space.
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10
#define EEXIST 17
#define SOCK_DGRAM 2
#define SOCK_BINDPORT_LOCK 8
/*
 * SKB_GSO_UDP_L4 of the anonymous enum of GSO types, unchanged since Linux
 * 4.18; an anonymous enum cannot be relocated.
 */
#define GSO_UDP_L4 (1U << 17)

/* TCP states in which the FIN of the local side is queued. */
#define TCPF_FIN_QUEUED                                                    \
	((1U << TCP_FIN_WAIT1) | (1U << TCP_FIN_WAIT2) | (1U << TCP_CLOSING) | \
	 (1U << TCP_LAST_ACK))

/* Flags of struct shawk_sock_state. */
#define SS_READY (1U << 0)   /* the key is complete and traffic is accounted */
#define SS_COUNTED (1U << 1) /* the connection has been counted in conns */
#define SS_IGNORE (1U << 2)  /* owned by the tracer itself */
/*
 * An additional subflow of an MPTCP connection (MP_JOIN). The connection is
 * counted by its first subflow, so it counts no connection or failed
 * attempt.
 */
#define SS_JOIN (1U << 3)

#define IPPROTO_MPTCP_ 262

#define MAX_FLOWS 16384 /* overridden by user space */

/* Configuration set by user space before loading. */
const volatile bool learn_self = true; /* false to trace the tracer itself */
const volatile __u32 target_netns = 0; /* 0 means all network namespaces */
const volatile __u16 eph_port_low = 32768;
const volatile __u16 eph_port_high = 60999;

/* Runtime state shared with user space. */
volatile __u32 active_idx = 0;
/*
 * Set by user space during the walk of the sockets that exist at startup.
 * That walk only adopts connections and marks UDP server sockets: the
 * traffic of sockets the tracepoint already saw is accounted from the walk
 * of the first interval, so that it is not counted twice.
 */
volatile __u32 initial_scan = 0;
/*
 * The global thread group id of the tracer, learned by the iterators, which
 * run in the context of the process reading them. os.Getpid() would differ
 * when the tracer runs in a PID namespace.
 */
volatile __u32 self_tgid = 0xffffffff;
/* Incremented by user space before each walk of iter/task_file. */
volatile __u32 owner_scan = 0;
/* Flow updates dropped because the flow table was full. */
__u64 flow_drops = 0;
/*
 * TCP connections opened without socket storage, which the next walk adopts:
 * their connection and the traffic until then are not counted.
 */
__u64 storage_fails = 0;
/*
 * Connections waiting for iter/task_file to find their owner: connections
 * adopted at startup, and subflows of MPTCP connections whose owner is not
 * known yet. An increase makes user space walk the processes.
 */
__u64 adopted_unowned = 0;
/* Listening ports that did not fit in listen_ports or udp_listen_ports. */
__u64 listen_port_drops = 0;

/* Per-socket state attached to TCP sockets. */
struct shawk_sock_state {
	struct shawk_flow_key key;
	__u64 sent_base; /* tcp_sock.bytes_acked already accounted */
	__u64 recv_base; /* tcp_sock.bytes_received already accounted */
	__u32 retrans_base;
	__u32 pid;
	__u32 flags;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shawk_sock_state);
} sock_states SEC(".maps");

struct shawk_flow_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FLOWS);
	__type(key, struct shawk_flow_key);
	__type(value, struct shawk_flow_stats);
} flows_0 SEC(".maps"), flows_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct shawk_flow_map);
} flows SEC(".maps") = {
	.values = {&flows_0, &flows_1},
};

struct shawk_listen_key {
	__u32 netns;
	__u16 port;
	__u16 _pad;
};

/*
 * Listening TCP ports, rebuilt by iter/tcp at every scan. The capacity of
 * both port maps is set by user space.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct shawk_listen_key);
	__type(value, __u8);
} listen_ports SEC(".maps");

/* UDP server ports, rebuilt by iter/udp at every scan. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct shawk_listen_key);
	__type(value, __u8);
} udp_listen_ports SEC(".maps");

/* Direction of a UDP socket, decided by its first datagram. */
struct shawk_udp_state {
	__u32 dir;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shawk_udp_state);
} udp_states SEC(".maps");

/* The process an MPTCP connection belongs to. */
struct shawk_owner {
	char comm[TASK_COMM_LEN];
	__u64 cgroup_id;
	__u32 pid;
	__u32 scan; /* owner_scan when it was recorded */
};

/*
 * Owners of MPTCP connections by the address of their MPTCP socket, which
 * the TCP subflows point to. A subflow has no file, and on kernels before
 * 5.19 (bpf_skc_to_mptcp_sock) a program cannot reach the MPTCP socket of a
 * subflow as a socket, only read its address; so the owner is looked up by
 * that address. It is recorded when the first subflow connects, in the
 * process that called connect(2), and by iter/task_file for the MPTCP
 * sockets that processes hold, once per walk: an entry left by a former
 * socket at the same address is replaced by the next walk. Entries are
 * removed when the MPTCP socket closes; the least recently used are
 * evicted when the map is full. Its capacity is set by user space.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct shawk_owner);
} mptcp_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} cgroup_events SEC(".maps");

__u64 cgroup_event_drops = 0;

/* Make bpf2go emit Go types for the records read by user space. */
const struct shawk_iter_rec *unused_iter_rec __attribute__((unused));
const struct shawk_cgroup_event *unused_cgroup_event __attribute__((unused));

static __always_inline void learn_self_tgid(void)
{
	if (learn_self)
		self_tgid = bpf_get_current_pid_tgid() >> 32;
}

static __always_inline bool netns_ok(__u32 netns)
{
	return target_netns == 0 || target_netns == netns;
}

static __always_inline bool ephemeral(__u16 port)
{
	return port >= eph_port_low && port <= eph_port_high;
}

static __always_inline __u32 sock_netns(const struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline void v4mapped(__u8 *dst, __be32 addr)
{
	__builtin_memset(dst, 0, 10);
	dst[10] = 0xff;
	dst[11] = 0xff;
	__builtin_memcpy(dst + 12, &addr, 4);
}

/* Reads the local and remote addresses of a socket. */
static __always_inline int read_sock_addrs(const struct sock *sk, __u8 *laddr,
					   __u8 *raddr)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family == AF_INET) {
		v4mapped(laddr, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
		v4mapped(raddr, BPF_CORE_READ(sk, __sk_common.skc_daddr));
		return 0;
	}
	if (family == AF_INET6) {
		BPF_CORE_READ_INTO((struct in6_addr *)laddr, sk,
				   __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO((struct in6_addr *)raddr, sk,
				   __sk_common.skc_v6_daddr);
		return 0;
	}
	return -1;
}

static __always_inline int read_local_addr(const struct sock *sk, __u8 *laddr)
{
	__u8 raddr[16];

	return read_sock_addrs(sk, laddr, raddr);
}

/* Fills the addresses, port and protocol of a TCP flow key. */
static __always_inline int build_tcp_key(struct shawk_flow_key *key,
					 const struct sock *sk, __u8 direction)
{
	if (read_sock_addrs(sk, key->laddr, key->raddr))
		return -1;
	key->netns = sock_netns(sk);
	key->proto = IPPROTO_TCP;
	key->direction = direction;
	/*
	 * The local port of a socket that closes is already released (skc_num
	 * is zero) when the state change tracepoint runs, but not inet_sport.
	 */
	if (direction == DIR_IN)
		key->port = bpf_ntohs(BPF_CORE_READ((struct inet_sock *)sk, inet_sport));
	else
		key->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	return 0;
}

/*
 * Records the current process as the owner. The command name is taken from
 * the thread group leader because applications often name their threads
 * individually.
 */
static __always_inline void set_current_owner(struct shawk_flow_key *key)
{
	struct task_struct *task = bpf_get_current_task_btf();

	key->cgroup_id = bpf_get_current_cgroup_id();
	BPF_CORE_READ_STR_INTO(&key->comm, task, group_leader, comm);
}

static __always_inline void set_kernel_owner(struct shawk_flow_key *key)
{
	key->cgroup_id = 0;
	__builtin_memset(key->comm, 0, sizeof(key->comm));
	__builtin_memcpy(key->comm, KERNEL_COMM, sizeof(KERNEL_COMM));
}

/*
 * Gives a subflow the owner of its MPTCP connection. Returns the flags that
 * make it ready.
 */
static __always_inline __u32 set_mptcp_owner(struct shawk_flow_key *key,
					     __u32 *pid,
					     const struct shawk_owner *o)
{
	key->cgroup_id = o->cgroup_id;
	__builtin_memcpy(key->comm, o->comm, sizeof(key->comm));
	*pid = o->pid;
	return SS_READY | (o->pid == self_tgid ? SS_IGNORE : 0);
}

/*
 * Returns the address of the MPTCP socket that a TCP socket is a subflow
 * of, or zero for a plain TCP socket. join tells an additional subflow
 * (MP_JOIN) from the first one: request_join is set before an additional
 * subflow connects, and mp_join on both sides once it is established.
 * Kernels without MPTCP have no is_mptcp. A child of an MPTCP listener for a
 * client without MPTCP falls back to plain TCP, which clears is_mptcp.
 */
static __always_inline __u64 subflow_msk(struct sock *sk, bool *join)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct mptcp_subflow_context *ctx;

	*join = false;
	if (!bpf_core_field_exists(tp->is_mptcp) || !BPF_CORE_READ(tp, is_mptcp))
		return 0;
	ctx = BPF_CORE_READ((struct inet_connection_sock *)sk, icsk_ulp_data);
	if (!ctx)
		return 0;
	*join = BPF_CORE_READ_BITFIELD_PROBED(ctx, request_join) ||
		BPF_CORE_READ_BITFIELD_PROBED(ctx, mp_join);
	return (__u64)BPF_CORE_READ(ctx, conn);
}

/*
 * Whether a subflow is the one that counts its MPTCP connection as open:
 * the first of the subflows of the connection, usually the initial one,
 * and another once the initial one closed while others carry on.
 */
static __always_inline bool subflow_counts_open(struct sock *sk, __u64 msk)
{
	struct mptcp_sock *m = (struct mptcp_sock *)msk;
	struct mptcp_subflow_context *ctx;
	struct list_head *head;

	head = BPF_CORE_READ(m, conn_list.next);
	if (!head || head == (void *)msk + bpf_core_field_offset(m->conn_list))
		return false;
	ctx = (void *)head -
	      bpf_core_field_offset(((struct mptcp_subflow_context *)0)->node);
	return BPF_CORE_READ(ctx, tcp_sock) == sk;
}

/* syn_smc of struct tcp_sock, with CONFIG_SMC only. */
struct tcp_sock___smc {
	bool syn_smc;
} __attribute__((preserve_access_index));

/*
 * Whether a socket that connects, or sends a datagram, is opened and held
 * by the kernel itself, e.g. by the clients of NFS, iSCSI, CIFS or Ceph,
 * which connect in a kernel worker or in the process that happens to mount.
 * No process holds such a socket, though it may have a file: the NFS client
 * gives its sockets one. An orphan, closed by its process, has no struct
 * socket.
 *
 * The kernel also creates TCP sockets on behalf of processes: the subflows
 * of MPTCP, which the callers exclude, since they belong to the process
 * holding their MPTCP socket, and the TCP socket of an SMC socket, which
 * sends an SMC option in its SYN (syn_smc) and connects in connect(2) of
 * the process. The callers also exclude the children of listeners, which
 * inherit sk_kern_sock: the children of an MPTCP listener for clients
 * without MPTCP are plain TCP sockets accepted by a process, which inherit
 * it from the first subflow of the listener.
 */
static __always_inline bool kernel_owned(struct sock *sk)
{
	struct tcp_sock___smc *tp = (void *)sk;

	if (!BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock) ||
	    !BPF_CORE_READ(sk, sk_socket))
		return false;
	if (BPF_CORE_READ(sk, sk_protocol) == IPPROTO_TCP &&
	    bpf_core_field_exists(tp->syn_smc) &&
	    BPF_CORE_READ_BITFIELD_PROBED(tp, syn_smc))
		return false;
	return true;
}

/*
 * Whether a listening socket may be the kernel's: one the kernel created,
 * other than the first subflow of an MPTCP listener, one without a file,
 * which no process can hold, or one the kernel uses, such as a socket that
 * rpc.nfsd created and passed to nfsd. User space takes it for the
 * kernel's only if no process holds it either (see Tracer.listenerOwners).
 */
static __always_inline bool kernel_listener(struct sock *sk, __u8 proto,
					    __u64 ino)
{
	bool join;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock) &&
	    (proto != IPPROTO_TCP || !subflow_msk(sk, &join)))
		return true;
	return !ino || BPF_CORE_READ(sk, sk_user_data);
}

/*
 * Records the owner of an MPTCP connection, replacing that of a former
 * socket at the same address.
 */
static __always_inline void record_mptcp_owner(__u64 msk,
					       const struct shawk_flow_key *key,
					       __u32 pid)
{
	struct shawk_owner o = {};

	__builtin_memcpy(o.comm, key->comm, sizeof(o.comm));
	o.cgroup_id = key->cgroup_id;
	o.pid = pid;
	o.scan = owner_scan;
	bpf_map_update_elem(&mptcp_owners, &msk, &o, BPF_ANY);
}

/*
 * Returns the id of the cgroup v2 a socket belongs to: that of the process
 * that created it, which an accepted socket inherits from its listener.
 * Kernels before 5.15 store the cgroup in a tagged union instead; there the
 * owner is left to user space.
 */
static __always_inline __u64 sock_cgroup_id(const struct sock *sk)
{
	struct cgroup *cg;

	if (!bpf_core_field_exists(sk->sk_cgrp_data.cgroup))
		return 0;
	cg = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
	if (!cg)
		return 0;
	return BPF_CORE_READ(cg, kn, id);
}

static __always_inline __u64 task_cgroup_id(struct task_struct *task)
{
	return BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
}

/* Looks up or creates the bundled flow in the active map. */
static __always_inline struct shawk_flow_stats *
flow_get(const struct shawk_flow_key *k)
{
	struct shawk_flow_stats zero = {};
	struct shawk_flow_key key;
	struct shawk_flow_stats *fs;
	__u32 idx = active_idx & 1;
	void *map;
	long err;

	__builtin_memcpy(&key, k, sizeof(key));
	map = bpf_map_lookup_elem(&flows, &idx);
	if (!map)
		return NULL;
	fs = bpf_map_lookup_elem(map, &key);
	if (fs)
		return fs;
	err = bpf_map_update_elem(map, &key, &zero, BPF_NOEXIST);
	if (err && err != -EEXIST) {
		__sync_fetch_and_add(&flow_drops, 1);
		return NULL;
	}
	return bpf_map_lookup_elem(map, &key);
}

/* Cumulative counters of a TCP connection. */
struct shawk_tcp_counters {
	__u64 sent; /* bytes of data acknowledged by the peer */
	__u64 recv; /* bytes of data received */
	__u32 retrans;
};

/*
 * Reads the cumulative counters of a TCP connection. bytes_acked and
 * bytes_received count sequence numbers, which include the FIN of each side
 * once it is acknowledged or received; it is not data and is subtracted.
 * Each adjustment applies from the moment its FIN is counted on, so the
 * counters never decrease. state is the state of the socket, which is still
 * the old state in the state change tracepoint.
 */
static __always_inline void read_tcp_counters(struct sock *sk,
					      struct tcp_sock *tp, int state,
					      struct shawk_tcp_counters *c)
{
	c->sent = BPF_CORE_READ(tp, bytes_acked);
	c->recv = BPF_CORE_READ(tp, bytes_received);
	c->retrans = BPF_CORE_READ(tp, total_retrans);
	/*
	 * tcp_fin() sets SOCK_DONE when it receives the FIN of the peer. A
	 * listener drops a SYN with a FIN, so the FIN always counts.
	 */
	if (c->recv &&
	    (BPF_CORE_READ(sk, __sk_common.skc_flags) & (1UL << SOCK_DONE)))
		c->recv--;
	/* The local FIN is the last sequence number of the send queue. */
	if (c->sent && ((1U << state) & TCPF_FIN_QUEUED) &&
	    BPF_CORE_READ(tp, snd_una) == BPF_CORE_READ(tp, write_seq))
		c->sent--;
}

/*
 * Takes the traffic of a TCP connection since the last call, by comparing
 * its cumulative counters with the bases kept in the socket storage, and
 * advances the bases. Returns whether there was any.
 *
 * The bases are updated without atomic exchange, which the arm64 JIT only
 * supports since Linux 5.18; atomic adds are supported everywhere. The
 * iterator and the state change tracepoint do not interleave on a socket on
 * kernels whose TCP iterator locks each socket (Linux 5.19+, and RHEL 9 by
 * backport). On older kernels, the bytes of a connection that closes during
 * a scan may rarely be counted twice.
 */
static __always_inline bool take_tcp_delta(struct shawk_sock_state *ss,
					   struct sock *sk, struct tcp_sock *tp,
					   int state,
					   struct shawk_tcp_counters *d)
{
	struct shawk_tcp_counters c;

	read_tcp_counters(sk, tp, state, &c);
	d->sent = 0;
	d->recv = 0;
	d->retrans = 0;
	if (c.sent > ss->sent_base) {
		d->sent = c.sent - ss->sent_base;
		ss->sent_base = c.sent;
	}
	if (c.recv > ss->recv_base) {
		d->recv = c.recv - ss->recv_base;
		ss->recv_base = c.recv;
	}
	if (c.retrans > ss->retrans_base) {
		d->retrans = c.retrans - ss->retrans_base;
		ss->retrans_base = c.retrans;
	}
	return d->sent || d->recv || d->retrans;
}

static __always_inline void add_tcp_delta(struct shawk_flow_stats *fs,
					  const struct shawk_tcp_counters *d)
{
	if (d->sent)
		__sync_fetch_and_add(&fs->bytes_sent, d->sent);
	if (d->recv)
		__sync_fetch_and_add(&fs->bytes_recv, d->recv);
	if (d->retrans)
		__sync_fetch_and_add(&fs->retrans, d->retrans);
}

/*
 * Sets the current counters as the bases, so that only the traffic from now
 * on is accounted.
 */
static __always_inline void reset_base(struct shawk_sock_state *ss,
				       struct sock *sk, struct tcp_sock *tp,
				       int state)
{
	struct shawk_tcp_counters c;

	read_tcp_counters(sk, tp, state, &c);
	ss->sent_base = c.sent;
	ss->recv_base = c.recv;
	ss->retrans_base = c.retrans;
}

/*
 * Sets the bases when a connection is established. bytes_received counts no
 * SYN. bytes_acked counts the local SYN on an active open only: the child of
 * a listener starts with its SYN-ACK acknowledged. What the counters hold
 * beyond that is data, e.g. carried by the SYN with TCP Fast Open.
 */
static __always_inline void established_base(struct shawk_sock_state *ss,
					     struct tcp_sock *tp, bool active)
{
	ss->sent_base = active && BPF_CORE_READ(tp, bytes_acked) ? 1 : 0;
	ss->recv_base = 0;
	ss->retrans_base = BPF_CORE_READ(tp, total_retrans);
}

static __always_inline bool ss_ready(const struct shawk_sock_state *ss)
{
	return (ss->flags & (SS_READY | SS_IGNORE)) == SS_READY;
}

static __always_inline void count_conn(struct shawk_sock_state *ss)
{
	struct shawk_flow_stats *fs;

	if (ss->flags & SS_COUNTED)
		return;
	ss->flags |= SS_COUNTED;
	fs = flow_get(&ss->key);
	if (fs) {
		__sync_fetch_and_add(&fs->conns, 1);
		if (ss->pid)
			fs->pid = ss->pid;
	}
}

/*
 * Gives a subflow of the MPTCP socket msk that waits for its owner the
 * owner of its connection, once iter/task_file recorded it. Returns whether
 * it is ready.
 */
static __always_inline bool resolve_subflow(struct shawk_sock_state *ss,
					    __u64 msk)
{
	struct shawk_owner *o;

	if (msk && !(ss->flags & (SS_READY | SS_IGNORE))) {
		o = bpf_map_lookup_elem(&mptcp_owners, &msk);
		if (o)
			ss->flags |= set_mptcp_owner(&ss->key, &ss->pid, o);
	}
	return ss_ready(ss);
}

/* ---------------------------------------------------------------- TCP --- */

/*
 * CLOSE -> SYN_SENT: called in connect(2) by the client process, except for
 * sockets of the kernel, which may connect in a kernel worker or in any
 * process, and for the additional subflows of MPTCP connections, which the
 * path manager opens in a kernel worker. Both are given their owner
 * instead of the current task.
 */
static __always_inline void on_active_open(struct sock *sk)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	struct shawk_owner *o;
	__u32 flags = SS_READY;
	bool join;
	__u64 msk;

	if (build_tcp_key(&key, sk, DIR_OUT))
		return;
	if (!netns_ok(key.netns))
		return;
	msk = subflow_msk(sk, &join);
	if (msk && join) {
		/*
		 * Without a known owner, the subflow waits for iter/tcp to find
		 * it in mptcp_owners once iter/task_file recorded it.
		 */
		flags = SS_COUNTED | SS_JOIN;
		tgid = 0;
		o = bpf_map_lookup_elem(&mptcp_owners, &msk);
		if (o)
			flags |= set_mptcp_owner(&key, &tgid, o);
		else
			__sync_fetch_and_add(&adopted_unowned, 1);
	} else if (!msk && kernel_owned(sk)) {
		set_kernel_owner(&key);
		tgid = 0;
	} else {
		set_current_owner(&key);
		if (msk)
			record_mptcp_owner(msk, &key, tgid);
	}

	ss = bpf_sk_storage_get(&sock_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss) {
		__sync_fetch_and_add(&storage_fails, 1);
		return;
	}
	ss->key = key;
	ss->sent_base = 0;
	ss->recv_base = 0;
	ss->retrans_base = 0;
	ss->pid = tgid;
	ss->flags = flags | (tgid == self_tgid ? SS_IGNORE : 0);
}

/*
 * Whether a child of a listener that leaves SYN_RECV for another state than
 * ESTABLISHED was a connection: a child created by a TCP Fast Open SYN is
 * accepted at once and may be closed by the server before the handshake
 * completes (FIN_WAIT1), or reset or timed out (CLOSE). Other children leave
 * SYN_RECV for CLOSE only when they fail to be created, e.g. without a route
 * to the client or when two CPUs complete the same request, and were never
 * established. A Fast Open child still has its request, except when reset,
 * which removes it first; one that carried data has syn_data_acked.
 */
static __always_inline bool fastopen_child(struct sock *sk)
{
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);

	if (!tp)
		return false;
	return BPF_CORE_READ(tp, fastopen_rsk) ||
	       BPF_CORE_READ_BITFIELD_PROBED(tp, syn_data_acked);
}

/*
 * A child socket of a listener leaves SYN_RECV: usually for ESTABLISHED, or
 * for another state for a TCP Fast Open child (see fastopen_child()).
 * Returns the storage of the socket.
 */
static __always_inline struct shawk_sock_state *on_passive_open(struct sock *sk)
{
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	struct tcp_sock *tp;
	bool join;

	if (build_tcp_key(&key, sk, DIR_IN))
		return NULL;
	if (!netns_ok(key.netns))
		return NULL;
	/*
	 * The cgroup tells apart different programs sharing a port with
	 * SO_REUSEPORT; user space resolves the command name.
	 */
	key.cgroup_id = sock_cgroup_id(sk);

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return NULL;
	ss = bpf_sk_storage_get(&sock_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss) {
		__sync_fetch_and_add(&storage_fails, 1);
		return NULL;
	}
	ss->key = key;
	established_base(ss, tp, false);
	ss->pid = 0;
	ss->flags = SS_READY;
	/* An additional MPTCP subflow is not another connection. */
	if (subflow_msk(sk, &join) && join)
		ss->flags |= SS_COUNTED | SS_JOIN;
	count_conn(ss);
	return ss;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(shawk_inet_sock_set_state, const struct sock *csk, int oldstate,
	     int newstate)
{
	struct sock *sk = (struct sock *)csk;
	struct shawk_tcp_counters d;
	struct shawk_sock_state *ss;
	struct shawk_flow_stats *fs;
	struct tcp_sock *tp;
	__u16 proto;
	bool join;
	__u64 msk;

	proto = BPF_CORE_READ(sk, sk_protocol);
	if (proto == IPPROTO_MPTCP_) {
		if (newstate == TCP_CLOSE) {
			msk = (__u64)sk;
			bpf_map_delete_elem(&mptcp_owners, &msk);
		}
		return 0;
	}
	if (proto != IPPROTO_TCP)
		return 0;

	if (newstate == TCP_SYN_SENT) {
		on_active_open(sk);
		return 0;
	}

	ss = bpf_sk_storage_get(&sock_states, sk, NULL, 0);
	/*
	 * The children of a listener have no storage yet, since sock_states is
	 * not cloned. A socket with an outgoing key went through SYN_SENT and
	 * ends a simultaneous open, e.g. a socket connected to itself. A child
	 * that is closed at once accounts its data below.
	 */
	if (oldstate == TCP_SYN_RECV && (!ss || ss->key.direction != DIR_OUT)) {
		if (newstate != TCP_ESTABLISHED && !fastopen_child(sk))
			return 0;
		ss = on_passive_open(sk);
		if (!ss || newstate != TCP_CLOSE)
			return 0;
	} else if (!ss || (ss->flags & SS_IGNORE) ||
		   !(ss->flags & (SS_READY | SS_JOIN))) {
		return 0;
	} else if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV) {
		/*
		 * Also for an MPTCP subflow whose owner is not known yet, so that
		 * its bases are set once its owner is found. Such a subflow is
		 * SS_COUNTED and counts no connection.
		 */
		if (ss->key.direction != DIR_OUT)
			return 0;
		if (newstate == TCP_ESTABLISHED) {
			tp = bpf_skc_to_tcp_sock(sk);
			if (!tp)
				return 0;
			/* The local address is final once established. */
			read_sock_addrs(sk, ss->key.laddr, ss->key.raddr);
			established_base(ss, tp, true);
			count_conn(ss);
		} else if (newstate == TCP_CLOSE && !(ss->flags & SS_JOIN)) {
			fs = flow_get(&ss->key);
			if (fs) {
				__sync_fetch_and_add(&fs->conn_fails, 1);
				fs->pid = ss->pid;
			}
		}
		return 0;
	} else if (!ss_ready(ss)) {
		/* A subflow closing before the next walk found its owner. */
		if (newstate != TCP_CLOSE ||
		    !resolve_subflow(ss, subflow_msk(sk, &join)))
			return 0;
	}

	if (newstate != TCP_CLOSE)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return 0;
	/*
	 * A connection whose traffic the last walk accounted, e.g. one reset
	 * since, adds nothing: no empty flow is created.
	 */
	if (!take_tcp_delta(ss, sk, tp, oldstate, &d))
		return 0;
	fs = flow_get(&ss->key);
	if (fs) {
		add_tcp_delta(fs, &d);
		if (ss->pid)
			fs->pid = ss->pid;
	}
	return 0;
}

static __always_inline void emit_listener(struct seq_file *seq,
					  const struct sock *sk, __u32 netns,
					  __u16 port, __u8 proto)
{
	struct shawk_iter_rec rec = {};

	if (read_local_addr(sk, rec.addr))
		return;
	rec.type = REC_LISTENER;
	rec.proto = proto;
	rec.netns = netns;
	rec.port = port;
	/* Zero when the socket has no file. */
	rec.ino = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
	if (kernel_listener((struct sock *)sk, proto, rec.ino))
		__builtin_memcpy(rec.comm, KERNEL_COMM, sizeof(KERNEL_COMM));
	bpf_seq_write(seq, &rec, sizeof(rec));
}

/*
 * Returns the direction of a connection established before the tracer
 * started, and whether its local port is listening.
 *
 * A connection whose port nothing listens on may still have been accepted:
 * by a listener that is gone (a server draining its connections after a
 * graceful restart, an FTP data connection) or, with TPROXY, on another port
 * than the listener's. listen(2) sets sk_max_ack_backlog, and the
 * connections a listener accepts are clones of it that keep it
 * (sk_clone_lock() copies the socket and never resets it), while a socket
 * that connects never listened. Ports and ranges cannot tell: a client may
 * bind any port before connecting, and a server may listen anywhere.
 */
static __always_inline __u8 adopted_direction(struct sock *sk, __u32 netns,
					      __u16 lport, bool *listening)
{
	struct shawk_listen_key lk = {.netns = netns, .port = lport};

	*listening = bpf_map_lookup_elem(&listen_ports, &lk) != NULL;
	if (*listening || BPF_CORE_READ(sk, sk_max_ack_backlog))
		return DIR_IN;
	return DIR_OUT;
}

/* Starts tracking a connection established before the tracer started. */
static __always_inline void adopt_tcp(struct tcp_sock *tp, struct sock *sk,
				      __u32 netns, __u16 lport, int state)
{
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	struct shawk_owner *o;
	__u32 flags = SS_COUNTED;
	bool listening, join;
	__u32 pid = 0;
	__u64 msk;
	__u8 dir;

	dir = adopted_direction(sk, netns, lport, &listening);
	if (build_tcp_key(&key, sk, dir))
		return;
	if (dir == DIR_IN)
		key.cgroup_id = sock_cgroup_id(sk);
	msk = subflow_msk(sk, &join);
	if (msk && join)
		flags |= SS_JOIN;
	/*
	 * Connections accepted by a listener belong to its owner, which user
	 * space resolves, and outgoing sockets of the kernel to the kernel.
	 * The subflows of MPTCP connections belong to the owner of the
	 * connection, and the others to the process holding them; both wait
	 * for iter/task_file to find it.
	 */
	if (listening) {
		flags |= SS_READY;
	} else if (msk) {
		o = bpf_map_lookup_elem(&mptcp_owners, &msk);
		if (o)
			flags |= set_mptcp_owner(&key, &pid, o);
	} else if (dir == DIR_OUT && kernel_owned(sk)) {
		set_kernel_owner(&key);
		flags |= SS_READY;
	}
	ss = bpf_sk_storage_get(&sock_states, tp, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	/* Only traffic after the adoption is accounted. */
	reset_base(ss, sk, tp, state);
	ss->pid = pid;
	ss->flags = flags;
	if (!(flags & SS_READY))
		__sync_fetch_and_add(&adopted_unowned, 1);
}

/*
 * Walks all TCP sockets. Listening sockets come before established ones in
 * the walk, so listen_ports is complete when adopting connections.
 */
SEC("iter/tcp")
int shawk_iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct shawk_sock_state *ss;
	struct shawk_flow_stats *fs;
	struct shawk_tcp_counters d;
	struct tcp_sock *tp;
	struct sock *sk;
	__u16 family, lport;
	__u32 netns, srtt;
	bool join;
	__u64 msk;
	__u8 state;

	learn_self_tgid();
	if (!skc)
		return 0;
	family = BPF_CORE_READ(skc, skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	sk = (struct sock *)skc;
	netns = sock_netns(sk);
	if (!netns_ok(netns))
		return 0;
	state = BPF_CORE_READ(skc, skc_state);
	lport = BPF_CORE_READ(skc, skc_num);

	if (state == TCP_LISTEN) {
		struct shawk_listen_key lk = {.netns = netns, .port = lport};
		__u8 one = 1;

		if (bpf_map_update_elem(&listen_ports, &lk, &one, BPF_ANY))
			__sync_fetch_and_add(&listen_port_drops, 1);
		emit_listener(seq, sk, netns, lport, IPPROTO_TCP);
		return 0;
	}

	/* Skips time-wait and request sockets, which are not full sockets. */
	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		return 0;
	if (state == TCP_SYN_SENT || state == TCP_SYN_RECV ||
	    state == TCP_CLOSE)
		return 0;

	ss = bpf_sk_storage_get(&sock_states, tp, NULL, 0);
	if (!ss) {
		adopt_tcp(tp, sk, netns, lport, state);
		return 0;
	}
	msk = subflow_msk(sk, &join);
	if (!resolve_subflow(ss, msk) || initial_scan)
		return 0;

	fs = flow_get(&ss->key);
	if (!fs)
		return 0;
	if (take_tcp_delta(ss, sk, tp, state, &d))
		add_tcp_delta(fs, &d);
	/* An MPTCP connection is open once, whatever its subflows. */
	if (!msk || subflow_counts_open(sk, msk))
		__sync_fetch_and_add(&fs->open_conns, 1);
	srtt = BPF_CORE_READ(tp, srtt_us) >> 3;
	if (srtt) {
		__sync_fetch_and_add(&fs->rtt_sum_us, srtt);
		__sync_fetch_and_add(&fs->rtt_samples, 1);
	}
	if (!fs->pid && ss->pid)
		fs->pid = ss->pid;
	return 0;
}

/* ---------------------------------------------------------------- UDP --- */

static __always_inline bool port_bound(const struct sock *sk)
{
	__u8 locks = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_userlocks);

	return locks & SOCK_BINDPORT_LOCK;
}

/*
 * The direction of a UDP socket is decided by its first datagram: a socket
 * that receives first is a server and one that sends first is a client.
 * Ports cannot tell them apart: resolvers bind random source ports anywhere
 * in 1024-65535 and servers may listen in the ephemeral range.
 *
 * A socket that sends first is still a server when it uses the port of a
 * known server socket, e.g. the per-client connected sockets of a QUIC
 * server. Server sockets that existed before the tracer started are marked
 * by iter/udp at startup.
 */
static __always_inline __u32 udp_direction(struct sock *sk, __u32 netns,
					   __u16 lport, bool sending)
{
	struct shawk_listen_key lk = {.netns = netns, .port = lport};
	struct shawk_udp_state *us;
	__u32 dir = DIR_IN;

	us = bpf_sk_storage_get(&udp_states, sk, NULL, 0);
	if (us)
		return us->dir;
	if (sending && !bpf_map_lookup_elem(&udp_listen_ports, &lk))
		dir = DIR_OUT;
	us = bpf_sk_storage_get(&udp_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (us)
		us->dir = dir;
	return dir;
}

/* Whether a UDP socket is an unconnected server socket worth listing. */
static __always_inline bool udp_listener(struct sock *sk, __u16 port)
{
	struct shawk_udp_state *us;

	if (!port || BPF_CORE_READ(sk, __sk_common.skc_dport))
		return false;
	us = bpf_sk_storage_get(&udp_states, sk, NULL, 0);
	if (us)
		return us->dir == DIR_IN;
	/* Idle since the tracer started: trust an explicitly bound port. */
	return port_bound(sk) && !ephemeral(port);
}

/*
 * Sets the owner of a UDP flow: the kernel for its own sockets, e.g. of the
 * NFS client or lockd, which send from kernel threads, else the current
 * process. Returns the process id, zero for the kernel.
 */
static __always_inline __u32 set_udp_owner(struct shawk_flow_key *key,
					   struct sock *sk, __u32 tgid)
{
	if (kernel_owned(sk)) {
		set_kernel_owner(key);
		return 0;
	}
	set_current_owner(key);
	return tgid;
}

/* Raw sockets of protocol 17 also send through ip_send_skb(). */
static __always_inline bool is_udp_sock(const struct sock *sk)
{
	return BPF_CORE_READ(sk, sk_protocol) == IPPROTO_UDP &&
	       BPF_CORE_READ(sk, sk_type) == SOCK_DGRAM;
}

struct shawk_l3l4 {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 ulen;
};

/*
 * Reads addresses and ports of a UDP datagram from its headers. The callers
 * have checked that the socket is a UDP socket, so the transport header is
 * the UDP header, also after IPv6 extension headers or IPv4 options.
 */
static __always_inline int read_udp_headers(struct sk_buff *skb,
					    struct shawk_l3l4 *h)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh = BPF_CORE_READ(skb, network_header);
	__u16 th = BPF_CORE_READ(skb, transport_header);
	struct udphdr uh;
	__u8 ver;

	if (bpf_probe_read_kernel(&ver, sizeof(ver), head + nh))
		return -1;
	ver >>= 4;
	if (ver == 4) {
		struct iphdr ih;

		if (bpf_probe_read_kernel(&ih, sizeof(ih), head + nh))
			return -1;
		v4mapped(h->saddr, ih.saddr);
		v4mapped(h->daddr, ih.daddr);
	} else if (ver == 6) {
		struct ipv6hdr ih6;

		if (bpf_probe_read_kernel(&ih6, sizeof(ih6), head + nh))
			return -1;
		__builtin_memcpy(h->saddr, &ih6.saddr, 16);
		__builtin_memcpy(h->daddr, &ih6.daddr, 16);
	} else {
		return -1;
	}
	if (bpf_probe_read_kernel(&uh, sizeof(uh), head + th))
		return -1;
	h->sport = bpf_ntohs(uh.source);
	h->dport = bpf_ntohs(uh.dest);
	h->ulen = bpf_ntohs(uh.len);
	return 0;
}

/*
 * Returns the number of datagrams an skb carries: one, or the segments of a
 * UDP GSO send (UDP_SEGMENT) or of a GRO receive delivered whole to a socket
 * with UDP_GRO. Legacy UFO (SKB_GSO_UDP) carries one datagram. Packets of a
 * guest's virtio device may leave gso_segs unset; the UDP header holds the
 * length of all segments, which then counts them.
 */
static __always_inline __u32 udp_segments(struct sk_buff *skb, __u16 ulen)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	/* An offset on 64-bit kernels (NET_SKBUFF_DATA_USES_OFFSET). */
	__u32 end = BPF_CORE_READ(skb, end);
	struct skb_shared_info *shinfo = (void *)(head + end);
	__u32 size, data;
	__u16 segs;

	size = BPF_CORE_READ(shinfo, gso_size);
	if (!size || !(BPF_CORE_READ(shinfo, gso_type) & GSO_UDP_L4))
		return 1;
	segs = BPF_CORE_READ(shinfo, gso_segs);
	if (segs)
		return segs;
	if (ulen <= sizeof(struct udphdr))
		return 1;
	data = ulen - sizeof(struct udphdr);
	return (data + size - 1) / size;
}

static __always_inline int handle_udp_send(struct sk_buff *skb)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct shawk_flow_key key = {};
	struct shawk_flow_stats *fs;
	struct shawk_l3l4 h = {};
	struct sock *sk;

	if (tgid == self_tgid)
		return 0;
	/* A direct access keeps the pointer usable with socket storage. */
	sk = skb->sk;
	if (!sk || !is_udp_sock(sk))
		return 0;
	key.netns = sock_netns(sk);
	if (!netns_ok(key.netns))
		return 0;
	if (read_udp_headers(skb, &h))
		return 0;

	__builtin_memcpy(key.laddr, h.saddr, 16);
	__builtin_memcpy(key.raddr, h.daddr, 16);
	key.direction = udp_direction(sk, key.netns, h.sport, true);
	key.port = key.direction == DIR_IN ? h.sport : h.dport;
	key.proto = IPPROTO_UDP;
	tgid = set_udp_owner(&key, sk, tgid);

	fs = flow_get(&key);
	if (!fs)
		return 0;
	/* The UDP header of a GSO skb holds the length of all segments. */
	__sync_fetch_and_add(&fs->msgs_sent, udp_segments(skb, h.ulen));
	if (h.ulen > sizeof(struct udphdr))
		__sync_fetch_and_add(&fs->bytes_sent,
				     h.ulen - sizeof(struct udphdr));
	if (tgid)
		fs->pid = tgid;
	return 0;
}

SEC("fentry/ip_send_skb")
int BPF_PROG(shawk_ip_send_skb, struct net *net, struct sk_buff *skb)
{
	return handle_udp_send(skb);
}

SEC("fentry/ip6_send_skb")
int BPF_PROG(shawk_ip6_send_skb, struct sk_buff *skb)
{
	return handle_udp_send(skb);
}

/*
 * Called from udp_recvmsg()/udpv6_recvmsg() with the number of copied bytes,
 * negated with MSG_PEEK. A peeked datagram stays in the receive queue, while
 * one that is read was unlinked from it: this also tells a peek at an empty
 * datagram (-0) from its read.
 */
SEC("fentry/skb_consume_udp")
int BPF_PROG(shawk_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct shawk_flow_key key = {};
	struct shawk_flow_stats *fs;
	struct shawk_l3l4 h = {};

	if (len < 0 || BPF_CORE_READ(skb, next) || tgid == self_tgid)
		return 0;
	/* UDP-Lite sockets are received by the same functions. */
	if (!is_udp_sock(sk))
		return 0;
	key.netns = sock_netns(sk);
	if (!netns_ok(key.netns))
		return 0;
	if (read_udp_headers(skb, &h))
		return 0;

	__builtin_memcpy(key.laddr, h.daddr, 16);
	__builtin_memcpy(key.raddr, h.saddr, 16);
	key.direction = udp_direction(sk, key.netns, h.dport, false);
	key.port = key.direction == DIR_IN ? h.dport : h.sport;
	key.proto = IPPROTO_UDP;
	tgid = set_udp_owner(&key, sk, tgid);

	fs = flow_get(&key);
	if (!fs)
		return 0;
	__sync_fetch_and_add(&fs->msgs_recv, udp_segments(skb, h.ulen));
	__sync_fetch_and_add(&fs->bytes_recv, len);
	if (tgid)
		fs->pid = tgid;
	return 0;
}

/*
 * Emits UDP server sockets and records their ports. At startup it marks the
 * bound, unconnected sockets as servers, since their first datagram after
 * the tracer started may be a reply.
 */
SEC("iter/udp")
int shawk_iter_udp(struct bpf_iter__udp *ctx)
{
	struct udp_sock *udp = ctx->udp_sk;
	struct seq_file *seq = ctx->meta->seq;
	struct shawk_listen_key lk = {};
	struct shawk_udp_state *us;
	struct sock *sk;
	__u16 family, port;
	__u32 netns;
	__u8 one = 1;

	learn_self_tgid();
	if (!udp)
		return 0;
	sk = (struct sock *)udp;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	netns = sock_netns(sk);
	if (!netns_ok(netns))
		return 0;
	port = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (initial_scan && port && port_bound(sk) &&
	    !BPF_CORE_READ(sk, __sk_common.skc_dport)) {
		us = bpf_sk_storage_get(&udp_states, udp, NULL,
					BPF_SK_STORAGE_GET_F_CREATE);
		if (us && !us->dir)
			us->dir = DIR_IN;
	}
	if (!udp_listener(sk, port))
		return 0;
	lk.netns = netns;
	lk.port = port;
	if (bpf_map_update_elem(&udp_listen_ports, &lk, &one, BPF_ANY))
		__sync_fetch_and_add(&listen_port_drops, 1);
	emit_listener(seq, sk, netns, port, IPPROTO_UDP);
	return 0;
}

/* ------------------------------------------------------------ cgroups --- */

/*
 * Reports every cgroup v2 created on the host with its path. Flows carry
 * cgroup ids, and the cgroup of a short-lived job (a cron job's session scope,
 * a timer's service) is often removed before user space could look up its
 * path in the cgroup file system.
 */
SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(shawk_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
	struct shawk_cgroup_event *e;

	/* Hierarchy 0 is cgroup v2, whose ids the other programs record. */
	if (BPF_CORE_READ(cgrp, root, hierarchy_id) != 0)
		return 0;
	e = bpf_ringbuf_reserve(&cgroup_events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&cgroup_event_drops, 1);
		return 0;
	}
	e->id = BPF_CORE_READ(cgrp, kn, id);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------------- owners --- */

/*
 * Walks the file descriptors of all processes to find the owners of
 * adopted outgoing TCP connections, of MPTCP connections and of listening
 * sockets.
 *
 * Applications using MPTCP (Go listens with it by default since 1.24) hold
 * an MPTCP socket whose TCP subflows carry the traffic. Its listeners are
 * reported as TCP since the subflows are what the TCP hooks observe. The
 * owners of its connections are recorded in mptcp_owners, where iter/tcp
 * finds them for the subflows.
 */
SEC("iter/task_file")
int shawk_iter_task_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct shawk_iter_rec rec = {};
	struct shawk_sock_state *ss;
	struct shawk_owner o = {}, *e;
	struct socket *sock;
	struct sock *sk;
	__u16 family, proto, port;
	__u32 netns, tgid;
	__u64 msk;
	__u8 state;

	learn_self_tgid();
	if (!task || !file)
		return 0;
	sock = bpf_sock_from_file(file);
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	netns = sock_netns(sk);
	if (!netns_ok(netns))
		return 0;
	proto = BPF_CORE_READ(sk, sk_protocol);
	port = BPF_CORE_READ(sk, __sk_common.skc_num);
	state = BPF_CORE_READ(sk, __sk_common.skc_state);
	tgid = BPF_CORE_READ(task, tgid);

	switch (proto) {
	case IPPROTO_TCP:
		if (state == TCP_LISTEN)
			break;
		ss = bpf_sk_storage_get(&sock_states, sk, NULL, 0);
		if (!ss || (ss->flags & SS_READY))
			return 0;
		BPF_CORE_READ_STR_INTO(&rec.comm, task, group_leader, comm);
		__builtin_memcpy(ss->key.comm, rec.comm, sizeof(rec.comm));
		ss->key.cgroup_id = task_cgroup_id(task);
		ss->pid = tgid;
		ss->flags |= SS_READY | (tgid == self_tgid ? SS_IGNORE : 0);
		return 0;
	case IPPROTO_MPTCP_:
		if (state != TCP_LISTEN) {
			/*
			 * The first process found holding it in this walk, as for
			 * TCP. A socket that never connected is freed without a
			 * state change that would remove it.
			 */
			msk = (__u64)sk;
			if (state == TCP_CLOSE)
				return 0;
			e = bpf_map_lookup_elem(&mptcp_owners, &msk);
			if (e && e->scan == owner_scan)
				return 0;
			BPF_CORE_READ_STR_INTO(&o.comm, task, group_leader, comm);
			o.cgroup_id = task_cgroup_id(task);
			o.pid = tgid;
			o.scan = owner_scan;
			bpf_map_update_elem(&mptcp_owners, &msk, &o, BPF_ANY);
			return 0;
		}
		proto = IPPROTO_TCP;
		break;
	case IPPROTO_UDP:
		if (!is_udp_sock(sk) || !udp_listener(sk, port))
			return 0;
		break;
	default:
		return 0;
	}

	if (read_local_addr(sk, rec.addr))
		return 0;
	BPF_CORE_READ_STR_INTO(&rec.comm, task, group_leader, comm);
	rec.type = REC_OWNER;
	rec.proto = proto;
	rec.netns = netns;
	rec.port = port;
	rec.pid = tgid;
	rec.cgroup_id = task_cgroup_id(task);
	rec.ino = BPF_CORE_READ(file, f_inode, i_ino);
	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}
