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
 *       SYN_RECV -> ESTABLISHED passive open; counts an incoming connection.
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
 *     bundle datagrams in process context. A socket whose local port was
 *     explicitly bound by the application is regarded as the server side.
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
#define SOCK_BINDPORT_LOCK 8

/* TCP states in which the FIN of the local side is queued. */
#define TCPF_FIN_QUEUED                                                    \
	((1U << TCP_FIN_WAIT1) | (1U << TCP_FIN_WAIT2) | (1U << TCP_CLOSING) | \
	 (1U << TCP_LAST_ACK))

/* Flags of struct shawk_sock_state. */
#define SS_READY (1U << 0)   /* the key is complete and traffic is accounted */
#define SS_COUNTED (1U << 1) /* the connection has been counted in conns */
#define SS_IGNORE (1U << 2)  /* owned by the tracer itself */

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
__u64 flow_drops = 0;
__u64 adopted_unowned = 0;

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

/* Listening TCP ports, rebuilt by iter/tcp at every scan. */
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
	if (direction == DIR_IN)
		key->port = BPF_CORE_READ(sk, __sk_common.skc_num);
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
	/* tcp_fin() sets SOCK_DONE when it receives the FIN of the peer. */
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
 * on is accounted: when a connection is established, the sequence number
 * consumed by the SYN is not counted as data.
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

/* ---------------------------------------------------------------- TCP --- */

/* CLOSE -> SYN_SENT: called in connect(2) by the client process. */
static __always_inline void on_active_open(struct sock *sk)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;

	if (build_tcp_key(&key, sk, DIR_OUT))
		return;
	if (!netns_ok(key.netns))
		return;
	set_current_owner(&key);

	ss = bpf_sk_storage_get(&sock_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	ss->sent_base = 0;
	ss->recv_base = 0;
	ss->retrans_base = 0;
	ss->pid = tgid;
	ss->flags = SS_READY | (tgid == self_tgid ? SS_IGNORE : 0);
}

/* SYN_RECV -> ESTABLISHED: a child socket of a listener was established. */
static __always_inline void on_passive_open(struct sock *sk)
{
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	struct tcp_sock *tp;

	if (build_tcp_key(&key, sk, DIR_IN))
		return;
	if (!netns_ok(key.netns))
		return;
	/*
	 * The cgroup tells apart different programs sharing a port with
	 * SO_REUSEPORT; user space resolves the command name.
	 */
	key.cgroup_id = sock_cgroup_id(sk);

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;
	ss = bpf_sk_storage_get(&sock_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	reset_base(ss, sk, tp, TCP_ESTABLISHED);
	ss->pid = 0;
	ss->flags = SS_READY;
	count_conn(ss);
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

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	if (newstate == TCP_SYN_SENT) {
		on_active_open(sk);
		return 0;
	}

	ss = bpf_sk_storage_get(&sock_states, sk, NULL, 0);
	/*
	 * The children of a listener have no storage yet, since sock_states is
	 * not cloned. A socket with an outgoing key went through SYN_SENT and
	 * ends a simultaneous open, e.g. a socket connected to itself.
	 */
	if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED &&
	    (!ss || ss->key.direction != DIR_OUT)) {
		on_passive_open(sk);
		return 0;
	}
	if (!ss || !ss_ready(ss))
		return 0;

	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV) {
		if (ss->key.direction != DIR_OUT)
			return 0;
		if (newstate == TCP_ESTABLISHED) {
			tp = bpf_skc_to_tcp_sock(sk);
			if (!tp)
				return 0;
			/* The local address is final once established. */
			read_sock_addrs(sk, ss->key.laddr, ss->key.raddr);
			reset_base(ss, sk, tp, TCP_ESTABLISHED);
			count_conn(ss);
		} else if (newstate == TCP_CLOSE) {
			fs = flow_get(&ss->key);
			if (fs) {
				__sync_fetch_and_add(&fs->conn_fails, 1);
				fs->pid = ss->pid;
			}
		}
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
	if (fs)
		add_tcp_delta(fs, &d);
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
	bpf_seq_write(seq, &rec, sizeof(rec));
}

/*
 * Whether the local port of a connection was allocated by connect(2). Such a
 * port gets a bind bucket of its own, marked as not reusable by bind(2)
 * (fastreuse -1). Ports bound by bind(2) or listen(2) do not: the connections
 * accepted by a listener share its bucket, and keep it after it is closed.
 */
static __always_inline bool connect_bound(struct sock *sk)
{
	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
	struct inet_bind_bucket *tb = BPF_CORE_READ(icsk, icsk_bind_hash);

	if (!tb)
		return true;
	return BPF_CORE_READ(tb, fastreuse) < 0;
}

/*
 * Returns the direction of a connection established before the tracer
 * started, and whether its local port is listening.
 */
static __always_inline __u8 adopted_direction(struct sock *sk, __u32 netns,
					      __u16 lport, bool *listening)
{
	struct shawk_listen_key lk = {.netns = netns, .port = lport};
	__u16 rport;

	*listening = bpf_map_lookup_elem(&listen_ports, &lk) != NULL;
	if (*listening)
		return DIR_IN;
	if (connect_bound(sk))
		return DIR_OUT;
	/*
	 * The port was bound by bind(2) or listen(2), but nothing listens on
	 * it: mostly a connection accepted by a listener that is gone (a server
	 * draining its connections, an FTP data connection) or, with TPROXY, on
	 * another port than the listener's. A client may also bind its port
	 * before connecting, e.g. to choose its source address; it then gets a
	 * port of the ephemeral range, and talks to a service port, which is
	 * usually below the range.
	 */
	rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (ephemeral(lport) && rport < eph_port_low)
		return DIR_OUT;
	return DIR_IN;
}

/* Starts tracking a connection established before the tracer started. */
static __always_inline void adopt_tcp(struct tcp_sock *tp, struct sock *sk,
				      __u32 netns, __u16 lport, int state)
{
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	bool listening;
	__u8 dir;

	dir = adopted_direction(sk, netns, lport, &listening);
	if (build_tcp_key(&key, sk, dir))
		return;
	if (dir == DIR_IN)
		key.cgroup_id = sock_cgroup_id(sk);
	ss = bpf_sk_storage_get(&sock_states, tp, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	/* Only traffic after the adoption is accounted. */
	reset_base(ss, sk, tp, state);
	ss->pid = 0;
	/*
	 * Connections accepted by a listener belong to its owner, which user
	 * space resolves. The others wait for iter/task_file to find the
	 * process holding them.
	 */
	if (listening) {
		ss->flags = SS_COUNTED | SS_READY;
	} else {
		ss->flags = SS_COUNTED;
		__sync_fetch_and_add(&adopted_unowned, 1);
	}
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

		bpf_map_update_elem(&listen_ports, &lk, &one, BPF_ANY);
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
	if (!ss_ready(ss) || initial_scan)
		return 0;

	fs = flow_get(&ss->key);
	if (!fs)
		return 0;
	if (take_tcp_delta(ss, sk, tp, state, &d))
		add_tcp_delta(fs, &d);
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

struct shawk_l3l4 {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 ulen;
};

/* Reads addresses and ports of a UDP datagram from its headers. */
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
		if (ih.protocol != IPPROTO_UDP)
			return -1;
		v4mapped(h->saddr, ih.saddr);
		v4mapped(h->daddr, ih.daddr);
	} else if (ver == 6) {
		struct ipv6hdr ih6;

		if (bpf_probe_read_kernel(&ih6, sizeof(ih6), head + nh))
			return -1;
		if (ih6.nexthdr != IPPROTO_UDP)
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
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP)
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
	set_current_owner(&key);

	fs = flow_get(&key);
	if (!fs)
		return 0;
	__sync_fetch_and_add(&fs->msgs_sent, 1);
	if (h.ulen > sizeof(struct udphdr))
		__sync_fetch_and_add(&fs->bytes_sent,
				     h.ulen - sizeof(struct udphdr));
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

/* Called from udp_recvmsg()/udpv6_recvmsg() with the number of copied bytes. */
SEC("fentry/skb_consume_udp")
int BPF_PROG(shawk_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct shawk_flow_key key = {};
	struct shawk_flow_stats *fs;
	struct shawk_l3l4 h = {};

	/* A negative length means MSG_PEEK; the datagram is not consumed. */
	if (len < 0 || tgid == self_tgid)
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
	set_current_owner(&key);

	fs = flow_get(&key);
	if (!fs)
		return 0;
	__sync_fetch_and_add(&fs->msgs_recv, 1);
	__sync_fetch_and_add(&fs->bytes_recv, len);
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
	bpf_map_update_elem(&udp_listen_ports, &lk, &one, BPF_ANY);
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

#define IPPROTO_MPTCP_ 262

/*
 * Walks the file descriptors of all processes to find the owners of
 * adopted outgoing TCP connections and of listening sockets.
 *
 * Applications listening with MPTCP (the default of Go since 1.24) hold an
 * MPTCP socket whose TCP subflows carry the traffic. Such listeners are
 * reported as TCP since the subflows are what the TCP hooks observe.
 */
SEC("iter/task_file")
int shawk_iter_task_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct shawk_iter_rec rec = {};
	struct shawk_sock_state *ss;
	struct socket *sock;
	struct sock *sk;
	__u16 family, proto, port;
	__u32 netns, tgid;
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
		if (state != TCP_LISTEN)
			return 0;
		proto = IPPROTO_TCP;
		break;
	case IPPROTO_UDP:
		if (!udp_listener(sk, port))
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
	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}
