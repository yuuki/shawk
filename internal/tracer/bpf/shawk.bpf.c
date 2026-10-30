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
 *                               socket, which user space resolves.
 *       * -> CLOSE              accounts the remaining bytes.
 *   - iter/tcp periodically walks all TCP sockets. It accounts the byte
 *     deltas of long-lived connections from the cumulative counters kept in
 *     struct tcp_sock and adopts connections established before the tracer
 *     started.
 *   - iter/task_file resolves the owners of adopted outgoing connections and
 *     of listening sockets.
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

/* Flags of struct shawk_sock_state. */
#define SS_READY (1U << 0)   /* the key is complete and traffic is accounted */
#define SS_COUNTED (1U << 1) /* the connection has been counted in conns */
#define SS_ADOPTED (1U << 2) /* established before the tracer started */
#define SS_IGNORE (1U << 3)  /* owned by the tracer itself */

#define MAX_FLOWS 16384 /* overridden by user space */

/* Configuration set by user space before loading. */
const volatile __u32 self_tgid = 0;
const volatile __u32 target_netns = 0; /* 0 means all network namespaces */
const volatile __u16 eph_port_low = 32768;
const volatile __u16 eph_port_high = 60999;

/* Runtime state shared with user space. */
volatile __u32 active_idx = 0;
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

/* Make bpf2go emit Go types for the records read from iterators. */
const struct shawk_iter_rec *unused_iter_rec __attribute__((unused));

static __always_inline bool netns_ok(__u32 netns)
{
	return target_netns == 0 || target_netns == netns;
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

/*
 * Accounts the bytes transferred on a TCP connection since the last call by
 * reading the cumulative counters of struct tcp_sock. Exchanging the base
 * atomically prevents double counting when the iterator and the state change
 * tracepoint race on the same socket.
 */
static __always_inline void account_tcp(struct shawk_sock_state *ss,
					struct tcp_sock *tp,
					struct shawk_flow_stats *fs)
{
	__u64 acked = BPF_CORE_READ(tp, bytes_acked);
	__u64 rcvd = BPF_CORE_READ(tp, bytes_received);
	__u32 retrans = BPF_CORE_READ(tp, total_retrans);
	__u64 prev;
	__u32 prev32;

	prev = __sync_lock_test_and_set(&ss->sent_base, acked);
	if (acked > prev)
		__sync_fetch_and_add(&fs->bytes_sent, acked - prev);
	prev = __sync_lock_test_and_set(&ss->recv_base, rcvd);
	if (rcvd > prev)
		__sync_fetch_and_add(&fs->bytes_recv, rcvd - prev);
	prev32 = __sync_lock_test_and_set(&ss->retrans_base, retrans);
	if (retrans > prev32)
		__sync_fetch_and_add(&fs->retrans, retrans - prev32);
}

/*
 * Sets the byte counters as the base when a connection is established, so
 * that the sequence number consumed by the SYN is not counted as data.
 */
static __always_inline void reset_base(struct shawk_sock_state *ss,
				       struct sock *sk)
{
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);

	if (!tp)
		return;
	ss->sent_base = BPF_CORE_READ(tp, bytes_acked);
	ss->recv_base = BPF_CORE_READ(tp, bytes_received);
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

	if (build_tcp_key(&key, sk, DIR_IN))
		return;
	if (!netns_ok(key.netns))
		return;

	ss = bpf_sk_storage_get(&sock_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	reset_base(ss, sk);
	ss->pid = 0;
	ss->flags = SS_READY;
	count_conn(ss);
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(shawk_inet_sock_set_state, const struct sock *csk, int oldstate,
	     int newstate)
{
	struct sock *sk = (struct sock *)csk;
	struct shawk_sock_state *ss;
	struct shawk_flow_stats *fs;
	struct tcp_sock *tp;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	if (newstate == TCP_SYN_SENT) {
		on_active_open(sk);
		return 0;
	}
	if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
		on_passive_open(sk);
		return 0;
	}

	ss = bpf_sk_storage_get(&sock_states, sk, NULL, 0);
	if (!ss || !ss_ready(ss))
		return 0;

	if (oldstate == TCP_SYN_SENT) {
		if (newstate == TCP_ESTABLISHED) {
			/* The local address is final once established. */
			read_sock_addrs(sk, ss->key.laddr, ss->key.raddr);
			reset_base(ss, sk);
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
	fs = flow_get(&ss->key);
	if (fs)
		account_tcp(ss, tp, fs);
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

/* Starts tracking a connection established before the tracer started. */
static __always_inline void adopt_tcp(struct tcp_sock *tp, struct sock *sk,
				      __u32 netns, __u16 lport)
{
	struct shawk_listen_key lk = {.netns = netns, .port = lport};
	struct shawk_flow_key key = {};
	struct shawk_sock_state *ss;
	__u8 dir;

	dir = bpf_map_lookup_elem(&listen_ports, &lk) ? DIR_IN : DIR_OUT;
	if (build_tcp_key(&key, sk, dir))
		return;
	ss = bpf_sk_storage_get(&sock_states, tp, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!ss)
		return;
	ss->key = key;
	/* Only traffic after the adoption is accounted. */
	ss->sent_base = BPF_CORE_READ(tp, bytes_acked);
	ss->recv_base = BPF_CORE_READ(tp, bytes_received);
	ss->retrans_base = BPF_CORE_READ(tp, total_retrans);
	ss->pid = 0;
	/*
	 * Incoming connections belong to the owner of the listener, which user
	 * space resolves. Outgoing ones wait for iter/task_file.
	 */
	if (dir == DIR_IN) {
		ss->flags = SS_ADOPTED | SS_COUNTED | SS_READY;
	} else {
		ss->flags = SS_ADOPTED | SS_COUNTED;
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
	struct tcp_sock *tp;
	struct sock *sk;
	__u16 family, lport;
	__u32 netns, srtt;
	__u8 state;

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
		adopt_tcp(tp, sk, netns, lport);
		return 0;
	}
	if (!ss_ready(ss))
		return 0;

	fs = flow_get(&ss->key);
	if (!fs)
		return 0;
	account_tcp(ss, tp, fs);
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

static __always_inline bool ephemeral(__u16 port)
{
	return port >= eph_port_low && port <= eph_port_high;
}

static __always_inline bool port_bound(const struct sock *sk)
{
	__u8 locks = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_userlocks);

	return locks & SOCK_BINDPORT_LOCK;
}

/*
 * A UDP socket is regarded as a server when the application bound its port
 * explicitly. Clients that bind a random port in the ephemeral range for
 * source port randomization (e.g. DNS resolvers) are excluded when the peer
 * uses a port outside the range.
 */
static __always_inline bool udp_server(const struct sock *sk, __u16 lport,
				       __u16 rport)
{
	if (!port_bound(sk))
		return false;
	if (ephemeral(lport) && !ephemeral(rport))
		return false;
	return true;
}

/* Whether a UDP socket is a bound server socket worth listing. */
static __always_inline bool udp_listener(const struct sock *sk, __u16 port)
{
	return port && !BPF_CORE_READ(sk, __sk_common.skc_dport) &&
	       port_bound(sk) && !ephemeral(port);
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
	sk = BPF_CORE_READ(skb, sk);
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP)
		return 0;
	key.netns = sock_netns(sk);
	if (!netns_ok(key.netns))
		return 0;
	if (read_udp_headers(skb, &h))
		return 0;

	__builtin_memcpy(key.laddr, h.saddr, 16);
	__builtin_memcpy(key.raddr, h.daddr, 16);
	if (udp_server(sk, h.sport, h.dport)) {
		key.direction = DIR_IN;
		key.port = h.sport;
	} else {
		key.direction = DIR_OUT;
		key.port = h.dport;
	}
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
	if (udp_server(sk, h.dport, h.sport)) {
		key.direction = DIR_IN;
		key.port = h.dport;
	} else {
		key.direction = DIR_OUT;
		key.port = h.sport;
	}
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

/* Emits bound UDP server sockets. */
SEC("iter/udp")
int shawk_iter_udp(struct bpf_iter__udp *ctx)
{
	struct udp_sock *udp = ctx->udp_sk;
	struct seq_file *seq = ctx->meta->seq;
	struct sock *sk;
	__u16 family, port;
	__u32 netns;

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
	if (!udp_listener(sk, port))
		return 0;
	emit_listener(seq, sk, netns, port, IPPROTO_UDP);
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
