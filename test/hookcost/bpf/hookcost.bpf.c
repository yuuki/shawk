// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2026 Yuuki Tsubouchi */

/*
 * The hooks compared in docs/research/kernel-hooks/kernel_hooks.md (#165).
 * Each program does the work that its hook would do in shawk: it finds the
 * state of the socket and the bundled flow of the event, and adds to the
 * flow. The *_empty programs return at once, which tells the cost of a hook
 * from the cost of the work.
 *
 * Programs of type kprobe cannot use socket local storage:
 * bpf_sk_storage_get() is given to tracing programs (fentry, fexit, tp_btf,
 * iterators) and to programs on sockets (cgroup_skb) only. The kprobe
 * variants keep the state of a socket in an LRU hash keyed by its address
 * instead, as a design with kprobes would have to.
 *
 * Folding (§3.6 of the design) and the sockets of the kernel are left out
 * of every variant alike.
 */

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define EEXIST 17
#define AF_INET6 10
#define SOCK_DGRAM 2
#define SOCK_BINDPORT_LOCK 8
#define GSO_UDP_L4 (1U << 17)
#define DIR_OUT 1
#define DIR_IN 2

/* The key and value of a bundled flow, of the size of shawk's. */
struct hc_flow_key {
	__u8 laddr[16];
	__u8 raddr[16];
	__u64 cgroup_id;
	__u32 netns;
	__u16 port;
	__u8 direction;
	__u8 proto;
	char comm[16];
	__u8 flags;
	__u8 _pad[7];
};

struct hc_flow_stats {
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u64 msgs_sent;
	__u64 msgs_recv;
	__u64 conns;
	__u32 pid;
	__u32 _pad;
};

/* The state of a TCP connection: its flow and owner. */
struct hc_sock_state {
	struct hc_flow_key key;
	__u32 pid;
	__u32 _pad;
};

/* The process that accepted a connection. */
struct hc_owner {
	__u64 cgroup_id;
	__u32 pid;
	char comm[16];
};

struct hc_listen_key {
	__u32 netns;
	__u16 port;
	__u16 _pad;
};

struct hc_flow_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct hc_flow_key);
	__type(value, struct hc_flow_stats);
} flows_0 SEC(".maps"), flows_1 SEC(".maps");

/* As in shawk, the active map is selected through an array of maps. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct hc_flow_map);
} flows SEC(".maps") = {
	.values = {&flows_0, &flows_1},
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct hc_sock_state);
} sk_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct hc_sock_state);
} sk_states_h SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} udp_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u32);
} udp_states_h SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct hc_listen_key);
	__type(value, __u8);
} udp_listen_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct hc_owner);
} accepted SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct hc_owner);
} accepted_h SEC(".maps");

__u32 active_idx = 0;
__u64 flow_drops = 0;

static const struct hc_flow_stats zero_stats = {};

/* ------------------------------------------------------------ common --- */

/*
 * The arguments and return value of a kprobe. The object is shared by
 * x86_64 and arm64, so the registers are found by CO-RE, and read with
 * bpf_probe_read_kernel() as in shawk.bpf.c (kprobe_arg1()).
 */
struct pt_regs___x86 {
	unsigned long di;
	unsigned long si;
	unsigned long dx;
	unsigned long ax;
} __attribute__((preserve_access_index));

struct pt_regs___arm64 {
	unsigned long regs[31];
} __attribute__((preserve_access_index));

static __always_inline __u64 karg0(struct pt_regs *ctx)
{
	struct pt_regs___x86 *x = (void *)ctx;
	struct pt_regs___arm64 *a = (void *)ctx;

	if (bpf_core_field_exists(x->di))
		return BPF_CORE_READ(x, di);
	return BPF_CORE_READ(a, regs[0]);
}

static __always_inline __u64 karg1(struct pt_regs *ctx)
{
	struct pt_regs___x86 *x = (void *)ctx;
	struct pt_regs___arm64 *a = (void *)ctx;

	if (bpf_core_field_exists(x->si))
		return BPF_CORE_READ(x, si);
	return BPF_CORE_READ(a, regs[1]);
}

static __always_inline __u64 karg2(struct pt_regs *ctx)
{
	struct pt_regs___x86 *x = (void *)ctx;
	struct pt_regs___arm64 *a = (void *)ctx;

	if (bpf_core_field_exists(x->dx))
		return BPF_CORE_READ(x, dx);
	return BPF_CORE_READ(a, regs[2]);
}

static __always_inline __u64 kret(struct pt_regs *ctx)
{
	struct pt_regs___x86 *x = (void *)ctx;
	struct pt_regs___arm64 *a = (void *)ctx;

	if (bpf_core_field_exists(x->ax))
		return BPF_CORE_READ(x, ax);
	return BPF_CORE_READ(a, regs[0]);
}

static __always_inline void v4mapped(__u8 *dst, __be32 addr)
{
	__builtin_memset(dst, 0, 10);
	dst[10] = 0xff;
	dst[11] = 0xff;
	__builtin_memcpy(dst + 12, &addr, 4);
}

static __always_inline __u32 sock_netns(struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline int read_sock_addrs(struct sock *sk, __u8 *laddr,
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

/* The owner of a flow, as shawk's set_current_owner(). */
static __always_inline void set_current_owner(struct hc_flow_key *key)
{
	struct task_struct *task = (void *)bpf_get_current_task();

	key->cgroup_id = bpf_get_current_cgroup_id();
	BPF_CORE_READ_STR_INTO(&key->comm, task, group_leader, comm);
}

/* Looks up or creates the bundled flow in the active map, as shawk. */
static __always_inline struct hc_flow_stats *flow_get(const struct hc_flow_key *k)
{
	struct hc_flow_key key;
	struct hc_flow_stats *fs;
	__u32 idx = active_idx & 1;
	void *map;
	int err;

	__builtin_memcpy(&key, k, sizeof(key));
	map = bpf_map_lookup_elem(&flows, &idx);
	if (!map)
		return NULL;
	fs = bpf_map_lookup_elem(map, &key);
	if (fs)
		return fs;
	err = bpf_map_update_elem(map, &key, &zero_stats, BPF_NOEXIST);
	if (err && err != -EEXIST) {
		__sync_fetch_and_add(&flow_drops, 1);
		return NULL;
	}
	return bpf_map_lookup_elem(map, &key);
}

/* ------------------------------------------------------- TCP messages --- */

/*
 * The key of a TCP connection. A connection accepted by a listener keeps
 * its backlog (adopted_direction() in shawk.bpf.c).
 */
static __always_inline int tcp_key(struct hc_flow_key *k, struct sock *sk)
{
	if (read_sock_addrs(sk, k->laddr, k->raddr))
		return -1;
	k->netns = sock_netns(sk);
	k->proto = IPPROTO_TCP;
	if (BPF_CORE_READ(sk, sk_max_ack_backlog)) {
		k->direction = DIR_IN;
		k->port = BPF_CORE_READ(sk, __sk_common.skc_num);
	} else {
		k->direction = DIR_OUT;
		k->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	}
	set_current_owner(k);
	return 0;
}

/*
 * The state of a connection in the LRU hash. In shawk it would be created
 * by the state change tracepoint; here the first message creates it.
 */
static __always_inline struct hc_sock_state *tcp_state_h(struct sock *sk)
{
	struct hc_sock_state *st, n = {};
	__u64 p = (__u64)sk;

	st = bpf_map_lookup_elem(&sk_states_h, &p);
	if (st)
		return st;
	if (tcp_key(&n.key, sk))
		return NULL;
	n.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&sk_states_h, &p, &n, BPF_NOEXIST);
	return bpf_map_lookup_elem(&sk_states_h, &p);
}

/* The state of a connection in socket local storage. */
static __always_inline struct hc_sock_state *tcp_state_s(struct sock *sk)
{
	struct hc_sock_state *st;

	st = bpf_sk_storage_get(&sk_states, sk, NULL, 0);
	if (st)
		return st;
	st = bpf_sk_storage_get(&sk_states, sk, NULL,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!st)
		return NULL;
	if (tcp_key(&st->key, sk))
		return NULL;
	st->pid = bpf_get_current_pid_tgid() >> 32;
	return st;
}

/* Counts a message and its bytes in the flow of its connection. */
static __always_inline void tcp_msg(struct hc_sock_state *st, __s64 bytes,
				    bool send)
{
	struct hc_flow_stats *fs;

	if (!st || bytes <= 0)
		return;
	fs = flow_get(&st->key);
	if (!fs)
		return;
	if (send) {
		__sync_fetch_and_add(&fs->msgs_sent, 1);
		__sync_fetch_and_add(&fs->bytes_sent, bytes);
	} else {
		__sync_fetch_and_add(&fs->msgs_recv, 1);
		__sync_fetch_and_add(&fs->bytes_recv, bytes);
	}
	fs->pid = st->pid;
}

/* The original implementation: kprobes on tcp_sendmsg and tcp_cleanup_rbuf. */
SEC("kprobe/tcp_sendmsg")
int k_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (void *)karg0(ctx);

	tcp_msg(tcp_state_h(sk), karg2(ctx), true);
	return 0;
}

/*
 * tcp_recvmsg() calls tcp_cleanup_rbuf() also before it waits for data,
 * with nothing copied: those calls return before any lookup.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int k_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
	int copied = karg1(ctx);

	if (copied > 0)
		tcp_msg(tcp_state_h((void *)karg0(ctx)), copied, false);
	return 0;
}

/* The same through fprobe (kprobe_multi), which needs CONFIG_FPROBE. */
SEC("kprobe.multi/tcp_sendmsg")
int km_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (void *)karg0(ctx);

	tcp_msg(tcp_state_h(sk), karg2(ctx), true);
	return 0;
}

SEC("kprobe.multi/tcp_cleanup_rbuf")
int km_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
	int copied = karg1(ctx);

	if (copied > 0)
		tcp_msg(tcp_state_h((void *)karg0(ctx)), copied, false);
	return 0;
}

/* The same with BPF trampolines, and socket local storage. */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(f_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	tcp_msg(tcp_state_s(sk), size, true);
	return 0;
}

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(f_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied > 0)
		tcp_msg(tcp_state_s(sk), copied, false);
	return 0;
}

/* ---------------------------------------------------------- the hooks --- */

/* Attached to any function, for the cost of a kprobe itself. */
SEC("kprobe/tcp_sendmsg")
int k_empty(struct pt_regs *ctx)
{
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kr_empty(struct pt_regs *ctx)
{
	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(f_empty_tcp_sendmsg)
{
	return 0;
}

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(f_empty_tcp_cleanup_rbuf)
{
	return 0;
}

SEC("fentry/ip_send_skb")
int BPF_PROG(f_empty_ip_send_skb)
{
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(f_empty_skb_consume_udp)
{
	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(tp_empty)
{
	return 0;
}

SEC("cgroup_skb/egress")
int cg_empty_egress(struct __sk_buff *skb)
{
	return 1;
}

SEC("cgroup_skb/ingress")
int cg_empty_ingress(struct __sk_buff *skb)
{
	return 1;
}

/* ------------------------------------------------------------- accept --- */

static __always_inline void fill_owner(struct hc_owner *o)
{
	struct task_struct *task = (void *)bpf_get_current_task();

	o->pid = bpf_get_current_pid_tgid() >> 32;
	o->cgroup_id = bpf_get_current_cgroup_id();
	BPF_CORE_READ_STR_INTO(&o->comm, task, group_leader, comm);
}

/*
 * The task that accepts a connection. A kretprobe reads only the return
 * value, whatever the parameters of inet_csk_accept().
 */
SEC("kretprobe/inet_csk_accept")
int kr_inet_csk_accept(struct pt_regs *ctx)
{
	struct hc_owner o = {};
	__u64 sk = kret(ctx);

	if (!sk)
		return 0;
	fill_owner(&o);
	bpf_map_update_elem(&accepted_h, &sk, &o, BPF_ANY);
	return 0;
}

/* fexit needs the parameters: before Linux 6.10 ... */
SEC("fexit/inet_csk_accept")
int BPF_PROG(fx_inet_csk_accept, struct sock *sk, int flags, int *err,
	     bool kern, struct sock *ret)
{
	struct hc_owner *o;

	if (!ret)
		return 0;
	o = bpf_sk_storage_get(&accepted, ret, NULL,
			       BPF_SK_STORAGE_GET_F_CREATE);
	if (o)
		fill_owner(o);
	return 0;
}

/* ... and since, with struct proto_accept_arg (backported to RHEL 9). */
SEC("fexit/inet_csk_accept")
int BPF_PROG(fx_inet_csk_accept_arg, struct sock *sk, void *arg,
	     struct sock *ret)
{
	struct hc_owner *o;

	if (!ret)
		return 0;
	o = bpf_sk_storage_get(&accepted, ret, NULL,
			       BPF_SK_STORAGE_GET_F_CREATE);
	if (o)
		fill_owner(o);
	return 0;
}

/* ---------------------------------------------------------------- UDP --- */

static __always_inline bool port_bound(struct sock *sk)
{
	__u8 locks = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_userlocks);

	return locks & SOCK_BINDPORT_LOCK;
}

static __always_inline bool is_udp_sock(struct sock *sk)
{
	return BPF_CORE_READ(sk, sk_protocol) == IPPROTO_UDP &&
	       BPF_CORE_READ(sk, sk_type) == SOCK_DGRAM;
}

/*
 * The direction of a UDP socket, decided by its first datagram as in
 * shawk's udp_direction(), in socket storage or in the LRU hash.
 */
static __always_inline __u32 udp_direction(struct sock *sk, __u32 netns,
					   __u16 lport, bool sending, bool hash)
{
	struct hc_listen_key lk = {.netns = netns, .port = lport};
	__u64 p = (__u64)sk;
	bool listening, bound;
	__u32 dir = DIR_IN;
	__u32 *us;
	__u8 one = 1;

	if (hash)
		us = bpf_map_lookup_elem(&udp_states_h, &p);
	else
		us = bpf_sk_storage_get(&udp_states, sk, NULL, 0);
	if (us)
		return *us;
	listening = bpf_map_lookup_elem(&udp_listen_ports, &lk) != NULL;
	bound = port_bound(sk);
	if (sending) {
		if (!listening)
			dir = DIR_OUT;
	} else if (BPF_CORE_READ(sk, __sk_common.skc_dport)) {
		if (!bound && !listening)
			dir = DIR_OUT;
	} else if (bound && !listening) {
		bpf_map_update_elem(&udp_listen_ports, &lk, &one, BPF_ANY);
	}
	if (hash) {
		bpf_map_update_elem(&udp_states_h, &p, &dir, BPF_ANY);
	} else {
		us = bpf_sk_storage_get(&udp_states, sk, NULL,
					BPF_SK_STORAGE_GET_F_CREATE);
		if (us)
			*us = dir;
	}
	return dir;
}

struct hc_l3l4 {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 ulen;
};

/* The headers of a datagram, from the skb (read_udp_headers() of shawk). */
static __always_inline int read_udp_headers(struct sk_buff *skb,
					    struct hc_l3l4 *h)
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

static __always_inline __u32 udp_segments(struct sk_buff *skb, __u16 ulen)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
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

/* A datagram sent (handle_udp_send() of shawk). */
static __always_inline int udp_send(struct sk_buff *skb, struct sock *sk,
				    bool hash)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct hc_flow_key key = {};
	struct hc_flow_stats *fs;
	struct hc_l3l4 h = {};

	if (!sk || !is_udp_sock(sk))
		return 0;
	key.netns = sock_netns(sk);
	if (read_udp_headers(skb, &h))
		return 0;
	__builtin_memcpy(key.laddr, h.saddr, 16);
	__builtin_memcpy(key.raddr, h.daddr, 16);
	key.direction = udp_direction(sk, key.netns, h.sport, true, hash);
	key.port = key.direction == DIR_IN ? h.sport : h.dport;
	key.proto = IPPROTO_UDP;
	set_current_owner(&key);
	fs = flow_get(&key);
	if (!fs)
		return 0;
	__sync_fetch_and_add(&fs->msgs_sent, udp_segments(skb, h.ulen));
	if (h.ulen > sizeof(struct udphdr))
		__sync_fetch_and_add(&fs->bytes_sent,
				     h.ulen - sizeof(struct udphdr));
	fs->pid = tgid;
	return 0;
}

/* A datagram read (shawk_skb_consume_udp()). */
static __always_inline int udp_recv(struct sock *sk, struct sk_buff *skb,
				    int len, bool hash)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct hc_flow_key key = {};
	struct hc_flow_stats *fs;
	struct hc_l3l4 h = {};

	if (len < 0 || BPF_CORE_READ(skb, next))
		return 0;
	if (!is_udp_sock(sk))
		return 0;
	key.netns = sock_netns(sk);
	if (read_udp_headers(skb, &h))
		return 0;
	__builtin_memcpy(key.laddr, h.daddr, 16);
	__builtin_memcpy(key.raddr, h.saddr, 16);
	key.direction = udp_direction(sk, key.netns, h.dport, false, hash);
	key.port = key.direction == DIR_IN ? h.dport : h.sport;
	key.proto = IPPROTO_UDP;
	set_current_owner(&key);
	fs = flow_get(&key);
	if (!fs)
		return 0;
	__sync_fetch_and_add(&fs->msgs_recv, udp_segments(skb, h.ulen));
	__sync_fetch_and_add(&fs->bytes_recv, len);
	fs->pid = tgid;
	return 0;
}

SEC("fentry/ip_send_skb")
int BPF_PROG(f_ip_send_skb, struct net *net, struct sk_buff *skb)
{
	return udp_send(skb, skb->sk, false);
}

SEC("fentry/ip6_send_skb")
int BPF_PROG(f_ip6_send_skb, struct sk_buff *skb)
{
	return udp_send(skb, skb->sk, false);
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(f_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
	return udp_recv(sk, skb, len, false);
}

SEC("kprobe/ip_send_skb")
int k_ip_send_skb(struct pt_regs *ctx)
{
	struct sk_buff *skb = (void *)karg1(ctx);

	return udp_send(skb, BPF_CORE_READ(skb, sk), true);
}

SEC("kprobe/ip6_send_skb")
int k_ip6_send_skb(struct pt_regs *ctx)
{
	struct sk_buff *skb = (void *)karg0(ctx);

	return udp_send(skb, BPF_CORE_READ(skb, sk), true);
}

SEC("kprobe/skb_consume_udp")
int k_skb_consume_udp(struct pt_regs *ctx)
{
	return udp_recv((void *)karg0(ctx), (void *)karg1(ctx),
			(int)karg2(ctx), true);
}

/*
 * cgroup_skb on the root cgroup sees every packet of the sockets of the
 * host, in the cgroup of the socket rather than in the context of a task:
 * the comm and process of a flow would be resolved from its cgroup in user
 * space. TCP packets go through it too.
 */
struct hc_ip4h {
	__u8 vihl;
	__u8 tos;
	__u16 len;
	__u16 id;
	__u16 frag;
	__u8 ttl;
	__u8 proto;
	__u16 csum;
	__u32 saddr;
	__u32 daddr;
};

struct hc_ip6h {
	__u32 vtcfl;
	__u16 plen;
	__u8 nexthdr;
	__u8 hop;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct hc_udph {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};

static __always_inline int cg_udp(struct __sk_buff *skb, bool egress)
{
	struct bpf_sock *sk = skb->sk;
	struct hc_flow_key key = {};
	struct hc_flow_stats *fs;
	__u8 src[16], dst[16];
	struct hc_listen_key lk = {};
	__u16 sport, dport, ulen;
	struct hc_udph uh;
	__u32 off, *us, segs;
	__u8 ver;

	if (!sk)
		return 1;
	sk = bpf_sk_fullsock(sk);
	if (!sk || sk->protocol != IPPROTO_UDP || sk->type != SOCK_DGRAM)
		return 1;
	if (bpf_skb_load_bytes(skb, 0, &ver, 1))
		return 1;
	ver >>= 4;
	if (ver == 4) {
		struct hc_ip4h ih;

		if (bpf_skb_load_bytes(skb, 0, &ih, sizeof(ih)))
			return 1;
		v4mapped(src, ih.saddr);
		v4mapped(dst, ih.daddr);
		off = (ih.vihl & 0xf) * 4;
	} else if (ver == 6) {
		struct hc_ip6h ih6;

		if (bpf_skb_load_bytes(skb, 0, &ih6, sizeof(ih6)))
			return 1;
		__builtin_memcpy(src, ih6.saddr, 16);
		__builtin_memcpy(dst, ih6.daddr, 16);
		off = sizeof(ih6);
	} else {
		return 1;
	}
	if (bpf_skb_load_bytes(skb, off & 0x3f, &uh, sizeof(uh)))
		return 1;
	sport = bpf_ntohs(uh.source);
	dport = bpf_ntohs(uh.dest);
	ulen = bpf_ntohs(uh.len);
	if (egress) {
		__builtin_memcpy(key.laddr, src, 16);
		__builtin_memcpy(key.raddr, dst, 16);
	} else {
		__builtin_memcpy(key.laddr, dst, 16);
		__builtin_memcpy(key.raddr, src, 16);
	}
	lk.port = egress ? sport : dport;
	us = bpf_sk_storage_get(&udp_states, sk, NULL, 0);
	if (!us) {
		us = bpf_sk_storage_get(&udp_states, sk, NULL,
					BPF_SK_STORAGE_GET_F_CREATE);
		if (!us)
			return 1;
		*us = DIR_IN;
		if (egress && !bpf_map_lookup_elem(&udp_listen_ports, &lk))
			*us = DIR_OUT;
	}
	key.direction = *us;
	key.port = key.direction == DIR_IN ? lk.port : (egress ? dport : sport);
	key.proto = IPPROTO_UDP;
	key.cgroup_id = bpf_skb_cgroup_id(skb);
	fs = flow_get(&key);
	if (!fs)
		return 1;
	segs = skb->gso_segs ? skb->gso_segs : 1;
	if (egress) {
		__sync_fetch_and_add(&fs->msgs_sent, segs);
		if (ulen > sizeof(uh))
			__sync_fetch_and_add(&fs->bytes_sent, ulen - sizeof(uh));
	} else {
		__sync_fetch_and_add(&fs->msgs_recv, segs);
		if (ulen > sizeof(uh))
			__sync_fetch_and_add(&fs->bytes_recv, ulen - sizeof(uh));
	}
	return 1;
}

SEC("cgroup_skb/egress")
int cg_udp_egress(struct __sk_buff *skb)
{
	return cg_udp(skb, true);
}

SEC("cgroup_skb/ingress")
int cg_udp_ingress(struct __sk_buff *skb)
{
	return cg_udp(skb, false);
}

/* ------------------------------------------- errors of active opens --- */

/*
 * Where the error of a failed active open can be read, compared with the
 * state change SYN_SENT -> CLOSE where shawk reads it (fail_reason()). On
 * kernels without tcp_done_with_error(), tcp_write_err() and
 * tcp_v4_err()/tcp_v6_err() report the error, which wakes the task, before
 * tcp_done(); the task may take it with SO_ERROR first.
 *
 *   kprobe/sk_error_report        before the task is woken
 *   tp_btf/inet_sk_error_report   after sk->sk_error_report() woke it
 *
 * Since tcp_done_with_error() (Linux 6.11, and backports), the error is
 * reported after tcp_done(), but it is set before: a task that polls the
 * socket meanwhile may still take it first. Its kprobe sees the error as
 * an argument.
 *
 *   kprobe/tcp_done_with_error    before the error is set
 *
 * And before any of them, with the error as a value rather than in sk_err:
 *
 *   tp_btf/tcp_receive_reset      first in tcp_reset()
 *   kprobe/ip_icmp_error          tcp_v4_err() calls it in SYN_SENT before
 *   kprobe/ipv6_icmp_error        it sets sk_err, also while the task holds
 *                                 the socket
 */
struct hc_err_seen {
	__s32 kprobe_err;
	__s32 tp_err;
	__s32 early_err;
	__s32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct hc_err_seen);
} errs SEC(".maps");

/* Failed active opens, and those whose error each hook saw. */
__u64 fails = 0;
__u64 fails_err_close = 0;
__u64 fails_err_kprobe = 0;
__u64 fails_err_tp = 0;
__u64 fails_err_early = 0;

static __always_inline bool syn_sent_tcp(struct sock *sk)
{
	return BPF_CORE_READ(sk, sk_protocol) == IPPROTO_TCP &&
	       BPF_CORE_READ(sk, __sk_common.skc_state) == TCP_SYN_SENT;
}

SEC("kprobe/sk_error_report")
int k_sk_error_report(struct pt_regs *ctx)
{
	struct sock *sk = (void *)karg0(ctx);
	struct hc_err_seen *e, n = {};
	__u64 p = (__u64)sk;

	if (!syn_sent_tcp(sk))
		return 0;
	e = bpf_map_lookup_elem(&errs, &p);
	if (!e) {
		bpf_map_update_elem(&errs, &p, &n, BPF_NOEXIST);
		e = bpf_map_lookup_elem(&errs, &p);
		if (!e)
			return 0;
	}
	e->kprobe_err = BPF_CORE_READ(sk, sk_err);
	return 0;
}

SEC("kprobe/tcp_done_with_error")
int k_tcp_done_with_error(struct pt_regs *ctx)
{
	struct sock *sk = (void *)karg0(ctx);
	struct hc_err_seen *e, n = {};
	__u64 p = (__u64)sk;

	if (!syn_sent_tcp(sk))
		return 0;
	e = bpf_map_lookup_elem(&errs, &p);
	if (!e) {
		bpf_map_update_elem(&errs, &p, &n, BPF_NOEXIST);
		e = bpf_map_lookup_elem(&errs, &p);
		if (!e)
			return 0;
	}
	e->kprobe_err = karg1(ctx);
	return 0;
}

static __always_inline struct hc_err_seen *err_seen(struct sock *sk)
{
	struct hc_err_seen *e, n = {};
	__u64 p = (__u64)sk;

	e = bpf_map_lookup_elem(&errs, &p);
	if (e)
		return e;
	bpf_map_update_elem(&errs, &p, &n, BPF_NOEXIST);
	return bpf_map_lookup_elem(&errs, &p);
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(tp_tcp_receive_reset, struct sock *sk)
{
	struct hc_err_seen *e;

	if (!syn_sent_tcp(sk))
		return 0;
	e = err_seen(sk);
	if (e)
		e->early_err = 111; /* ECONNREFUSED */
	return 0;
}

static __always_inline int icmp_error(struct pt_regs *ctx)
{
	struct sock *sk = (void *)karg0(ctx);
	struct hc_err_seen *e;

	if (!syn_sent_tcp(sk))
		return 0;
	e = err_seen(sk);
	if (e)
		e->early_err = karg2(ctx);
	return 0;
}

SEC("kprobe/ip_icmp_error")
int k_ip_icmp_error(struct pt_regs *ctx)
{
	return icmp_error(ctx);
}

SEC("kprobe/ipv6_icmp_error")
int k_ipv6_icmp_error(struct pt_regs *ctx)
{
	return icmp_error(ctx);
}

SEC("tp_btf/inet_sk_error_report")
int BPF_PROG(tp_inet_sk_error_report, struct sock *sk)
{
	struct hc_err_seen *e, n = {};
	__u64 p = (__u64)sk;

	if (!syn_sent_tcp(sk))
		return 0;
	e = bpf_map_lookup_elem(&errs, &p);
	if (!e) {
		bpf_map_update_elem(&errs, &p, &n, BPF_NOEXIST);
		e = bpf_map_lookup_elem(&errs, &p);
		if (!e)
			return 0;
	}
	e->tp_err = BPF_CORE_READ(sk, sk_err);
	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(tp_fail_state, const struct sock *csk, int oldstate, int newstate)
{
	struct sock *sk = (struct sock *)csk;
	struct hc_err_seen *e;
	__u64 p = (__u64)sk;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP ||
	    oldstate != TCP_SYN_SENT || newstate != TCP_CLOSE)
		return 0;
	__sync_fetch_and_add(&fails, 1);
	if (BPF_CORE_READ(sk, sk_err))
		__sync_fetch_and_add(&fails_err_close, 1);
	e = bpf_map_lookup_elem(&errs, &p);
	if (!e)
		return 0;
	if (e->kprobe_err)
		__sync_fetch_and_add(&fails_err_kprobe, 1);
	if (e->tp_err)
		__sync_fetch_and_add(&fails_err_tp, 1);
	if (e->early_err)
		__sync_fetch_and_add(&fails_err_early, 1);
	bpf_map_delete_elem(&errs, &p);
	return 0;
}
