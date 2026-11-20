// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2026 Yuuki Tsubouchi */

/*
 * The classifier of wire protocols (../bpf/wire.h) in programs that the
 * tests run with BPF_PROG_RUN: wire_run copies a payload from the memory of
 * the test through iovecs, as shawk_tcp_sendmsg copies the first send of a
 * connection, and classifies it (TestWireClassify); peek_run runs
 * peek_msg() on a msghdr made up for the running kernel (TestWirePeekMsg).
 * The tests compile them with clang when they run; they are not part of the
 * agent.
 */

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>

#include "shawk.h"
#include "wire.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* The context of a run, struct wireRun of the test. */
struct wire_run {
	__u64 size;   /* in: the bytes of the send in all */
	__u64 nr;     /* in: the iovecs */
	__u64 skip;   /* in: the bytes to skip into the first iovec */
	__u8 server;  /* in */
	__u8 answer;  /* in */
	__u8 fill;    /* in: the bytes the buffer holds before the copy */
	__u8 held;    /* in: a first send of 4 bytes, prefix, was held */
	__s32 proto;  /* out: enum shawk_wire_proto */
	__u32 peeked; /* out: the end of the bytes in the buffer */
	__u32 prefix; /* in: the bytes of the held send */
	struct iovec iov[PEEK_SEGS]; /* in: in the memory of the test */
};

/* The kernel's copy of the iovecs, and the buffer, as in the agent. */
struct wire_scratch {
	struct shawk_peek peek;
	struct iovec iov[PEEK_SEGS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wire_scratch);
} scratch SEC(".maps");

SEC("syscall")
int wire_run(struct wire_run *ctx)
{
	struct wire_scratch *s;
	__u32 zero = 0, off = 0;

	s = bpf_map_lookup_elem(&scratch, &zero);
	if (!s)
		return 1;
	__builtin_memset(s->peek.buf, ctx->fill, sizeof(s->peek.buf));
	__builtin_memcpy(s->iov, ctx->iov, sizeof(s->iov));
	/* As shawk_tcp_sendmsg classifies the send after a held one. */
	if (ctx->held) {
		*(__u32 *)s->peek.buf = ctx->prefix;
		off = 4;
	}
	ctx->peeked = peek_iovecs(s->peek.buf, off, s->iov, ctx->nr, ctx->skip, ctx->size);
	ctx->proto = ctx->peeked > off ? wire_classify(s->peek.buf, ctx->peeked, ctx->size + off,
						       ctx->server, ctx->answer, ctx->held) : -1;
	return 0;
}

/* The context of a run of peek_msg(), struct peekRun of the test. */
struct peek_run {
	__u64 size;   /* in: the count of the iov_iter */
	__u64 nr;     /* in: the iovecs, for ITER_IOVEC */
	__u64 skip;   /* in: its iov_offset */
	__u8 ubuf;    /* in: ITER_UBUF, from iov[0].iov_base, rather than ITER_IOVEC */
	__u8 _pad[3];
	__s32 proto;  /* out: enum shawk_wire_proto of a client */
	__u32 peeked; /* out: the end of the bytes in the buffer */
	__u32 _pad2;
	struct iovec iov[PEEK_SEGS]; /* in: in the memory of the test */
};

/* A msghdr made up in a map value, larger than that of any kernel. */
struct peek_scratch {
	struct shawk_peek peek;
	struct iovec iov[PEEK_SEGS];
	__u8 msg[512];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct peek_scratch);
} peek_scratch SEC(".maps");

/*
 * Runs peek_msg() of the agent on a send of the test: the members of the
 * msghdr are written at their offsets in the running kernel (CO-RE), with
 * the values of enum iter_type of the running kernel.
 */
SEC("syscall")
int peek_run(struct peek_run *ctx)
{
	struct peek_scratch *s;
	struct msghdr *m;
	struct iov_iter___ubuf *ub;
	struct iov_iter___iov64 *it64;
	struct iov_iter___iov *old;
	__u32 zero = 0;

	s = bpf_map_lookup_elem(&peek_scratch, &zero);
	if (!s)
		return 1;
	if (bpf_core_type_size(struct msghdr) > sizeof(s->msg))
		return 2;
	__builtin_memset(s->peek.buf, 0, sizeof(s->peek.buf));
	__builtin_memset(s->msg, 0, sizeof(s->msg));
	__builtin_memcpy(s->iov, ctx->iov, sizeof(s->iov));
	m = (void *)s->msg;
	ub = (void *)&m->msg_iter;
	it64 = (void *)&m->msg_iter;
	old = (void *)&m->msg_iter;
	m->msg_iter.iov_offset = ctx->skip;
	m->msg_iter.count = ctx->size;
	if (ctx->ubuf) {
		if (!bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) ||
		    !bpf_core_field_exists(ub->ubuf))
			return 3;
		m->msg_iter.iter_type = bpf_core_enum_value(enum iter_type, ITER_UBUF);
		ub->ubuf = s->iov[0].iov_base;
	} else {
		m->msg_iter.iter_type = bpf_core_enum_value(enum iter_type, ITER_IOVEC);
		m->msg_iter.nr_segs = ctx->nr;
		if (bpf_core_field_exists(it64->__iov))
			it64->__iov = s->iov;
		else
			old->iov = s->iov;
	}
	ctx->peeked = peek_msg(s->peek.buf, 0, m);
	ctx->proto = ctx->peeked ? wire_classify(s->peek.buf, ctx->peeked, ctx->size, false, false, false) : -1;
	return 0;
}
