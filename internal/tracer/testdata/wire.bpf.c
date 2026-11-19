// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2026 Yuuki Tsubouchi */

/*
 * The classifier of wire protocols (../bpf/wire.h) in a program that the
 * tests run with BPF_PROG_RUN (TestWireClassify): it copies a payload from
 * the memory of the test through iovecs, as shawk_tcp_sendmsg copies the
 * first send of a connection, and classifies it. The tests compile it with
 * clang when they run; it is not part of the agent.
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
						       ctx->server, ctx->answer) : -1;
	return 0;
}
