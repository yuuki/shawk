/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2026 Yuuki Tsubouchi */

/*
 * The wire protocol of a TCP connection, from the first payload that the
 * local socket sends (see shawk_tcp_sendmsg): the first bytes are read
 * once per connection into a buffer, and wire_classify() matches them with
 * the signatures of enum shawk_wire_proto.
 *
 * The functions read the buffer through rd8(), whose index is masked to
 * the buffer, so that the verifier accepts any offset; the bounds of what
 * was read are checked against its length. The tests compile this file
 * with a program of their own (testdata/wire.bpf.c) and run it on payloads.
 */
#ifndef __SHAWK_WIRE_H
#define __SHAWK_WIRE_H

/*
 * The bytes read of a first payload. A ClientHello of TLS tells the
 * highest version it offers in an extension after its cipher suites,
 * within about 300 bytes of the start for OpenSSL, Go and Java.
 */
#define PEEK_LEN 512
/*
 * The buffer is twice as long, so that a copy of up to PEEK_LEN bytes at
 * an offset below PEEK_LEN stays within it, and the index of rd8() is
 * masked to it.
 */
#define PEEK_BUF (2 * PEEK_LEN)
#define PEEK_MASK (PEEK_BUF - 1)
/* The segments of a writev(2) read: Slurm writes its length apart. */
#define PEEK_SEGS 4

struct shawk_peek {
	__u8 buf[PEEK_BUF];
};

/*
 * The barrier keeps the mask of a computed offset: clang drops a mask it
 * finds redundant, and the verifier may not know the bound clang relied on.
 */
static __always_inline __u32 rd8(const __u8 *b, __u32 off)
{
	if (!__builtin_constant_p(off))
		barrier_var(off);
	return b[off & PEEK_MASK];
}

static __always_inline __u32 rd16(const __u8 *b, __u32 off)
{
	return rd8(b, off) << 8 | rd8(b, off + 1);
}

static __always_inline __u32 rd32(const __u8 *b, __u32 off)
{
	return rd16(b, off) << 16 | rd16(b, off + 2);
}

/* Little endian, as MySQL has its integers. */
static __always_inline __u32 rd24le(const __u8 *b, __u32 off)
{
	return rd8(b, off) | rd8(b, off + 1) << 8 | rd8(b, off + 2) << 16;
}

static __always_inline __u32 rd32le(const __u8 *b, __u32 off)
{
	return rd24le(b, off) | rd8(b, off + 3) << 24;
}

/* Whether the payload starts with the n bytes of s, a string constant. */
static __always_inline bool starts(const __u8 *b, __u32 len, const char *s,
				   __u32 n)
{
	__u32 i;

	if (len < n)
		return false;
	for (i = 0; i < n; i++)
		if (b[i] != (__u8)s[i])
			return false;
	return true;
}

static __always_inline bool is_digit(__u32 c)
{
	return c >= '0' && c <= '9';
}

static __always_inline bool is_upper(__u32 c)
{
	return c >= 'A' && c <= 'Z';
}

/*
 * The highest version of TLS in the extension supported_versions of a
 * ClientHello, whose body of n bytes starts at off: a length and versions
 * of 2 bytes. GREASE values (RFC 8701) are skipped, and drafts of TLS 1.3
 * (0x7fxx) count as TLS 1.3.
 */
static __always_inline int tls_offered(const __u8 *b, __u32 len, __u32 off,
				       __u32 n)
{
	__u32 i, v, best = 0, list;

	if (n < 3 || off >= len)
		return WIRE_TLS;
	list = rd8(b, off);
	off++;
	/* Clients offer a few versions, the highest first. */
	for (i = 0; i < 8; i++) {
		if (2 * i + 2 > list)
			break;
		if (off + 2 > len)
			return WIRE_TLS;
		v = rd16(b, off);
		off += 2;
		if (v >= 0x0304 && (v & 0x0f0f) != 0x0a0a)
			return WIRE_TLS_1_3;
		if ((v & 0x0f0f) != 0x0a0a && v > best)
			best = v;
	}
	if (best == 0x0303)
		return WIRE_TLS_1_2;
	if (best == 0x0302)
		return WIRE_TLS_1_1;
	if (best)
		return WIRE_TLS_1_0;
	return WIRE_TLS;
}

/* The protocol of the version field of a TLS hello, before TLS 1.2. */
static __always_inline int tls_legacy(__u32 v)
{
	if (v == 0x0302)
		return WIRE_TLS_1_1;
	if (v == 0x0300 || v == 0x0301)
		return WIRE_TLS_1_0;
	return WIRE_TLS;
}

/*
 * A record of TLS: a type, a version 3.x and a length, then, for a
 * handshake, its type, length of 3 bytes and version. A ServerHello tells
 * the version the server chose: its version field before TLS 1.3, and for
 * TLS 1.3 the version 1.2 and a cipher suite that only TLS 1.3 has (0x13xx,
 * and the SM4 suites of RFC 8998, 0x00c6 and 0x00c7). A ClientHello tells
 * the highest version the client offers: its version field before TLS 1.2,
 * then the extension supported_versions, which clients of TLS 1.3 send, and
 * some of TLS 1.2. A hello longer than its record (a client that splits its
 * ClientHello, as some evade inspection) and other records, such as an
 * alert that refuses a client, are TLS of an unknown version.
 */
static __always_inline int wire_tls(const __u8 *b, __u32 len)
{
	__u32 off, end, rec, ver, type, n, i;

	if (len < 11 || rd8(b, 0) != 0x16)
		return WIRE_TLS;
	ver = rd16(b, 9);
	type = rd8(b, 5);
	if (type != 1 && type != 2)
		return WIRE_TLS;
	if (ver != 0x0303)
		return tls_legacy(ver);
	rec = 5 + rd16(b, 3);
	if (9 + (rd8(b, 6) << 16 | rd16(b, 7)) > rec)
		return WIRE_TLS;
	/* The session id follows the version and the random of 32 bytes. */
	off = 43;
	if (off >= len)
		return WIRE_TLS;
	off += 1 + rd8(b, off);
	if (type == 2) {
		if (off + 2 > len || off + 2 > rec)
			return WIRE_TLS;
		n = rd16(b, off);
		if ((n >> 8) == 0x13 || n == 0x00c6 || n == 0x00c7)
			return WIRE_TLS_1_3;
		return WIRE_TLS_1_2;
	}
	/* The cipher suites and the compression methods of a ClientHello. */
	if (off + 2 > len)
		return WIRE_TLS;
	off += 2 + rd16(b, off);
	if (off + 1 > len)
		return WIRE_TLS;
	off += 1 + rd8(b, off);
	/* A ClientHello without extensions, which ends its record. */
	if (off >= rec)
		return WIRE_TLS_1_2;
	if (off + 2 > len)
		return WIRE_TLS;
	end = off + 2 + rd16(b, off);
	off += 2;
	for (i = 0; i < 24; i++) {
		if (off >= end)
			return WIRE_TLS_1_2;
		if (off + 4 > len)
			return WIRE_TLS;
		type = rd16(b, off);
		n = rd16(b, off + 2);
		if (type == 0x002b)
			return tls_offered(b, len, off + 4, n);
		off += 4 + n;
	}
	return WIRE_TLS;
}

/*
 * A ClientHello in the format of SSL 2.0, which clients of SSL 3.0 and TLS
 * 1.0 to 1.2 could send to reach servers of SSL 2.0 (Java 6, OpenSSL 0.9.8
 * by default): a length of 15 bits with the high bit set, which counts the
 * rest of the send, the message 1 and the highest version offered.
 * Returns -1 for another payload.
 */
static __always_inline int sslv2_hello(const __u8 *b, __u32 len, __u64 size)
{
	__u32 v;

	if (len < 5 || !(rd8(b, 0) & 0x80) || rd8(b, 2) != 1 ||
	    ((rd8(b, 0) & 0x7f) << 8 | rd8(b, 1)) + 2ULL != size)
		return -1;
	v = rd16(b, 3);
	if (v == 0x0002 || v == 0x0300 || v == 0x0301)
		return WIRE_TLS_1_0;
	if (v == 0x0302)
		return WIRE_TLS_1_1;
	if (v == 0x0303)
		return WIRE_TLS_1_2;
	return -1;
}

/* The request line of HTTP/1.x. */
static __always_inline bool http1_request(const __u8 *b, __u32 len)
{
	return starts(b, len, "GET ", 4) || starts(b, len, "POST ", 5) ||
	       starts(b, len, "PUT ", 4) || starts(b, len, "HEAD ", 5) ||
	       starts(b, len, "DELETE ", 7) || starts(b, len, "OPTIONS ", 8) ||
	       starts(b, len, "PATCH ", 6) || starts(b, len, "CONNECT ", 8) ||
	       starts(b, len, "TRACE ", 6);
}

/*
 * The first message of a client of PostgreSQL: SSLRequest, which asks for
 * TLS, GSSENCRequest, which asks for the encryption of GSSAPI, and
 * CancelRequest, of fixed codes, or a StartupMessage of protocol 3.x, in
 * clear text, whose parameters start with a name (user, database, or _pq_.
 * of protocol 3.2). A request of Kafka has a length and a type and version
 * like a StartupMessage, but a number of the request after them, whose
 * first byte is not a letter. Returns -1 for another payload.
 */
static __always_inline int postgres_request(const __u8 *b, __u32 len)
{
	__u32 n, code, c;

	if (len < 8)
		return -1;
	n = rd32(b, 0);
	code = rd32(b, 4);
	if (n == 8 && code == 80877103)
		return WIRE_POSTGRES_TLS;
	if (n == 8 && code == 80877104)
		return WIRE_POSTGRES;
	/* The key of protocol 3.2 has up to 256 bytes rather than 4. */
	if (n >= 16 && n <= 12 + 256 && code == 80877102)
		return WIRE_POSTGRES;
	if (len < 9 || n <= 8 || n >= 10000 || (code >> 16) != 3 || (code & 0xffff) > 9)
		return -1;
	c = rd8(b, 8);
	return (c >= 'a' && c <= 'z') || c == '_' ? WIRE_POSTGRES : -1;
}

/*
 * The answer of a server of PostgreSQL: S alone, which accepts a request of
 * TLS, N or G alone, which refuses it or accepts GSSAPI, an authentication
 * request (R, a length and a method up to 12) or an error (E, a length and
 * the field of its severity). Returns -1 for another payload.
 */
static __always_inline int postgres_answer(const __u8 *b, __u32 len, __u64 size)
{
	__u32 c = rd8(b, 0), n;

	if (size == 1 && len == 1) {
		if (c == 'S')
			return WIRE_POSTGRES_TLS;
		return c == 'N' || c == 'G' ? WIRE_POSTGRES : -1;
	}
	if (len < 9)
		return -1;
	n = rd32(b, 1);
	if (c == 'R' && n >= 8 && n <= 2048 && rd32(b, 5) <= 12)
		return WIRE_POSTGRES;
	if (c == 'E' && n >= 8 && n <= 8192 && (rd8(b, 5) == 'S' || rd8(b, 5) == 'V'))
		return WIRE_POSTGRES;
	return -1;
}

/*
 * The packet a client of MySQL or MariaDB answers the greeting of the
 * server with, HandshakeResponse41 or SSLRequest: a length of 3 bytes, the
 * sequence number 1, capabilities with CLIENT_PROTOCOL_41, and CLIENT_SSL
 * when the client asks for TLS, the size of a packet, a character set and a
 * filler of zeros, whose last 4 bytes MariaDB uses. Returns -1 for another
 * payload.
 */
static __always_inline int mysql_response(const __u8 *b, __u32 len)
{
	__u32 i, caps;

	if (len < 36 || rd8(b, 3) != 1 || rd24le(b, 0) < 32)
		return -1;
	caps = rd32le(b, 4);
	if (!(caps & 0x200))
		return -1;
	for (i = 13; i < 32; i++)
		if (rd8(b, i))
			return -1;
	return caps & 0x800 ? WIRE_MYSQL_TLS : WIRE_MYSQL;
}

/*
 * The greeting of a server of MySQL or MariaDB: a length, the sequence
 * number 0, the protocol 10 and the version of the server, which starts
 * with a digit.
 */
static __always_inline bool mysql_greeting(const __u8 *b, __u32 len)
{
	__u32 n;

	if (len < 6)
		return false;
	n = rd24le(b, 0);
	return n >= 20 && n <= 1024 && rd8(b, 3) == 0 && rd8(b, 4) == 10 &&
	       is_digit(rd8(b, 5));
}

/* Whether CR LF follows the digits of a length of RESP at off. */
static __always_inline bool resp_number(const __u8 *b, __u32 len, __u32 off)
{
	__u32 i, c;

	if (off < len && rd8(b, off) == '-')
		off++;
	for (i = 0; i < 12; i++) {
		if (off + i + 2 > len)
			return false;
		c = rd8(b, off + i);
		if (c == '\r')
			return i > 0 && rd8(b, off + i + 1) == '\n';
		if (!is_digit(c))
			return false;
	}
	return false;
}

/*
 * A command of a client of RESP (Redis, Valkey): an array of bulk strings,
 * *<n> CR LF $<len> CR LF.
 */
static __always_inline bool redis_command(const __u8 *b, __u32 len)
{
	__u32 i;

	if (len < 9 || rd8(b, 0) != '*' || !resp_number(b, len, 1))
		return false;
	for (i = 2; i < 8; i++)
		if (rd8(b, i) == '\n')
			return rd8(b, i + 1) == '$';
	return false;
}

/*
 * The reply of a server of RESP: a simple string of capitals followed by CR
 * LF (+OK, +PONG, +QUEUED; not the +OK of a greeting of POP3, which goes on
 * with text), an error of capitals (-ERR, -NOAUTH), or a number, a bulk
 * string, an array, a map or a set of RESP3 (the reply to HELLO) with its
 * length.
 */
static __always_inline bool redis_reply(const __u8 *b, __u32 len)
{
	__u32 c = rd8(b, 0), i;

	if (len < 4)
		return false;
	if (c == '+') {
		for (i = 1; i < 16; i++) {
			if (i + 1 >= len)
				return false;
			c = rd8(b, i);
			if (c == '\r')
				return i > 2 && rd8(b, i + 1) == '\n';
			if (!is_upper(c))
				return false;
		}
		return false;
	}
	if (c == '-')
		return is_upper(rd8(b, 1)) && is_upper(rd8(b, 2));
	if (c == ':' || c == '$' || c == '*' || c == '%' || c == '~')
		return resp_number(b, len, 1);
	return false;
}

/* The versions of the protocol of Slurm, from 2.3 (23 << 8) on. */
static __always_inline bool slurm_version(__u32 hi, __u32 lo)
{
	return hi >= 23 && hi < 96 && lo == 0;
}

/* The types of the messages of Slurm, from REQUEST_NODE_REGISTRATION_STATUS. */
static __always_inline bool slurm_type(__u32 t)
{
	return t >= 1001 && t < 0x8000;
}

/*
 * A message of Slurm: its length in 4 bytes, which counts the rest of the
 * send, then a header of the version, flags and type, or, on the
 * connections of slurmdbd (SLURMDBD_CONNECTION), of the type first.
 */
static __always_inline bool slurm_message(const __u8 *b, __u32 len, __u64 size)
{
	if (len < 12 || rd32(b, 0) + 4ULL != size)
		return false;
	if (slurm_version(rd8(b, 4), rd8(b, 5)) && rd16(b, 6) < 0x200 &&
	    slurm_type(rd16(b, 8)))
		return true;
	return slurm_type(rd16(b, 4)) && slurm_version(rd8(b, 6), rd8(b, 7)) &&
	       (rd16(b, 8) & 0x2);
}

/*
 * The SETTINGS frame that a server of HTTP/2 starts with: a length of
 * settings of 6 bytes, the type 4, no flags and the stream 0.
 */
static __always_inline bool http2_settings(const __u8 *b, __u32 len)
{
	__u32 n;

	if (len < 9 || rd8(b, 3) != 4 || rd8(b, 4) != 0 || rd32(b, 5) != 0)
		return false;
	n = rd8(b, 0) << 16 | rd16(b, 1);
	return n % 6 == 0 && n <= 6 * 16;
}

/*
 * Returns the enum shawk_wire_proto of the first payload of a connection:
 * len bytes of it in b, of size in all. server tells the server side, and
 * answer that the local socket received data before, so that a server
 * answers a request rather than greets: a client of PostgreSQL, Redis or
 * HTTP speaks first, a server of MySQL or SSH greets first.
 */
static __always_inline int wire_classify(const __u8 *b, __u32 len, __u64 size,
					 bool server, bool answer)
{
	__u32 c;
	int p;

	/*
	 * The copies leave len in ranges that differ by path; one range lets
	 * the verifier check what follows once rather than for each.
	 */
	barrier_var(len);
	if (!len || len > PEEK_LEN)
		return WIRE_UNKNOWN;
	c = rd8(b, 0);
	/* Handshake, alert, change_cipher_spec or data, version 3.x. */
	if (c >= 0x14 && c <= 0x17 && len >= 3 && rd8(b, 1) == 3 && rd8(b, 2) <= 4)
		return wire_tls(b, len);
	if (starts(b, len, "SSH-", 4))
		return WIRE_SSH;
	if (!server) {
		if (starts(b, len, "PRI * HTTP/2.0\r\n", 16))
			return WIRE_HTTP2;
		if (http1_request(b, len))
			return WIRE_HTTP1;
		if (slurm_message(b, len, size))
			return WIRE_SLURM;
		if ((p = sslv2_hello(b, len, size)) >= 0)
			return p;
		if ((p = postgres_request(b, len)) >= 0)
			return p;
		if (answer && (p = mysql_response(b, len)) >= 0)
			return p;
		if (redis_command(b, len))
			return WIRE_REDIS;
		return WIRE_UNKNOWN;
	}
	if (starts(b, len, "HTTP/1.", 7))
		return WIRE_HTTP1;
	if (slurm_message(b, len, size))
		return WIRE_SLURM;
	if (http2_settings(b, len))
		return WIRE_HTTP2;
	/*
	 * A greeting, also after the header of the PROXY protocol, which a
	 * load balancer sends before its client speaks.
	 */
	if (mysql_greeting(b, len))
		return WIRE_MYSQL;
	if (!answer)
		return WIRE_UNKNOWN;
	if ((p = postgres_answer(b, len, size)) >= 0)
		return p;
	if (redis_reply(b, len))
		return WIRE_REDIS;
	return WIRE_UNKNOWN;
}

/*
 * Copies up to n bytes of user memory at src to b at off, within PEEK_LEN,
 * and returns how many were copied: none if the memory cannot be read.
 */
static __always_inline __u32 peek_user(__u8 *b, __u32 off, const void *src,
				       __u64 n)
{
	__u32 size;

	if (off >= PEEK_LEN || !n)
		return 0;
	size = PEEK_LEN - off;
	if (n < size)
		size = n;
	/* Bounds the verifier knows, whatever clang made of those above. */
	barrier_var(off);
	off &= PEEK_LEN - 1;
	barrier_var(size);
	if (size > PEEK_LEN)
		return 0;
	if (bpf_probe_read_user(b + off, size, src))
		return 0;
	return size;
}

/*
 * Copies the first bytes of a send from the user memory of its iovecs, the
 * kernel's copy of the array of writev(2) and sendmsg(2), to b from off:
 * up to PEEK_SEGS of nr segments, the first skip bytes into its first one,
 * count bytes in all. Returns the end of the bytes in b.
 */
static __always_inline __u32 peek_iovecs(__u8 *b, __u32 off,
					 const struct iovec *iov, __u64 nr,
					 __u64 skip, __u64 count)
{
	struct iovec v;
	__u32 got, i;
	__u64 n;

	for (i = 0; i < PEEK_SEGS; i++) {
		if (i >= nr || off >= PEEK_LEN || !count)
			break;
		if (bpf_probe_read_kernel(&v, sizeof(v), &iov[i]))
			break;
		n = v.iov_len;
		if (skip >= n) {
			skip -= n;
			continue;
		}
		n -= skip;
		if (n > count)
			n = count;
		got = peek_user(b, off, (const __u8 *)v.iov_base + skip, n);
		if (!got)
			break;
		skip = 0;
		off += got;
		count -= got;
		/* The buffer is full. */
		if (got < n)
			break;
	}
	return off;
}

#endif /* __SHAWK_WIRE_H */
