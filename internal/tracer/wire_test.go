package tracer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestWireProtocolNames(t *testing.T) {
	want := map[WireProtocol]bpfShawkWireProto{
		WireUnknown: bpfShawkWireProtoWIRE_UNKNOWN, WireTLS: bpfShawkWireProtoWIRE_TLS,
		WireTLS10: bpfShawkWireProtoWIRE_TLS_10, WireTLS11: bpfShawkWireProtoWIRE_TLS_11,
		WireTLS12: bpfShawkWireProtoWIRE_TLS_12, WireTLS13: bpfShawkWireProtoWIRE_TLS_13,
		WireHTTP1: bpfShawkWireProtoWIRE_HTTP1, WireHTTP2: bpfShawkWireProtoWIRE_HTTP2,
		WireSSH: bpfShawkWireProtoWIRE_SSH, WirePostgres: bpfShawkWireProtoWIRE_POSTGRES,
		WireMySQL: bpfShawkWireProtoWIRE_MYSQL, WireRedis: bpfShawkWireProtoWIRE_REDIS,
		WireSlurm: bpfShawkWireProtoWIRE_SLURM, WirePostgresTLS: bpfShawkWireProtoWIRE_POSTGRES_TLS,
		WireMySQLTLS: bpfShawkWireProtoWIRE_MYSQL_TLS,
	}
	if len(want) != NumWireProtocols {
		t.Fatalf("%d protocols checked, want %d", len(want), NumWireProtocols)
	}
	for p, v := range want {
		if uint32(p) != uint32(v) {
			t.Errorf("%v = %d, enum shawk_wire_proto has %d", p, p, v)
		}
	}
	s := WireProtocols(1<<WireTLS13 | 1<<WireHTTP1)
	if got := s.String(); got != "tls_1_3,http1" {
		t.Errorf("String() = %q", got)
	}
	b, err := json.Marshal(s)
	if err != nil || string(b) != `["tls_1_3","http1"]` {
		t.Errorf("MarshalJSON() = %s, %v", b, err)
	}
	if b, _ := json.Marshal(WireProtocols(0)); string(b) != `[]` {
		t.Errorf("MarshalJSON() of no protocol = %s", b)
	}
}

// wireRun is the context of the program of testdata/wire.bpf.c.
type wireRun struct {
	Size, Nr, Skip             uint64
	Server, Answer, Fill, Held uint8
	Proto                      int32
	Peeked                     uint32
	Prefix                     uint32
	Iov                        [4]struct{ Base, Len uint64 }
}

// wireClassifier runs the classifier of wire protocols of the BPF programs,
// compiled with the test program of testdata/wire.bpf.c.
type wireClassifier struct {
	t    *testing.T
	prog *ebpf.Program
}

func newWireClassifier(t *testing.T) *wireClassifier {
	t.Helper()
	requireRoot(t)
	clang, err := exec.LookPath("clang")
	if err != nil {
		// The kernels of make vm-test have no compiler; CI has one.
		t.Skip("the classifier is compiled with clang, which is not installed")
	}
	// Next to this file: make test-root runs the compiled tests elsewhere.
	_, self, _, _ := runtime.Caller(0)
	dir := filepath.Dir(self)
	obj := filepath.Join(t.TempDir(), "wire.o")
	cmd := exec.Command(clang, "-O2", "-g", "-Wall", "-Werror", "-mcpu=v3", "-target", "bpfel",
		"-I", filepath.Join(dir, "bpf", "include"), "-I", filepath.Join(dir, "bpf"),
		"-c", filepath.Join(dir, "testdata", "wire.bpf.c"), "-o", obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compiling testdata/wire.bpf.c: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("loading the classifier: %+v", verr)
		}
		// BPF_PROG_TYPE_SYSCALL needs Linux 5.14.
		skipUnavailable(t, "loading the classifier: %v", err)
	}
	t.Cleanup(func() { coll.Close() })
	return &wireClassifier{t: t, prog: coll.Programs["wire_run"]}
}

// wireNone is what run returns when nothing was classified.
const wireNone = WireProtocol(255)

// wireSend is a send to classify: its segments, the bytes to skip into
// the first, the side and whether it answers, and the 4 bytes of a first
// send held before it, if any.
type wireSend struct {
	segs           [][]byte
	skip           int
	server, answer bool
	held           []byte
}

// classify runs the classifier on a send of segments, skipping skip bytes
// into the first, and returns the protocol and the bytes copied.
func (c *wireClassifier) classify(segs [][]byte, skip int, server, answer bool) (WireProtocol, int) {
	c.t.Helper()
	return c.run(wireSend{segs: segs, skip: skip, server: server, answer: answer})
}

// run classifies a send, with the buffer filled with zeros, with 0xff and
// with $ before, which must not change the result: the bytes beyond what
// was copied are those of an earlier send, which the agent wipes, or
// garbage. It returns -1 as WireProtocol(255) when nothing was classified.
func (c *wireClassifier) run(w wireSend) (WireProtocol, int) {
	c.t.Helper()
	var (
		results [3]wireRun
		size    int
	)
	for _, s := range w.segs {
		size += len(s)
	}
	for i, fill := range []uint8{0, 0xff, '$'} {
		run := wireRun{Size: uint64(size - w.skip), Nr: uint64(len(w.segs)), Skip: uint64(w.skip), Fill: fill}
		if w.server {
			run.Server = 1
		}
		if w.answer {
			run.Answer = 1
		}
		if w.held != nil {
			run.Held = 1
			run.Prefix = binary.NativeEndian.Uint32(w.held)
		}
		for j, s := range w.segs[:min(len(w.segs), len(run.Iov))] {
			if len(s) > 0 {
				run.Iov[j].Base = uint64(uintptr(unsafe.Pointer(&s[0])))
			}
			run.Iov[j].Len = uint64(len(s))
		}
		var in bytes.Buffer
		if err := binary.Write(&in, binary.NativeEndian, &run); err != nil {
			c.t.Fatal(err)
		}
		out := make([]byte, in.Len())
		ret, err := c.prog.Run(&ebpf.RunOptions{Context: in.Bytes(), ContextOut: out})
		runtime.KeepAlive(w.segs)
		if err != nil || ret != 0 {
			c.t.Fatalf("running the classifier: %d, %v", ret, err)
		}
		if err := binary.Read(bytes.NewReader(out), binary.NativeEndian, &results[i]); err != nil {
			c.t.Fatal(err)
		}
	}
	for _, r := range results[1:] {
		if r.Proto != results[0].Proto || r.Peeked != results[0].Peeked {
			c.t.Errorf("the result depends on the bytes beyond the payload: %+v", results)
			break
		}
	}
	return WireProtocol(uint8(results[0].Proto)), int(results[0].Peeked)
}

// tlsCertificate returns a self-signed certificate for the servers of TLS.
func tlsCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// firstWrite returns the first write of a peer of a net.Pipe.
func firstWrite(t *testing.T, c net.Conn) []byte {
	t.Helper()
	b := make([]byte, 1<<16)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("reading the first write: %v", err)
	}
	return b[:n]
}

// tlsHellos returns the ClientHello of a client of crypto/tls that offers
// TLS up to maxVersion and the first write of a server up to it, which
// starts with its ServerHello.
func tlsHellos(t *testing.T, cert tls.Certificate, maxVersion uint16) (client, server []byte) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tc := tls.Client(c1, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: maxVersion})
	go tc.Handshake()
	client = firstWrite(t, c2)

	s1, s2 := net.Pipe()
	defer s1.Close()
	defer s2.Close()
	ts := tls.Server(s1, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
	go ts.Handshake()
	go s2.Write(client)
	server = firstWrite(t, s2)
	return client, server
}

// clientHello builds a ClientHello of TLS 1.2 whose extensions are exts,
// each a type and a body, after a session id of 32 bytes and 16 cipher
// suites.
func clientHello(exts ...[]byte) []byte {
	var body []byte
	body = append(body, 3, 3)
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = binary.BigEndian.AppendUint16(body, 32)
	for i := range 16 {
		body = binary.BigEndian.AppendUint16(body, 0xc000+uint16(i))
	}
	body = append(body, 1, 0)
	var ext []byte
	for _, e := range exts {
		ext = append(ext, e...)
	}
	if exts != nil {
		body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
		body = append(body, ext...)
	}
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// extension builds an extension of TLS.
func extension(typ uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

// supportedVersions builds the body of the extension supported_versions.
func supportedVersions(vs ...uint16) []byte {
	b := []byte{byte(2 * len(vs))}
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

// slurmHeader builds the header of a message of Slurm 24.05 of a type:
// the version, flags, type, length of the body, no forward or returns, and
// an address.
func slurmHeader(msgType uint16, flags uint16, body int) []byte {
	var b []byte
	if flags&0x2 != 0 {
		b = binary.BigEndian.AppendUint16(b, msgType)
	}
	b = binary.BigEndian.AppendUint16(b, 41<<8)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, msgType)
	b = binary.BigEndian.AppendUint32(b, uint32(body))
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	return append(b, 0, 0)
}

// slurmSend returns the iovecs Slurm writes a message with (slurm_bufs_sendto):
// the length of the rest, the header, the credential and the body.
func slurmSend(header, auth, body []byte) [][]byte {
	n := binary.BigEndian.AppendUint32(nil, uint32(len(header)+len(auth)+len(body)))
	return [][]byte{n, header, auth, body}
}

// mysqlPacket builds a packet of MySQL of a sequence number.
func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// serverHello builds a ServerHello of version 1.2 that chose a cipher
// suite, after a session id of 32 bytes.
func serverHello(cipher uint16) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0, 0, 0)
	hs := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// tlsRecords splits the handshake of a record of TLS into records of n
// bytes, as clients that evade inspection do.
func tlsRecords(record []byte, n int) []byte {
	var out []byte
	for hs := record[5:]; len(hs) > 0; {
		k := min(n, len(hs))
		out = append(out, record[0], record[1], record[2], byte(k>>8), byte(k))
		out = append(out, hs[:k]...)
		hs = hs[k:]
	}
	return out
}

// sslv2Hello builds a ClientHello in the format of SSL 2.0 that offers up
// to version.
func sslv2Hello(version uint16) []byte {
	body := []byte{1}
	body = binary.BigEndian.AppendUint16(body, version)
	body = append(body, 0, 6, 0, 0, 0, 16)      // cipher specs, session id, challenge
	body = append(body, 0, 0, 0x2f, 0, 0, 0x35) // two cipher specs
	body = append(body, make([]byte, 16)...)
	return append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
}

// mysqlGreeting is the greeting of a server of MySQL 8.0.
func mysqlGreeting() []byte {
	return mysqlPacket(0, append([]byte("\x0a8.0.36\x00\x01\x00\x00\x00abcdefgh\x00\xff\xff\x21\x02\x00\xff\xdf\x15"),
		append(make([]byte, 10), []byte("ijklmnopqrstu\x00caching_sha2_password\x00")...)...))
}

// mysqlResponse is the HandshakeResponse41 of a client of MySQL without
// TLS, and mysqlSSLRequest the SSLRequest of one that asks for it
// (CLIENT_SSL).
func mysqlResponse() []byte {
	return mysqlPacket(1, append(append([]byte("\x85\xa6\xff\x19\x00\x00\x00\x01\x21"), make([]byte, 23)...),
		[]byte("root\x00\x14abcdefghijklmnopqrst")...))
}

func mysqlSSLRequest() []byte {
	return mysqlPacket(1, append([]byte("\x85\xae\xff\x19\x00\x00\x00\x01\x21"), make([]byte, 23)...))
}

func TestWireClassify(t *testing.T) {
	c := newWireClassifier(t)
	cert := tlsCertificate(t)
	type tc struct {
		name           string
		segs           [][]byte
		server, answer bool
		held           []byte
		want           WireProtocol
	}
	one := func(s string) [][]byte { return [][]byte{[]byte(s)} }
	var (
		cases      []tc
		tls13Hello []byte
	)
	for _, v := range []struct {
		version uint16
		want    WireProtocol
	}{{tls.VersionTLS13, WireTLS13}, {tls.VersionTLS12, WireTLS12}, {tls.VersionTLS11, WireTLS11}, {tls.VersionTLS10, WireTLS10}} {
		client, server := tlsHellos(t, cert, v.version)
		if v.want == WireTLS13 {
			tls13Hello = client
		}
		cases = append(cases,
			tc{name: "ClientHello up to " + v.want.String(), segs: [][]byte{client}, want: v.want},
			tc{name: "ServerHello of " + v.want.String(), segs: [][]byte{server}, server: true, answer: true, want: v.want})
	}
	startup := []byte("\x00\x00\x00\x00\x00\x03\x00\x00user\x00postgres\x00database\x00app\x00\x00")
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))
	greeting, response, sslRequest := mysqlGreeting(), mysqlResponse(), mysqlSSLRequest()
	settings := []byte("\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\xfa\x00\x04\x00\x10\x00\x00\x00\x06\x00\x10\x01\x40")
	ping := []byte("body of the ping")
	cases = append(cases,
		// TLS whose version the first bytes do not tell.
		tc{name: "supported_versions beyond the bytes read", segs: [][]byte{clientHello(
			extension(0x0015, make([]byte, 600)), extension(0x002b, supportedVersions(0x0304, 0x0303)))}, want: WireTLS},
		tc{name: "supported_versions with GREASE", segs: [][]byte{clientHello(
			extension(0x002b, supportedVersions(0x1a1a, 0x0304, 0x0303)))}, want: WireTLS13},
		tc{name: "supported_versions up to TLS 1.2", segs: [][]byte{clientHello(
			extension(0x000a, []byte{0, 2, 0, 0x1d}), extension(0x002b, supportedVersions(0x0303)))}, want: WireTLS12},
		tc{name: "ClientHello without supported_versions", segs: [][]byte{clientHello(extension(0x000a, []byte{0, 2, 0, 0x1d}))},
			want: WireTLS12},
		tc{name: "ClientHello without extensions", segs: [][]byte{clientHello()}, want: WireTLS12},
		tc{name: "alert", segs: [][]byte{{0x15, 3, 3, 0, 2, 2, 70}}, server: true, answer: true, want: WireTLS},
		tc{name: "ServerHello of SM4 (RFC 8998)", segs: [][]byte{serverHello(0x00c6)}, server: true, answer: true, want: WireTLS13},
		tc{name: "ServerHello of TLS 1.2", segs: [][]byte{serverHello(0xc02f)}, server: true, answer: true, want: WireTLS12},
		tc{name: "ClientHello in records of 60 bytes", segs: [][]byte{tlsRecords(tls13Hello, 60)}, want: WireTLS},
		tc{name: "SSL 2.0 ClientHello up to TLS 1.0", segs: [][]byte{sslv2Hello(0x0301)}, want: WireTLS10},
		tc{name: "SSL 2.0 ClientHello up to TLS 1.2", segs: [][]byte{sslv2Hello(0x0303)}, want: WireTLS12},
		// HTTP.
		tc{name: "HTTP/1.1 request", segs: one("GET / HTTP/1.1\r\nHost: app\r\n\r\n"), want: WireHTTP1},
		tc{name: "HTTP/1.1 request in iovecs", segs: [][]byte{[]byte("POST /v1/x HTTP/1.1\r\n"), []byte("Host: app\r\n\r\n")},
			want: WireHTTP1},
		tc{name: "HTTP/1.1 response", segs: one("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), server: true, answer: true,
			want: WireHTTP1},
		tc{name: "HTTP/2 preface", segs: [][]byte{append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), settings...)}, want: WireHTTP2},
		tc{name: "HTTP/2 settings of a server", segs: [][]byte{settings}, server: true, want: WireHTTP2},
		// SSH.
		tc{name: "SSH client", segs: one("SSH-2.0-OpenSSH_9.6\r\n"), answer: true, want: WireSSH},
		tc{name: "SSH server", segs: one("SSH-2.0-OpenSSH_8.7\r\n"), server: true, want: WireSSH},
		// PostgreSQL.
		tc{name: "PostgreSQL SSLRequest", segs: [][]byte{{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}}, want: WirePostgresTLS},
		tc{name: "PostgreSQL GSSENCRequest", segs: [][]byte{{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30}}, want: WirePostgres},
		tc{name: "PostgreSQL CancelRequest", segs: [][]byte{{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 1, 2, 3, 4, 5, 6}},
			want: WirePostgres},
		tc{name: "PostgreSQL CancelRequest of protocol 3.2", segs: [][]byte{append([]byte{0, 0, 0, 44, 0x04, 0xd2, 0x16, 0x2e,
			0, 0, 1, 2}, make([]byte, 32)...)}, want: WirePostgres},
		tc{name: "PostgreSQL StartupMessage", segs: [][]byte{startup}, want: WirePostgres},
		tc{name: "PostgreSQL accepts TLS", segs: one("S"), server: true, answer: true, want: WirePostgresTLS},
		tc{name: "PostgreSQL refuses TLS", segs: one("N"), server: true, answer: true, want: WirePostgres},
		// A request of Kafka without ApiVersions first: Metadata (3) of
		// version 1, a number and a client id.
		tc{name: "Kafka Metadata", segs: [][]byte{append(binary.BigEndian.AppendUint32(nil, 20),
			[]byte("\x00\x03\x00\x01\x00\x00\x00\x07\x00\x06client\xff\xff\xff\xff")...)}, want: WireUnknown},
		tc{name: "PostgreSQL asks for SCRAM", segs: one("R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\x00\x00"), server: true,
			answer: true, want: WirePostgres},
		tc{name: "PostgreSQL refuses", segs: one("E\x00\x00\x00\x40SFATAL\x00VFATAL\x00C28000\x00Mno pg_hba.conf entry\x00\x00"),
			server: true, answer: true, want: WirePostgres},
		// MySQL.
		tc{name: "MySQL greeting", segs: [][]byte{greeting}, server: true, want: WireMySQL},
		tc{name: "MySQL handshake response", segs: [][]byte{response}, answer: true, want: WireMySQL},
		tc{name: "MySQL SSLRequest", segs: [][]byte{sslRequest}, answer: true, want: WireMySQLTLS},
		// A load balancer sent the header of the PROXY protocol first.
		tc{name: "MySQL greeting after a PROXY header", segs: [][]byte{greeting}, server: true, answer: true, want: WireMySQL},
		tc{name: "POP3 greeting after a PROXY header", segs: one("+OK POP3 server ready\r\n"), server: true, answer: true,
			want: WireUnknown},
		// RESP.
		tc{name: "Redis command", segs: one("*1\r\n$4\r\nPING\r\n"), want: WireRedis},
		tc{name: "Redis command of many arguments", segs: one("*12\r\n$4\r\nHSET\r\n$3\r\nkey\r\n"), want: WireRedis},
		tc{name: "Redis reply", segs: one("+PONG\r\n"), server: true, answer: true, want: WireRedis},
		tc{name: "Redis OK", segs: one("+OK\r\n"), server: true, answer: true, want: WireRedis},
		// 8 bytes: the byte after them, which a $ would make a command, is
		// not read.
		tc{name: "Redis array of 8 bytes", segs: one("*12345\r\n"), want: WireUnknown},
		tc{name: "Redis error", segs: one("-NOAUTH Authentication required.\r\n"), server: true, answer: true, want: WireRedis},
		tc{name: "Redis map of HELLO 3", segs: one("%7\r\n$6\r\nserver\r\n$5\r\nredis\r\n"), server: true, answer: true,
			want: WireRedis},
		// Greetings of servers that speak first are not replies.
		tc{name: "POP3 greeting", segs: one("+OK POP3 server ready\r\n"), server: true, want: WireUnknown},
		tc{name: "SMTP greeting", segs: one("220 mail.example ESMTP\r\n"), server: true, want: WireUnknown},
		// Slurm.
		tc{name: "Slurm ping", segs: slurmSend(slurmHeader(1008, 0, len(ping)), []byte("auth/munge credential"), ping),
			want: WireSlurm},
		tc{name: "Slurm reply", segs: slurmSend(slurmHeader(8001, 0, 4), nil, []byte{0, 0, 0, 0}), server: true, answer: true,
			want: WireSlurm},
		tc{name: "slurmdbd", segs: slurmSend(slurmHeader(1407, 0x2, len(ping)), []byte("cred"), ping), want: WireSlurm},
		tc{name: "Slurm length that is not the send's", segs: [][]byte{append(binary.BigEndian.AppendUint32(nil, 99),
			slurmHeader(1008, 0, 4)...)}, want: WireUnknown},
		// Slurm before 24.05 sends the length apart, which is held: the
		// next send is classified after it.
		tc{name: "Slurm after its length held", segs: [][]byte{slurmHeader(1008, 0, len(ping)), []byte("auth"), ping},
			held: binary.BigEndian.AppendUint32(nil, uint32(len(slurmHeader(1008, 0, len(ping)))+4+len(ping))), want: WireSlurm},
		// Others.
		tc{name: "text", segs: one("hello\n"), want: WireUnknown},
		tc{name: "one byte", segs: one("x"), server: true, answer: true, want: WireUnknown},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n := c.run(wireSend{segs: tc.segs, server: tc.server, answer: tc.answer, held: tc.held})
			if got != tc.want {
				t.Errorf("classified as %v, want %v", got, tc.want)
			}
			size := len(tc.held)
			for _, s := range tc.segs {
				size += len(s)
			}
			if want := min(size, 512); n != want {
				t.Errorf("%d bytes in the buffer, want %d", n, want)
			}
		})
	}
}

// TestWirePeek checks the copy of the first bytes of a send from its
// iovecs: the offset into the first, empty segments, and the bound of the
// buffer.
func TestWirePeek(t *testing.T) {
	c := newWireClassifier(t)
	req := []byte("GET / HTTP/1.1\r\n\r\n")
	for _, tc := range []struct {
		name string
		segs [][]byte
		skip int
		want int
	}{
		{"offset into the first", [][]byte{append([]byte("xx"), req...)}, 2, len(req)},
		{"offset beyond the first", [][]byte{[]byte("xxx"), req}, 3, len(req)},
		{"empty segments", [][]byte{{}, req[:3], {}, req[3:]}, 0, len(req)},
		{"longer than the buffer", [][]byte{bytes.Repeat(req, 100)}, 0, 512},
		{"segments longer than the buffer", [][]byte{bytes.Repeat(req, 20), bytes.Repeat(req, 20)}, 0, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, n := c.classify(tc.segs, tc.skip, false, false)
			if got != WireHTTP1 || n != tc.want {
				t.Errorf("%v of %d bytes, want http1 of %d", got, n, tc.want)
			}
		})
	}
	// A fifth segment is not read: a send of nothing else is not
	// classified.
	got, n := c.classify([][]byte{{}, {}, {}, {}, req}, 0, false, false)
	if got != wireNone || n != 0 {
		t.Errorf("a fifth segment: %v of %d bytes, want nothing", got, n)
	}
}

// requireProtocols skips a test of the classification of wire protocols
// when the kernel cannot attach its program, which needs BPF trampolines.
// SHAWK_TEST_NO_TRAMPOLINES=1 declares a kernel without them: the program
// must then be reported unattached, and the test is skipped even in strict
// mode.
func requireProtocols(t *testing.T, tr *Tracer) {
	t.Helper()
	if noTrampolines, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_TRAMPOLINES")); noTrampolines {
		if tr.ProtocolsEnabled() {
			t.Fatal("wire protocols are classified, but SHAWK_TEST_NO_TRAMPOLINES declares no BPF trampolines")
		}
		t.Skip("wire protocols are not classified without BPF trampolines")
	}
	if !tr.ProtocolsEnabled() {
		skipUnavailable(t, "wire protocols are not classified on this kernel")
	}
}

// wireServer accepts connections and runs serve on each.
func wireServer(t *testing.T, serve func(net.Conn)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				serve(c)
			}()
		}
	}()
	return ln
}

// exchange writes each request and reads an answer to it.
func exchange(c net.Conn, requests ...string) error {
	buf := make([]byte, 4096)
	for _, r := range requests {
		if _, err := c.Write([]byte(r)); err != nil {
			return err
		}
		if _, err := c.Read(buf); err != nil {
			return err
		}
	}
	return nil
}

// answer reads requests and answers each with the next of answers.
func answer(answers ...string) func(net.Conn) {
	return func(c net.Conn) {
		buf := make([]byte, 4096)
		for _, a := range answers {
			if _, err := c.Read(buf); err != nil {
				return
			}
			if _, err := c.Write([]byte(a)); err != nil {
				return
			}
		}
	}
}

// TestWireProtocols checks the wire protocols of connections on loopback,
// on both sides, from their first payloads: TLS as crypto/tls offers and
// chooses it, and protocols in clear text.
func TestWireProtocols(t *testing.T) {
	requireRoot(t)
	cert := tlsCertificate(t)
	// A connection that predates the tracer is adopted, and its first
	// payload was sent before: it is not classified.
	adopted := wireServer(t, answer("HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"))
	old, err := net.Dial("tcp4", adopted.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := exchange(old, "GET / HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	tr, err := New(Options{TraceSelf: true, OwnerScanInterval: time.Hour, ClassifyProtocols: true, Logger: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	requireProtocols(t, tr)

	tlsServe := func(c net.Conn) {
		answer("pong\n")(tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	}
	tlsDial := func(maxVersion uint16) func(net.Conn) error {
		return func(c net.Conn) error {
			return exchange(tls.Client(c, &tls.Config{InsecureSkipVerify: true, MaxVersion: maxVersion}), "ping\n")
		}
	}
	plain := func(requests ...string) func(net.Conn) error {
		return func(c net.Conn) error { return exchange(c, requests...) }
	}
	// A client of a server that greets first reads the greeting first.
	greeted := func(requests ...string) func(net.Conn) error {
		return func(c net.Conn) error {
			if _, err := c.Read(make([]byte, 4096)); err != nil {
				return err
			}
			return exchange(c, requests...)
		}
	}
	greet := func(greeting string, answers ...string) func(net.Conn) {
		return func(c net.Conn) {
			if _, err := c.Write([]byte(greeting)); err == nil {
				answer(answers...)(c)
			}
		}
	}
	// Slurm 24.05 and later write the length of a message with it, in one
	// writev(2), which reaches the iovecs of the kernel; before, apart.
	// Each side reads the whole message of the other.
	ping := []byte("body of the ping")
	slurmPing := slurmSend(slurmHeader(1008, 0, len(ping)), []byte("auth/munge credential"), ping)
	slurmRC := slurmSend(slurmHeader(8001, 0, 4), nil, []byte{0, 0, 0, 0})
	slurmWrite := func(c net.Conn, msg [][]byte, apart bool) error {
		if apart {
			if _, err := c.Write(msg[0]); err != nil {
				return err
			}
			_, err := c.Write(bytes.Join(msg[1:], nil))
			return err
		}
		_, err := (&net.Buffers{msg[0], msg[1], msg[2], msg[3]}).WriteTo(c)
		return err
	}
	slurmRead := func(c net.Conn, msg [][]byte) error {
		_, err := io.ReadFull(c, make([]byte, len(bytes.Join(msg, nil))))
		return err
	}
	slurmClient := func(apart bool) func(net.Conn) error {
		return func(c net.Conn) error {
			if err := slurmWrite(c, slurmPing, apart); err != nil {
				return err
			}
			return slurmRead(c, slurmRC)
		}
	}
	slurmServer := func(apart bool) func(net.Conn) {
		return func(c net.Conn) {
			if slurmRead(c, slurmPing) == nil {
				slurmWrite(c, slurmRC, apart)
			}
		}
	}
	cases := []struct {
		name           string
		serve          func(net.Conn)
		dial           func(net.Conn) error
		client, server WireProtocol
	}{
		{"TLS 1.3", tlsServe, tlsDial(tls.VersionTLS13), WireTLS13, WireTLS13},
		{"TLS 1.2", tlsServe, tlsDial(tls.VersionTLS12), WireTLS12, WireTLS12},
		{"HTTP/1.1", answer("HTTP/1.1 204 No Content\r\n\r\n"), plain("GET / HTTP/1.1\r\nHost: app\r\n\r\n"), WireHTTP1, WireHTTP1},
		{"Redis", answer("+PONG\r\n"), plain("*1\r\n$4\r\nPING\r\n"), WireRedis, WireRedis},
		{"unknown", answer("hello\n"), plain("hello\n"), WireUnknown, WireUnknown},
		// Only the first payload counts.
		{"HTTP/1.1, then RESP", answer("HTTP/1.1 200 OK\r\n\r\n", "+PONG\r\n"),
			plain("GET / HTTP/1.1\r\n\r\n", "*1\r\n$4\r\nPING\r\n"), WireHTTP1, WireHTTP1},
		{"PostgreSQL refusing TLS", answer("N"), plain("\x00\x00\x00\x08\x04\xd2\x16\x2f"), WirePostgresTLS, WirePostgres},
		{"SSH", greet("SSH-2.0-OpenSSH_8.7\r\n", "\x00\x00\x01\x0c"), greeted("SSH-2.0-OpenSSH_9.6\r\n"), WireSSH, WireSSH},
		{"MySQL", greet(string(mysqlGreeting()), "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"),
			greeted(string(mysqlResponse())), WireMySQL, WireMySQL},
		{"Slurm 24.05", slurmServer(false), slurmClient(false), WireSlurm, WireSlurm},
		{"Slurm 23.11", slurmServer(true), slurmClient(true), WireSlurm, WireSlurm},
	}
	ports := map[string]uint16{}
	for _, tc := range cases {
		ln := wireServer(t, tc.serve)
		ports[tc.name] = uint16(ln.Addr().(*net.TCPAddr).Port)
		for range 2 {
			c, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.dial(c); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			c.Close()
		}
	}
	if err := exchange(old, "GET /again HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, side := range []struct {
				dir  Direction
				want WireProtocol
			}{{DirOut, tc.client}, {DirIn, tc.server}} {
				f := findFlow(snap.Flows, side.dir, ProtoTCP, ports[tc.name], lo)
				if f == nil {
					t.Fatalf("no %v flow to port %d in %+v", side.dir, ports[tc.name], snap.Flows)
				}
				if want := WireProtocols(1 << side.want); f.Protocols != want {
					t.Errorf("%v flow: protocols %v, want %v", side.dir, f.Protocols, want)
				}
			}
		})
	}
	port := uint16(adopted.Addr().(*net.TCPAddr).Port)
	for _, dir := range []Direction{DirOut, DirIn} {
		if f := findFlow(snap.Flows, dir, ProtoTCP, port, lo); f != nil && f.Protocols != 0 {
			t.Errorf("adopted %v flow: protocols %v, want none", dir, f.Protocols)
		}
	}
}
