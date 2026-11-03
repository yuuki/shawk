package tracer

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireConntrack skips a test of translations when the kernel cannot
// translate addresses: nf_conntrack and nf_tables with NAT, as modules
// loaded or built in. SHAWK_TEST_NO_CONNTRACK=1 declares a kernel without
// them, as a virtual machine without the modules: the test is then skipped
// even in strict mode.
func requireConntrack(t *testing.T) {
	t.Helper()
	if no, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_CONNTRACK")); no {
		t.Skip("the kernel has no conntrack, as SHAWK_TEST_NO_CONNTRACK declares")
	}
}

// natNetNS returns a network namespace with 10.99.0.0/24 and 10.200.0.0/24
// on loopback, and NAT rules of nftables:
//
//	10.200.0.1:6432 -> 10.99.0.2:5435  DNAT in OUTPUT (kube-proxy on the host of the client)
//	10.99.0.3:5436 from 10.99.0.200    SNAT in POSTROUTING (a masquerade)
//
// It skips the test if nftables cannot translate.
func natNetNS(t *testing.T) (func(f func()), uint32) {
	t.Helper()
	requireConntrack(t)
	run, ns := newNetNS(t)
	run(func() {
		addLoopbackAddr(t, netip.MustParsePrefix("10.99.0.1/24"))
		addLoopbackAddr(t, netip.MustParsePrefix("10.200.0.1/24"))
		err := nftNAT([]nftChain{
			{name: "out", hook: unix.NF_INET_LOCAL_OUT, priority: -100, rules: [][]byte{
				nftRule(nftTCPTo(netip.MustParseAddrPort("10.200.0.1:6432")),
					nftNatTo(unix.NFT_NAT_DNAT, netip.MustParseAddrPort("10.99.0.2:5435"))),
			}},
			{name: "post", hook: unix.NF_INET_POST_ROUTING, priority: 100, rules: [][]byte{
				nftRule(nftTCPTo(netip.MustParseAddrPort("10.99.0.3:5436")),
					nftNatTo(unix.NFT_NAT_SNAT, netip.AddrPortFrom(netip.MustParseAddr("10.99.0.200"), 0))),
			}},
		})
		if err != nil {
			skipUnavailable(t, "adding NAT rules with nftables: %v", err)
		}
	})
	return run, ns
}

// listenIn listens on addr in the namespace of run and accepts until the
// test ends, keeping the connections open. It returns a function that
// closes the listener and the connections.
func listenIn(t *testing.T, run func(func()), addr string) (closeAll func()) {
	t.Helper()
	var (
		ln  net.Listener
		err error
	)
	run(func() { ln, err = net.Listen("tcp4", addr) })
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	closeAll = func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}
	t.Cleanup(closeAll)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return closeAll
}

func findTranslation(xs []Translation, want Translation) bool {
	return slices.Contains(xs, want)
}

// TestTranslations checks the translations learned from conntrack: DNAT and
// SNAT, none without NAT, while their connections are open without new
// ones, and gone once their entries are.
func TestTranslations(t *testing.T) {
	run, ns := natNetNS(t)
	tr := startTracer(t, Options{NetNS: ns, LearnTranslations: true})
	if !tr.TranslationsTraced() {
		skipUnavailable(t, "translations are not learned from conntrack")
	}
	var closers []func()
	for _, a := range []string{"10.99.0.2:5435", "10.99.0.3:5436"} {
		closers = append(closers, listenIn(t, run, a))
	}
	collect(t, tr)
	dnat := dialFrom(t, run, "tcp4", "10.99.0.1", "10.200.0.1:6432")
	snat := dialFrom(t, run, "tcp4", "10.99.0.1", "10.99.0.3:5436")
	// Without NAT, no translation.
	direct := dialFrom(t, run, "tcp4", "10.99.0.1", "10.99.0.2:5435")
	a := netip.MustParseAddr
	want := []Translation{
		{Proto: ProtoTCP, NetNS: ns, Client: a("10.99.0.1"), Virtual: a("10.200.0.1"), VirtualPort: 6432,
			Source: a("10.99.0.1"), Backend: a("10.99.0.2"), BackendPort: 5435},
		{Proto: ProtoTCP, NetNS: ns, Client: a("10.99.0.1"), Virtual: a("10.99.0.3"), VirtualPort: 5436,
			Source: a("10.99.0.200"), Backend: a("10.99.0.3"), BackendPort: 5436},
	}
	for i := range 3 {
		snap := collect(t, tr)
		if len(snap.Translations) != len(want) {
			t.Errorf("interval %d: translations = %+v, want %+v", i, snap.Translations, want)
			continue
		}
		for _, w := range want {
			if !findTranslation(snap.Translations, w) {
				t.Errorf("interval %d: translation %+v not in %+v", i, w, snap.Translations)
			}
		}
		if snap.TranslationDrops != 0 {
			t.Errorf("interval %d: %d translations dropped", i, snap.TranslationDrops)
		}
	}
	dnat.Close()
	snat.Close()
	direct.Close()
	for _, c := range closers {
		c()
	}
	// The entries of the namespace go with it, once its sockets are closed.
	unix.Unmount(netnsPath(t, ns), unix.MNT_DETACH)
	deadline := time.Now().Add(30 * time.Second)
	for {
		snap := collect(t, tr)
		if len(snap.Translations) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("translations still alive after their namespace went: %+v", snap.Translations)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if n := len(tr.xlatLast); n != 0 {
		t.Errorf("%d idle translations kept", n)
	}
}

// TestTranslationsShortLived checks that a translation whose connection
// opened and closed within the interval is reported in it.
func TestTranslationsShortLived(t *testing.T) {
	run, ns := natNetNS(t)
	tr := startTracer(t, Options{NetNS: ns, LearnTranslations: true})
	if !tr.TranslationsTraced() {
		skipUnavailable(t, "translations are not learned from conntrack")
	}
	listenIn(t, run, "10.99.0.2:5435")
	collect(t, tr)
	dialFrom(t, run, "tcp4", "10.99.0.1", "10.200.0.1:6432").Close()
	snap := collect(t, tr)
	a := netip.MustParseAddr
	want := Translation{Proto: ProtoTCP, NetNS: ns, Client: a("10.99.0.1"), Virtual: a("10.200.0.1"), VirtualPort: 6432,
		Source: a("10.99.0.1"), Backend: a("10.99.0.2"), BackendPort: 5435}
	if !findTranslation(snap.Translations, want) {
		t.Errorf("translation %+v not in %+v", want, snap.Translations)
	}
}

// TestTranslationsFiltered checks that translations of other network
// namespaces than the traced one are not learned, nor, with folding, those
// whose source is outside the internal ranges.
func TestTranslationsFiltered(t *testing.T) {
	run, ns := natNetNS(t)
	for _, a := range []string{"10.99.0.2:5435", "10.99.0.3:5436"} {
		listenIn(t, run, a)
	}
	other := startTracer(t, Options{NetNS: ns + 1, LearnTranslations: true})
	folding := startTracer(t, Options{NetNS: ns, LearnTranslations: true, Fold: FoldIn,
		InternalPeers: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/25")}})
	for _, tr := range []*Tracer{other, folding} {
		if !tr.TranslationsTraced() {
			skipUnavailable(t, "translations are not learned from conntrack")
		}
		collect(t, tr)
	}
	dialFrom(t, run, "tcp4", "10.99.0.1", "10.200.0.1:6432")
	dialFrom(t, run, "tcp4", "10.99.0.1", "10.99.0.3:5436")
	if snap := collect(t, other); len(snap.Translations) != 0 {
		t.Errorf("translations of another namespace: %+v", snap.Translations)
	}
	snap := collect(t, folding)
	if len(snap.Translations) != 1 || snap.Translations[0].VirtualPort != 6432 {
		t.Errorf("with folding, translations = %+v, want the DNAT to 10.200.0.1:6432 alone", snap.Translations)
	}
}

// TestTranslationsDisabled checks that a tracer without LearnTranslations
// loads no conntrack program.
func TestTranslationsDisabled(t *testing.T) {
	tr := startTracer(t, Options{})
	if tr.TranslationsTraced() {
		t.Error("translations are learned without LearnTranslations")
	}
	for _, p := range conntrackPrograms {
		if _, ok := tr.progs[p.prog]; ok {
			t.Errorf("program %s loaded", p.prog)
		}
	}
	if snap := collect(t, tr); snap.Translations != nil {
		t.Errorf("translations = %+v", snap.Translations)
	}
}

// TestConntrackNotLoaded checks that the tracer starts without the module
// and loads the programs once it appears, at most once per retry.
func TestConntrackNotLoaded(t *testing.T) {
	requireConntrack(t)
	missing := t.TempDir() + "/nf_conntrack"
	defer func(m string) { conntrackModule = m }(conntrackModule)
	conntrackModule = missing
	tr := startTracer(t, Options{LearnTranslations: true})
	if tr.TranslationsTraced() {
		t.Fatal("translations learned without the module")
	}
	if err := os.Mkdir(missing, 0o755); err != nil {
		t.Fatal(err)
	}
	collect(t, tr)
	if tr.TranslationsTraced() {
		t.Error("the module was looked up again before the retry interval")
	}
	tr.mu.Lock()
	tr.conntrackTried = tr.conntrackTried.Add(-conntrackRetry)
	tr.mu.Unlock()
	collect(t, tr)
	if !tr.TranslationsTraced() {
		skipUnavailable(t, "translations are not learned from conntrack once the module is there")
	}
}

// netnsPath returns the mount of the namespace with inode ns created by
// createNetNS.
func netnsPath(t *testing.T, ns uint32) string {
	t.Helper()
	entries, err := os.ReadDir("/run/netns")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		var st unix.Stat_t
		p := "/run/netns/" + e.Name()
		if unix.Stat(p, &st) == nil && uint32(st.Ino) == ns {
			return p
		}
	}
	t.Fatalf("no mount of the namespace %d", ns)
	return ""
}

// nftChain is a base chain of NAT in the table of the tests.
type nftChain struct {
	name     string
	hook     uint32
	priority int32
	rules    [][]byte // NFTA_RULE_EXPRESSIONS of each rule
}

const nftTable = "shawktest"

// nftNAT creates the table of the tests with chains of type nat in the
// network namespace of the thread, in one batch of nf_tables.
func nftNAT(chains []nftChain) error {
	var msgs [][]byte
	msgs = append(msgs, nfMsg(unix.NFNL_MSG_BATCH_BEGIN, unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, 0, nil))
	msgs = append(msgs, nfMsg(nftType(unix.NFT_MSG_NEWTABLE), unix.NFPROTO_IPV4, 0,
		unix.NLM_F_CREATE|unix.NLM_F_ACK, rtAttr(unix.NFTA_TABLE_NAME, cstr(nftTable))))
	for _, c := range chains {
		hook := append(rtAttr(unix.NFTA_HOOK_HOOKNUM, be32(c.hook)), rtAttr(unix.NFTA_HOOK_PRIORITY, be32(uint32(c.priority)))...)
		body := rtAttr(unix.NFTA_CHAIN_TABLE, cstr(nftTable))
		body = append(body, rtAttr(unix.NFTA_CHAIN_NAME, cstr(c.name))...)
		body = append(body, rtAttr(unix.NFTA_CHAIN_HOOK|unix.NLA_F_NESTED, hook)...)
		body = append(body, rtAttr(unix.NFTA_CHAIN_TYPE, cstr("nat"))...)
		msgs = append(msgs, nfMsg(nftType(unix.NFT_MSG_NEWCHAIN), unix.NFPROTO_IPV4, 0, unix.NLM_F_CREATE|unix.NLM_F_ACK, body))
		for _, exprs := range c.rules {
			body := rtAttr(unix.NFTA_RULE_TABLE, cstr(nftTable))
			body = append(body, rtAttr(unix.NFTA_RULE_CHAIN, cstr(c.name))...)
			body = append(body, rtAttr(unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, exprs)...)
			msgs = append(msgs, nfMsg(nftType(unix.NFT_MSG_NEWRULE), unix.NFPROTO_IPV4, 0,
				unix.NLM_F_CREATE|unix.NLM_F_APPEND|unix.NLM_F_ACK, body))
		}
	}
	msgs = append(msgs, nfMsg(unix.NFNL_MSG_BATCH_END, unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, 0, nil))
	return nfnetlink(msgs)
}

func nftType(msg int) uint16 { return uint16(unix.NFNL_SUBSYS_NFTABLES<<8 | msg) }

// nftRule returns the expressions of a rule.
func nftRule(exprs ...[][]byte) []byte {
	var out []byte
	for _, es := range exprs {
		for _, e := range es {
			out = append(out, rtAttr(unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, e)...)
		}
	}
	return out
}

func nftExpr(name string, data []byte) []byte {
	return append(rtAttr(unix.NFTA_EXPR_NAME, cstr(name)), rtAttr(unix.NFTA_EXPR_DATA|unix.NLA_F_NESTED, data)...)
}

func nftCmp(value []byte) []byte {
	return nftExpr("cmp", slices.Concat(
		rtAttr(unix.NFTA_CMP_SREG, be32(unix.NFT_REG_1)),
		rtAttr(unix.NFTA_CMP_OP, be32(unix.NFT_CMP_EQ)),
		rtAttr(unix.NFTA_CMP_DATA|unix.NLA_F_NESTED, rtAttr(unix.NFTA_DATA_VALUE, value))))
}

func nftPayload(base, offset, length uint32) []byte {
	return nftExpr("payload", slices.Concat(
		rtAttr(unix.NFTA_PAYLOAD_DREG, be32(unix.NFT_REG_1)),
		rtAttr(unix.NFTA_PAYLOAD_BASE, be32(base)),
		rtAttr(unix.NFTA_PAYLOAD_OFFSET, be32(offset)),
		rtAttr(unix.NFTA_PAYLOAD_LEN, be32(length))))
}

// nftTCPTo matches TCP to an IPv4 address and port.
func nftTCPTo(ap netip.AddrPort) [][]byte {
	addr := ap.Addr().As4()
	return [][]byte{
		nftExpr("meta", slices.Concat(rtAttr(unix.NFTA_META_DREG, be32(unix.NFT_REG_1)),
			rtAttr(unix.NFTA_META_KEY, be32(unix.NFT_META_L4PROTO)))),
		nftCmp([]byte{unix.IPPROTO_TCP}),
		nftPayload(unix.NFT_PAYLOAD_NETWORK_HEADER, 16, 4),
		nftCmp(addr[:]),
		nftPayload(unix.NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2),
		nftCmp(binary.BigEndian.AppendUint16(nil, ap.Port())),
	}
}

func nftImmediate(reg uint32, value []byte) []byte {
	return nftExpr("immediate", slices.Concat(
		rtAttr(unix.NFTA_IMMEDIATE_DREG, be32(reg)),
		rtAttr(unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, rtAttr(unix.NFTA_DATA_VALUE, value))))
}

// nftNatTo translates to an IPv4 address, and to a port unless it is 0.
func nftNatTo(typ uint32, to netip.AddrPort) [][]byte {
	addr := to.Addr().As4()
	exprs := [][]byte{nftImmediate(unix.NFT_REG_1, addr[:])}
	nat := slices.Concat(
		rtAttr(unix.NFTA_NAT_TYPE, be32(typ)),
		rtAttr(unix.NFTA_NAT_FAMILY, be32(unix.NFPROTO_IPV4)),
		rtAttr(unix.NFTA_NAT_REG_ADDR_MIN, be32(unix.NFT_REG_1)))
	if to.Port() != 0 {
		exprs = append(exprs, nftImmediate(unix.NFT_REG_2, binary.BigEndian.AppendUint16(nil, to.Port())))
		nat = append(nat, rtAttr(unix.NFTA_NAT_REG_PROTO_MIN, be32(unix.NFT_REG_2))...)
	}
	return append(exprs, nftExpr("nat", nat))
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func cstr(s string) []byte { return append([]byte(s), 0) }

// nfMsg returns a netlink message of nfnetlink: the header, struct
// nfgenmsg and the attributes.
func nfMsg(typ uint16, family uint8, resID uint16, flags uint16, attrs []byte) []byte {
	msg := make([]byte, unix.SizeofNlMsghdr+4, unix.SizeofNlMsghdr+4+len(attrs))
	binary.NativeEndian.PutUint32(msg, uint32(unix.SizeofNlMsghdr+4+len(attrs)))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	binary.NativeEndian.PutUint16(msg[6:], flags|unix.NLM_F_REQUEST)
	msg[unix.SizeofNlMsghdr] = family
	msg[unix.SizeofNlMsghdr+1] = unix.NFNETLINK_V0
	binary.BigEndian.PutUint16(msg[unix.SizeofNlMsghdr+2:], resID)
	return append(msg, attrs...)
}

// nfnetlink sends a batch of messages to nfnetlink in the network
// namespace of the thread and returns the first error acknowledged.
func nfnetlink(msgs [][]byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	var batch []byte
	acks := 0
	for i, m := range msgs {
		binary.NativeEndian.PutUint32(m[8:], uint32(i+1))
		if binary.NativeEndian.Uint16(m[6:])&unix.NLM_F_ACK != 0 {
			acks++
		}
		batch = append(batch, m...)
	}
	if err := unix.Sendto(fd, batch, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 1<<16)
	for acks > 0 {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("reading the acknowledgements of nf_tables: %w", err)
		}
		for b := buf[:n]; len(b) >= unix.SizeofNlMsghdr; {
			l := int(binary.NativeEndian.Uint32(b))
			if l < unix.SizeofNlMsghdr || l > len(b) {
				return fmt.Errorf("malformed netlink reply")
			}
			if binary.NativeEndian.Uint16(b[4:]) == unix.NLMSG_ERROR && l >= unix.SizeofNlMsghdr+4 {
				if errno := int32(binary.NativeEndian.Uint32(b[unix.SizeofNlMsghdr:])); errno != 0 {
					return unix.Errno(-errno)
				}
				acks--
			}
			b = b[(l+3)&^3:]
		}
	}
	return nil
}
