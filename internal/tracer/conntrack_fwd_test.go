package tracer

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// vethInfoPeer is VETH_INFO_PEER of linux/veth.h.
const vethInfoPeer = 1

// addVeth creates a veth pair in the network namespace of the thread, name
// there and peer in the namespace mounted at peerNS, both up.
func addVeth(t *testing.T, name, peer, peerNS string) {
	t.Helper()
	ns, err := os.Open(peerNS)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ifinfo := make([]byte, unix.SizeofIfInfomsg) // AF_UNSPEC, no flags
	peerInfo := slices.Concat(ifinfo, rtAttr(unix.IFLA_IFNAME, cstr(peer)),
		rtAttr(unix.IFLA_NET_NS_FD, binary.NativeEndian.AppendUint32(nil, uint32(ns.Fd()))))
	linkInfo := slices.Concat(rtAttr(unix.IFLA_INFO_KIND, []byte("veth")),
		rtAttr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, rtAttr(vethInfoPeer|unix.NLA_F_NESTED, peerInfo)))
	body := slices.Concat(ifinfo, rtAttr(unix.IFLA_IFNAME, cstr(name)), rtAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, linkInfo))
	if err := rtnetlink(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		skipUnavailable(t, "creating a veth pair: %v", err)
	}
	if err := linkUp(name); err != nil {
		t.Fatal(err)
	}
}

// linkUp brings up an interface of the network namespace of the thread.
func linkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("reading the flags of %s: %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing up %s: %w", name, err)
	}
	return nil
}

// addAddr adds an IPv4 address with its prefix to an interface of the
// network namespace of the thread.
func addAddr(t *testing.T, name string, p netip.Prefix) {
	t.Helper()
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{unix.AF_INET, byte(p.Bits()), 0, unix.RT_SCOPE_UNIVERSE}
	body = binary.NativeEndian.AppendUint32(body, uint32(ifc.Index))
	body = append(body, rtAttr(unix.IFA_LOCAL, p.Addr().AsSlice())...)
	body = append(body, rtAttr(unix.IFA_ADDRESS, p.Addr().AsSlice())...)
	if err := rtnetlink(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		t.Fatalf("adding %s to %s: %v", p, name, err)
	}
}

// addDefaultRoute adds an IPv4 default route through a gateway in the
// network namespace of the thread.
func addDefaultRoute(t *testing.T, gw netip.Addr) {
	t.Helper()
	// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
	// type, flags.
	body := []byte{unix.AF_INET, 0, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body = append(body, rtAttr(unix.RTA_GATEWAY, gw.AsSlice())...)
	if err := rtnetlink(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		t.Fatalf("adding the default route through %s: %v", gw, err)
	}
}

// TestTranslationsForwarded checks the translations of a host that forwards,
// as a Docker host or a Kubernetes node does: a client in a namespace of its
// own reaches a published port of the host, which DNATs it in PREROUTING to
// a container on a bridge (confirmed in POSTROUTING after FORWARD), over TCP
// and UDP; a REDIRECT to a port of the host (confirmed in INPUT); and the
// container reaches the client through a masquerade.
//
//	client 10.97.0.2 --- 10.97.0.1 host 10.98.0.1 --- 10.98.0.2 container
func TestTranslationsForwarded(t *testing.T) {
	requireConntrack(t)
	runX, nsX := newNetNS(t)
	runH, nsH := newNetNS(t)
	runK, nsK := newNetNS(t)
	a := netip.MustParseAddr
	ap := netip.MustParseAddrPort
	runH(func() {
		addVeth(t, "hx", "xe", netnsPath(t, nsX))
		addVeth(t, "hk", "ke", netnsPath(t, nsK))
		addAddr(t, "hx", netip.MustParsePrefix("10.97.0.1/24"))
		addAddr(t, "hk", netip.MustParsePrefix("10.98.0.1/24"))
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := nftNAT(unix.NFPROTO_IPV4, []nftChain{
			{name: "pre", hook: unix.NF_INET_PRE_ROUTING, priority: -100, rules: [][]byte{
				nftRule(nftTCPTo(ap("10.97.0.1:8080")), nftNatTo(unix.NFT_NAT_DNAT, ap("10.98.0.2:80"))),
				nftRule(nftTo(unix.IPPROTO_UDP, ap("10.97.0.1:5353")), nftNatTo(unix.NFT_NAT_DNAT, ap("10.98.0.2:53"))),
				nftRule(nftTCPTo(ap("10.97.0.1:8081")), nftRedir(9090)),
			}},
			{name: "post", hook: unix.NF_INET_POST_ROUTING, priority: 100, rules: [][]byte{
				nftRule(nftTCPTo(ap("10.97.0.2:90")), nftMasq()),
			}},
		})
		if err != nil {
			skipUnavailable(t, "adding NAT rules with nftables: %v", err)
		}
	})
	for _, n := range []struct {
		run  func(func())
		link string
		addr string
		gw   string
	}{{runX, "xe", "10.97.0.2/24", "10.97.0.1"}, {runK, "ke", "10.98.0.2/24", "10.98.0.1"}} {
		n.run(func() {
			if err := linkUp(n.link); err != nil {
				t.Fatal(err)
			}
			addAddr(t, n.link, netip.MustParsePrefix(n.addr))
			addDefaultRoute(t, a(n.gw))
		})
	}
	tr := startTracer(t, Options{NetNS: nsH, LearnTranslations: true})
	if !tr.TranslationsTraced() {
		skipUnavailable(t, "translations are not learned from conntrack")
	}
	listenIn(t, runK, "10.98.0.2:80")
	listenIn(t, runH, "10.97.0.1:9090")
	listenIn(t, runX, "10.97.0.2:90")
	var udp net.PacketConn
	var err error
	runK(func() { udp, err = net.ListenPacket("udp4", "10.98.0.2:53") })
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	collect(t, tr)

	dialFrom(t, runX, "tcp4", "10.97.0.2", "10.97.0.1:8080")
	dialFrom(t, runX, "tcp4", "10.97.0.2", "10.97.0.1:8081")
	u := dialFrom(t, runX, "udp4", "10.97.0.2", "10.97.0.1:5353")
	if _, err := u.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	if err := udp.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := udp.ReadFrom(make([]byte, 16)); err != nil {
		t.Fatalf("the datagram did not reach the container: %v", err)
	}
	dialFrom(t, runK, "tcp4", "10.98.0.2", "10.97.0.2:90")
	snap := collect(t, tr)
	for _, want := range []Translation{
		{Proto: ProtoTCP, NetNS: nsH, Client: a("10.97.0.2"), Virtual: a("10.97.0.1"), VirtualPort: 8080,
			Source: a("10.97.0.2"), Backend: a("10.98.0.2"), BackendPort: 80},
		{Proto: ProtoUDP, NetNS: nsH, Client: a("10.97.0.2"), Virtual: a("10.97.0.1"), VirtualPort: 5353,
			Source: a("10.97.0.2"), Backend: a("10.98.0.2"), BackendPort: 53},
		{Proto: ProtoTCP, NetNS: nsH, Client: a("10.97.0.2"), Virtual: a("10.97.0.1"), VirtualPort: 8081,
			Source: a("10.97.0.2"), Backend: a("10.97.0.1"), BackendPort: 9090},
		{Proto: ProtoTCP, NetNS: nsH, Client: a("10.98.0.2"), Virtual: a("10.97.0.2"), VirtualPort: 90,
			Source: a("10.97.0.1"), Backend: a("10.97.0.2"), BackendPort: 90},
	} {
		if !findTranslation(snap.Translations, want) {
			t.Errorf("translation %+v not in %+v", want, snap.Translations)
		}
	}
	if len(snap.Translations) != 4 {
		t.Errorf("%d translations, want 4: %+v", len(snap.Translations), snap.Translations)
	}
}

// TestTranslationsIPv6 checks a DNAT of IPv6 in OUTPUT.
func TestTranslationsIPv6(t *testing.T) {
	requireConntrack(t)
	skipIfNoNetwork(t, "tcp6")
	run, ns := newNetNS(t)
	ap := netip.MustParseAddrPort
	run(func() {
		for _, p := range []string{"fd00:99::1/128", "fd00:99::2/128", "fd00:200::1/128"} {
			addLoopbackAddr(t, netip.MustParsePrefix(p))
		}
		err := nftNAT(unix.NFPROTO_IPV6, []nftChain{{name: "out", hook: unix.NF_INET_LOCAL_OUT, priority: -100, rules: [][]byte{
			nftRule(nftTCPTo(ap("[fd00:200::1]:6432")), nftNatTo(unix.NFT_NAT_DNAT, ap("[fd00:99::2]:5435"))),
		}}})
		if err != nil {
			skipUnavailable(t, "adding NAT rules of IPv6 with nftables: %v", err)
		}
	})
	tr := startTracer(t, Options{NetNS: ns, LearnTranslations: true})
	if !tr.TranslationsTraced() {
		skipUnavailable(t, "translations are not learned from conntrack")
	}
	var ln net.Listener
	var err error
	run(func() { ln, err = net.Listen("tcp6", "[fd00:99::2]:5435") })
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	collect(t, tr)
	dialFrom(t, run, "tcp6", "fd00:99::1", "[fd00:200::1]:6432")
	snap := collect(t, tr)
	a := netip.MustParseAddr
	want := Translation{Proto: ProtoTCP, NetNS: ns, Client: a("fd00:99::1"), Virtual: a("fd00:200::1"), VirtualPort: 6432,
		Source: a("fd00:99::1"), Backend: a("fd00:99::2"), BackendPort: 5435}
	if !findTranslation(snap.Translations, want) {
		t.Errorf("translation %+v not in %+v", want, snap.Translations)
	}
}
