package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests in this file send packets through the tables that the command
// writes: between two network namespaces joined by a pair of virtual
// interfaces, one for the host of the rules and one for its peers, with
// the kernel's own nftables and connection tracking. They tell what no
// reading of the text of a table can: what a table lets pass, and what its
// counters count. They are skipped where the namespaces cannot be made.
//
// The test binary is its own helper: started with netHelperEnv set, it
// serves or opens connections in the namespace it was started in, and
// does what the lines of its standard input ask.

const netHelperEnv = "SHAWK_POLICY_TEST_NET_HELPER"

func TestMain(m *testing.M) {
	if spec := os.Getenv(netHelperEnv); spec != "" {
		os.Exit(netHelper(strings.Fields(spec)))
	}
	os.Exit(m.Run())
}

// netHelper runs a helper: `serve udp:ADDR tcp:ADDR ...` answers every
// message on the addresses until it is killed, and `flow udp|tcp LOCAL
// REMOTE` opens one connection from LOCAL to REMOTE, then sends a message
// and waits for its answer once per line of its input, and writes `ok` or
// `fail` with the reason.
func netHelper(args []string) int {
	out := bufio.NewWriter(os.Stdout)
	say := func(format string, a ...any) {
		fmt.Fprintf(out, format+"\n", a...)
		out.Flush()
	}
	switch args[0] {
	case "serve":
		for _, a := range args[1:] {
			proto, addr, _ := strings.Cut(a, ":")
			if proto == "udp" {
				c, err := net.ListenPacket("udp4", addr)
				if err != nil {
					say("fail %v", err)
					return 1
				}
				go func() {
					buf := make([]byte, 64)
					for {
						if _, peer, err := c.ReadFrom(buf); err == nil {
							_, _ = c.WriteTo([]byte("a"), peer)
						}
					}
				}()
				continue
			}
			l, err := net.Listen("tcp4", addr)
			if err != nil {
				say("fail %v", err)
				return 1
			}
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func() {
						buf := make([]byte, 64)
						for {
							if _, err := c.Read(buf); err != nil {
								return
							}
							_, _ = c.Write([]byte("a"))
						}
					}()
				}
			}()
		}
		say("ready")
		select {}
	case "flow":
		var local net.Addr
		var err error
		if args[1] == "udp" {
			local, err = net.ResolveUDPAddr("udp4", args[2])
		} else {
			local, err = net.ResolveTCPAddr("tcp4", args[2])
		}
		if err != nil {
			say("fail %v", err)
			return 1
		}
		d := net.Dialer{LocalAddr: local, Timeout: 700 * time.Millisecond}
		c, err := d.Dial(args[1]+"4", args[3])
		if err != nil {
			say("fail %v", err)
			return 1
		}
		say("ready")
		in := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 64)
		for in.Scan() {
			_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
			if _, err = c.Write([]byte("q")); err == nil {
				_, err = c.Read(buf)
			}
			if err != nil {
				say("fail %v", err)
				continue
			}
			say("ok")
		}
	}
	return 0
}

// netLab is two network namespaces: h, where the tables are loaded, with
// the address 10.0.0.11, and p, with the addresses of its peers.
type netLab struct {
	t    *testing.T
	h, p []string
}

// netFlow is a connection that a helper holds.
type netFlow struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Scanner
	// opened tells that the connection could be opened: the first packet
	// of a TCP connection that a table refuses fails here.
	opened bool
}

// newNetLab makes the namespaces, or skips the test.
func newNetLab(t *testing.T) *netLab {
	t.Helper()
	unshare := inNetns(t)
	for _, tool := range []string{"nsenter", "ip", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	lab := &netLab{t: t}
	hold := func(start []string) []string {
		cmd := exec.Command(start[0], append(start[1:], "sleep", "600")...)
		if err := cmd.Start(); err != nil {
			t.Skipf("no network namespace: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		enter := []string{"nsenter", "-t", strconv.Itoa(cmd.Process.Pid), "-n"}
		if unshare[1] == "-rn" {
			// As root of a user namespace of its own.
			enter = append(enter, "-U", "--preserve-credentials")
		}
		// The namespace is there once the command that holds it runs in it.
		for range 100 {
			if exec.Command(enter[0], append(enter[1:], "true")...).Run() == nil {
				return enter
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Skip("the network namespace cannot be entered (nsenter)")
		return nil
	}
	lab.h = hold(unshare)
	// The namespace of the peers is made from within that of the host, so
	// that one user namespace owns both.
	lab.p = hold(append(append([]string{}, lab.h...), "unshare", "-n"))
	peer := lab.p[2]
	setup := [][]string{
		append(append([]string{}, lab.h...), "ip", "link", "set", "lo", "up"),
		append(append([]string{}, lab.h...), "ip", "link", "add", "va", "type", "veth", "peer", "name", "vb", "netns", peer),
		append(append([]string{}, lab.h...), "ip", "addr", "add", "10.0.0.11/24", "dev", "va"),
		append(append([]string{}, lab.h...), "ip", "link", "set", "va", "up"),
		append(append([]string{}, lab.p...), "ip", "link", "set", "lo", "up"),
		append(append([]string{}, lab.p...), "ip", "link", "set", "vb", "up"),
	}
	for _, a := range []string{"10.0.0.10", "10.0.0.12", "10.0.0.53", "10.0.0.99", "10.0.0.200"} {
		setup = append(setup, append(append([]string{}, lab.p...), "ip", "addr", "add", a+"/24", "dev", "vb"))
	}
	for i, c := range setup {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			if i < 2 {
				t.Skipf("the namespaces cannot be joined: %v: %s", err, out)
			}
			t.Fatalf("%v: %v: %s", c, err, out)
		}
	}
	return lab
}

// helper starts the test binary as a helper in a namespace and waits
// until it is ready.
func (lab *netLab) helper(ns []string, spec string) *netFlow {
	lab.t.Helper()
	cmd := exec.Command(ns[0], append(ns[1:], os.Args[0])...)
	cmd.Env = append(os.Environ(), netHelperEnv+"="+spec)
	in, err := cmd.StdinPipe()
	if err != nil {
		lab.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		lab.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		lab.t.Fatal(err)
	}
	lab.t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	f := &netFlow{t: lab.t, name: spec, cmd: cmd, in: in, out: bufio.NewScanner(out)}
	f.opened = f.out.Scan() && f.out.Text() == "ready"
	return f
}

// end closes the connection and waits until its helper is gone, so that
// its address is free again.
func (f *netFlow) end() {
	_ = f.in.Close()
	_ = f.cmd.Wait()
}

// serve answers messages on addresses of a namespace.
func (lab *netLab) serve(ns []string, addrs ...string) {
	lab.t.Helper()
	if f := lab.helper(ns, "serve "+strings.Join(addrs, " ")); !f.opened {
		lab.t.Fatalf("the helper cannot serve %v: %s", addrs, f.out.Text())
	}
}

// flow opens a connection from an address of a namespace.
func (lab *netLab) flow(ns []string, proto, local, remote string) *netFlow {
	lab.t.Helper()
	return lab.helper(ns, "flow "+proto+" "+local+" "+remote)
}

// exchange sends n messages over the connection and returns how many of
// them were answered.
func (f *netFlow) exchange(n int) int {
	f.t.Helper()
	if !f.opened {
		return 0
	}
	answered := 0
	for range n {
		if _, err := io.WriteString(f.in, "\n"); err != nil {
			f.t.Fatalf("%s: %v", f.name, err)
		}
		if !f.out.Scan() {
			f.t.Fatalf("%s: the helper ended", f.name)
		}
		if f.out.Text() == "ok" {
			answered++
		}
	}
	return answered
}

// load loads a table into the namespace of the host.
func (lab *netLab) load(text string) {
	lab.t.Helper()
	file := filepath.Join(lab.t.TempDir(), "policy.nft")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		lab.t.Fatal(err)
	}
	if out, err := exec.Command(lab.h[0], append(lab.h[1:], "nft", "-f", file)...).CombinedOutput(); err != nil {
		lab.t.Fatalf("nft refuses the table: %v: %s\n%s", err, out, text)
	}
}

// counters returns the packets that the counters of the table counted,
// egress_unlisted and ingress_unlisted, and clears them. It waits first
// for what is still on its way: the acknowledgement of a message, which
// TCP may delay.
func (lab *netLab) counters() (egress, ingress int) {
	lab.t.Helper()
	time.Sleep(300 * time.Millisecond)
	out, err := exec.Command(lab.h[0], append(lab.h[1:], "nft", "-j", "reset", "counters", "table", "inet", nftTable)...).Output()
	if err != nil {
		lab.t.Fatalf("nft reset counters: %v", err)
	}
	var listing struct {
		Nftables []struct {
			Counter *struct {
				Name    string
				Packets int
			}
		}
	}
	if err := json.Unmarshal(out, &listing); err != nil {
		lab.t.Fatalf("%v\n%s", err, out)
	}
	for _, o := range listing.Nftables {
		switch {
		case o.Counter == nil:
		case o.Counter.Name == nftEgressCounter:
			egress = o.Counter.Packets
		case o.Counter.Name == nftIngressCounter:
			ingress = o.Counter.Packets
		}
	}
	return egress, ingress
}

// labFlows are the flows of the host of the lab: it opens connections to
// a database and a resolver, and accepts those of a proxy.
func labFlows() []flow {
	return []flow{
		testFlow(egress, "shop/app", "tcp", "10.0.0.10/32", 5432, "shop/postgres"),
		testFlow(egress, "shop/app", "udp", "10.0.0.53/32", 53, "~unresolved"),
		testFlow(ingress, "shop/app", "tcp", "10.0.0.12/32", 8080, "nginx"),
	}
}

// TestAuditFormCountsWhatLasts: the audit form rejects nothing, and its
// counters count every packet that the opening side of a connection sends
// where no rule lists the connection, for as long as it lives: also after
// they were cleared, which is when a counter of first packets would say
// that nothing is left. A connection that a rule lists is never counted,
// and one that a rule lists later is not counted any more.
func TestAuditFormCountsWhatLasts(t *testing.T) {
	lab := newNetLab(t)
	lab.serve(lab.p, "tcp:10.0.0.10:5432", "tcp:10.0.0.99:5432", "udp:10.0.0.99:51820", "udp:10.0.0.53:53")
	lab.serve(lab.h, "tcp:10.0.0.11:8080")
	lab.load(render(testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, labFlows()...)))

	listed := []*netFlow{
		lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.10:5432"),
		lab.flow(lab.h, "udp", "10.0.0.11:0", "10.0.0.53:53"),
		lab.flow(lab.p, "tcp", "10.0.0.12:0", "10.0.0.11:8080"),
	}
	// What no rule lists: a session that stays open, an exchange between
	// fixed ports as a tunnel of the kernel keeps, and a client from
	// another address.
	session := lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.99:5432")
	tunnel := lab.flow(lab.h, "udp", "10.0.0.11:51820", "10.0.0.99:51820")
	client := lab.flow(lab.p, "tcp", "10.0.0.99:0", "10.0.0.11:8080")
	all := append([]*netFlow{session, tunnel, client}, listed...)
	for _, f := range all {
		if got := f.exchange(2); got != 2 {
			t.Fatalf("the audit form is loaded, and %q had %d of 2 messages answered", f.name, got)
		}
	}
	if egress, ingress := lab.counters(); egress < 3 || ingress < 2 {
		t.Errorf("the first packets of what no rule lists: %d egress and %d ingress packets counted", egress, ingress)
	}
	// The counters were cleared. The connections that the rules list go
	// on, and none of their packets is counted.
	for _, f := range listed {
		if got := f.exchange(3); got != 3 {
			t.Fatalf("%q had %d of 3 messages answered", f.name, got)
		}
	}
	if egress, ingress := lab.counters(); egress != 0 || ingress != 0 {
		t.Errorf("connections that the rules list: %d egress and %d ingress packets counted", egress, ingress)
	}
	// Those that no rule lists go on too, and every packet of their
	// opening side is counted: the datagrams that the host sends, not the
	// answers to them.
	if got := tunnel.exchange(3); got != 3 {
		t.Fatalf("the exchange of UDP had %d of 3 messages answered", got)
	}
	if egress, ingress := lab.counters(); egress != 3 || ingress != 0 {
		t.Errorf("3 datagrams of an exchange that no rule lists, after the counters were cleared: %d egress and %d ingress packets counted",
			egress, ingress)
	}
	if got := session.exchange(3); got != 3 {
		t.Fatalf("the session had %d of 3 messages answered", got)
	}
	if egress, ingress := lab.counters(); egress < 3 || ingress != 0 {
		t.Errorf("3 messages of a session that no rule lists: %d egress and %d ingress packets counted", egress, ingress)
	}
	if got := client.exchange(3); got != 3 {
		t.Fatalf("the client had %d of 3 messages answered", got)
	}
	if egress, ingress := lab.counters(); egress != 0 || ingress < 3 {
		t.Errorf("3 messages of a client that no rule lists: %d egress and %d ingress packets counted", egress, ingress)
	}

	// The rules are written again with the exchange in them: it has its
	// label still, and is not counted any more.
	lab.load(render(testReport(t, target{Host: "app-01"}, formatNftables, ingressSources,
		append(labFlows(), testFlow(egress, "shop/app", "udp", "10.0.0.99/32", 51820, "~unresolved"))...)))
	if got := tunnel.exchange(3); got != 3 {
		t.Fatalf("the exchange of UDP had %d of 3 messages answered", got)
	}
	if got := session.exchange(1); got != 1 {
		t.Fatalf("the session had %d of 1 message answered", got)
	}
	if egress, ingress := lab.counters(); egress < 1 || egress > 2 || ingress != 0 {
		t.Errorf("the exchange is listed now and the session is not: %d egress and %d ingress packets counted", egress, ingress)
	}
}

// TestAuditFormOfOpenConnections: on a host that tracked connections
// before the table, the audit form compares the connections that were
// open with the rules too, at every packet of their opening side: the
// form that rejects accepts them as established, and would refuse them
// when they are opened again.
func TestAuditFormOfOpenConnections(t *testing.T) {
	lab := newNetLab(t)
	lab.serve(lab.p, "tcp:10.0.0.10:5432", "tcp:10.0.0.99:5432", "udp:10.0.0.99:51820")
	lab.serve(lab.h, "tcp:10.0.0.11:8080")
	// Another table of the host tracks connections.
	lab.load("table inet other {\n\tchain c {\n\t\ttype filter hook input priority -10;\n\t\tct state established counter\n\t}\n}\n")
	listed := []*netFlow{
		lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.10:5432"),
		lab.flow(lab.p, "tcp", "10.0.0.12:0", "10.0.0.11:8080"),
	}
	session := lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.99:5432")
	tunnel := lab.flow(lab.h, "udp", "10.0.0.11:51820", "10.0.0.99:51820")
	client := lab.flow(lab.p, "tcp", "10.0.0.99:0", "10.0.0.11:8080")
	all := append([]*netFlow{session, tunnel, client}, listed...)
	for _, f := range all {
		if got := f.exchange(2); got != 2 {
			t.Fatalf("before the table, %q had %d of 2 messages answered", f.name, got)
		}
	}
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, labFlows()...)
	lab.load(render(r))
	lab.counters()
	for _, f := range listed {
		if got := f.exchange(3); got != 3 {
			t.Fatalf("%q had %d of 3 messages answered", f.name, got)
		}
	}
	if egress, ingress := lab.counters(); egress != 0 || ingress != 0 {
		t.Errorf("open connections that the rules list: %d egress and %d ingress packets counted", egress, ingress)
	}
	if got := tunnel.exchange(3); got != 3 {
		t.Fatalf("the exchange of UDP had %d of 3 messages answered", got)
	}
	if egress, ingress := lab.counters(); egress != 3 || ingress != 0 {
		t.Errorf("3 datagrams of an open exchange that no rule lists: %d egress and %d ingress packets counted", egress, ingress)
	}
	if session.exchange(3) != 3 || client.exchange(3) != 3 {
		t.Fatal("the audit form stopped an open connection")
	}
	if egress, ingress := lab.counters(); egress < 3 || ingress < 3 {
		t.Errorf("open connections that no rule lists: %d egress and %d ingress packets counted", egress, ingress)
	}
	// The form that rejects lets them all go on: they are established.
	// It refuses a connection of the same kind that begins.
	r.Mode = modeEnforce
	lab.load(render(r))
	for _, f := range all {
		if got := f.exchange(1); got != 1 {
			t.Errorf("the form that rejects stopped the established %q", f.name)
		}
	}
	if f := lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.99:5432"); f.exchange(1) != 0 {
		t.Error("the form that rejects let a connection that no rule lists begin")
	}
	if f := lab.flow(lab.h, "tcp", "10.0.0.11:0", "10.0.0.10:5432"); f.exchange(1) != 1 {
		t.Error("the form that rejects refused a connection that a rule lists")
	}
}

// TestOtherWayOfUDPWithPackets: the rule of the other way of a UDP flow
// opens the exchange between the port of the flow on both sides, and no
// other port: neither a port of the host to whoever sends from the port
// of a server that the host asks, nor another port of a peer to the socket
// of the host.
func TestOtherWayOfUDPWithPackets(t *testing.T) {
	lab := newNetLab(t)
	// The host asks a resolver, and has a socket of gossip on 8301 that
	// was recorded as accepting from its peer; it serves 9999 to one
	// client, and 5353 to nobody that was seen.
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources,
		testFlow(egress, "shop/app", "udp", "10.0.0.53/32", 53, "~unresolved"),
		testFlow(ingress, "consul", "udp", "10.0.0.200/32", 8301, "~unresolved"),
		testFlow(ingress, "shop/app", "udp", "10.0.0.12/32", 9999, "~unresolved"))
	r.Mode = modeEnforce
	lab.serve(lab.h, "udp:10.0.0.11:9999", "udp:10.0.0.11:5353", "udp:10.0.0.11:53")
	lab.serve(lab.p, "udp:10.0.0.200:8301", "udp:10.0.0.200:9", "udp:10.0.0.99:8301")
	lab.load(render(r))
	for _, c := range []struct {
		what          string
		ns            []string
		local, remote string
		want          int
	}{
		{"the client of 9999, which was seen", lab.p, "10.0.0.12:40000", "10.0.0.11:9999", 1},
		{"the resolver, from its port 53, to the server on 9999", lab.p, "10.0.0.53:53", "10.0.0.11:9999", 0},
		{"the resolver, from its port 53, to the server on 5353", lab.p, "10.0.0.53:53", "10.0.0.11:5353", 0},
		{"the resolver, from its port 53, to the port 53 of the host", lab.p, "10.0.0.53:53", "10.0.0.11:53", 1},
		{"another address, from its port 53, to the port 53 of the host", lab.p, "10.0.0.99:53", "10.0.0.11:53", 0},
		{"the host, from 8301, to the port 8301 of its peer", lab.h, "10.0.0.11:8301", "10.0.0.200:8301", 1},
		{"the host, from 8301, to another port of its peer", lab.h, "10.0.0.11:8301", "10.0.0.200:9", 0},
		{"the host, from 8301, to the port 8301 of another address", lab.h, "10.0.0.11:8301", "10.0.0.99:8301", 0},
	} {
		f := lab.flow(c.ns, "udp", c.local, c.remote)
		if !f.opened {
			t.Fatalf("%s: the helper could not open %s: %s", c.what, c.local, f.out.Text())
		}
		if got := f.exchange(1); got != c.want {
			t.Errorf("%s: %d messages answered, want %d", c.what, got, c.want)
		}
		f.end()
	}
}
