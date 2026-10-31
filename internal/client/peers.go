package client

import (
	"fmt"
	"net/netip"
	"strings"
)

// privatePrefixes are the address ranges of a typical internal network.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// Peers decides which hosts the client may contact. Queries follow
// addresses learned from ledgers, which include any client of a service,
// e.g. hosts on the internet; contacting them would send them the bearer
// token and let them answer with forged data.
type Peers struct {
	any      bool
	prefixes []netip.Prefix
	hosts    map[string]bool
}

// ParsePeers parses a comma-separated list of "private" (loopback, RFC 1918,
// CGNAT and IPv6 ULA ranges), CIDR prefixes, or "any".
func ParsePeers(s string) (*Peers, error) {
	p := &Peers{hosts: map[string]bool{}}
	for _, f := range strings.Split(s, ",") {
		switch f = strings.TrimSpace(f); f {
		case "":
		case "any":
			p.any = true
		case "private":
			p.prefixes = append(p.prefixes, privatePrefixes...)
		default:
			prefix, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("invalid peer range %q", f)
			}
			p.prefixes = append(p.prefixes, prefix.Masked())
		}
	}
	return p, nil
}

// AddHost allows a host named by the user.
func (p *Peers) AddHost(host string) { p.hosts[host] = true }

// Allow reports whether host may be contacted. Host names are allowed since
// only the user names hosts; ledgers record addresses.
func (p *Peers) Allow(host string) bool {
	if p.any || p.hosts[host] {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	addr = addr.WithZone("").Unmap()
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
