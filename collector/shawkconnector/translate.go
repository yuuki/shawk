package shawkconnector

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// TranslationConfig is a relay without an agent that rewrites the
// addresses of the connections it forwards: a load balancer, a keepalived or
// LVS virtual address, a TCP proxy. Clients connect to a virtual address;
// the servers see their own address, and as the client either the address
// of the client (DNAT) or an address of the relay (SNAT, a proxy).
type TranslationConfig struct {
	// Virtual lists the addresses clients connect to, with a port or for
	// every port: 10.0.100.1:5432, [2001:db8::1]:443, 10.0.100.1.
	Virtual []string `mapstructure:"virtual"`
	// Backends lists the addresses or ranges of the servers the relay
	// forwards to, with their port, or without one for the port the client
	// connected to: 10.0.1.10:6432, 10.0.1.0/24, [2001:db8:1::/64]:8080.
	Backends []string `mapstructure:"backends"`
	// Sources lists the addresses or ranges the servers see the clients at
	// when the relay replaces their addresses (SNAT, a proxy). Empty when
	// the servers see the addresses of the clients (DNAT only).
	Sources []string `mapstructure:"sources"`
	// Transport is tcp or udp; empty for both.
	Transport string `mapstructure:"transport"`
}

// translation is a parsed TranslationConfig.
type translation struct {
	name   string
	protos []string
	// virtual are the virtual addresses, with port 0 for every port.
	virtual []netip.AddrPort
	// backends are the ranges of the servers, with port 0 for the port the
	// client connected to.
	backends []backend
	sources  []netip.Prefix
}

type backend struct {
	prefix netip.Prefix
	port   uint16
}

func (t *translation) has(proto string) bool { return slices.Contains(t.protos, proto) }

// reaches tells whether a server at local on port is a backend of the
// translation: fixed if a backend has that port, which every virtual port
// reaches, and same if a backend takes the port the client connected to.
func (t *translation) reaches(local netip.Addr, port uint16) (fixed, same bool) {
	for _, b := range t.backends {
		if !b.prefix.Contains(local) {
			continue
		}
		switch b.port {
		case port:
			fixed = true
		case 0:
			same = true
		}
	}
	return fixed, same
}

// parseTranslations parses and checks the translations of the
// configuration, ordered by name. Two translations may not share a virtual
// address and port, so that a client edge reaches at most one.
func parseTranslations(m map[string]TranslationConfig) ([]translation, error) {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []translation
	var errs []error
	type virtualKey struct {
		addr  netip.Addr
		proto string
	}
	seen := map[virtualKey]map[uint16]string{} // virtual address -> port -> translation
	for _, name := range names {
		t, err := parseTranslation(name, m[name])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, v := range t.virtual {
			for _, proto := range t.protos {
				k := virtualKey{v.Addr(), proto}
				ports := seen[k]
				if ports == nil {
					ports = map[uint16]string{}
					seen[k] = ports
				}
				for p, other := range ports {
					if p == v.Port() || p == 0 || v.Port() == 0 {
						err = fmt.Errorf("translations: %s/%s is in both %s and %s", formatAddrPort(v), proto, other, name)
					}
				}
				ports[v.Port()] = name
			}
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, t)
	}
	return out, errors.Join(errs...)
}

func parseTranslation(name string, c TranslationConfig) (translation, error) {
	t := translation{name: name}
	fail := func(format string, args ...any) (translation, error) {
		return translation{}, fmt.Errorf("translations: %s: "+format, append([]any{name}, args...)...)
	}
	if strings.TrimSpace(name) == "" {
		return translation{}, errors.New("translations: a translation has no name")
	}
	switch c.Transport {
	case "":
		t.protos = []string{"tcp", "udp"}
	case "tcp", "udp":
		t.protos = []string{c.Transport}
	default:
		return fail("transport must be tcp, udp or empty, not %q", c.Transport)
	}
	if len(c.Virtual) == 0 {
		return fail("no virtual address")
	}
	if len(c.Backends) == 0 {
		return fail("no backend")
	}
	allPorts := false
	for _, s := range c.Virtual {
		p, port, err := parseEndpoint(s)
		if err != nil {
			return fail("virtual: %v", err)
		}
		if !p.IsSingleIP() {
			return fail("virtual: %s is a range; list the addresses", s)
		}
		if p.Addr().IsUnspecified() {
			return fail("virtual: %s is unspecified", s)
		}
		ap := netip.AddrPortFrom(p.Addr(), port)
		if !slices.Contains(t.virtual, ap) {
			t.virtual = append(t.virtual, ap)
		}
		allPorts = allPorts || port == 0
	}
	for _, s := range c.Backends {
		p, port, err := parseEndpoint(s)
		if err != nil {
			return fail("backends: %v", err)
		}
		if port != 0 && allPorts {
			// Every port of a virtual address cannot reach one port.
			return fail("backends: %s has a port, but a virtual address has none", s)
		}
		b := backend{prefix: p, port: port}
		if !slices.Contains(t.backends, b) {
			t.backends = append(t.backends, b)
		}
	}
	for _, s := range c.Sources {
		p, port, err := parseEndpoint(s)
		if err != nil {
			return fail("sources: %v", err)
		}
		if port != 0 {
			return fail("sources: %s has a port", s)
		}
		if !slices.Contains(t.sources, p) {
			t.sources = append(t.sources, p)
		}
	}
	return t, nil
}

// parseEndpoint parses an address or a range with an optional port:
// 10.0.0.1, 10.0.0.1:80, 10.0.0.0/24, 10.0.0.0/24:80, 2001:db8::1,
// [2001:db8::1]:80, [2001:db8::/64]:80. An IPv4-mapped address is taken as
// the IPv4 address, as agents send them.
func parseEndpoint(s string) (netip.Prefix, uint16, error) {
	s = strings.TrimSpace(s)
	host, portStr := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return netip.Prefix{}, 0, fmt.Errorf("%q: no closing ]", s)
		}
		host, portStr = s[1:end], s[end+1:]
		if portStr == "" {
			break
		}
		if !strings.HasPrefix(portStr, ":") {
			return netip.Prefix{}, 0, fmt.Errorf("%q: expected :port after ]", s)
		}
		portStr = portStr[1:]
		if portStr == "" {
			return netip.Prefix{}, 0, fmt.Errorf("%q: empty port", s)
		}
	case strings.Count(s, ":") == 1:
		// IPv4 with a port; IPv6 has more colons, and takes brackets for a
		// port.
		host, portStr, _ = strings.Cut(s, ":")
		if portStr == "" {
			return netip.Prefix{}, 0, fmt.Errorf("%q: empty port", s)
		}
	}
	var port uint16
	if portStr != "" {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || n == 0 {
			return netip.Prefix{}, 0, fmt.Errorf("%q: invalid port", s)
		}
		port = uint16(n)
	}
	if strings.Contains(host, "%") {
		return netip.Prefix{}, 0, fmt.Errorf("%q: zones are not allowed", s)
	}
	if strings.Contains(host, "/") {
		p, err := parsePrefix(host)
		if err != nil {
			return netip.Prefix{}, 0, fmt.Errorf("%q: %w", s, err)
		}
		return p, port, nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("%q: %w", s, err)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), port, nil
}

func formatAddrPort(ap netip.AddrPort) string {
	if ap.Port() == 0 {
		return ap.Addr().String()
	}
	return ap.String()
}

// translationRow is a row of shawk.translations.
type translationRow struct {
	name, side, proto string
	prefix            netip.Prefix
	port              uint16
}

// translationRows returns the rows of shawk.translations for translations.
func translationRows(ts []translation) []translationRow {
	var out []translationRow
	for _, t := range ts {
		for _, proto := range t.protos {
			for _, v := range t.virtual {
				out = append(out, translationRow{t.name, "virtual", proto,
					netip.PrefixFrom(v.Addr(), v.Addr().BitLen()), v.Port()})
			}
			for _, b := range t.backends {
				out = append(out, translationRow{t.name, "backend", proto, b.prefix, b.port})
			}
			for _, s := range t.sources {
				out = append(out, translationRow{t.name, "source", proto, s, 0})
			}
		}
	}
	return out
}
