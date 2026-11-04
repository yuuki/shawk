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

// DynamicPortsConfig is a range of ports that servers get anew at every
// run, such as the SrunPortRange of a Slurm cluster, on which dependencies
// are aggregated without their port.
type DynamicPortsConfig struct {
	// Hosts lists the addresses or ranges of the servers: 10.1.0.0/16,
	// 2001:db8::/64. Empty for every address.
	Hosts []string `mapstructure:"hosts"`
	// Transport is tcp or udp; empty for both.
	Transport string `mapstructure:"transport"`
	// Ports is the range of ports, 60001-63000, or a single port.
	Ports string `mapstructure:"ports"`
}

// portRules tells the dependencies whose port is not kept when they are
// aggregated by service: those on a service of port_agnostic_services, and
// those on a server address and port in a range of dynamic_ports. The
// edges keep their port.
type portRules struct {
	services []string // sorted
	ranges   []dynamicPorts
}

// dynamicPorts is a parsed DynamicPortsConfig.
type dynamicPorts struct {
	name     string
	protos   []string
	prefixes []netip.Prefix // every address when empty
	from, to uint16
}

// portAgnostic tells whether a dependency on service at server, port and
// proto is aggregated without its port. server is the address of the
// server as the edge sees it.
func (r *portRules) portAgnostic(service string, server netip.Addr, port uint16, proto string) bool {
	if r == nil {
		return false
	}
	if _, ok := slices.BinarySearch(r.services, service); ok {
		return true
	}
	for _, d := range r.ranges {
		if port < d.from || port > d.to || !slices.Contains(d.protos, proto) {
			continue
		}
		if len(d.prefixes) == 0 || slices.ContainsFunc(d.prefixes, func(p netip.Prefix) bool { return p.Contains(server) }) {
			return true
		}
	}
	return false
}

// parsePortRules parses port_agnostic_services and dynamic_ports, the
// ranges ordered by name.
func parsePortRules(services []string, m map[string]DynamicPortsConfig) (*portRules, error) {
	r := &portRules{}
	var errs []error
	for _, s := range services {
		if strings.TrimSpace(s) == "" {
			errs = append(errs, errors.New("port_agnostic_services: a service has no name"))
			continue
		}
		if strings.TrimSpace(s) != s {
			// It would never match the name of a service.
			errs = append(errs, fmt.Errorf("port_agnostic_services: %q has spaces around it", s))
			continue
		}
		if !slices.Contains(r.services, s) {
			r.services = append(r.services, s)
		}
	}
	sort.Strings(r.services)
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d, err := parseDynamicPorts(name, m[name])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.ranges = append(r.ranges, d)
	}
	return r, errors.Join(errs...)
}

func parseDynamicPorts(name string, c DynamicPortsConfig) (dynamicPorts, error) {
	d := dynamicPorts{name: name}
	fail := func(format string, args ...any) (dynamicPorts, error) {
		return dynamicPorts{}, fmt.Errorf("dynamic_ports: %s: "+format, append([]any{name}, args...)...)
	}
	if strings.TrimSpace(name) == "" {
		return dynamicPorts{}, errors.New("dynamic_ports: a range has no name")
	}
	switch c.Transport {
	case "":
		d.protos = []string{"tcp", "udp"}
	case "tcp", "udp":
		d.protos = []string{c.Transport}
	default:
		return fail("transport must be tcp, udp or empty, not %q", c.Transport)
	}
	from, to, ok := strings.Cut(strings.TrimSpace(c.Ports), "-")
	if !ok {
		to = from
	}
	lo, err1 := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
	hi, err2 := strconv.ParseUint(strings.TrimSpace(to), 10, 16)
	if err1 != nil || err2 != nil || lo == 0 || hi < lo {
		return fail("ports must be a port or a range of ports such as 60001-63000, not %q", c.Ports)
	}
	d.from, d.to = uint16(lo), uint16(hi)
	for _, s := range c.Hosts {
		p, port, err := parseEndpoint(s)
		if err != nil {
			return fail("hosts: %v", err)
		}
		if port != 0 {
			return fail("hosts: %s has a port; the ports are in ports", s)
		}
		if !slices.Contains(d.prefixes, p) {
			d.prefixes = append(d.prefixes, p)
		}
	}
	return d, nil
}

// keys returns the rules as the rows of the tables, sorted, so that the
// rules of two connectors compare.
func (r *portRules) keys() []string {
	var out []string
	if r != nil {
		for _, s := range r.services {
			out = append(out, "service "+s)
		}
	}
	for _, d := range r.dynamicPortsRows() {
		out = append(out, d.key())
	}
	sort.Strings(out)
	return out
}

// dynamicPortsRow is a row of shawk.dynamic_ports.
type dynamicPortsRow struct {
	name, proto string
	prefix      netip.Prefix
	from, to    uint16
}

func (d dynamicPortsRow) key() string {
	return fmt.Sprintf("dynamic_ports %s %s %s %d-%d", d.name, d.proto, d.prefix, d.from, d.to)
}

// dynamicPortsRows returns the rows of shawk.dynamic_ports: a range for
// every address has the rows 0.0.0.0/0 and ::/0.
func (r *portRules) dynamicPortsRows() []dynamicPortsRow {
	if r == nil {
		return nil
	}
	every := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	var out []dynamicPortsRow
	for _, d := range r.ranges {
		prefixes := d.prefixes
		if len(prefixes) == 0 {
			prefixes = every
		}
		for _, proto := range d.protos {
			for _, p := range prefixes {
				out = append(out, dynamicPortsRow{d.name, proto, p, d.from, d.to})
			}
		}
	}
	return out
}
