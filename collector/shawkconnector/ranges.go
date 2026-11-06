package shawkconnector

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// namedPrefix is a range of addresses and its name.
type namedPrefix struct {
	name   string
	prefix netip.Prefix
}

// parseRanges parses ranges of addresses by name, the setting option of
// the configuration (peer_cidrs, networks): a value may list several
// prefixes separated by commas. Names must not be empty or start with ~,
// which the values shawk gives itself start with, and a prefix may have one
// name only. IPv4-mapped prefixes are unmapped, as the addresses of edges
// are. The ranges are returned narrowest first, so that the first that
// holds an address is the narrowest.
func parseRanges(option string, m map[string]string) ([]namedPrefix, error) {
	var out []namedPrefix
	seen := map[netip.Prefix]string{}
	for name, v := range m {
		if name == "" || strings.HasPrefix(name, "~") {
			return nil, fmt.Errorf("%s: invalid name %q", option, name)
		}
		for _, s := range strings.Split(v, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", option, name, err)
			}
			p = unmapPrefix(p.Masked())
			if other, dup := seen[p]; dup {
				return nil, fmt.Errorf("%s: %s is named both %s and %s", option, p, other, name)
			}
			seen[p] = name
			out = append(out, namedPrefix{name: name, prefix: p})
		}
	}
	sortPrefixes(out)
	return out, nil
}

// unmapPrefix returns an IPv4-mapped prefix (within ::ffff:0:0/96) as the
// IPv4 prefix it holds, and other prefixes as they are.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// sortPrefixes orders prefixes from the narrowest.
func sortPrefixes(ps []namedPrefix) {
	slices.SortStableFunc(ps, func(a, b namedPrefix) int {
		if a.prefix.Bits() != b.prefix.Bits() {
			return b.prefix.Bits() - a.prefix.Bits()
		}
		return a.prefix.Addr().Compare(b.prefix.Addr())
	})
}

// rangeOf returns the name of the narrowest of ranges, sorted narrowest
// first, that holds an address.
func rangeOf(ranges []namedPrefix, a netip.Addr) (string, bool) {
	for _, p := range ranges {
		if p.prefix.Contains(a) {
			return p.name, true
		}
	}
	return "", false
}

// wholeRangeOf returns the name of a range that holds every address of the
// family of a (0.0.0.0/0 or ::/0): the range of a folded peer, which stands
// for every address outside the internal ranges of its agent.
func wholeRangeOf(ranges []namedPrefix, a netip.Addr) (string, bool) {
	for _, p := range ranges {
		if p.prefix.Bits() == 0 && p.prefix.Addr().BitLen() == a.BitLen() {
			return p.name, true
		}
	}
	return "", false
}
