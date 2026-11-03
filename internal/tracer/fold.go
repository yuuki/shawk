package tracer

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// v4InV6 are the IPv4-mapped IPv6 addresses, by which the programs look up
// IPv4 peers.
var v4InV6 = netip.MustParsePrefix("::ffff:0:0/96")

// CheckInternalPeer reports an internal range that the programs would not
// tell from the other address family: IPv4 peers are looked up as
// IPv4-mapped IPv6 addresses, so an IPv6 range that overlaps them, such as
// ::/0, would also keep the IPv4 peers in it.
func CheckInternalPeer(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("invalid internal range %s", p)
	}
	if p.Addr().Is6() && p.Overlaps(v4InV6) {
		return fmt.Errorf("the IPv6 range %s overlaps the IPv4-mapped addresses (%s), which stand for IPv4 peers; list IPv4 ranges as such", p, v4InV6)
	}
	return nil
}

// keyFolded is KEY_FOLDED of struct shawk_flow_key.
const keyFolded = 1 << 0

// alwaysInternal are the ranges whose peers are never folded.
var alwaysInternal = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// maxLocalPeers bounds the addresses of the host given to SetLocalAddrs.
const maxLocalPeers = 4096

// peerPrefixKey returns the key of internal_peers for a prefix: IPv4
// prefixes are IPv4-mapped, as the addresses of the flows are.
func peerPrefixKey(p netip.Prefix) bpfShawkPeerPrefix {
	p = p.Masked()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	return bpfShawkPeerPrefix{Prefixlen: uint32(bits), Addr: p.Addr().As16()}
}

// SetLocalAddrs sets the addresses of the host, whose peers are never
// folded, e.g. a host that connects to its own public address. It replaces
// the addresses of the previous call (or of Options.LocalAddrs); those in
// an internal range need no entry, and only the first maxLocalPeers of the
// others are kept.
func (t *Tracer) SetLocalAddrs(addrs []netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.setLocalAddrs(addrs)
}

func (t *Tracer) setLocalAddrs(addrs []netip.Addr) error {
	if t.opts.Fold == FoldNone {
		return nil
	}
	want := make(map[bpfShawkPeerPrefix]bool, len(addrs))
	for _, a := range addrs {
		a = a.WithZone("").Unmap()
		if !a.IsValid() || t.internalAddr(a) {
			continue
		}
		if len(want) == maxLocalPeers {
			break
		}
		want[peerPrefixKey(netip.PrefixFrom(a, a.BitLen()))] = true
	}
	// Former addresses go first, so that the trie has room for new ones.
	for k := range t.localPeers {
		if want[k] {
			continue
		}
		if err := t.internalPeers.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("removing a local address from the internal ranges: %w", err)
		}
		delete(t.localPeers, k)
	}
	for k := range want {
		if t.localPeers[k] {
			continue
		}
		if err := t.internalPeers.Update(&k, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("adding a local address to the internal ranges: %w", err)
		}
		t.localPeers[k] = true
	}
	return nil
}

// internalAddr tells whether an address is in a range that is always kept
// or in an internal range of the options.
func (t *Tracer) internalAddr(a netip.Addr) bool {
	for _, ps := range [][]netip.Prefix{alwaysInternal, t.opts.InternalPeers} {
		for _, p := range ps {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}
