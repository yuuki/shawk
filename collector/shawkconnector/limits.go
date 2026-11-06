package shawkconnector

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// maxHostsPerCertificate bounds the hosts held of one client certificate
// (host_identity: certificate). The certificate names the host.name, but
// neither the host.id nor the case of host.name or a final dot, which all
// tell hosts apart (hostKey), so that one certificate would otherwise hold
// any number of hosts. A host whose machine id changes, on a reinstall or
// at every boot of a stateless node (§4.1 of docs/design.md), becomes a new
// host while the former is held for idle_ttl: four let it boot three times
// within idle_ttl.
const maxHostsPerCertificate = 4

// limits bounds what the connector holds of the hosts that send to it, which
// every map of its state is keyed by: at most maxHosts hosts, at most
// maxHostsPerCertificate of one certificate, and per host at most maxSeries
// edges, listeners, translations and addresses. A host or a series is held
// from its first request until the TTL after its latest, as the state the
// connector keeps of it. A new host beyond the bounds is refused, and the
// new series of a host beyond it are dropped, so that what is held is never
// evicted.
type limits struct {
	maxHosts, maxSeries int
	ttl                 time.Duration

	mu    sync.Mutex
	hosts map[string]*heldHost
	// certificates counts the hosts held of every certificate.
	certificates map[string]int
}

// admission tells whether limits takes the request of a host.
type admission int

const (
	// admitted: the host is held.
	admitted admission = iota
	// hostsFull: the host is new and maxHosts hosts are held.
	hostsFull
	// certificateFull: the host is new and maxHostsPerCertificate hosts of
	// its certificate are held.
	certificateFull
)

// heldHost is what limits holds of a host, each with when it was last
// received.
type heldHost struct {
	certificate  string
	seen         time.Time
	edges        map[edgeID]time.Time
	listeners    map[listenerID]time.Time
	translations map[translationID]time.Time
	addrs        map[netip.Addr]time.Time
	// dropped tells that series of the host were dropped since its latest
	// request that closed an interval.
	dropped bool
}

func newLimits(maxHosts, maxSeries int, ttl time.Duration) *limits {
	return &limits{maxHosts: maxHosts, maxSeries: maxSeries, ttl: ttl, hosts: map[string]*heldHost{},
		certificates: map[string]int{}}
}

// admit takes a request received at now. It refuses a host that is not
// held if maxHosts hosts are, or maxHostsPerCertificate of its certificate,
// if it has one. Otherwise it removes from b the series that are not held,
// beyond maxSeries, and returns how many it removed. A request that closes
// an interval tells in b.limited whether series of the host were removed in
// the interval.
func (l *limits) admit(b *hostBatch, now time.Time) (admission, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hosts[b.key]
	if h == nil {
		if len(l.hosts) >= l.maxHosts {
			return hostsFull, 0
		}
		if b.certificate != "" && l.certificates[b.certificate] >= maxHostsPerCertificate {
			return certificateFull, 0
		}
		h = &heldHost{
			certificate:  b.certificate,
			edges:        map[edgeID]time.Time{},
			listeners:    map[listenerID]time.Time{},
			translations: map[translationID]time.Time{},
			addrs:        map[netip.Addr]time.Time{},
		}
		l.hosts[b.key] = h
		if h.certificate != "" {
			l.certificates[h.certificate]++
		}
	}
	h.seen = now
	n := len(h.edges) + len(h.listeners) + len(h.translations) + len(h.addrs)
	dropped := 0
	// The addresses of the host come first, then its series in the order
	// the agent sends them.
	b.addrs = slices.DeleteFunc(b.addrs, func(a netip.Addr) bool {
		if hold(h.addrs, a, &n, l.maxSeries, now) {
			return false
		}
		dropped++
		return true
	})
	for id := range b.listeners {
		if !hold(h.listeners, id, &n, l.maxSeries, now) {
			delete(b.listeners, id)
			dropped++
		}
	}
	for id := range b.translations {
		if !hold(h.translations, id, &n, l.maxSeries, now) {
			delete(b.translations, id)
			dropped++
		}
	}
	for id := range b.edges {
		if !hold(h.edges, id, &n, l.maxSeries, now) {
			delete(b.edges, id)
			dropped++
		}
	}
	if dropped > 0 {
		h.dropped = true
	}
	if b.final {
		b.limited, h.dropped = h.dropped, false
	}
	return admitted, dropped
}

// hold marks k of a host with n series as received at now, and tells
// whether it is held: whether it was, or the host holds fewer than max.
func hold[K comparable](m map[K]time.Time, k K, n *int, max int, now time.Time) bool {
	if _, ok := m[k]; !ok {
		if *n >= max {
			return false
		}
		*n++
	}
	m[k] = now
	return true
}

// expire forgets the series and hosts not received for the TTL, as the
// connector forgets their state.
func (l *limits) expire(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, h := range l.hosts {
		if now.Sub(h.seen) > l.ttl {
			delete(l.hosts, key)
			if h.certificate != "" {
				if l.certificates[h.certificate]--; l.certificates[h.certificate] == 0 {
					delete(l.certificates, h.certificate)
				}
			}
			continue
		}
		expireHeld(h.edges, now, l.ttl)
		expireHeld(h.listeners, now, l.ttl)
		expireHeld(h.translations, now, l.ttl)
		expireHeld(h.addrs, now, l.ttl)
	}
}

func expireHeld[K comparable](m map[K]time.Time, now time.Time, ttl time.Duration) {
	for k, t := range m {
		if now.Sub(t) > ttl {
			delete(m, k)
		}
	}
}
