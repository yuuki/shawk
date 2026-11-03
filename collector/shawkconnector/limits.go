package shawkconnector

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// limits bounds what the connector holds of the hosts that send to it, which
// every map of its state is keyed by: at most maxHosts hosts, and per host at
// most maxSeries edges, listeners, translations and addresses. A host or a
// series is held from its first request until the TTL after its latest, as
// the state the connector keeps of it. A new host beyond the bound is
// refused, and the new series of a host beyond it are dropped, so that what
// is held is never evicted.
type limits struct {
	maxHosts, maxSeries int
	ttl                 time.Duration

	mu    sync.Mutex
	hosts map[string]*heldHost
}

// heldHost is what limits holds of a host, each with when it was last
// received.
type heldHost struct {
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
	return &limits{maxHosts: maxHosts, maxSeries: maxSeries, ttl: ttl, hosts: map[string]*heldHost{}}
}

// admit takes a request received at now. It returns false if the host is
// not held and maxHosts hosts are. Otherwise it removes from b the series
// that are not held, beyond maxSeries, and returns how many it removed. A
// request that closes an interval tells in b.limited whether series of the
// host were removed in the interval.
func (l *limits) admit(b *hostBatch, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hosts[b.key]
	if h == nil {
		if len(l.hosts) >= l.maxHosts {
			return false, 0
		}
		h = &heldHost{
			edges:        map[edgeID]time.Time{},
			listeners:    map[listenerID]time.Time{},
			translations: map[translationID]time.Time{},
			addrs:        map[netip.Addr]time.Time{},
		}
		l.hosts[b.key] = h
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
	return true, dropped
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
