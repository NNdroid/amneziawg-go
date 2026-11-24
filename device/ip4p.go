/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2026 AmneziaWG project. All Rights Reserved.
 *
 * IP4P (IPv4 privacy) address decoding and periodic refresh.
 *
 * An IP4P address is an IPv6 address of the form
 *
 *	{prefix}:0:0:0:0:{port}:{ipv4-hi16}:{ipv4-lo16}
 *
 * where the last three 16-bit groups encode the destination port and the two
 * halves of an IPv4 address. The default prefix is "2001::". The IPv4 address
 * and port encoded in such an address are expected to change over time, so the
 * address must be re-resolved (via DNS AAAA) periodically and the decoded
 * endpoint refreshed.
 */

package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultIP4PPrefix is the default IPv6 prefix used to recognise IP4P
// addresses when no explicit prefix is configured.
const DefaultIP4PPrefix = "2001::"

// ip4pRefreshInterval is how often IP4P endpoints are re-resolved. The encoded
// IPv4 address and port are expected to be dynamic, so a periodic refresh keeps
// the tunnel pointed at the current address.
const ip4pRefreshInterval = 1 * time.Minute

// ip4pState carries the per-device IP4P configuration and the background
// refresher lifecycle.
type ip4pState struct {
	// servers is the parsed bootstrap DNS servers.
	servers []bootstrapDnsServer
	// prefix is the IPv6 prefix used to recognise IP4P addresses.
	prefix string
	// prefixBytes is the fixed leading bytes of the prefix (5 x 16-bit groups).
	prefixBytes [10]byte
	// prefixValid is true when prefixBytes holds a usable prefix.
	prefixValid bool
	// stop is closed to stop the refresher goroutine.
	stop chan struct{}
	// running reports whether the refresher goroutine is active.
	running atomic.Bool
}

// newIP4PState builds an ip4pState from raw bootstrap DNS server specifiers
// and an optional IPv6 prefix. An empty prefix defaults to DefaultIP4PPrefix.
func newIP4PState(servers []string, prefix string) (*ip4pState, error) {
	s := &ip4pState{}
	for _, spec := range servers {
		srv, err := parseBootstrapDnsServer(spec)
		if err != nil {
			return nil, err
		}
		s.servers = append(s.servers, srv)
	}
	if prefix == "" {
		prefix = DefaultIP4PPrefix
	}
	s.prefix = prefix
	if err := s.setPrefix(prefix); err != nil {
		return nil, err
	}
	return s, nil
}

// setPrefix stores the IP4P prefix and precomputes the fixed leading bytes.
func (s *ip4pState) setPrefix(prefix string) error {
	addr, err := netip.ParseAddr(prefix)
	if err != nil {
		return fmt.Errorf("invalid IP4P prefix %q: %w", prefix, err)
	}
	if !addr.Is6() {
		return fmt.Errorf("IP4P prefix must be an IPv6 address, got %q", prefix)
	}
	b := addr.As16()
	copy(s.prefixBytes[:], b[:10]) // first five 16-bit groups
	s.prefixValid = true
	return nil
}

// decodeIP4P decodes an IPv6 address into an IP4P endpoint if the address
// matches the configured prefix. It returns the real IPv4:port endpoint and
// true on success, or a zero value and false if addr is not an IP4P address.
func (s *ip4pState) decodeIP4P(addr netip.Addr) (netip.AddrPort, bool) {
	if !s.prefixValid || !addr.Is6() {
		return netip.AddrPort{}, false
	}
	b := addr.As16()
	for i := 0; i < 10; i++ {
		if b[i] != s.prefixBytes[i] {
			return netip.AddrPort{}, false
		}
	}
	// Last three 16-bit groups: port, ipv4-hi16, ipv4-lo16.
	port := uint16(b[10])<<8 | uint16(b[11])
	hi := uint16(b[12])<<8 | uint16(b[13])
	lo := uint16(b[14])<<8 | uint16(b[15])
	ipv4 := netip.AddrFrom4([4]byte{byte(hi >> 8), byte(hi), byte(lo >> 8), byte(lo)})
	return netip.AddrPortFrom(ipv4, port), true
}

// resolveIP4P resolves host to an IP4P endpoint by querying the bootstrap DNS
// servers for AAAA records and decoding the first matching IP4P address.
func (s *ip4pState) resolveIP4P(ctx context.Context, host string) (netip.AddrPort, error) {
	if len(s.servers) == 0 {
		return netip.AddrPort{}, errors.New("no bootstrap DNS servers configured")
	}
	var lastErr error
	for _, server := range s.servers {
		addrs, err := server.lookupAAAA(ctx, host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, addr := range addrs {
			if ep, ok := s.decodeIP4P(addr); ok {
				return ep, nil
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no IP4P address in DNS AAAA answers")
	}
	return netip.AddrPort{}, fmt.Errorf("resolve IP4P %q: %w", host, lastErr)
}

// isIP4PHost reports whether host looks like a literal IP4P IPv6 address that
// should be decoded directly rather than resolved via DNS.
func (s *ip4pState) isIP4PHost(host string) bool {
	if !s.prefixValid {
		return false
	}
	// Strip IPv6 brackets if present.
	h := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	_, ok := s.decodeIP4P(addr)
	return ok
}

// tryIP4PEndpoint attempts to resolve an endpoint value as an IP4P endpoint.
// It returns true if the value should be handled as IP4P (either a literal
// IP4P IPv6 address, or a hostname that must be resolved via the bootstrap DNS
// servers). On success it records the IP4P state on the peer and stores the
// decoded IPv4:port endpoint. It returns false when IP4P is not configured or
// the value is a plain numeric endpoint that should be handled normally.
func (device *Device) tryIP4PEndpoint(peer *Peer, value string) (bool, error) {
	device.ip4pMutex.Lock()
	ip := device.ip4p
	device.ip4pMutex.Unlock()
	if ip == nil || !ip.prefixValid {
		device.log.Verbosef("IP4P: endpoint %q not handled, IP4P not configured (prefixValid=%v, state=%v)", value, ip != nil && ip.prefixValid, ip != nil)
		return false, nil
	}

	host := value
	// Strip a trailing :port, handling both "host:port" and "[v6]:port".
	if h, _, err := net.SplitHostPort(value); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	// A literal IP4P IPv6 address decodes directly.
	if addr, err := netip.ParseAddr(host); err == nil {
		if ep, ok := ip.decodeIP4P(addr); ok {
			device.log.Verbosef("IP4P: literal endpoint %q decoded to %v", value, ep)
			peer.enableIP4P(value, host)
			peer.setIP4PResolved(ep)
			return true, nil
		}
		device.log.Verbosef("IP4P: literal %q does not match prefix %q; falling back to plain endpoint", value, ip.prefix)
		return false, nil
	}

	// Otherwise treat it as a hostname to resolve via bootstrap DNS.
	if len(ip.servers) == 0 {
		device.log.Verbosef("IP4P: endpoint %q is a hostname but no bootstrap DNS servers configured; not handling as IP4P", value)
		return false, nil
	}
	device.log.Verbosef("IP4P: resolving endpoint host %q via %d bootstrap DNS server(s)", host, len(ip.servers))
	ep, err := ip.resolveIP4P(context.Background(), host)
	if err != nil {
		device.log.Errorf("IP4P: resolve of %q failed: %v", host, err)
		return true, err
	}
	device.log.Verbosef("IP4P: endpoint host %q resolved to %v", host, ep)
	peer.enableIP4P(value, host)
	peer.setIP4PResolved(ep)
	return true, nil
}

// startRefresher launches the background goroutine that periodically
// re-resolves IP4P endpoints for all peers. It is a no-op if already running.
func (device *Device) startIP4PRefresher() {
	device.ip4pMutex.Lock()
	ip := device.ip4p
	device.ip4pMutex.Unlock()
	if ip == nil || !ip.prefixValid || len(ip.servers) == 0 {
		device.log.Verbosef("IP4P refresher not started (configured=%v, prefixValid=%v, servers=%d)",
			ip != nil, ip != nil && ip.prefixValid, func() int {
				if ip == nil {
					return 0
				}
				return len(ip.servers)
			}())
		return
	}
	if !ip.running.CompareAndSwap(false, true) {
		return
	}
	ip.stop = make(chan struct{})
	device.log.Verbosef("IP4P refresher started (prefix=%q, %d server(s))", ip.prefix, len(ip.servers))
	go device.ip4pRefreshLoop(ip)
}

// bootstrapDnsCount returns the number of configured bootstrap DNS servers.
// It is used for diagnostics in UAPI logging.
func (device *Device) bootstrapDnsCount() int {
	device.ip4pMutex.Lock()
	defer device.ip4pMutex.Unlock()
	if device.ip4p == nil {
		return 0
	}
	return len(device.ip4p.servers)
}

// stopRefresher stops the background IP4P refresher goroutine.
func (device *Device) stopIP4PRefresher() {
	ip := device.ip4p
	if ip == nil || !ip.running.CompareAndSwap(true, false) {
		return
	}
	close(ip.stop)
}

// ip4pRefreshLoop periodically re-resolves every peer's IP4P endpoint.
func (device *Device) ip4pRefreshLoop(ip *ip4pState) {
	defer ip.running.Store(false)
	ticker := time.NewTicker(ip4pRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ip.stop:
			return
		case <-ticker.C:
			device.refreshIP4PEndpoints(context.Background(), ip)
		}
	}
}

// refreshIP4PEndpoints walks all peers and, for any whose endpoint is a host
// that resolves to an IP4P address, re-resolves and updates the stored
// endpoint.
func (device *Device) refreshIP4PEndpoints(ctx context.Context, ip *ip4pState) {
	device.peers.RLock()
	peers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	device.peers.RUnlock()

	var refreshed int
	for _, peer := range peers {
		if !peer.ip4p.enabled {
			continue
		}
		host := peer.ip4p.host
		addrPort, err := ip.resolveIP4P(ctx, host)
		if err != nil {
			device.log.Errorf("IP4P refresh of %q failed: %v", host, err)
			continue
		}
		device.log.Verbosef("IP4P refresh %q -> %v", host, addrPort)
		peer.setIP4PResolved(addrPort)
		refreshed++
	}
	device.log.Verbosef("IP4P refresh pass complete (%d endpoint(s) refreshed)", refreshed)
}
