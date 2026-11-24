/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2026 AmneziaWG project. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"
)

func TestDecodeIP4P(t *testing.T) {
	s, err := newIP4PState(nil, "")
	if err != nil {
		t.Fatalf("newIP4PState: %v", err)
	}

	// 2001:0:0:0:0:1f90:0ac8:0201 -> 10.200.2.1:8080
	addr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")
	ep, ok := s.decodeIP4P(addr)
	if !ok {
		t.Fatalf("expected IP4P decode to succeed for %v", addr)
	}
	want := netip.MustParseAddrPort("10.200.2.1:8080")
	if ep != want {
		t.Fatalf("decodeIP4P(%v) = %v, want %v", addr, ep, want)
	}
}

func TestDecodeIP4PNonIP4P(t *testing.T) {
	s, err := newIP4PState(nil, "")
	if err != nil {
		t.Fatalf("newIP4PState: %v", err)
	}

	// A normal IPv6 address (different prefix) must not decode as IP4P.
	addr := netip.MustParseAddr("2001:db8::1")
	if _, ok := s.decodeIP4P(addr); ok {
		t.Fatalf("expected %v to not be IP4P", addr)
	}

	// IPv4 addresses are never IP4P.
	v4 := netip.MustParseAddr("10.200.2.1")
	if _, ok := s.decodeIP4P(v4); ok {
		t.Fatalf("expected IPv4 %v to not be IP4P", v4)
	}
}

func TestDecodeIP4PCustomPrefix(t *testing.T) {
	s, err := newIP4PState(nil, "fd00::")
	if err != nil {
		t.Fatalf("newIP4PState: %v", err)
	}
	// fd00:0:0:0:0:1f90:0ac8:0201 -> 10.200.2.1:8080
	addr := netip.MustParseAddr("fd00:0:0:0:0:1f90:0ac8:0201")
	ep, ok := s.decodeIP4P(addr)
	if !ok {
		t.Fatalf("expected custom-prefix IP4P decode to succeed for %v", addr)
	}
	want := netip.MustParseAddrPort("10.200.2.1:8080")
	if ep != want {
		t.Fatalf("decodeIP4P(%v) = %v, want %v", addr, ep, want)
	}

	// Default prefix 2001:: must not match under custom prefix.
	if _, ok := s.decodeIP4P(netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")); ok {
		t.Fatalf("expected default-prefix address to not match custom prefix")
	}
}

func TestDecodeIP4PInvalidPrefix(t *testing.T) {
	if _, err := newIP4PState(nil, "not-an-ip"); err == nil {
		t.Fatal("expected invalid prefix to error")
	}
	if _, err := newIP4PState(nil, "10.0.0.1"); err == nil {
		t.Fatal("expected IPv4 prefix to error")
	}
}

func TestParseBootstrapDnsServer(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantAddr string
	}{
		{"1.1.1.1:53", "udp", "1.1.1.1:53"},
		{"dns://1.1.1.1:53", "udp", "1.1.1.1:53"},
		{"tcp://1.1.1.1:53", "tcp", "1.1.1.1:53"},
		{"dot://1.1.1.1:853", "dot", "1.1.1.1:853"},
		{"doh://dns.google/dns-query", "doh", "https://dns.google/dns-query"},
		{"https://dns.google/dns-query", "doh", "https://dns.google/dns-query"},
		{"dns://1.1.1.1", "udp", "1.1.1.1:53"},
		{"dot://1.1.1.1", "dot", "1.1.1.1:853"},
	}
	for _, tc := range cases {
		s, err := parseBootstrapDnsServer(tc.in)
		if err != nil {
			t.Errorf("parseBootstrapDnsServer(%q): %v", tc.in, err)
			continue
		}
		if s.kind != tc.wantKind || s.addr != tc.wantAddr {
			t.Errorf("parseBootstrapDnsServer(%q) = {%q %q}, want {%q %q}", tc.in, s.kind, s.addr, tc.wantKind, tc.wantAddr)
		}
	}

	if _, err := parseBootstrapDnsServer(""); err == nil {
		t.Error("expected empty server to error")
	}
}
