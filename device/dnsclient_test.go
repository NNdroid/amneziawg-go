/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2026 AmneziaWG project. All Rights Reserved.
 */

package device

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// startMockDnsUDP starts a UDP DNS server that answers every AAAA query with
// the given addresses. It returns the server's address and a stop function.
func startMockDnsUDP(t *testing.T, answers ...netip.Addr) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			resp := buildAAAAResponse(buf[:n], answers)
			conn.WriteToUDP(resp, addr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		close(done)
		conn.Close()
	}
}

// buildAAAAResponse constructs a DNS response echoing the question and adding
// AAAA answers.
func buildAAAAResponse(query []byte, answers []netip.Addr) []byte {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 uint16(query[0])<<8 | uint16(query[1]),
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{q},
	}
	for _, a := range answers {
		if a.Is6() {
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AAAAResource{AAAA: a.As16()},
			})
		} else {
			b4 := a.As4()
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: b4},
			})
		}
	}
	out, _ := msg.Pack()
	return out
}

func TestLookupAAAAMock(t *testing.T) {
	want := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")
	addr, stop := startMockDnsUDP(t, want)
	defer stop()

	srv, err := parseBootstrapDnsServer(addr)
	if err != nil {
		t.Fatalf("parseBootstrapDnsServer: %v", err)
	}
	addrs, err := srv.lookupAAAA(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("lookupAAAA: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("lookupAAAA = %v, want %v", addrs, []netip.Addr{want})
	}
}

func TestResolveIP4PWithMockDns(t *testing.T) {
	want := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")
	addr, stop := startMockDnsUDP(t, want)
	defer stop()

	s, err := newIP4PState([]string{addr}, "")
	if err != nil {
		t.Fatalf("newIP4PState: %v", err)
	}
	ep, err := s.resolveIP4P(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("resolveIP4P: %v", err)
	}
	wantEP := netip.MustParseAddrPort("10.200.2.1:8080")
	if ep != wantEP {
		t.Fatalf("resolveIP4P = %v, want %v", ep, wantEP)
	}
}

// TestDoHBasicAuth verifies that userinfo in a DoH URL is converted into an
// HTTP Basic Authorization header, and that the userinfo is stripped from the
// request URL.
func TestDoHBasicAuth(t *testing.T) {
	ip4pAddr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))

	var gotAuth string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.String()
		// Respond with a DNS AAAA message.
		req, _ := io.ReadAll(r.Body)
		resp := buildAAAAResponse(req, []netip.Addr{ip4pAddr})
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:port; inject userinfo.
	dohURL := strings.Replace(srv.URL, "http://", "http://user:pass@", 1) + "/dns-query"

	srv2 := bootstrapDnsServer{addr: dohURL, kind: "doh"}
	addrs, err := srv2.lookupAAAA(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("lookupAAAA over DoH: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ip4pAddr {
		t.Fatalf("lookupAAAA = %v, want %v", addrs, []netip.Addr{ip4pAddr})
	}
	if gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", gotAuth, wantAuth)
	}
	if strings.Contains(gotPath, "user:pass") {
		t.Errorf("userinfo leaked into request URL: %q", gotPath)
	}
}

// testRootPool returns a cert pool trusting the httptest server's certificate,
// so tests can verify against a self-signed TLS server.
func testRootPool(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// TestDoHHTTPSOverUTLS verifies the HTTPS DoH path: it uses uTLS and, when the
// server supports HTTP/2, negotiates h2 and succeeds.
func TestDoHHTTPSOverUTLS(t *testing.T) {
	ip4pAddr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")

	var proto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		req, _ := io.ReadAll(r.Body)
		resp := buildAAAAResponse(req, []netip.Addr{ip4pAddr})
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	dohURL := srv.URL + "/dns-query"
	s := bootstrapDnsServer{
		addr:      dohURL,
		kind:      "doh",
		tlsConfig: &tls.Config{RootCAs: testRootPool(srv)},
	}
	addrs, err := s.lookupAAAA(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("lookupAAAA over HTTPS DoH: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ip4pAddr {
		t.Fatalf("lookupAAAA = %v, want %v", addrs, []netip.Addr{ip4pAddr})
	}
	if proto != "HTTP/2.0" {
		t.Errorf("negotiated protocol = %q, want HTTP/2.0", proto)
	}
}

// TestDoHHTTPSFallbackHTTP1 verifies the HTTPS DoH path falls back to HTTP/1.1
// when the server does not support HTTP/2, while still using uTLS.
func TestDoHHTTPSFallbackHTTP1(t *testing.T) {
	ip4pAddr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")

	var proto string
	// NewTLSServer (without EnableHTTP2) serves HTTP/1.1 only.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		req, _ := io.ReadAll(r.Body)
		resp := buildAAAAResponse(req, []netip.Addr{ip4pAddr})
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	defer srv.Close()

	dohURL := srv.URL + "/dns-query"
	s := bootstrapDnsServer{
		addr:      dohURL,
		kind:      "doh",
		tlsConfig: &tls.Config{RootCAs: testRootPool(srv)},
	}
	addrs, err := s.lookupAAAA(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("lookupAAAA over HTTPS DoH (fallback): %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ip4pAddr {
		t.Fatalf("lookupAAAA = %v, want %v", addrs, []netip.Addr{ip4pAddr})
	}
	if proto != "HTTP/1.1" {
		t.Errorf("negotiated protocol = %q, want HTTP/1.1", proto)
	}
}

// TestDoTOverUTLS verifies the DoT path performs a length-prefixed DNS query
// over a uTLS connection (browser fingerprint).
func TestDoTOverUTLS(t *testing.T) {
	ip4pAddr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")

	// Reuse an httptest TLS server's certificate for a raw TLS listener.
	certSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certSrv.Close()
	cert := certSrv.TLS.Certificates[0]

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		resp := buildAAAAResponse(q, []netip.Addr{ip4pAddr})
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		conn.Write(out[:])
		conn.Write(resp)
	}()

	s := bootstrapDnsServer{
		addr:      ln.Addr().String(),
		kind:      "dot",
		tlsConfig: &tls.Config{RootCAs: testRootPool(certSrv)},
	}
	addrs, err := s.lookupAAAA(context.Background(), "tunnel.example.com")
	if err != nil {
		t.Fatalf("lookupAAAA over DoT: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ip4pAddr {
		t.Fatalf("lookupAAAA = %v, want %v", addrs, []netip.Addr{ip4pAddr})
	}
}
