/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2026 AmneziaWG project. All Rights Reserved.
 *
 * A minimal bootstrap DNS client used to resolve IP4P (IPv4 privacy)
 * addresses from a configured set of DNS servers. It supports four query
 * transports: plain UDP (with TCP fallback), TCP, DNS-over-TLS (DoT) and
 * DNS-over-HTTPS (DoH).
 */

package device

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	// uTLS declares itself as "package tls" (a drop-in replacement for
	// crypto/tls), so alias it to utls to avoid colliding with crypto/tls.
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

// bootstrapDnsServer describes a single configured bootstrap DNS server and
// the transport used to reach it.
type bootstrapDnsServer struct {
	// addr is the dialable address, e.g. "1.1.1.1:53" or "https://dns.google/dns-query".
	addr string
	// kind is one of "udp", "tcp", "dot", "doh".
	kind string
	// tlsConfig optionally customises TLS verification for DoT/DoH (e.g. a
	// test root pool). When nil, the system roots are used.
	tlsConfig *tls.Config
	// protect, when non-nil, is invoked with the socket file descriptor before
	// the socket is connected, so the query can bypass the tunnel (VpnService
	// protect on Android). It prevents bootstrap DNS traffic from looping back
	// through the VPN that is being configured.
	protect func(fd int) error
}

// dialer returns a net.Dialer whose sockets are protected (via s.protect)
// before connecting. This ensures bootstrap DNS traffic bypasses the tunnel.
func (s bootstrapDnsServer) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if s.protect != nil {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var fd int
			if err := c.Control(func(f uintptr) { fd = int(f) }); err != nil {
				return err
			}
			return s.protect(fd)
		}
	}
	return d
}

// parseBootstrapDnsServer parses a bootstrap DNS server specifier. Accepted
// forms:
//
//	1.1.1.1:53          -> udp (with tcp fallback)
//	dns://1.1.1.1:53    -> udp
//	tcp://1.1.1.1:53    -> tcp
//	dot://1.1.1.1:853   -> dot (DNS-over-TLS)
//	doh://dns.google/dns-query or https://dns.google/dns-query -> doh
func parseBootstrapDnsServer(spec string) (bootstrapDnsServer, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return bootstrapDnsServer{}, errors.New("empty bootstrap DNS server")
	}

	var host string
	var kind string

	switch {
	case strings.HasPrefix(spec, "dns://"):
		host = strings.TrimPrefix(spec, "dns://")
		kind = "udp"
	case strings.HasPrefix(spec, "tcp://"):
		host = strings.TrimPrefix(spec, "tcp://")
		kind = "tcp"
	case strings.HasPrefix(spec, "dot://"):
		host = strings.TrimPrefix(spec, "dot://")
		kind = "dot"
	case strings.HasPrefix(spec, "doh://"):
		rest := strings.TrimPrefix(spec, "doh://")
		if strings.HasPrefix(rest, "https://") {
			// Already absolute, e.g. doh://https://dns.google/dns-query
			host = rest
		} else {
			host = "https://" + rest
		}
		kind = "doh"
	case strings.HasPrefix(spec, "https://"):
		host = spec
		kind = "doh"
	default:
		// Bare ip:port is treated as UDP.
		host = spec
		kind = "udp"
	}

	if host == "" {
		return bootstrapDnsServer{}, fmt.Errorf("bootstrap DNS server %q has no host", spec)
	}
	if kind != "doh" && !strings.Contains(host, ":") {
		// Default port per transport.
		switch kind {
		case "udp", "tcp":
			host += ":53"
		case "dot":
			host += ":853"
		}
	}
	return bootstrapDnsServer{addr: host, kind: kind}, nil
}

// lookupAAAA queries a single bootstrap DNS server for the AAAA records of
// host and returns the resulting IPv6 addresses.
func (s bootstrapDnsServer) lookupAAAA(ctx context.Context, host string) ([]netip.Addr, error) {
	// dnsmessage requires canonical (fully-qualified) names ending in a dot.
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS name %q: %w", host, err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               dnsMessageID(),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		}},
	}
	query, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	var resp []byte
	switch s.kind {
	case "udp":
		resp, err = s.exchangeUDP(ctx, query)
		if err != nil {
			// Retry over TCP on truncation / failure, matching stub resolver
			// behaviour. DoT is not a valid TCP fallback here.
			resp, err = s.exchangeTCP(ctx, query)
		}
	case "tcp":
		resp, err = s.exchangeTCP(ctx, query)
	case "dot":
		resp, err = s.exchangeTLS(ctx, query)
	case "doh":
		resp, err = s.exchangeDoH(ctx, query)
	default:
		err = fmt.Errorf("unknown bootstrap DNS transport %q", s.kind)
	}
	if err != nil {
		return nil, err
	}

	return parseAAAAAnswers(resp)
}

// exchangeUDP sends the DNS query over UDP and reads the response. It returns
// an error if the reply is truncated so the caller can fall back to TCP.
func (s bootstrapDnsServer) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	conn, err := s.dialer().DialContext(ctx, "udp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("udp dial %s: %w", s.addr, err)
	}
	defer conn.Close()

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("udp write: %w", err)
	}

	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("udp read: %w", err)
	}
	msg := buf[:n]

	var p dnsmessage.Parser
	header, err := p.Start(msg)
	if err != nil {
		return nil, fmt.Errorf("udp parse header: %w", err)
	}
	if header.Truncated {
		return nil, errors.New("udp response truncated")
	}
	return msg, nil
}

// exchangeTCP sends the DNS query over TCP (length-prefixed) and reads the
// response.
func (s bootstrapDnsServer) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	conn, err := s.dialer().DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", s.addr, err)
	}
	defer conn.Close()

	if err := writeTCPMessage(conn, query); err != nil {
		return nil, err
	}
	return readTCPMessage(conn)
}

// exchangeTLS sends the DNS query over DNS-over-TLS and reads the response.
func (s bootstrapDnsServer) exchangeTLS(ctx context.Context, query []byte) ([]byte, error) {
	host, _, err := net.SplitHostPort(s.addr)
	if err != nil {
		host = s.addr
	}
	// DoT uses a browser uTLS fingerprint to avoid revealing that the client
	// is a Go-based VPN resolver. The fingerprint's default ALPN (h2,
	// http/1.1) is harmless on port 853, where DoT servers treat ALPN as
	// optional.
	conn, err := utlsDialContext(ctx, s.dialer(), "tcp", s.addr, host, false, s.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dot dial %s: %w", s.addr, err)
	}
	defer conn.Close()

	if err := writeTCPMessage(conn, query); err != nil {
		return nil, err
	}
	return readTCPMessage(conn)
}

// exchangeDoH sends the DNS query as a DNS-over-HTTPS POST request. If the
// configured URL contains userinfo (e.g. https://user:pass@host/dns-query),
// it is sent as an HTTP Basic Authorization header, which is how many private
// DoH resolvers (NextDNS, AdGuard, Cloudflare token endpoints) authenticate.
//
// For https:// endpoints the request is made over a uTLS connection using a
// browser fingerprint to avoid revealing the client's TLS fingerprint. HTTP/2
// is attempted first (with ALPN h2); if the server does not support it the
// request transparently falls back to HTTP/1.1 over the same uTLS transport.
// Plain http:// endpoints (used by tests and local resolvers) are sent over
// an ordinary HTTP/1.1 client without TLS.
func (s bootstrapDnsServer) exchangeDoH(ctx context.Context, query []byte) ([]byte, error) {
	u, err := url.Parse(s.addr)
	if err != nil {
		return nil, fmt.Errorf("doh parse url: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		host = u.Host
	}

	// Plaintext HTTP is only used for local/test resolvers; no TLS, so no
	// uTLS fingerprint masking is needed.
	if u.Scheme != "https" {
		client := &http.Client{
			Timeout:   dohTimeout,
			Transport: s.newProtectedHTTPTransport(),
		}
		body, _, err := s.exchangeDoHHTTP(ctx, query, client)
		return body, err
	}

	// HTTPS: try HTTP/2 over uTLS first, then fall back to HTTP/1.1. Only fall
	// back on a transport-level failure (no HTTP response was obtained); if the
	// h2 server answered (even with an error status) the response is final.
	h2client := s.newDoHH2Client(host)
	body, gotResp, err := s.exchangeDoHHTTP(ctx, query, h2client)
	if err == nil {
		return body, nil
	}
	if gotResp {
		return nil, err
	}

	h1client := s.newDoHH1Client(host)
	body, _, err = s.exchangeDoHHTTP(ctx, query, h1client)
	return body, err
}

// exchangeDoHHTTP performs a single DoH POST request using the provided HTTP
// client and reads the DNS response body. gotResp reports whether the server
// returned an HTTP response (as opposed to a transport-level dial/TLS error).
func (s bootstrapDnsServer) exchangeDoHHTTP(ctx context.Context, query []byte, client *http.Client) ([]byte, bool, error) {
	req, err := s.newDoHRequest(ctx, query)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("doh query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, true, fmt.Errorf("doh read: %w", err)
	}
	return body, true, nil
}

// newDoHRequest builds a POST request with the DNS message body, the standard
// DoH content types and any HTTP Basic Authorization derived from the URL's
// userinfo.
func (s bootstrapDnsServer) newDoHRequest(ctx context.Context, query []byte) (*http.Request, error) {
	reqURL := s.addr
	u, err := url.Parse(s.addr)
	if err != nil {
		return nil, fmt.Errorf("doh parse url: %w", err)
	}
	var user *url.Userinfo
	if u.User != nil {
		user = u.User
		// Strip the userinfo from the URL; Go's HTTP client does not send it
		// as Authorization automatically.
		u.User = nil
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(query)))
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	if user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

// newDoHH2Client returns an HTTP client whose TLS is provided by uTLS and
// which uses HTTP/2 (preferred). The transport's dialer completes a uTLS
// handshake that must negotiate ALPN "h2"; otherwise the request fails so the
// caller can fall back to HTTP/1.1.
func (s bootstrapDnsServer) newDoHH2Client(host string) *http.Client {
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return utlsDialContext(ctx, s.dialer(), network, addr, host, true, s.tlsConfig)
		},
	}
	return &http.Client{Transport: tr, Timeout: dohTimeout}
}

// newDoHH1Client returns an HTTP/1.1 client whose TLS is provided by uTLS.
func (s bootstrapDnsServer) newDoHH1Client(host string) *http.Client {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, s.dialer(), network, addr, host, false, s.tlsConfig)
		},
	}
	return &http.Client{Transport: tr, Timeout: dohTimeout}
}

// newProtectedHTTPTransport returns an http.Transport that dials through the
// protected dialer without TLS. It is used for plaintext DoH to local/test
// resolvers.
func (s bootstrapDnsServer) newProtectedHTTPTransport() http.RoundTripper {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialer().DialContext(ctx, network, addr)
		},
	}
	return tr
}

// parseAAAAAnswers parses a DNS response and extracts the AAAA addresses.
func parseAAAAAnswers(resp []byte) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	header, err := p.Start(resp)
	if err != nil {
		return nil, fmt.Errorf("parse DNS response: %w", err)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS query failed with RCode %d", header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("skip questions: %w", err)
	}

	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse answer header: %w", err)
		}
		switch ah.Type {
		case dnsmessage.TypeAAAA:
			ar, err := p.AAAAResource()
			if err != nil {
				return nil, fmt.Errorf("parse AAAA: %w", err)
			}
			addr, ok := netip.AddrFromSlice(ar.AAAA[:])
			if ok {
				addrs = append(addrs, addr.Unmap())
			}
		case dnsmessage.TypeA:
			// Skip A records; IP4P uses AAAA.
			_, err := p.AResource()
			if err != nil {
				return nil, fmt.Errorf("parse A: %w", err)
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("skip answer: %w", err)
			}
		}
	}
	return addrs, nil
}

// writeTCPMessage writes a length-prefixed DNS message over a stream.
func writeTCPMessage(w io.Writer, msg []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

// readTCPMessage reads a length-prefixed DNS message from a stream.
func readTCPMessage(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return msg, nil
}

// dnsMessageID returns a pseudo-random DNS message ID. A single atomic
// counter is adequate for a bootstrap resolver that only needs to
// demultiplex one query at a time; it is not cryptographically significant.
var dnsMessageCounter atomic.Uint32

func dnsMessageID() uint16 {
	return uint16(dnsMessageCounter.Add(1))
}

// dohTimeout is the per-request timeout for a DoH query.
const dohTimeout = 10 * time.Second

// utlsHello is the browser TLS fingerprint used for DoT and DoH to mask the
// client's handshake so it is not identifiable as a Go-based VPN resolver.
// The Chrome fingerprint advertises h2 and http/1.1 ALPN, which is exactly
// what the DoH HTTP/2 transport needs while still looking like a browser.
var utlsHello = utls.HelloChrome_Auto

// utlsDialContext dials addr over TCP and completes a uTLS handshake using a
// browser fingerprint. verify, when non-nil, customises certificate
// verification (e.g. a test root pool); when nil the system roots are used.
// When requireH2 is true the connection must have negotiated ALPN "h2";
// otherwise it is closed and an error is returned so the DoH caller can fall
// back to HTTP/1.1.
func utlsDialContext(ctx context.Context, dialer *net.Dialer, network, addr, serverName string, requireH2 bool, verify *tls.Config) (*utls.UConn, error) {
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	cfg := &utls.Config{ServerName: serverName}
	if verify != nil {
		cfg.InsecureSkipVerify = verify.InsecureSkipVerify
		cfg.RootCAs = verify.RootCAs
	}
	conn := utls.UClient(rawConn, cfg, utlsHello)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	if requireH2 {
		if proto := conn.ConnectionState().NegotiatedProtocol; proto != "h2" {
			conn.Close()
			return nil, fmt.Errorf("server did not negotiate h2 (got %q)", proto)
		}
	}
	return conn, nil
}
