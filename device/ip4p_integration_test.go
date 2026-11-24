/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2026 AmneziaWG project. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// TestIP4PEndToEnd verifies that configuring a device with a bootstrap DNS
// server and a hostname endpoint that resolves to an IP4P address results in
// the decoded IPv4:port endpoint being used and reported via IpcGet.
func TestIP4PEndToEnd(t *testing.T) {
	ip4pAddr := netip.MustParseAddr("2001:0:0:0:0:1f90:0ac8:0201")
	dnsAddr, stop := startMockDnsUDP(t, ip4pAddr)
	defer stop()

	var priv NoisePrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var peerPub NoisePublicKey
	if _, err := rand.Read(peerPub[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	dev := NewDevice(tuntest.NewChannelTUN().TUN(), &fakeBindSized{size: 1}, NewLogger(LogLevelError, "test: "))
	defer dev.Close()

	cfg := uapiCfg(
		"private_key", hex.EncodeToString(priv[:]),
		"bootstrap_dns", dnsAddr,
		"ip4p_prefix", DefaultIP4PPrefix,
		"replace_peers", "true",
		"public_key", hex.EncodeToString(peerPub[:]),
		"endpoint", "tunnel.example.com:51820",
	)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	// The endpoint must have been decoded to the IP4P IPv4:port.
	var out bytes.Buffer
	if err := dev.IpcGetOperation(&out); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "endpoint=10.200.2.1:8080") {
		t.Errorf("IpcGet missing decoded endpoint; got:\n%s", got)
	}
	if !strings.Contains(got, "endpoint_ip4p=1") {
		t.Errorf("IpcGet missing endpoint_ip4p=1; got:\n%s", got)
	}
	if !strings.Contains(got, "ip4p_host=tunnel.example.com") {
		t.Errorf("IpcGet missing ip4p_host; got:\n%s", got)
	}
	if !strings.Contains(got, "ip4p_orig=tunnel.example.com:51820") {
		t.Errorf("IpcGet missing ip4p_orig; got:\n%s", got)
	}
	if !strings.Contains(got, "ip4p_update_sec=") || !strings.Contains(got, "ip4p_update_nsec=") {
		t.Errorf("IpcGet missing ip4p_update_sec/nsec; got:\n%s", got)
	}
}
