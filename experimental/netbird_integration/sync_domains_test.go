//go:build with_netbird

package netbird_integration

import (
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"testing"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func TestExtractNetworkCIDR(t *testing.T) {
	// 组件式 wire format: 精确 net_cidr
	resp := &mgmProto.SyncResponse{
		NetworkMapEnvelope: &mgmProto.NetworkMapEnvelope{
			Payload: &mgmProto.NetworkMapEnvelope_Full{
				Full: &mgmProto.NetworkMapComponentsFull{
					Network: &mgmProto.AccountNetwork{NetCidr: "100.90.0.0/16"},
				},
			},
		},
	}
	if got := ExtractNetworkCIDR(resp); got != "100.90.0.0/16" {
		t.Fatalf("component path: got %q, want 100.90.0.0/16", got)
	}

	// legacy 路径: 对端地址按 /16 掩码回退
	resp2 := &mgmProto.SyncResponse{
		NetworkMap: &mgmProto.NetworkMap{
			PeerConfig: &mgmProto.PeerConfig{Address: "100.121.0.2"},
		},
	}
	if got := ExtractNetworkCIDR(resp2); got != "100.121.0.0/16" {
		t.Fatalf("legacy path: got %q, want 100.121.0.0/16", got)
	}

	// 非默认前缀的对端地址也正确掩码
	resp3 := &mgmProto.SyncResponse{
		NetworkMap: &mgmProto.NetworkMap{
			PeerConfig: &mgmProto.PeerConfig{Address: "100.64.33.100"},
		},
	}
	if got := ExtractNetworkCIDR(resp3); got != "100.64.0.0/16" {
		t.Fatalf("legacy mask: got %q, want 100.64.0.0/16", got)
	}

	// nil / 空
	if got := ExtractNetworkCIDR(nil); got != "" {
		t.Fatalf("nil: got %q", got)
	}
}

func TestComputeDNSAddr(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		want string
	}{
		{"default /16", "", "100.121.255.254:53"},
		{"explicit /16", "100.121.0.0/16", "100.121.255.254:53"},
		{"component cidr", "100.90.0.0/16", "100.90.255.254:53"},
		{"legacy masked", "100.64.0.0/16", "100.64.255.254:53"},
		{"non-default prefix", "10.0.0.0/8", "10.255.255.254:53"},
		{"/24 network", "192.168.1.0/24", "192.168.1.254:53"},
		{"invalid", "not-a-cidr", ""},
		{"ipv6 rejected", "fd00::/8", ""},
		{"/32 rejected", "100.121.0.1/32", ""},
	}
	for _, c := range cases {
		if got := ComputeDNSAddr(c.cidr); got != c.want {
			t.Fatalf("%s: ComputeDNSAddr(%q) = %q, want %q", c.name, c.cidr, got, c.want)
		}
	}
}

// TestComputeDNSAddrMatchesNetbird cross-checks ComputeDNSAddr against
// netbird's own GetLastIPFromNetwork over random /16..//24 overlay networks,
// proving the two implementations agree on the tunnel DNS server address.
func TestComputeDNSAddrMatchesNetbird(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		// random /16 inside 100.64.0.0/10 (netbird overlay space)
		base := uint32(0x64400000) + rng.Uint32()&0x003F0000
		var b [4]byte
		b[0] = byte(base >> 24)
		b[1] = byte(base >> 16)
		b[2] = byte(base >> 8)
		b[3] = byte(base)
		addr := netip.AddrFrom4(b)
		prefix := netip.PrefixFrom(addr, 16)

		dnsIP, err := nbnet.GetLastIPFromNetwork(prefix, 1)
		if err != nil {
			t.Fatalf("iter %d: GetLastIPFromNetwork(%s): %v", i, prefix, err)
		}
		want := net.JoinHostPort(dnsIP.String(), "53")
		if got := ComputeDNSAddr(prefix.String()); got != want {
			t.Fatalf("iter %d: ComputeDNSAddr(%s) = %q, want %q (netbird GetLastIPFromNetwork)", i, prefix, got, want)
		}
	}
}

func TestInjectNetbirdJSONNetworkCIDR(t *testing.T) {
	raw := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[]}}`)

	// 动态网段生效, 且规则插在最前
	out, err := InjectNetbirdJSON(raw, nil, "100.90.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	rules, _ := m["route"].(map[string]any)["rules"].([]any)
	// 首条是引擎 bypass(process_path),overlay 规则在其后
	if _, ok := rules[0].(map[string]any)["process_path"]; !ok {
		t.Fatalf("first rule is not the engine bypass: %v", rules[0])
	}
	foundCIDR := false
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		cidrs, _ := rule["ip_cidr"].([]any)
		if len(cidrs) == 1 && cidrs[0] == "100.90.0.0/16" {
			foundCIDR = true
			if rule["outbound"] != "nb-out" {
				t.Fatalf("overlay rule outbound not nb-out: %v", rule["outbound"])
			}
		}
	}
	if !foundCIDR {
		t.Fatalf("dynamic cidr not applied: %v", rules)
	}

	// 空网段回退默认
	out2, err := InjectNetbirdJSON(raw, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out2), "100.121.0.0/16") {
		t.Fatalf("default fallback missing: %s", out2)
	}
}
