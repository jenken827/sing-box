package netbird_integration

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const testConfig = `{
  "dns": {"servers": [{"tag": "main", "address": "223.5.5.5"}], "rules": [{"domain_suffix": ["example.com"], "server": "main"}]},
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "vless", "tag": "proxy"}],
  "route": {"rules": [
    {"rule_set": "geosite-geolocation-!cn", "outbound": "proxy"},
    {"rule_set": "geoip-cn", "outbound": "direct"}
  ]}
}`

func ruleList(t *testing.T, raw []byte) (route []any, dnsRules []any) {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	route = cfg["route"].(map[string]any)["rules"].([]any)
	dnsRules = cfg["dns"].(map[string]any)["rules"].([]any)
	return
}

func countRouteRules(route []any, kind string) int {
	n := 0
	for _, r := range route {
		m := r.(map[string]any)
		switch kind {
		case "process":
			if _, ok := m["process_path"]; ok {
				n++
			}
		case "domain-direct":
			if m["outbound"] == "direct" {
				if _, ok := m["domain_suffix"]; ok {
					n++
				}
			}
		}
	}
	return n
}

func TestInjectBypassUserspace(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)
	exe, _ := os.Executable()

	out, err := InjectNetbirdJSON([]byte(testConfig), nil, "", "https://nb.example.wang")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)

	// process_path bypass = current executable, outbound direct
	foundProc := false
	for _, r := range route {
		m := r.(map[string]any)
		if pp, ok := m["process_path"].([]any); ok {
			foundProc = true
			if len(pp) != 1 || fmt.Sprint(pp[0]) != exe {
				t.Fatalf("process_path = %v, want [%s]", pp, exe)
			}
			if m["outbound"] != "direct" {
				t.Fatalf("process bypass outbound = %v, want direct", m["outbound"])
			}
		}
	}
	if !foundProc {
		t.Fatal("no process_path bypass injected")
	}

	// domain bypass covers netbird.io + mgmt host
	foundDom := false
	for _, r := range route {
		m := r.(map[string]any)
		if m["outbound"] == "direct" {
			if ds, ok := m["domain_suffix"].([]any); ok {
				s := fmt.Sprint(ds)
				if strings.Contains(s, "netbird.io") && strings.Contains(s, "nb.example.wang") {
					foundDom = true
				}
			}
		}
	}
	if !foundDom {
		t.Fatal("no domain bypass injected")
	}

	// bypass must be prepended before the proxy rule
	if _, ok := route[0].(map[string]any)["process_path"]; !ok {
		t.Fatal("process bypass not at the front of route.rules")
	}

	// dns-direct rule present
	_, dnsR := ruleList(t, out)
	foundDNS := false
	for _, r := range dnsR {
		if r.(map[string]any)["server"] == "dns-direct" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Fatal("no dns-direct rule injected")
	}

	// userspace: nb-out outbound + overlay CIDR rule
	var cfg map[string]any
	json.Unmarshal(out, &cfg)
	foundNB := false
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == "nb-out" {
			foundNB = true
		}
	}
	if !foundNB {
		t.Fatal("nb-out not injected in userspace mode")
	}
	foundOverlay := false
	for _, r := range route {
		if cidrs, ok := r.(map[string]any)["ip_cidr"].([]any); ok {
			for _, c := range cidrs {
				if fmt.Sprint(c) == "100.121.0.0/16" {
					foundOverlay = true
				}
			}
		}
	}
	if !foundOverlay {
		t.Fatal("overlay CIDR rule missing in userspace mode")
	}
}

func TestInjectKernelMode(t *testing.T) {
	SetKernelMode(true)
	defer SetKernelMode(false)

	out, err := InjectNetbirdJSON([]byte(testConfig), []string{"svc.example.net"}, "100.121.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)

	// bypass (process rule) must be present in kernel mode too
	if countRouteRules(route, "process") != 1 {
		t.Fatal("kernel mode: process bypass missing")
	}
	// overlay route rule must NOT be injected (kernel route handles it)
	for _, r := range route {
		if cidrs, ok := r.(map[string]any)["ip_cidr"].([]any); ok {
			for _, c := range cidrs {
				if fmt.Sprint(c) == "100.121.0.0/16" {
					t.Fatal("kernel mode: overlay rule must not be injected")
				}
			}
		}
	}
	// nb-out must NOT be injected
	var cfg map[string]any
	json.Unmarshal(out, &cfg)
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == "nb-out" {
			t.Fatal("kernel mode: nb-out must not be injected")
		}
	}
	// custom domain DNS rule still injected
	_, dnsR := ruleList(t, out)
	foundCustom := false
	for _, r := range dnsR {
		m := r.(map[string]any)
		if m["server"] == "nb" && strings.Contains(fmt.Sprint(m["domain_suffix"]), "svc.example.net") {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Fatal("kernel mode: custom domain DNS rule missing")
	}
	// mgmtURL empty → dns-direct rule covers only netbird.io
	foundDNS := false
	for _, r := range dnsR {
		m := r.(map[string]any)
		if m["server"] == "dns-direct" {
			ds := m["domain_suffix"].([]any)
			if len(ds) == 1 && fmt.Sprint(ds[0]) == "netbird.io" {
				foundDNS = true
			}
		}
	}
	if !foundDNS {
		t.Fatal("kernel mode: dns-direct rule missing or wrong domains")
	}
}

func TestInjectIdempotent(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)

	first, err := InjectNetbirdJSON([]byte(testConfig), nil, "", "https://nb.example.wang")
	if err != nil {
		t.Fatal(err)
	}
	second, err := InjectNetbirdJSON(first, nil, "", "https://nb.example.wang")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, second)
	if n := countRouteRules(route, "process"); n != 1 {
		t.Fatalf("process rules after double inject = %d, want 1", n)
	}
	if n := countRouteRules(route, "domain-direct"); n != 1 {
		t.Fatalf("domain-direct rules after double inject = %d, want 1", n)
	}
	_, dnsR := ruleList(t, second)
	dnsCount := 0
	for _, r := range dnsR {
		if r.(map[string]any)["server"] == "dns-direct" {
			dnsCount++
		}
	}
	if dnsCount != 1 {
		t.Fatalf("dns-direct rules after double inject = %d, want 1", dnsCount)
	}
	var cfg map[string]any
	json.Unmarshal(second, &cfg)
	nbCount := 0
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == "nb-out" {
			nbCount++
		}
	}
	if nbCount != 1 {
		t.Fatalf("nb-out after double inject = %d, want 1", nbCount)
	}
}

func TestInjectExistingManualRulesNotDuplicated(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)
	exe, _ := os.Executable()
	exeJSON, _ := json.Marshal(exe)

	cfg := `{
	  "route": {"rules": [
	    {"process_path": [` + string(exeJSON) + `], "outbound": "direct"},
	    {"domain_suffix": ["netbird.io", "nb.example.wang"], "outbound": "direct"},
	    {"rule_set": "geosite-geolocation-!cn", "outbound": "proxy"}
	  ]},
	  "dns": {"rules": [{"domain_suffix": ["netbird.io", "nb.example.wang"], "server": "dns-direct"}]}
	}`
	out, err := InjectNetbirdJSON([]byte(cfg), nil, "", "https://nb.example.wang")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)
	if n := countRouteRules(route, "process"); n != 1 {
		t.Fatalf("manual process rule duplicated: %d", n)
	}
	if n := countRouteRules(route, "domain-direct"); n != 1 {
		t.Fatalf("manual domain rule duplicated: %d", n)
	}
	_, dnsR := ruleList(t, out)
	dnsCount := 0
	for _, r := range dnsR {
		if r.(map[string]any)["server"] == "dns-direct" {
			dnsCount++
		}
	}
	if dnsCount != 1 {
		t.Fatalf("manual dns-direct duplicated: %d", dnsCount)
	}
}

func TestInjectStaleOverlayCleaned(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)

	cfg := `{"route": {"rules": [
	  {"ip_cidr": ["100.121.0.0/16"], "outbound": "nb-out"},
	  {"rule_set": "geosite-!cn", "outbound": "proxy"}
	]}, "dns": {}}`
	out, err := InjectNetbirdJSON([]byte(cfg), nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)
	count := 0
	for _, r := range route {
		m := r.(map[string]any)
		if cidrs, ok := m["ip_cidr"].([]any); ok {
			count++
			for _, c := range cidrs {
				if fmt.Sprint(c) == "100.121.0.0/16" && m["outbound"] != "nb-out" {
					t.Fatal("stale overlay rule not cleaned")
				}
			}
		}
	}
	if count != 1 {
		t.Fatalf("ip_cidr rules = %d, want 1 (stale cleaned, fresh injected)", count)
	}
}
