package netbird_integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// testRuleSetPath / testCIDRPath are (possibly non-existent) rule-set file
// paths used to exercise the custom-domain/CIDR rule-set injection. Injection
// only references the paths — it never reads the files.
var testRuleSetPath = filepath.Join(os.TempDir(), "nb-domains-test.json")
var testCIDRPath = filepath.Join(os.TempDir(), "nb-cidr-test.json")

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

	out, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)

	// process_path bypass removed: embedded-bypass (socket-level
	// IP_UNICAST_IF/protect/fwmark) replaces the route-rule bypass.
	if n := countRouteRules(route, "process"); n != 0 {
		t.Fatalf("process_path rules = %d, want 0 (bypass removed)", n)
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

	// bypass must be prepended before the proxy rule (ip_cidr ctlIPs → direct
	// is the first injected bypass now that process_path was removed)
	first, ok := route[0].(map[string]any)
	if !ok || first["outbound"] != "direct" {
		t.Fatal("bypass rule not at the front of route.rules")
	}
	if _, hasCIDR := first["ip_cidr"]; !hasCIDR {
		if _, hasDom := first["domain_suffix"]; !hasDom {
			t.Fatal("front bypass rule is neither ip_cidr nor domain_suffix")
		}
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

	// userspace: nb-out outbound + nb-cidr rule-set 规则(静态 ip_cidr 规则
	// 已移除 — overlay 路由由 rule-set 引用承载, 见 InjectNetbirdJSON 注释)
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
	// 不再注入静态 ip_cidr overlay 规则
	for _, r := range route {
		if cidrs, ok := r.(map[string]any)["ip_cidr"].([]any); ok {
			for _, c := range cidrs {
				if fmt.Sprint(c) == "100.121.0.0/16" {
					t.Fatal("static overlay CIDR rule must not be injected (nb-cidr rule-set replaces it)")
				}
			}
		}
	}
}

func TestInjectKernelMode(t *testing.T) {
	SetKernelMode(true)
	defer SetKernelMode(false)

	out, err := InjectNetbirdJSON([]byte(testConfig), "", nil, testRuleSetPath, testCIDRPath)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)

	// process_path bypass removed: kernel mode uses fwmark-based socket
	// bypass (control-plane marked 0x1BD00 → main), no route rule needed.
	if countRouteRules(route, "process") != 0 {
		t.Fatal("kernel mode: process bypass must not be injected (removed)")
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
	// custom domain DNS rule still injected (via the local rule-set, not
	// per-domain rules — the set is declared in route.rule_set which is the
	// registry both route and DNS rules resolve through)
	_, dnsR := ruleList(t, out)
	foundCustom := false
	for _, r := range dnsR {
		m := r.(map[string]any)
		if m["server"] == "nb" && fmt.Sprint(m["rule_set"]) == customRuleSetTag {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Fatal("kernel mode: custom domain DNS rule (rule_set → nb) missing")
	}
	// the rule-set declaration must be present in route.rule_set
	var routeCfg map[string]any
	json.Unmarshal(out, &routeCfg)
	declFound := false
	for _, rs := range routeCfg["route"].(map[string]any)["rule_set"].([]any) {
		if fmt.Sprint(rs.(map[string]any)["tag"]) == customRuleSetTag {
			declFound = true
		}
	}
	if !declFound {
		t.Fatal("kernel mode: nb-custom-domains rule-set declaration missing")
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

	first, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", nil, testRuleSetPath, testCIDRPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InjectNetbirdJSON(first, "https://nb.example.wang", nil, testRuleSetPath, testCIDRPath)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, second)
	// process_path bypass was removed: embedded-bypass (socket-level
	// IP_UNICAST_IF/protect/fwmark) makes it dead weight.
	if n := countRouteRules(route, "process"); n != 0 {
		t.Fatalf("process rules after double inject = %d, want 0 (process_path bypass removed)", n)
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
	out, err := InjectNetbirdJSON([]byte(cfg), "https://nb.example.wang", nil, "", "")
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
	out, err := InjectNetbirdJSON([]byte(cfg), "", nil, "", "")
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
	// 静态 overlay 规则已整体移除(rule-set 承载): 残留被清理且不再重新注入
	if count != 0 {
		t.Fatalf("ip_cidr rules = %d, want 0 (stale cleaned, no static re-injection)", count)
	}
}

func TestInjectControlPlaneIPs(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)
	ctlIPs := []string{"203.0.113.1/32", "1.2.3.4/32"}

	out, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", ctlIPs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	route, _ := ruleList(t, out)

	found := false
	for _, r := range route {
		m := r.(map[string]any)
		if m["outbound"] == "direct" {
			if cidrs, ok := m["ip_cidr"].([]any); ok {
				s := fmt.Sprint(cidrs)
				if s == fmt.Sprint([]any{"203.0.113.1/32", "1.2.3.4/32"}) {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("no control-plane ip_cidr → direct rule injected")
	}

	// Idempotent: same IPs must not duplicate the rule.
	second, err := InjectNetbirdJSON(out, "https://nb.example.wang", ctlIPs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	route2, _ := ruleList(t, second)
	count := 0
	for _, r := range route2 {
		m := r.(map[string]any)
		if cidrs, ok := m["ip_cidr"].([]any); ok {
			if fmt.Sprint(cidrs) == fmt.Sprint([]any{"203.0.113.1/32", "1.2.3.4/32"}) {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("control-plane ip_cidr rules = %d, want 1 (idempotent)", count)
	}
}

func TestInjectDNSFallback(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)

	// Profile with dns-remote server + geosite-geolocation-!cn rule-set:
	// final must stay untouched (no final=nb fallback — it would drag every
	// unmatched domain through the tunnel DNS and stall up to 10s), and no
	// geosite-!cn → dns-remote rule may be injected either.
	cfg := `{
	  "dns": {"servers": [
	    {"type": "https", "tag": "dns-direct", "server": "223.5.5.5"},
	    {"type": "https", "tag": "dns-remote", "server": "1.1.1.1"}
	  ], "final": "dns-remote"},
	  "outbounds": [{"type": "direct", "tag": "direct"}],
	  "route": {"rule_set": [{"tag": "geosite-geolocation-!cn", "type": "remote"}], "rules": []}
	}`
	out, err := InjectNetbirdJSON([]byte(cfg), "https://nb.example.wang", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)
	dns := parsed["dns"].(map[string]any)
	if fmt.Sprint(dns["final"]) != "dns-remote" {
		t.Fatalf("final = %v, want dns-remote untouched (no final=nb fallback)", dns["final"])
	}
	for _, r := range dns["rules"].([]any) {
		m := r.(map[string]any)
		if m["server"] == "dns-remote" && m["rule_set"] == "geosite-geolocation-!cn" {
			t.Fatal("geosite-!cn → dns-remote rule must not be injected")
		}
	}
}

func TestInjectDNSFallbackMinimalProfile(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)

	// Minimal profile without final: inject must not set final at all
	// (previously it forced final=nb which broke non-CN resolution).
	out, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	json.Unmarshal(out, &parsed)
	dns := parsed["dns"].(map[string]any)
	if _, hasFinal := dns["final"]; hasFinal {
		t.Fatalf("final must not be injected, got %v", dns["final"])
	}
}

func TestWriteDomainsRuleSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nb-domains.json")

	// non-empty domains → {"version":1,"rules":[{"domain_suffix":[...]}]}
	if err := writeDomainsRuleSet(path, []string{"b.example.", "a.example"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, data)
	}
	if fmt.Sprint(m["version"]) != "1" {
		t.Fatalf("version = %v, want 1 (PlainRuleSetCompat requires it)", m["version"])
	}
	rules := m["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	// domain rule present with trailing dots trimmed; NO ip_cidr rule
	// (a DNS-referenced rule-set with IP fields is rejected by sing-box 1.14)
	if _, hasCIDR := rules[0].(map[string]any)["ip_cidr"]; hasCIDR {
		t.Fatal("rule-set must not contain ip_cidr (legacy DNS address-filter rejection)")
	}
	ds := rules[0].(map[string]any)["domain_suffix"].([]any)
	if len(ds) != 2 || fmt.Sprint(ds[0]) != "b.example" || fmt.Sprint(ds[1]) != "a.example" {
		t.Fatalf("domain_suffix wrong (trailing dots must be trimmed): %v", ds)
	}

	// empty domains → valid empty rule-set ({"version":1,"rules":[]})
	if err := writeDomainsRuleSet(path, nil); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(path)
	var m2 map[string]any
	if err := json.Unmarshal(data2, &m2); err != nil {
		t.Fatalf("empty rule-set bad JSON: %v\n%s", err, data2)
	}
	if len(m2["rules"].([]any)) != 0 {
		t.Fatal("empty domains must produce an empty rules array")
	}
}

func TestInjectCustomDomainRuleSet(t *testing.T) {
	SetKernelMode(false)
	defer SetKernelMode(false)

	out, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", nil, testRuleSetPath, testCIDRPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(out, &cfg)

	// 1. route.rule_set declares BOTH local sets (domains + cidr) with paths
	declFound := false
	declCIDRFound := false
	for _, rs := range cfg["route"].(map[string]any)["rule_set"].([]any) {
		m := rs.(map[string]any)
		switch fmt.Sprint(m["tag"]) {
		case customRuleSetTag:
			declFound = true
			if fmt.Sprint(m["type"]) != "local" || fmt.Sprint(m["path"]) != testRuleSetPath {
				t.Fatalf("rule-set decl wrong: %v", m)
			}
			// format 必须显式(Windows 盘符路径会破坏 1.14 的扩展名推断)
			if fmt.Sprint(m["format"]) != "source" {
				t.Fatalf("rule-set decl must carry explicit format=source: %v", m)
			}
		case customCIDRRuleSetTag:
			declCIDRFound = true
			if fmt.Sprint(m["type"]) != "local" || fmt.Sprint(m["path"]) != testCIDRPath {
				t.Fatalf("cidr rule-set decl wrong: %v", m)
			}
			if fmt.Sprint(m["format"]) != "source" {
				t.Fatalf("cidr rule-set decl must carry explicit format=source: %v", m)
			}
		}
	}
	if !declFound {
		t.Fatal("route.rule_set: nb-domains declaration missing")
	}
	if !declCIDRFound {
		t.Fatal("route.rule_set: nb-cidr declaration missing")
	}

	// 2. route rules reference both sets → nb-out (userspace)
	route, _ := ruleList(t, out)
	routeRef := false
	routeCIDRRef := false
	for _, r := range route {
		m := r.(map[string]any)
		if fmt.Sprint(m["rule_set"]) == customRuleSetTag && m["outbound"] == "nb-out" {
			routeRef = true
		}
		if fmt.Sprint(m["rule_set"]) == customCIDRRuleSetTag && m["outbound"] == "nb-out" {
			routeCIDRRef = true
		}
	}
	if !routeRef {
		t.Fatal("route rule nb-domains → nb-out missing")
	}
	if !routeCIDRRef {
		t.Fatal("route rule nb-cidr → nb-out missing")
	}

	// 3. dns rule references ONLY the domain set → nb (the CIDR set must
	// never be referenced by a DNS rule — 1.14 legacy-address-filter check)
	_, dnsR := ruleList(t, out)
	dnsRef := false
	for _, r := range dnsR {
		m := r.(map[string]any)
		if fmt.Sprint(m["rule_set"]) == customRuleSetTag && m["server"] == "nb" {
			dnsRef = true
		}
		if fmt.Sprint(m["rule_set"]) == customCIDRRuleSetTag {
			t.Fatal("dns rule must not reference nb-cidr (legacy address-filter rejection)")
		}
	}
	if !dnsRef {
		t.Fatal("dns rule rule_set → nb missing")
	}

	// 4. idempotent: double inject keeps exactly one decl / one rule each
	second, err := InjectNetbirdJSON(out, "https://nb.example.wang", nil, testRuleSetPath, testCIDRPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 map[string]any
	json.Unmarshal(second, &cfg2)
	declCount, declCIDRCount := 0, 0
	for _, rs := range cfg2["route"].(map[string]any)["rule_set"].([]any) {
		switch fmt.Sprint(rs.(map[string]any)["tag"]) {
		case customRuleSetTag:
			declCount++
		case customCIDRRuleSetTag:
			declCIDRCount++
		}
	}
	if declCount != 1 || declCIDRCount != 1 {
		t.Fatalf("rule-set decl counts after double inject = %d/%d, want 1/1", declCount, declCIDRCount)
	}
	route2, dns2 := ruleList(t, second)
	routeRefCount, routeCIDRRefCount, dnsRefCount := 0, 0, 0
	for _, r := range route2 {
		switch fmt.Sprint(r.(map[string]any)["rule_set"]) {
		case customRuleSetTag:
			routeRefCount++
		case customCIDRRuleSetTag:
			routeCIDRRefCount++
		}
	}
	for _, r := range dns2 {
		if fmt.Sprint(r.(map[string]any)["rule_set"]) == customRuleSetTag {
			dnsRefCount++
		}
	}
	if routeRefCount != 1 || routeCIDRRefCount != 1 || dnsRefCount != 1 {
		t.Fatalf("rule refs after double inject: route=%d routeCidr=%d dns=%d, want 1/1/1", routeRefCount, routeCIDRRefCount, dnsRefCount)
	}

	// 5. empty ruleSetPath → no rule-set machinery at all
	noPath, err := InjectNetbirdJSON([]byte(testConfig), "https://nb.example.wang", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg3 map[string]any
	json.Unmarshal(noPath, &cfg3)
	if _, hasRuleSet := cfg3["route"].(map[string]any)["rule_set"]; hasRuleSet {
		t.Fatal("rule_set must not be injected when ruleSetPath is empty")
	}
	route3, dns3 := ruleList(t, noPath)
	for _, r := range route3 {
		if fmt.Sprint(r.(map[string]any)["rule_set"]) == customRuleSetTag {
			t.Fatal("route rule_set ref must not be injected when path empty")
		}
	}
	for _, r := range dns3 {
		if fmt.Sprint(r.(map[string]any)["rule_set"]) == customRuleSetTag {
			t.Fatal("dns rule_set ref must not be injected when path empty")
		}
	}
}
