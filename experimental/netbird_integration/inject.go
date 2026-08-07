// No build tags — pure JSON manipulation, accessible in all builds.
package netbird_integration

import (
	"encoding/json"
	"fmt"
	"strings"
)

// InjectNetbirdJSON adds netbird DNS server, outbound, and route/rule-set entries
// to the raw sing-box config. It returns the modified JSON bytes.
//
// customDomains (from netbird SyncResponse) get domain-specific route and DNS rules
// pointing to netbird outbound/DNS server so they resolve through the netbird tunnel.
// networkCIDR (from netbird SyncResponse, e.g. "100.121.0.0/16") is the account's
// overlay subnet and is always routed through netbird; empty falls back to the
// netbird default 100.121.0.0/16.
func InjectNetbirdJSON(rawData []byte, customDomains []string, networkCIDR string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(rawData, &raw); err != nil {
		return nil, err
	}

	// Inject DNS server — netbird as DNS transport (domain-specific rules below)
	dnsSection, _ := raw["dns"].(map[string]any)
	if dnsSection == nil {
		dnsSection = make(map[string]any)
		raw["dns"] = dnsSection
	}
	servers, _ := dnsSection["servers"].([]any)
	servers = append(servers, map[string]any{"type": "netbird", "tag": "nb"})
	dnsSection["servers"] = servers
	// Don't set final="nb" — only route custom domains through netbird.

	// Inject netbird outbound
	outbounds, _ := raw["outbounds"].([]any)
	outbounds = append(outbounds, map[string]any{"type": "netbird", "tag": "nb-out"})
	raw["outbounds"] = outbounds

	// Inject route rules
	routeSection, _ := raw["route"].(map[string]any)
	if routeSection == nil {
		routeSection = make(map[string]any)
		raw["route"] = routeSection
	}
	routeRules, _ := routeSection["rules"].([]any)
	// Remove any existing rules for 100.121.0.0/16 (from earlier config edits)
	var cleaned []any
	for _, r := range routeRules {
		rule, ok := r.(map[string]any)
		skip := false
		if ok {
			if cidrs, ok := rule["ip_cidr"].([]any); ok {
				for _, c := range cidrs {
					if fmt.Sprint(c) == "100.121.0.0/16" {
						skip = true
						break
					}
				}
			}
		}
		if !skip {
			cleaned = append(cleaned, r)
		}
	}
	// Netbird internal IP range — always route through netbird outbound
	// (dynamic from sync; falls back to the netbird default /16)
	nbCIDR := networkCIDR
	if nbCIDR == "" {
		nbCIDR = "100.121.0.0/16"
	}
	var nbRouteRules []any
	nbRouteRules = append(nbRouteRules, map[string]any{
		"ip_cidr":  []string{nbCIDR},
		"outbound": "nb-out",
	})
	// Domain-specific route rules for each custom domain
	for _, d := range customDomains {
		clean := strings.TrimSuffix(d, ".")
		nbRouteRules = append(nbRouteRules, map[string]any{
			"domain_suffix": clean,
			"outbound":      "nb-out",
		})
	}
	routeSection["rules"] = append(nbRouteRules, cleaned...)

	// Domain-specific DNS rules for each custom domain
	for _, d := range customDomains {
		clean := strings.TrimSuffix(d, ".")
		rules, _ := dnsSection["rules"].([]any)
		rules = append(rules, map[string]any{
			"domain_suffix": clean,
			"server":        "nb",
		})
		dnsSection["rules"] = rules
	}

	return json.Marshal(raw)
}
