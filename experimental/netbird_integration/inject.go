// No build tags — pure JSON manipulation, accessible in all builds.
package netbird_integration

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// kernelMode selects the Linux kernel-TUN data path (Route A):
//   - netbird creates a real kernel TUN (wt0) instead of the userspace netstack
//   - a single static kernel route sends the overlay CIDR straight to wt0,
//     bypassing the sing-box TUN stack (no double TCP termination)
//   - sing-box config injection skips the overlay route rules (kernel handles
//     the overlay), keeping the custom-domain DNS rules and the engine bypass
//
// Set by StartAll() before the engine starts. Only ever true on Linux.
var kernelMode bool

// IsKernelMode reports whether the kernel-TUN data path is active.
func IsKernelMode() bool { return kernelMode }

// SetKernelMode records whether the kernel-TUN data path is active.
func SetKernelMode(v bool) { kernelMode = v }

// Rule-set tags referencing the local custom-domain / overlay-CIDR files.
// They are SEPARATE sets: the DNS rule references only the domain set — a
// DNS-referenced rule-set carrying ip_cidr rules is rejected by sing-box 1.14
// ("Legacy Address Filter Fields in DNS rules is deprecated", see
// writeDomainsRuleSet). The CIDR set is referenced by route rules only.
const customRuleSetTag = "nb-domains"
const customCIDRRuleSetTag = "nb-cidr"

// InjectNetbirdJSON adds netbird DNS server, outbound, route/rule-set entries,
// and the engine-traffic bypass to the raw sing-box config. It returns the
// modified JSON bytes.
//
// Custom domains are NOT baked into per-domain rules: the config declares two
// local rule-sets and route/DNS rules reference them:
//   - nb-domains (file at ruleSetPath): domain_suffix list, referenced by the
//     DNS rule (server nb) and the route rule (outbound nb-out)
//   - nb-cidr (file at cidrRuleSetPath): the overlay CIDR, referenced by the
//     route rule only (DNS rules must not reference IP-bearing sets)
// The integration rewrites these files whenever the engine syncs; sing-box
// reloads the rule-sets at runtime (fswatch), so domains/CIDR arriving after
// startup (engine recovery) take effect without reloading the service. Both
// files must exist when the config loads (StartAll writes them, possibly
// empty/default, before returning). Empty ruleSetPath skips the rule-set
// machinery entirely (no custom-domain rules injected).
//
// mgmtURL is the netbird management URL (netbird-config.json management_url);
// its host — together with netbird.io — feeds the engine-traffic bypass rules.
// ctlIPs are the engine's control-plane server IPs (management/STUN/TURN/
// relay hosts, resolved from mgmtURL by the caller). They get an explicit
// ip_cidr → direct rule: remote rule-sets (geoip/geosite) are downloaded
// asynchronously and may not be loaded when the engine performs its first
// STUN probes at startup — without an explicit IP rule those probes fall
// through to `final` (usually the proxy) and the srflx candidate comes back
// poisoned with the proxy exit IP, breaking P2P until a restart.
//
// Engine-traffic bypass (BOTH kernel-TUN and userspace paths): the netbird
// engine's own sockets (STUN / management / relay / TURN / wg probes) are
// ordinary sockets, so auto_route captures them into the sing-box TUN like any
// app traffic. Without a bypass they hit `geosite-!cn → proxy` and their srflx
// candidates get poisoned with the proxy exit IP → ICE hole-punch fails → the
// tunnel silently falls back to the TURN relay (~350ms vs ~19ms direct).
// Note: kernel-TUN only kernel-routes the overlay CIDR to wt0; the engine's
// control traffic still goes through the sing-box TUN, so the bypass is
// required there too. Injected rules:
//   route: process_path [current executable] → direct  (matches raw-IP conns
//          such as STUN probes; the essential one)
//          domain_suffix [netbird.io, mgmt-host] → direct (SNI-carrying conns;
//          also the only reliable match on Android, where process-path lookup
//          resolves to the app process, not the embedded lib)
//   dns:   domain_suffix [netbird.io, mgmt-host] → dns-direct (control-plane
//          DNS must not go through dns-remote → proxy: 200-430ms → 58ms)
// All injections are idempotent: matching rules already present in the config
// (e.g. hand-edited) are kept and not duplicated.
func InjectNetbirdJSON(rawData []byte, mgmtURL string, ctlIPs []string, ruleSetPath string, cidrRuleSetPath string) ([]byte, error) {
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
	if !hasServerTag(servers, "nb") {
		servers = append(servers, map[string]any{"type": "netbird", "tag": "nb"})
		dnsSection["servers"] = servers
	}
	// Don't set final="nb" — only route custom domains through netbird.

	routeSection, _ := raw["route"].(map[string]any)
	if routeSection == nil {
		routeSection = make(map[string]any)
		raw["route"] = routeSection
	}
	routeRules, _ := routeSection["rules"].([]any)
	// Drop stale hand-edited overlay rules (from earlier config edits)
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

	// Control-plane domains: netbird.io (built-in default STUN + default mgmt)
	// plus the configured management host (self-hosted deployments).
	ctlDomains := []string{"netbird.io"}
	if mgmtURL != "" {
		if u, err := url.Parse(mgmtURL); err == nil && u.Hostname() != "" {
			ctlDomains = append(ctlDomains, u.Hostname())
		}
	}

	// Engine-traffic bypass — prepended so it always wins over proxy rules.
	prepended := []any{}
	// Control-plane IPs → direct. Must not depend on geoip/geosite rule-sets:
	// they load asynchronously and are often not ready when the engine does
	// its first STUN probes (StartAll runs before sing-box is created).
	if len(ctlIPs) > 0 && !hasIPDirectRule(cleaned, ctlIPs) {
		prepended = append(prepended, map[string]any{
			"ip_cidr":  ctlIPs,
			"outbound": "direct",
		})
	}
	if !hasDomainDirectRule(cleaned, ctlDomains) {
		prepended = append(prepended, map[string]any{
			"domain_suffix": ctlDomains,
			"outbound":      "direct",
		})
	}

	// Control-plane DNS direct (dns-direct is a built-in sing-box server).
	if !hasDNSDirectRule(dnsSection, ctlDomains) {
		dnsRules, _ := dnsSection["rules"].([]any)
		dnsSection["rules"] = append(dnsRules, map[string]any{
			"domain_suffix": ctlDomains,
			"server":        "dns-direct",
		})
	}

	// Netbird outbound + overlay route rules only in userspace (netstack) mode.
	// In kernel-TUN mode the kernel routes the overlay CIDR directly to wt0;
	// injecting route rules would pull overlay traffic into the sing-box TUN
	// stack and recreate the double-TCP overhead. (The engine bypass above is
	// still injected in kernel mode — the engine's control traffic is not
	// overlay traffic and does go through the sing-box TUN.)
	if !IsKernelMode() {
		outbounds, _ := raw["outbounds"].([]any)
		if !hasServerTag(outbounds, "nb-out") {
			outbounds = append(outbounds, map[string]any{"type": "netbird", "tag": "nb-out"})
			raw["outbounds"] = outbounds
		}

		// Custom domains → nb-out via the local domain rule-set (domains live
		// in the file, updated at runtime by the engine; see customRuleSetTag).
		// Idempotent: skip when an existing rule (cleaned) or a just-prepended
		// one already references the set.
		if ruleSetPath != "" && !hasRuleSetRule(prepended, customRuleSetTag) && !hasRuleSetRule(cleaned, customRuleSetTag) {
			prepended = append(prepended, map[string]any{
				"rule_set":  customRuleSetTag,
				"outbound": "nb-out",
			})
		}
		// Overlay CIDR → nb-out via the local CIDR rule-set (real-time updates
		// for accounts whose overlay differs from the default /16). The overlay
		// routing used to be a static ip_cidr rule baked into the config — it
		// was removed: the CIDR now lives in nb-cidr.json (written at StartAll
		// with the persisted/default value, refreshed by the engine after sync),
		// so the route rule-set reference covers it with zero startup ordering
		// dependency.
		if cidrRuleSetPath != "" && !hasRuleSetRule(prepended, customCIDRRuleSetTag) && !hasRuleSetRule(cleaned, customCIDRRuleSetTag) {
			prepended = append(prepended, map[string]any{
				"rule_set":  customCIDRRuleSetTag,
				"outbound": "nb-out",
			})
		}
		// nb-cidr rule-set declaration — userspace only (kernel mode routes
		// the overlay via the kernel route, no route rules at all).
		// format 必须显式: 1.14 的 ruleSetDefaultFormat 用 url.Parse 推断
		// 扩展名, Windows 盘符路径(C:\...)被当成 URL scheme → 推断失败 →
		// "missing format"(Android /data/... 路径正常)。显式 source 全平台稳。
		if cidrRuleSetPath != "" && !hasRuleSetDecl(routeSection, customCIDRRuleSetTag) {
			ruleSets, _ := routeSection["rule_set"].([]any)
			routeSection["rule_set"] = append(ruleSets, map[string]any{
				"type":   "local",
				"tag":    customCIDRRuleSetTag,
				"path":   cidrRuleSetPath,
				"format": "source",
			})
		}
	}
	routeSection["rules"] = append(prepended, cleaned...)

	// Local rule-set declaration (nb-domains): route AND DNS rules resolve
	// rule-set tags through the route.rule_set registry (box.go:
	// router.Initialize(routeOptions.RuleSet)). Declared in both modes — the
	// DNS custom-domain rule needs it in kernel mode too. format 显式, 理由
	// 同上(Windows 路径推断失败)。
	if ruleSetPath != "" && !hasRuleSetDecl(routeSection, customRuleSetTag) {
		ruleSets, _ := routeSection["rule_set"].([]any)
		routeSection["rule_set"] = append(ruleSets, map[string]any{
			"type":   "local",
			"tag":    customRuleSetTag,
			"path":   ruleSetPath,
			"format": "source",
		})
	}

	// Custom domains → nb DNS transport (both kernel-TUN and userspace: the
	// kernel route handles overlay IPs, but domain resolution still needs the
	// tunnel DNS). References ONLY the domain rule-set (an IP-bearing set
	// referenced by a DNS rule is rejected by the 1.14 legacy-address-filter
	// check).
	if ruleSetPath != "" {
		dnsRules, _ := dnsSection["rules"].([]any)
		if !hasRuleSetRule(dnsRules, customRuleSetTag) {
			dnsSection["rules"] = append(dnsRules, map[string]any{
				"rule_set": customRuleSetTag,
				"server":   "nb",
			})
		}
	}

	// 注意: 不做 final=nb 兜底。兜底会让所有未命中规则的域名(非 CN 冷门
	// 域名、rule_set 异步加载期间的域名)先走隧道 DNS —— 引擎在但隧道
	// 不通时一次解析 5s 超时 + fallback 5s, 直接卡死。自定义域名靠上面的
	// customDomains 显式规则(引擎 sync 成功后注入), 不影响其他域名。
	// final 保持用户 profile 原样(通常 dns-remote 走代理, 快)。

	return json.Marshal(raw)
}

// hasServerTag reports whether the JSON array already contains an entry
// (DNS server or outbound) with the given tag.
func hasServerTag(items []any, tag string) bool {
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(m["tag"]) == tag {
			return true
		}
	}
	return false
}

// hasRuleSetDecl reports whether the route.rule_set section already declares
// a rule-set with the given tag.
func hasRuleSetDecl(routeSection map[string]any, tag string) bool {
	ruleSets, _ := routeSection["rule_set"].([]any)
	for _, rs := range ruleSets {
		m, ok := rs.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(m["tag"]) == tag {
			return true
		}
	}
	return false
}

// hasRuleSetRule reports whether the rule list already contains a rule whose
// rule_set matcher references the given tag (route and DNS rules both use
// the same `rule_set` key; the value is a Listable string or array).
func hasRuleSetRule(rules []any, tag string) bool {
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		switch v := m["rule_set"].(type) {
		case string:
			if v == tag {
				return true
			}
		case []any:
			for _, s := range v {
				if fmt.Sprint(s) == tag {
					return true
				}
			}
		}
	}
	return false
}

// hasIPDirectRule reports whether rules already contain an ip_cidr rule with
// outbound "direct" covering all of the given IPs.
func hasIPDirectRule(rules []any, ips []string) bool {
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(rule["outbound"]) != "direct" {
			continue
		}
		cidrs, ok := rule["ip_cidr"].([]any)
		if !ok {
			continue
		}
		if containsAll(cidrs, ips) {
			return true
		}
	}
	return false
}

// hasDomainDirectRule reports whether rules already contain a domain_suffix
// rule covering all of domains with outbound "direct".
func hasDomainDirectRule(rules []any, domains []string) bool {
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(rule["outbound"]) != "direct" {
			continue
		}
		ds, ok := rule["domain_suffix"].([]any)
		if !ok {
			continue
		}
		if containsAll(ds, domains) {
			return true
		}
	}
	return false
}

// hasDNSDirectRule reports whether dns.rules already route all of domains to
// the built-in dns-direct server.
func hasDNSDirectRule(dnsSection map[string]any, domains []string) bool {
	rules, _ := dnsSection["rules"].([]any)
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(rule["server"]) != "dns-direct" {
			continue
		}
		ds, ok := rule["domain_suffix"].([]any)
		if !ok {
			continue
		}
		if containsAll(ds, domains) {
			return true
		}
	}
	return false
}

func containsAll(haystack []any, needles []string) bool {
	has := func(s string) bool {
		for _, h := range haystack {
			if fmt.Sprint(h) == s {
				return true
			}
		}
		return false
	}
	for _, n := range needles {
		if !has(n) {
			return false
		}
	}
	return true
}
