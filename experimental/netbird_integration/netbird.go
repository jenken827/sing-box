//go:build with_netbird

package netbird_integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	nbembed "github.com/netbirdio/netbird/client/embed"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// StartAllResult holds the result of StartAll.
type StartAllResult struct {
	// ModifiedConfig is the sing-box config with netbird rules injected.
	// nil if netbird was not started (no credentials).
	ModifiedConfig []byte
	// Engine is the running netbird engine. nil if not started.
	Engine *Engine
	// EngineErr is set when the engine failed to start (non-fatal: sing-box
	// still runs with the unmodified config). Empty when the engine was
	// never attempted (no credentials) or started successfully.
	EngineErr string
	// NetworkCIDR is the account overlay CIDR from the sync response
	// (e.g. "100.121.0.0/16"), or "" when unknown. Used by kernel-TUN mode
	// to install the static route to wt0.
	NetworkCIDR string
}

// StartAll starts the netbird engine, syncs with the management server,
// extracts custom domains, and injects netbird DNS/outbound/route rules
// into the sing-box config.
//
// If cfg is nil or has no credentials (SetupKey and JWTToken both empty),
// returns the original singBoxConfig unchanged with Engine=nil.
func StartAll(cfg *Config, singBoxConfig []byte) (*StartAllResult, error) {
	result := &StartAllResult{}

	if cfg == nil {
		return result, nil
	}
	hasCreds := cfg.SetupKey != "" || cfg.JWTToken != ""
	if !hasCreds {
		log.Info("netbird: no credentials, skipping")
		result.ModifiedConfig = singBoxConfig
		return result, nil
	}

	// Kernel-TUN mode is Linux-only: netbird creates a real kernel TUN (wt0)
	// and a single static kernel route sends the overlay CIDR straight to it,
	// bypassing the sing-box TUN stack (single TCP termination, official-app
	// performance). Windows/Android keep the userspace netstack path.
	kernelTun := cfg.KernelTun && runtime.GOOS == "linux"
	SetKernelMode(kernelTun)
	log.Info(fmt.Sprintf("netbird: data path: %s", map[bool]string{true: "kernel-tun (wt0)", false: "userspace netstack"}[kernelTun]))

	t0 := time.Now()

	// DNS 预热 + 控制面 IP 收集: 解析 mgmt 主机名。首次启动时系统 DNS
	// 冷缓存 + IPv6 AAAA 查询挂起(i/o timeout)会让引擎的 mgmt 连接慢到
	// 20s+, 吃掉 60s 启动预算导致首启失败; 此处提前解析, 引擎 Start 时
	// 走热缓存(自建部署 mgmt/relay/signal 同域名, 一次预热全覆盖)。
	// 位于 engine.Start() 之前, 不计入引擎启动超时。解析出的 IP 同时
	// 用于注入控制面 ip_cidr → direct 规则(见 InjectNetbirdJSON)。
	// 注: 引擎侧控制面域名解析已全部改为 IPv4-only(LookupNetIP "ip4",
	// netbird my_custom 分支), 彻底绕开 AAAA 慢查询。预热带 3s 超时,
	// 避免无网络时解析挂起拖慢骨架返回。
	var ctlIPs []string
	if u, err := url.Parse(cfg.ManagementURL); err == nil && u.Hostname() != "" {
		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, err := net.DefaultResolver.LookupIP(dnsCtx, "ip4", u.Hostname())
		dnsCancel()
		if err == nil {
			for _, a := range addrs {
				if ip4 := a.To4(); ip4 != nil {
					ctlIPs = append(ctlIPs, ip4.String()+"/32")
				}
			}
		}
	}

	engine := NewEngine(cfg)
	engineStarted := false
	if kernelTun {
		// 内核-TUN 模式(Linux CLI): 保持同步启动 — cmd_run_all 需要
		// result.NetworkCIDR 安装内核路由, 且 CLI 无 UI 阻塞问题。
		if err := engine.Start(); err != nil {
			log.Warn("netbird engine failed to start: ", err)
			SetKernelMode(false)
			result.EngineErr = err.Error()
		} else {
			engineStarted = true
		}
	} else {
		// 用户态(Android/Windows): 引擎异步启动 — engine.Start() 的
		// mgmt 连接可达 60s(无网络时重试风暴), 同步等待会让 sing-box
		// (TUN/通知/连通性)延迟最多 60s 才启动, 用户感知"自启动 2 分钟"。
		// 这里立即返回骨架配置, 引擎在后台连接; 就绪后 postStartSync
		// 接线(SetClient/sync/DNS 地址/域名+CIDR rule-set 文件/bridges),
		// 自定义域名实时注入由 LocalRuleSet fswatch 承接。
		go func() {
			if err := engine.Start(); err != nil {
				log.Warn("netbird engine failed to start (async): ", err)
				SetKernelMode(false)
				return
			}
			if engine.watchStopped() {
				// 服务在引擎启动期间被拆除: 别让孤儿引擎继续跑
				_ = engine.Stop()
				return
			}
			engine.postStartSync()
			log.Info("netbird: engine started and synced (async)")
		}()
		engineStarted = false
	}

	var customDomains []string
	var networkCIDR string
	if engineStarted {
		// 仅内核模式到达这里(用户态异步路径由 postStartSync 处理)。
		if c := engine.GetClient(); c != nil {
			SetClient(c)
			log.Info(fmt.Sprintf("netbird DNS resolver available (t=%.1fs)", time.Since(t0).Seconds()))
			t1 := time.Now()
			syncCtx, syncCancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := WaitSyncResponse(syncCtx, c)
			syncCancel()
			log.Info(fmt.Sprintf("netbird sync wait: %.1fs", time.Since(t1).Seconds()))
			if err != nil {
				log.Warn("wait for netbird sync: ", err)
			} else {
				customDomains = ExtractDomainsFromSync(resp)
				networkCIDR = ExtractNetworkCIDR(resp)
				result.NetworkCIDR = networkCIDR
				// Compute the tunnel DNS server address from the account network
				// (last-but-one IP of the overlay /16, e.g. 100.121.255.254:53).
				// Without this, the netbird DNS transport has no reachable target.
				// Netstack mode only: in kernel-TUN mode the DNS server binds the
				// WG interface's own IP:53, set by SetupKernelRoute.
				if !IsKernelMode() {
					SetDNSAddr(ComputeDNSAddr(networkCIDR))
				}
				log.Info(fmt.Sprintf("netbird custom domains: %v, network: %s", customDomains, networkCIDR))
			}
		}
		log.Info("netbird engine started")

		// Start configured overlay→local TCP bridges (expose_ports).
		// These must come after the engine + sync are up: BridgeTCP calls
		// client.ListenTCP which needs a running engine with a netstack.
		startBridges(cfg.ExposePorts)
	}

	// Control-plane IPs → direct: resolve the management host so the engine's
	// first STUN/TURN/relay probes are never routed through the proxy even
	// before remote rule-sets finish loading (see InjectNetbirdJSON).
	// ctlIPs 已在 StartAll 开头预热解析(DNS 预热), 此处仅注入。
	// 自定义域名/网段实时注入(rule-set 文件机制): 配置里的 route/DNS 规则
	// 引用两个本地 rule-set 文件(nb-domains.json + nb-cidr.json), 域名与
	// CIDR 本体写进文件。sing-box 的 LocalRuleSet 监视文件, 引擎恢复/管理端
	// 变更时重写即运行时生效, 无需重载服务。文件必须存在(缺失会导致配置
	// 加载失败): 首次运行创建默认文件, 后续运行保留上次持久化的内容
	// (异步路径下引擎尚未 sync 时依然生效)。
	ruleSetPath := domainsRuleSetPath(cfg)
	cidrPath := cidrRuleSetPath(cfg)
	if engineStarted {
		if err := engine.writeDomainsFiles(customDomains, networkCIDR); err != nil {
			log.Warn("netbird: write domains rule-set: ", err)
		}
	} else {
		// 只创建缺失的文件(勿整体重写 — 异步路径下旧文件里的域名/CIDR
		// 在引擎 sync 前依然有效, 整体覆盖会清空它们)。
		if _, err := os.Stat(ruleSetPath); os.IsNotExist(err) {
			if err := writeDomainsRuleSet(ruleSetPath, nil); err != nil {
				log.Warn("netbird: create default domains rule-set: ", err)
			}
		}
		if _, err := os.Stat(cidrPath); os.IsNotExist(err) {
			if err := writeCidrRuleSet(cidrPath, ""); err != nil {
				log.Warn("netbird: create default cidr rule-set: ", err)
			}
		}
	}
	modified, err := InjectNetbirdJSON(singBoxConfig, cfg.ManagementURL, ctlIPs, ruleSetPath, cidrPath)
	if err != nil {
		// Non-fatal: sing-box still runs, just without netbird rules
		log.Warn("inject netbird config: ", err)
		result.ModifiedConfig = singBoxConfig
	} else {
		result.ModifiedConfig = modified
	}
	result.Engine = engine

	// Watch the system default route and restart the engine on network
	// switches (WiFi ↔ hotspot ↔ WiFi, VPN toggle). The embedded engine's
	// own network monitor is skipped in netstack mode, so without this the
	// ICE candidates go stale and the tunnel silently falls back to relay.
	// 全平台启用网络监控(含 Android): 网络变化时重启引擎, 引擎意外停止时
	// 自动恢复。Android 的 VpnService TUN 接口名(tun0)已在 addrsSnapshot
	// 排除列表中, 不会把引擎自身接口变化误判为物理网络变化。
	go watchNetworkChanges(engine)
	return result, nil
}

// startBridges creates the configured overlay→local TCP forwards. Bridges
// depend on a running engine with a netstack (client.ListenTCP).
func startBridges(ports []ExposePortConfig) {
	if len(ports) == 0 {
		return
	}
	log.Infof("netbird: starting %d configured bridge(s)", len(ports))
	for _, ep := range ports {
		if ep.Port <= 0 || ep.Port > 65535 || ep.Target == "" {
			log.Warnf("netbird: skipping invalid expose port config: %+v", ep)
			continue
		}
		if _, err := BridgeTCP(ep.Port, ep.Target); err != nil {
			log.Warnf("netbird: bridge :%d → %s failed: %v", ep.Port, ep.Target, err)
		}
	}
}

// restartOnNetworkChange restarts the engine and re-syncs after the system
// default route changed. Called by watchNetworkChanges. The old client's
// ICE candidates / bridges died with it; re-creating them restores P2P
// (and the expose_ports bridges) without a full app restart.
//
// Also serves as the recovery path: when the engine is not running (e.g. a
// previous restart failed because the network was still settling and the
// management dial timed out), it skips Stop and goes straight to Start.
func (e *Engine) restartOnNetworkChange() {
	if e.watchStopped() {
		log.Info("netbird: watcher shut down, skipping restart")
		return
	}
	if e.IsRunning() {
		log.Info("netbird: restarting engine after network change")
		if err := e.Stop(); err != nil {
			log.Warn("netbird: stop before restart: ", err)
		}
	}
	if err := e.Start(); err != nil {
		log.Warn("netbird: engine (re)start failed: ", err)
		return
	}
	e.postStartSync()
	log.Info("netbird: engine restarted after network change")
}

// postStartSync re-wires the sing-box integration after a (re)start:
// refresh the global embed client, wait for the management sync, recompute
// the tunnel DNS address, and recreate the overlay→local bridges.
func (e *Engine) postStartSync() {
	if e.watchStopped() {
		// Service teardown raced with a network-change restart: the client
		// just started will be stopped by Shutdown's Stop — do not let it
		// re-wire the global nb-out/DNS client.
		return
	}
	if c := e.GetClient(); c != nil {
		SetClient(c)
		syncCtx, syncCancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := WaitSyncResponse(syncCtx, c)
		syncCancel()
		if err != nil {
			log.Warn("netbird: re-sync after restart: ", err)
		} else {
			if !IsKernelMode() {
				SetDNSAddr(ComputeDNSAddr(ExtractNetworkCIDR(resp)))
			}
			// 引擎恢复后的自定义域名实时注入: 重写 rule-set 文件(域名+真实
			// CIDR), sing-box 的 LocalRuleSet fswatch 运行时重载规则 —
			// 冷启动无网络→引擎恢复场景下域名规则立即生效, 无需重载服务。
			e.refreshDomainsFile(ExtractDomainsFromSync(resp), ExtractNetworkCIDR(resp))
		}
	}
	// Overlay→local bridges died with the old client; recreate them.
	startBridges(e.cfg.ExposePorts)
}

// Engine wraps the netbird embed client.
type Engine struct {
	cfg      *Config
	mu       sync.Mutex
	running  bool
	starting bool // engine.Start() in flight (async start / concurrent guard)
	client   *nbembed.Client
	stopCh   chan struct{}
	stopOnce sync.Once
	// rule-set file state: fingerprints of the last written domain list and
	// overlay CIDR, so runtime refreshes only rewrite a file when it changed
	// (avoids needless fswatch reloads in sing-box).
	domainsMu  sync.Mutex
	domainsSig string
	cidrSig    string
}

// Config holds configuration for the netbird engine.
type Config struct {
	DeviceName    string `json:"device_name"`
	SetupKey      string `json:"setup_key"`
	JWTToken      string `json:"jwt_token"`
	ManagementURL string `json:"management_url"`
	AdminURL      string `json:"admin_url"`
	LogLevel      string `json:"log_level"`
	DataDir       string `json:"data_dir"`
	// KernelTun enables the Linux kernel-TUN data path (Route A):
	// netbird creates a real kernel TUN (wt0) and a single static kernel
	// route sends the overlay CIDR directly to it, bypassing the sing-box
	// TUN stack. Only honored on Linux; Windows/Android always use the
	// userspace netstack path. Requires root.
	KernelTun bool `json:"kernel_tun"`
	// PrivateKey authenticates as an existing device (direct key auth),
	// e.g. to reuse a running netbird daemon's identity during migration.
	// Mutually exclusive with SetupKey/JWTToken.
	PrivateKey string `json:"private_key"`
	// ExposePorts lists overlay→local TCP port forwards. Each entry makes
	// the netbird engine listen on the given port inside the overlay
	// (netstack) and forward accepted connections to the local target.
	// Needed because the userspace netstack cannot deliver inbound
	// connections to processes listening on the host kernel stack.
	ExposePorts []ExposePortConfig `json:"expose_ports"`
}

// ExposePortConfig declares one overlay→local TCP forward.
type ExposePortConfig struct {
	// Port is the port to listen on inside the netbird overlay.
	Port int `json:"port"`
	// Target is the local host:port to forward to (e.g. "127.0.0.1:8022").
	Target string `json:"target"`
}

// Status represents engine status.
type Status struct {
	Running bool `json:"running"`
}

// UnifiedConfig is the top-level config that wraps both engines.
type UnifiedConfig struct {
	Netbird *Config `json:"netbird"`
	// SingBox is left unstructured — sing-box parses its own section.
	SingBox json.RawMessage `json:"sing_box"`
}

// NewEngine creates a new netbird engine wrapper with the given config.
func NewEngine(cfg *Config) *Engine {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = "sing-netbird"
	}
	if cfg.ManagementURL == "" {
		cfg.ManagementURL = "https://api.netbird.io:443"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return &Engine{cfg: cfg, stopCh: make(chan struct{})}
}

// Start starts the netbird engine using the config from NewEngine.
// The mutex is only held for the state transitions (starting flag), NOT for
// the long mgmt dial (up to 60s) — otherwise a concurrent Start from the
// recovery loop would block the whole watcher for the entire attempt.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("netbird engine already running")
	}
	if e.starting {
		e.mu.Unlock()
		return fmt.Errorf("netbird engine already starting")
	}
	e.starting = true
	e.mu.Unlock()

	fail := func(err error) error {
		e.mu.Lock()
		e.starting = false
		e.mu.Unlock()
		return err
	}

	// Fall back to env vars for credentials if not in config
	setupKey := e.cfg.SetupKey
	jwtToken := e.cfg.JWTToken
	privateKey := e.cfg.PrivateKey
	if setupKey == "" {
		setupKey = os.Getenv("NB_SETUP_KEY")
	}
	if jwtToken == "" {
		jwtToken = os.Getenv("NB_JWT_TOKEN")
	}
	if privateKey == "" {
		privateKey = os.Getenv("NB_PRIVATE_KEY")
	}
	if setupKey == "" && jwtToken == "" && privateKey == "" {
		log.Warn("netbird: no SetupKey, JWTToken or PrivateKey set, engine may not authenticate")
	}

	opts := nbembed.Options{
		DeviceName:    e.cfg.DeviceName,
		SetupKey:      setupKey,
		JWTToken:      jwtToken,
		PrivateKey:    privateKey,
		ManagementURL: e.cfg.ManagementURL,
		LogLevel:      e.cfg.LogLevel,
	}
	// Persist state to reuse WireGuard key across restarts, avoiding
	// the ~20s management registration delay on subsequent starts.
	stateDir := filepath.Join(e.cfg.DataDir, "nb-state")
	os.MkdirAll(stateDir, 0700)
	opts.ConfigPath = filepath.Join(stateDir, "config.json")
	opts.StatePath = filepath.Join(stateDir, "state.json")
	// Send netbird engine logs to DataDir/nb-engine.log so relay/P2P
	// paths, peer states and bridge failures are diagnosable. The default
	// os.Stderr sink is swallowed by gomobile/libbox on Android.
	if logFile, err := os.OpenFile(
		filepath.Join(e.cfg.DataDir, "nb-engine.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600,
	); err == nil {
		opts.LogOutput = logFile
		log.Info("netbird: engine logs → " + filepath.Join(e.cfg.DataDir, "nb-engine.log"))
	} else {
		log.Warn("netbird: open nb-engine.log: ", err)
	}

	// Kernel-TUN mode (Linux only): real kernel TUN + no netbird-managed
	// routes. The embed Options expose NoUserspace and DisableClientRoutes;
	// DisableDNS/DisableFirewall are not exposed, so they are pre-seeded
	// into netbird's profile config file (profilemanager preserves file
	// values when the corresponding ConfigInput pointers are nil).
	kernelTun := e.cfg.KernelTun && runtime.GOOS == "linux"
	if kernelTun {
		opts.NoUserspace = true
		opts.DisableClientRoutes = true
		if err := writeNetbirdProfileConfig(opts.ConfigPath); err != nil {
			log.Warn("netbird: pre-write profile config: ", err)
		}
	}

	// Windows: 嵌入模式下控制面 socket 的接口选择(IP_UNICAST_IF)必须排除
	// sing-box 的 TUN(singtun), 落到物理网卡; 否则 selectInterface 会选中
	// metric-0 的 singtun 默认路由, 旁路失效, STUN 仍被劫持。
	if runtime.GOOS == "windows" {
		nbnet.SetVPNInterfaceName("singtun")
	}

	client, err := nbembed.New(opts)
	if err != nil {
		return fail(fmt.Errorf("netbird embed new: %w", err))
	}

	t1 := time.Now()
	startCtx, startCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer startCancel()
	t2 := time.Now()
	if err := client.Start(startCtx); err != nil {
		return fail(fmt.Errorf("netbird embed start: %w", err))
	}
	log.Infof("nbembed.Start() took %.1fs (New=%.1fs)", time.Since(t2).Seconds(), time.Since(t1).Seconds())

	e.mu.Lock()
	e.starting = false
	e.client = client
	e.running = true
	e.mu.Unlock()
	log.Info("netbird: engine started")
	return nil
}

// Stop stops the netbird engine.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer SetKernelMode(false)

	if !e.running || e.client == nil {
		return nil
	}

	log.Info("netbird: stopping engine")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.client.Stop(ctx); err != nil {
		return fmt.Errorf("netbird embed stop: %w", err)
	}

	e.running = false
	e.client = nil
	log.Info("netbird: engine stopped")
	return nil
}

// Shutdown stops the engine permanently: it stops the embed client AND
// terminates the network watcher (watchNetworkChanges) so the recovery
// loop can never resurrect the engine afterwards, then clears the global
// integration state (nb-out / DNS transport client, tunnel DNS address).
//
// Use when the host service is going away (VpnService teardown). Unlike a
// plain Stop() — which is used for in-place network-change restarts and
// must keep the watcher alive — Shutdown closes stopCh first, so the
// watcher exits even if the 10s Stop timeout is hit.
func (e *Engine) Shutdown() {
	e.stopOnce.Do(func() { close(e.stopCh) })
	if err := e.Stop(); err != nil {
		log.Warn("netbird: shutdown stop: ", err)
	}
	ClearClient()
	SetDNSAddr("")
	log.Info("netbird: engine shut down")
}

// watchStopped reports whether Shutdown has been called (stopCh closed).
// Used to skip re-wiring the global client when a network-change restart
// races with service teardown.
func (e *Engine) watchStopped() bool {
	select {
	case <-e.stopCh:
		return true
	default:
		return false
	}
}

// Rule-set source files: the custom-domain list (nb-domains.json, referenced
// by the DNS rule AND the route rule) and the overlay CIDR (nb-cidr.json,
// referenced by the route rule only). They must stay separate files — see
// writeDomainsRuleSet's NOTE on DNS-referenced IP-bearing sets.
const domainsRuleSetFile = "nb-domains.json"
const cidrRuleSetFile = "nb-cidr.json"

// defaultOverlayCIDR is the netbird default account overlay subnet, used when
// the sync response has not arrived yet.
const defaultOverlayCIDR = "100.121.0.0/16"

// domainsRuleSetPath returns the absolute path of the custom-domain rule-set
// file. Falls back to the OS temp dir when DataDir is unset (CLI runs).
func domainsRuleSetPath(cfg *Config) string {
	dir := cfg.DataDir
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, domainsRuleSetFile)
}

// cidrRuleSetPath returns the absolute path of the overlay-CIDR rule-set file.
func cidrRuleSetPath(cfg *Config) string {
	dir := cfg.DataDir
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, cidrRuleSetFile)
}

// domainsSig returns a stable fingerprint of the domain list (sorted join),
// used to skip redundant file rewrites.
func domainsSig(domains []string) string {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// writeDomainsRuleSet writes the custom domains to the rule-set source file.
// os.WriteFile truncates in place (same inode), so the fswatch watcher in
// sing-box's LocalRuleSet keeps watching and reloads the rules on change
// (an atomic rename would orphan the inotify watch). The file always carries
// a valid rule-set, even with zero domains.
//
// Domains are trimmed of trailing dots: the management server ships them with
// a trailing "." (e.g. "netbird.selfhosted.") but sing-box's domain_suffix
// matcher compares literally — an untrimmed rule never matches a real query.
//
// NOTE: this file must NOT carry ip_cidr rules. The DNS rule
// {rule_set: nb-domains, server: nb} references it; sing-box 1.14 treats a
// DNS-referenced rule-set with IP filter fields (without a match_response
// evaluate chain) as the deprecated legacy address-filter mode and REJECTS
// the reload ("Legacy Address Filter Fields in DNS rules is deprecated") —
// the watcher fires but the rules stay stale. The overlay CIDR lives in the
// separate nb-cidr.json (route rules only), see writeCidrRuleSet.
func writeDomainsRuleSet(path string, domains []string) error {
	rules := make([]map[string]any, 0, 1)
	if len(domains) > 0 {
		cleaned := make([]string, 0, len(domains))
		for _, d := range domains {
			if d != "" {
				cleaned = append(cleaned, strings.TrimSuffix(d, "."))
			}
		}
		if len(cleaned) > 0 {
			rules = append(rules, map[string]any{"domain_suffix": cleaned})
		}
	}
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"rules":   rules,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// writeCidrRuleSet writes the overlay CIDR to its rule-set file (route-only
// set: the route rule {rule_set: nb-cidr, outbound: nb-out} matches it, and
// no DNS rule references it, so the 1.14 legacy-address-filter validation
// never sees it). Empty cidr falls back to the netbird default.
func writeCidrRuleSet(path string, cidr string) error {
	if cidr == "" {
		cidr = defaultOverlayCIDR
	}
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"rules":   []map[string]any{{"ip_cidr": []string{cidr}}},
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// writeDomainsFiles writes both rule-set files (domains + CIDR) and records
// the fingerprints. Used at StartAll so the files exist before the config
// loads.
func (e *Engine) writeDomainsFiles(domains []string, cidr string) error {
	if err := writeDomainsRuleSet(domainsRuleSetPath(e.cfg), domains); err != nil {
		return err
	}
	if err := writeCidrRuleSet(cidrRuleSetPath(e.cfg), cidr); err != nil {
		return err
	}
	e.domainsMu.Lock()
	e.domainsSig = domainsSig(domains)
	e.cidrSig = cidr
	e.domainsMu.Unlock()
	return nil
}

// refreshDomainsFile rewrites the rule-set files when domains or the overlay
// CIDR changed. sing-box's LocalRuleSet fswatch picks the writes up and
// reloads the route/DNS rules at runtime — this is the "real-time custom
// domain / CIDR injection" path for engines that sync after startup (and for
// management-side changes: a different overlay network, or domain added to
// the account DNS config, takes effect without reloading the service).
func (e *Engine) refreshDomainsFile(domains []string, cidr string) {
	if cidr == "" {
		cidr = defaultOverlayCIDR
	}
	dSig := domainsSig(domains)
	e.domainsMu.Lock()
	dChanged := dSig != e.domainsSig
	cChanged := cidr != e.cidrSig
	e.domainsMu.Unlock()
	if !dChanged && !cChanged {
		return
	}
	if dChanged {
		if err := writeDomainsRuleSet(domainsRuleSetPath(e.cfg), domains); err != nil {
			log.Warn("netbird: refresh domains rule-set: ", err)
			return
		}
	}
	if cChanged {
		if err := writeCidrRuleSet(cidrRuleSetPath(e.cfg), cidr); err != nil {
			log.Warn("netbird: refresh cidr rule-set: ", err)
			return
		}
	}
	e.domainsMu.Lock()
	e.domainsSig = dSig
	e.cidrSig = cidr
	e.domainsMu.Unlock()
	log.Info(fmt.Sprintf("netbird: rule-sets refreshed (domains=%d changed=%v, cidr=%s changed=%v)", len(domains), dChanged, cidr, cChanged))
}

// refreshDomainsFromSync pulls the latest sync response and updates the
// domains rule-set if changed. Covers domains that arrive after the initial
// sync wait (slow first sync) and management-side domain changes.
func (e *Engine) refreshDomainsFromSync() {
	c := e.GetClient()
	if c == nil {
		return
	}
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 3*time.Second)
	resp, err := WaitSyncResponse(syncCtx, c)
	syncCancel()
	if err != nil || resp == nil {
		return
	}
	e.refreshDomainsFile(ExtractDomainsFromSync(resp), ExtractNetworkCIDR(resp))
}

// IsRunning returns whether the engine is running.
func (e *Engine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// GetClient returns the underlying netbird embed client, if available.
func (e *Engine) GetClient() *nbembed.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client
}

// GetStatus returns the current engine status.
func (e *Engine) GetStatus() *Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &Status{Running: e.running}
}

// ParseConfig parses a netbird config JSON string.
func ParseConfig(configJSON string) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("parse netbird config: %w", err)
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = "sing-netbird"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return &cfg, nil
}

// ReadUnifiedConfig reads a unified JSON config file and returns the parsed structure.
func ReadUnifiedConfig(path string) (*UnifiedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg UnifiedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// writeNetbirdProfileConfig pre-seeds netbird's own profile config file
// (nb-state/config.json) with the settings embed Options cannot express:
// DisableDNS (don't touch /etc/resolv.conf) and DisableFirewall (don't
// engage nftables). Existing keys are preserved — the file is read, patched
// and written back so a previously persisted PrivateKey survives.
func writeNetbirdProfileConfig(path string) error {
	cfg := make(map[string]any)
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &cfg) // tolerate partial/corrupt files
	}
	cfg["DisableDNS"] = true
	cfg["DisableFirewall"] = true
	cfg["DisableClientRoutes"] = true
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
