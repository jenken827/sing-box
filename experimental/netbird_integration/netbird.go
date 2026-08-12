//go:build with_netbird

package netbird_integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	nbembed "github.com/netbirdio/netbird/client/embed"
)

// StartAllResult holds the result of StartAll.
type StartAllResult struct {
	// ModifiedConfig is the sing-box config with netbird rules injected.
	// nil if netbird was not started (no credentials).
	ModifiedConfig []byte
	// Engine is the running netbird engine. nil if not started.
	Engine *Engine
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

	engine := NewEngine(cfg)
	if err := engine.Start(); err != nil {
		log.Warn("netbird engine failed to start: ", err)
		SetKernelMode(false)
		result.ModifiedConfig = singBoxConfig
		return result, nil // non-fatal: sing-box still runs
	}

	var customDomains []string
	var networkCIDR string
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
	if len(cfg.ExposePorts) > 0 {
		log.Infof("netbird: starting %d configured bridge(s)", len(cfg.ExposePorts))
		for _, ep := range cfg.ExposePorts {
			if ep.Port <= 0 || ep.Port > 65535 || ep.Target == "" {
				log.Warnf("netbird: skipping invalid expose port config: %+v", ep)
				continue
			}
			if _, err := BridgeTCP(ep.Port, ep.Target); err != nil {
				log.Warnf("netbird: bridge :%d → %s failed: %v", ep.Port, ep.Target, err)
			}
		}
	}

	modified, err := InjectNetbirdJSON(singBoxConfig, customDomains, networkCIDR, cfg.ManagementURL)
	if err != nil {
		// Non-fatal: sing-box still runs, just without netbird rules
		log.Warn("inject netbird config: ", err)
		result.ModifiedConfig = singBoxConfig
	} else {
		result.ModifiedConfig = modified
	}
	result.Engine = engine
	return result, nil
}

// Engine wraps the netbird embed client.
type Engine struct {
	cfg     *Config
	mu      sync.Mutex
	running bool
	client  *nbembed.Client
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
	return &Engine{cfg: cfg}
}

// Start starts the netbird engine using the config from NewEngine.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("netbird engine already running")
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

	client, err := nbembed.New(opts)
	if err != nil {
		return fmt.Errorf("netbird embed new: %w", err)
	}

	t1 := time.Now()
	startCtx, startCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer startCancel()
	t2 := time.Now()
	if err := client.Start(startCtx); err != nil {
		return fmt.Errorf("netbird embed start: %w", err)
	}
	log.Infof("nbembed.Start() took %.1fs (New=%.1fs)", time.Since(t2).Seconds(), time.Since(t1).Seconds())

	e.client = client
	e.running = true
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
