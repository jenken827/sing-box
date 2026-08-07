//go:build with_netbird

package netbird_integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	t0 := time.Now()

	engine := NewEngine(cfg)
	if err := engine.Start(); err != nil {
		log.Warn("netbird engine failed to start: ", err)
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
			// Compute the tunnel DNS server address from the account network
			// (last-but-one IP of the overlay /16, e.g. 100.121.255.254:53).
			// Without this, the netbird DNS transport has no reachable target.
			SetDNSAddr(ComputeDNSAddr(networkCIDR))
			log.Info(fmt.Sprintf("netbird custom domains: %v, network: %s", customDomains, networkCIDR))
		}
	}
	log.Info("netbird engine started")

	modified, err := InjectNetbirdJSON(singBoxConfig, customDomains, networkCIDR)
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
	if setupKey == "" {
		setupKey = os.Getenv("NB_SETUP_KEY")
	}
	if jwtToken == "" {
		jwtToken = os.Getenv("NB_JWT_TOKEN")
	}
	if setupKey == "" && jwtToken == "" {
		log.Warn("netbird: no SetupKey or JWTToken set, engine may not authenticate")
	}

	opts := nbembed.Options{
		DeviceName:    e.cfg.DeviceName,
		SetupKey:      setupKey,
		JWTToken:      jwtToken,
		ManagementURL: e.cfg.ManagementURL,
		LogLevel:      e.cfg.LogLevel,
	}
	// Persist state to reuse WireGuard key across restarts, avoiding
	// the ~20s management registration delay on subsequent starts.
	stateDir := filepath.Join(e.cfg.DataDir, "nb-state")
	os.MkdirAll(stateDir, 0700)
	opts.ConfigPath = filepath.Join(stateDir, "config.json")
	opts.StatePath = filepath.Join(stateDir, "state.json")

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
