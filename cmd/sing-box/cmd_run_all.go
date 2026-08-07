//go:build with_netbird

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/experimental/monitor"
	"github.com/sagernet/sing-box/experimental/netbird_integration"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/spf13/cobra"
)

var (
	runAllNetbirdConfig string
	runAllEnableNetbird bool
)

var commandRunAll = &cobra.Command{
	Use:   "run-all",
	Short: "Run sing-box and netbird engines simultaneously",
	Long: `Start sing-box and optionally netbird in one process.

-c: sing-box config (same format as 'run')
--netbird-config: netbird config JSON (optional, falls back to env vars)
--enable-netbird: start netbird engine alongside sing-box (default: false)

When --enable-netbird is true and netbird config is available:
  - netbird engine starts first
  - DNS queries route through netbird's handler chain
  - Traffic to 100.121.0.0/16 goes through netbird tunnel
When --enable-netbird is false (default), runs sing-box only.

Netbird config:
  {"device_name":"...", "setup_key":"...", "management_url":"..."}
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runAll(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandRunAll.PersistentFlags().StringVarP(&runAllNetbirdConfig, "netbird-config", "", "", "path to netbird config JSON")
	commandRunAll.PersistentFlags().BoolVarP(&runAllEnableNetbird, "enable-netbird", "", false, "start netbird engine alongside sing-box")
	mainCommand.AddCommand(commandRunAll)
}

func runAll() error {
	if len(configPaths) == 0 && len(configDirectories) == 0 {
		return E.New("-c config path required")
	}
	cleanup, err := runAllEngines(configPaths[0])
	if err != nil {
		return err
	}
	if cleanup == nil {
		return nil // idle, no config
	}
	defer cleanup()

	// /monitor/shutdown 优雅关闭支持:
	// Windows 上 Flutter 的 Process.kill 等价 TerminateProcess, 引擎拿不到
	// 清理机会 (TUN 适配器/路由残留)。Flutter stop() 先 POST /monitor/shutdown,
	// 这里关闭 stopCh 让 runAll 走与信号退出完全相同的 cleanup() 路径。
	stopCh := make(chan struct{})
	monitor.SetShutdownHandler(func() error {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
		return nil
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
		log.Info("received signal, stopping")
	case <-stopCh:
		log.Info("received shutdown request, stopping")
	}
	return nil
}

// runAllEngines starts netbird engine (if enabled), reads/injects config,
// and creates sing-box. Blocks until stopCh receives or sing-box exits.
// Returns a cleanup function (nil on setup failure).
func runAllEngines(cfgPath string) (func(), error) {
	t0 := time.Now()
	var nbEngine *netbird_integration.Engine

	if runAllEnableNetbird {
		nbCfg := buildNetbirdConfig(cfgPath)
		rawConfig, err := os.ReadFile(cfgPath)
		if err != nil {
			log.Warn("read config: ", err)
			return nil, nil
		}
		result, err := netbird_integration.StartAll(nbCfg, rawConfig)
		if err != nil {
			log.Warn("netbird start: ", err)
		}
		if result != nil {
			nbEngine = result.Engine
			if result.ModifiedConfig != nil {
				tmpPath := cfgPath + ".nb-tmp.json"
				if err := os.WriteFile(tmpPath, result.ModifiedConfig, 0644); err != nil {
					return nil, E.Cause(err, "write temp config")
				}
				defer os.Remove(tmpPath)
				configPaths = []string{tmpPath}
				log.Info(fmt.Sprintf("netbird: injected config written (t=%.1fs)", time.Since(t0).Seconds()))
			}
		}
	} else {
		log.Info("netbird disabled, running sing-box only")
	}

	// Ensure configPaths includes cfgPath for readConfig()
	if len(configPaths) == 0 {
		configPaths = []string{cfgPath}
	}

	optionsList, err := readConfig()
	if err != nil {
		return nil, E.Cause(err, "read config")
	}
	var options option.Options
	if len(optionsList) > 0 {
		options = optionsList[0].options
	}

	t1 := time.Now()
	instance, instanceCancel, err := create(options)
	if err != nil {
		return nil, err
	}
	_ = instance
	log.Info(fmt.Sprintf("sing-box started (t=%.1fs)", time.Since(t1).Seconds()))

	cleanup := func() {
		if nbEngine != nil {
			if err := nbEngine.Stop(); err != nil {
				log.Error("netbird stop: ", err)
			}
		}
		instanceCancel()
		log.Info("all engines stopped")
	}
	return cleanup, nil
}

func buildNetbirdConfig(cfgPath string) *netbird_integration.Config {
	// Derive data directory from the sing-box config file's location
	dataDir := filepath.Dir(cfgPath)
	cfg := &netbird_integration.Config{
		DeviceName:    envOrDefault("NB_DEVICE_NAME", "sing-netbird"),
		SetupKey:      os.Getenv("NB_SETUP_KEY"),
		JWTToken:      os.Getenv("NB_JWT_TOKEN"),
		ManagementURL: envOrDefault("NB_MANAGEMENT_URL", "https://api.netbird.io:443"),
		LogLevel:      envOrDefault("NB_LOG_LEVEL", "info"),
		DataDir:       dataDir,
	}
	// Try reading from --netbird-config flag, then from DataDir/netbird-config.json
	nbCfgPath := runAllNetbirdConfig
	if nbCfgPath == "" {
		nbCfgPath = filepath.Join(cfg.DataDir, "netbird-config.json")
	}
	if data, err := os.ReadFile(nbCfgPath); err == nil {
		var fileCfg netbird_integration.Config
		if err := json.Unmarshal(data, &fileCfg); err != nil {
			log.Warn("parse --netbird-config: ", err)
			return cfg
		}
		if fileCfg.SetupKey != "" {
			cfg.SetupKey = fileCfg.SetupKey
		}
		if fileCfg.JWTToken != "" {
			cfg.JWTToken = fileCfg.JWTToken
		}
		if fileCfg.ManagementURL != "" {
			cfg.ManagementURL = fileCfg.ManagementURL
		}
		if fileCfg.DeviceName != "" {
			cfg.DeviceName = fileCfg.DeviceName
		}
		if fileCfg.LogLevel != "" {
			cfg.LogLevel = fileCfg.LogLevel
		}
	}
	return cfg
}
