//go:build with_netbird

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/experimental/netbird_integration"
	"github.com/sagernet/sing/common/json"

	"github.com/spf13/cobra"
)

var (
	netbirdConfigPath string
)

var commandNetbirdRun = &cobra.Command{
	Use:   "netbird-run",
	Short: "Run netbird engine (embedded)",
	Long: `Start the netbird engine as an embedded client.

Requires --netbird-config flag or NB_SETUP_KEY/NB_JWT_TOKEN env vars.

Netbird config JSON format:
  {
    "device_name":    "my-device",
    "setup_key":      "your-setup-key",
    "management_url": "https://api.netbird.io:443"
  }`,
	Run: func(cmd *cobra.Command, args []string) {
		runNetbird()
	},
}

var commandNetbirdStatus = &cobra.Command{
	Use:   "netbird-status",
	Short: "Show netbird engine status",
	Run: func(cmd *cobra.Command, args []string) {
		status := nbEngine.GetStatus()
		if status.Running {
			fmt.Println("netbird: running")
		} else {
			fmt.Println("netbird: stopped")
		}
	},
}

var nbEngine *netbird_integration.Engine

func init() {
	commandNetbirdRun.PersistentFlags().StringVarP(&netbirdConfigPath, "netbird-config", "", "", "path to netbird config JSON")
	mainCommand.AddCommand(commandNetbirdRun)
	mainCommand.AddCommand(commandNetbirdStatus)
}

func runNetbird() {
	var cfg *netbird_integration.Config

	if netbirdConfigPath != "" {
		log.Info("reading config from: ", netbirdConfigPath)
		data, err := os.ReadFile(netbirdConfigPath)
		if err != nil {
			log.Fatal("read config: ", err)
		}
		cfg = &netbird_integration.Config{}
		if err := json.Unmarshal(data, cfg); err != nil {
			log.Fatal("parse config: ", err)
		}
		log.Info("netbird config loaded: device=", cfg.DeviceName, " mgmt=", cfg.ManagementURL)
	} else {
		// Fallback: build config from env vars
		if os.Getenv("NB_SETUP_KEY") == "" && os.Getenv("NB_JWT_TOKEN") == "" {
			log.Warn("no config file (-c) and NB_SETUP_KEY/NB_JWT_TOKEN not set")
		}
		cfg = &netbird_integration.Config{
			DeviceName:    envOrDefault("NB_DEVICE_NAME", "sing-netbird"),
			SetupKey:      os.Getenv("NB_SETUP_KEY"),
			JWTToken:      os.Getenv("NB_JWT_TOKEN"),
			ManagementURL: envOrDefault("NB_MANAGEMENT_URL", "https://api.netbird.io:443"),
			LogLevel:      envOrDefault("NB_LOG_LEVEL", "info"),
		}
	}

	engine := netbird_integration.NewEngine(cfg)

	if err := engine.Start(); err != nil {
		log.Fatal(err)
	}

	nbEngine = engine
	log.Info("netbird engine started successfully")

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("received signal: ", sig)

	if err := engine.Stop(); err != nil {
		log.Error(err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
