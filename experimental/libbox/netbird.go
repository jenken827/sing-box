//go:build with_netbird

package libbox

import (
	"strconv"

	"github.com/sagernet/sing-box/experimental/netbird_integration"
)

var (
	netbirdEngine *netbird_integration.Engine
)

// NetbirdStartAll takes netbird config JSON and sing-box config JSON,
// starts the netbird engine, syncs with management server, injects
// DNS/outbound/route rules into the sing-box config, and returns the
// modified sing-box config.
//
// If credentials are missing or incomplete, returns singBoxConfig unchanged.
func NetbirdStartAll(netbirdConfigJSON string, singBoxConfig string) (modified string, retErr error) {
	defer recoverError(&retErr)
	writeMarker("NetbirdStartAll ENTERED")
	writeMarker("NetbirdStartAll: nbConfig length=" + strconv.Itoa(len(netbirdConfigJSON)))

	cfg, err := netbird_integration.ParseConfig(netbirdConfigJSON)
	if err != nil {
		writeMarker("NetbirdStartAll: ParseConfig FAILED: " + err.Error())
		return singBoxConfig, err
	}

	// Inject basePath as DataDir if not already set (Android needs this for nb-state persistence)
	if cfg.DataDir == "" && sBasePath != "" {
		cfg.DataDir = sBasePath
		writeMarker("NetbirdStartAll: set DataDir=" + sBasePath)
	}

	result, err := netbird_integration.StartAll(cfg, []byte(singBoxConfig))
	if err != nil {
		writeMarker("NetbirdStartAll: StartAll FAILED: " + err.Error())
		return singBoxConfig, err
	}

	if result.Engine != nil {
		netbirdEngine = result.Engine
		writeMarker("NetbirdStartAll: engine started OK")
	} else {
		writeMarker("NetbirdStartAll: no credentials, engine not started")
	}

	return string(result.ModifiedConfig), nil
}
