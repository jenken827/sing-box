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

// NetbirdBridgeTCP starts an overlay→local TCP bridge on the given port.
// port is the overlay port to listen on; target is the local host:port to
// forward to (e.g. "127.0.0.1:8022"). Returns an error string on failure,
// empty string on success. Idempotent per port.
func NetbirdBridgeTCP(port int, target string) (errStr string) {
	err := netbirdBridgeTCP(port, target)
	if err != nil {
		writeMarker("NetbirdBridgeTCP FAILED: " + err.Error())
		return err.Error()
	}
	writeMarker("NetbirdBridgeTCP OK: :" + strconv.Itoa(port) + " → " + target)
	return ""
}

func netbirdBridgeTCP(port int, target string) (retErr error) {
	defer recoverError(&retErr)
	_, err := netbird_integration.BridgeTCP(port, target)
	return err
}

// NetbirdStopBridge stops an active overlay→local TCP bridge.
func NetbirdStopBridge(port int) (errStr string) {
	err := netbirdStopBridge(port)
	if err != nil {
		writeMarker("NetbirdStopBridge FAILED: " + err.Error())
		return err.Error()
	}
	writeMarker("NetbirdStopBridge OK: :" + strconv.Itoa(port))
	return ""
}

func netbirdStopBridge(port int) (retErr error) {
	defer recoverError(&retErr)
	return netbird_integration.StopBridge(port)
}
