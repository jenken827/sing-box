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

	// 同一进程内重复启动(Android stop→start、异常路径二次 start): 必须先
	// 停掉旧引擎。否则旧引擎仍持有同一 WireGuard key / mgmt 连接 / 状态文件,
	// 新引擎再拉一个同身份实例并存互踩 → netbird 隧道不可用(stop→start 必现)。
	if netbirdEngine != nil {
		writeMarker("NetbirdStartAll: stopping previous engine (stop→start)")
		netbirdEngine.Shutdown()
		netbirdEngine = nil
	}

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

	// 嵌入模式下 netbird 控制面 socket 需要绕过 VpnService TUN:
	// 把 Kotlin 注入的 Protector(VpnService.protect) 桥接给 netbird 引擎。
	if androidProtector != nil {
		netbird_integration.SetAndroidProtectFn(func(fd int32) bool {
			return androidProtector.Protect(fd)
		})
		writeMarker("NetbirdStartAll: android protect fn registered")
	} else {
		writeMarker("NetbirdStartAll: no android protector (netbird control-plane will use VpnService TUN)")
	}

	result, err := netbird_integration.StartAll(cfg, []byte(singBoxConfig))
	if err != nil {
		writeMarker("NetbirdStartAll: StartAll FAILED: " + err.Error())
		return singBoxConfig, err
	}

	if result.Engine != nil {
		netbirdEngine = result.Engine
		// 异步启动: 引擎实例已创建, 但连接/启动发生在后台 goroutine —
		// 这里不代表启动成功(无网络时引擎会在后台重试/失败)。真实状态
		// 看 nb-engine.log 的 "engine started"/"engine failed to start"。
		writeMarker("NetbirdStartAll: engine instance created (async start, status in nb-engine.log)")
	} else if result.EngineErr != "" {
		writeMarker("NetbirdStartAll: engine failed to start: " + result.EngineErr)
	} else {
		writeMarker("NetbirdStartAll: no credentials, engine not started")
	}

	return string(result.ModifiedConfig), nil
}

// NetbirdStop stops the netbird engine and clears the integration state
// (global nb-out/DNS client, tunnel DNS address, network watcher).
//
// Must be called when the host service (Android VpnService) is torn down:
// BoxService.stop() only closes the sing-box service — without this the
// embed client keeps its WireGuard key / management connection / state
// files alive, and the next start pulls up a second engine with the same
// identity, which fights the first one (stop→start leaves netbird dead).
func NetbirdStop() {
	writeMarker("NetbirdStop ENTERED")
	if netbirdEngine != nil {
		netbirdEngine.Shutdown()
		netbirdEngine = nil
		writeMarker("NetbirdStop: engine stopped")
	} else {
		writeMarker("NetbirdStop: no engine running")
	}
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
