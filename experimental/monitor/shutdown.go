// experimental/monitor/shutdown.go
package monitor

import (
	"errors"
	"sync"
	"time"
)

// /monitor/shutdown 端点支持:
//
// Windows 上 Dart 的 Process.kill 等价 TerminateProcess, 不会给引擎任何
// 清理机会 (TUN 适配器/路由/系统状态残留)。Flutter 端 stop() 先 POST
// /monitor/shutdown, 由 run-all 命令注册的回调触发完整的引擎清理
// (instanceCancel + netbird stop) 后正常退出。
//
// 注册时机: cmd/sing-box/cmd_run_all.go 的 runAll() 启动后调用
// SetShutdownHandler 注册真实关闭逻辑。

var (
	shutdownMu        sync.Mutex
	shutdownHandler   func() error
	shutdownTriggered bool
)

// SetShutdownHandler 注册引擎关闭回调 (幂等替换)。
func SetShutdownHandler(h func() error) {
	shutdownMu.Lock()
	shutdownHandler = h
	shutdownMu.Unlock()
}

// ShutdownHandlerRegistered 报告是否已注册关闭回调。
func ShutdownHandlerRegistered() bool {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	return shutdownHandler != nil
}

// TriggerShutdown 触发一次优雅关闭; 多次调用只生效一次。
// 回调延迟 ~150ms 执行, 确保 HTTP 响应先写回客户端 (引擎关闭时会关掉
// clash API server, 过早触发可能截断响应)。
func TriggerShutdown() error {
	shutdownMu.Lock()
	if shutdownTriggered {
		shutdownMu.Unlock()
		return nil
	}
	shutdownTriggered = true
	h := shutdownHandler
	shutdownMu.Unlock()
	if h == nil {
		return errors.New("no shutdown handler registered")
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = h()
	}()
	return nil
}
