//go:build android

package netbird_integration

import nbnet "github.com/netbirdio/netbird/client/net"

// SetAndroidProtectFn 注册 Android 平台的 socket protect 回调(VpnService.protect)。
//
// 嵌入模式下 netbird 控制面 socket 由 client/net 的 ControlProtectSocket 创建时
// 调用该回调, 使 socket 绕过 VpnService TUN 直走物理网络——与 Linux fwmark /
// Windows IP_UNICAST_IF 同层。宿主(Kotlin VpnService 就绪后经 libbox)注入。
func SetAndroidProtectFn(fn func(fd int32) bool) {
	nbnet.SetAndroidProtectSocketFn(fn)
}
