package libbox

// Protector 由宿主(Android Kotlin)注入: 对 socket fd 调用 VpnService.protect,
// 使该 socket 绕过 VpnService TUN 直走物理网络。用于 netbird 引擎的控制面
// socket(STUN/ICE/WireGuard)在嵌入模式下获得与 Linux fwmark / Windows
// IP_UNICAST_IF 同级的旁路。
type Protector interface {
	Protect(fd int32) bool
}

var androidProtector Protector

// SetProtector 注册 Android socket protector。Kotlin 在 VpnService 就绪后调用
// (VpnService.protect 依赖实例)。netbird 引擎启动前注册即可生效。
func SetProtector(p Protector) {
	androidProtector = p
}
