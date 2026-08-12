//go:build with_netbird && !linux

package netbird_integration

// SetupKernelRoute is a no-op on non-Linux platforms. Kernel-TUN mode is
// Linux-only (netbird creates a real wt0 interface there); Windows/Android
// always use the userspace netstack path where this route is unnecessary.
func SetupKernelRoute(networkCIDR string) (func(), error) {
	return func() {}, nil
}
