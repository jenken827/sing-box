//go:build !android

package netbird_integration

// SetAndroidProtectFn is a no-op on non-Android platforms.
func SetAndroidProtectFn(fn func(fd int32) bool) {
}
