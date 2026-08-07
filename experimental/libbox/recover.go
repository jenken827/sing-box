package libbox

import (
	"fmt"
	"runtime"
)

// recoverError catches panics in gomobile-exported functions and converts
// them to Go errors. Without this, a panic in Go code called via JNI will
// crash the entire Android process (SIGABRT) instead of being caught as a
// Java exception.
func recoverError(err *error) {
	if r := recover(); r != nil {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		msg := fmt.Sprintf("panic recovered: %v\n%s", r, buf[:n])
		writeMarker(msg)
		*err = fmt.Errorf("panic: %v", r)
	}
}
