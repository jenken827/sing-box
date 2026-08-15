//go:build with_netbird

package netbird_integration

import (
	"strings"
	"testing"
)

// TestAddrsSnapshot verifies the network fingerprint helper used by
// watchNetworkChanges: non-empty, "iface=addr" pairs, stable across calls
// when the network has not changed.
func TestAddrsSnapshot(t *testing.T) {
	first := addrsSnapshot()
	if first == "" {
		t.Fatal("addrsSnapshot returned empty (interface enumeration failed?)")
	}
	for _, part := range strings.Split(first, ",") {
		if !strings.Contains(part, "=") {
			t.Fatalf("snapshot part %q missing '=' separator (want iface=addr)", part)
		}
	}
	// Stable when nothing changed.
	second := addrsSnapshot()
	if first != second {
		t.Fatalf("snapshot not stable: %q != %q", first, second)
	}
}
