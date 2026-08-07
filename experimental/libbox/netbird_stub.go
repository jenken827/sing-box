//go:build !with_netbird

package libbox

import E "github.com/sagernet/sing/common/exceptions"

// NetbirdStartAll — stub when netbird is not compiled in.
func NetbirdStartAll(netbirdConfigJSON string, singBoxConfig string) (string, error) {
	return singBoxConfig, E.New("netbird not compiled in (build without with_netbird tag)")
}
