package app

import (
	"fmt"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

const (
	framingHeader = "Mqvpn-Framing"
	framingValue  = l3.FramingVersion
)

// Fragmentation requires both peers to opt into the exact framing version.
// Missing headers preserve byte-for-byte legacy CONNECT-ETHERNET behavior.
func acceptFraming(request string) bool {
	return request == framingValue
}

func negotiatedFraming(response string, offered bool) (bool, error) {
	switch response {
	case "":
		return false, nil
	case framingValue:
		if !offered {
			return false, fmt.Errorf("unsolicited VPN fragment framing %q", response)
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported VPN fragment framing %q", response)
	}
}
