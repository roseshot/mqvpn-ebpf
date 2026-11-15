package session

import "fmt"

// Mqvpn-Compression is authenticated inside TLS and scoped to a single
// CONNECT-ETHERNET session. An absent header selects uncompressed frames.
// No compressor state or dictionaries span packets or authenticated peers.
const (
	CompressionHeader = "Mqvpn-Compression"
	CompressionZstd   = "zstd-v1"
)

func AcceptCompression(requested string) bool {
	return requested == CompressionZstd && LocalCompressionAvailable()
}

func NegotiatedCompression(response string, advertised bool) (bool, error) {
	switch response {
	case "":
		return false, nil // Older or CPU-limited peer: safe fallback.
	case CompressionZstd:
		if !advertised {
			// A slow Client must not enable compression just because a
			// Server returned a capability it never offered.
			return false, fmt.Errorf("server enabled zstd-v1 without client offer")
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported VPN compression response %q", response)
	}
}
