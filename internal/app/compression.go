package app

import "fmt"

// Mqvpn-Compression is authenticated inside TLS and scoped to a single
// CONNECT-ETHERNET session. Silence means legacy uncompressed frames.
// No compressor state or dictionaries span packets or authenticated peers.
const (
	compressionHeader = "Mqvpn-Compression"
	compressionZstd   = "zstd-v1"
)

func acceptCompression(requested string) bool {
	return requested == compressionZstd && localCompressionAvailable()
}

func negotiatedCompression(response string, advertised bool) (bool, error) {
	switch response {
	case "":
		return false, nil // Older or CPU-limited peer: safe fallback.
	case compressionZstd:
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
