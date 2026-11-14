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
    return requested == compressionZstd
}

func negotiatedCompression(response string) (bool, error) {
    switch response {
    case "":
        return false, nil // older peer, safe fallback
    case compressionZstd:
        return true, nil
    default:
        return false, fmt.Errorf("unsupported VPN compression response %q", response)
    }
}
