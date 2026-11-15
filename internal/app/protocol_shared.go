package app

import (
	"fmt"
	"net"
	"strings"
)

// ClientRevocationConfig controls optional RFC 5280 leaf certificate CRL checks.
// "off" does not disable mTLS or peer-identity authorization.
type ClientRevocationConfig struct {
	Mode    string `yaml:"mode,omitempty"` // off (default), crl
	CRLFile string `yaml:"crl_file,omitempty"`
}

const (
	stickySessionHeader = "X-Mqvpn-Sticky-Voip"
	trafficRoleHeader   = "X-Mqvpn-Traffic-Role"
)

// SNI must be an unambiguous DNS hostname, not an IP literal or wildcard.
// An IP-literal HTTPS URL cannot reliably transmit SNI for demultiplexing.
func validateSNI(s string) error {
	// Go 1.27 CutLast checks for a non-empty terminal DNS label without
	// allocating a temporary slice or assuming that any dot is valid.
	_, topLevel, qualified := strings.CutLast(s, ".")
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil || !qualified || topLevel == "" {
		return fmt.Errorf("invalid server_name %q: use a DNS hostname, not an IP", s)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS server_name %q", s)
		}
		for _, b := range []byte(label) {
			if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
				continue
			}
			return fmt.Errorf("invalid DNS server_name %q", s)
		}
	}
	return nil
}

func hasHeaderToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
