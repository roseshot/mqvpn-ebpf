package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// clientEndpoint separates the QUIC UDP destination from its authenticated
// TLS identity. With multiple VPN tenants sharing one port, TLS SNI and the
// HTTP/3 :authority MUST identify the same tenant (and may differ from the
// literal IP used to dial the server).
type clientEndpoint struct {
	dialAddress string
	serverName string
	requestURL string
}

func planClientEndpoint(rawURL, connectIP, serverName string) (clientEndpoint, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil || u.Scheme != "https" || u.Opaque != "" ||
		u.Host == "" || u.Path == "" || u.User != nil || u.Fragment != "" ||
		u.RawQuery != "" {
		return clientEndpoint{}, errors.New("--url must be an https://host[:port]/path URL without query or fragment")
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return clientEndpoint{}, errors.New("--url must have an unambiguous DNS name or IP address")
	}
	if strings.HasSuffix(u.Host, ":") {
		return clientEndpoint{}, errors.New("empty --url UDP port")
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n <= 0 || n > 65535 {
			return clientEndpoint{}, fmt.Errorf("invalid --url UDP port %q", u.Port())
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	// net.ParseIP handles IPv4 and bracketed IPv6 URL literals. Other URL
	// hostnames must be valid server-side DNS SNI identities.
	urlIP := net.ParseIP(host)
	if serverName == "" {
		if urlIP != nil {
			return clientEndpoint{}, errors.New("IP URL requires --server-name DNS identity for TLS SNI and tenant routing")
		}
		serverName = host
	}
	serverName = strings.ToLower(serverName)
	if err := validateSNI(serverName); err != nil {
		return clientEndpoint{}, fmt.Errorf("--server-name: %w", err)
	}

	dialHost := host
	if connectIP != "" {
		override, err := netip.ParseAddr(connectIP)
		if err != nil || override.Zone() != "" || !override.IsValid() ||
			override.IsUnspecified() || override.IsMulticast() {
			return clientEndpoint{}, fmt.Errorf("invalid --connect-ip %q: expected unicast IP literal", connectIP)
		}
		if urlIP != nil {
			return clientEndpoint{}, errors.New("--connect-ip is redundant with an IP literal in --url")
		}
		dialHost = override.String()
	}
	// QUIC transport dials a literal IP when requested. The CONNECT
	// :authority always uses the authenticated domain, never the IP.
	authorityURL := *u
	authorityURL.Host = net.JoinHostPort(serverName, port)
	return clientEndpoint{
		dialAddress: net.JoinHostPort(dialHost, port),
		serverName: serverName,
		requestURL: authorityURL.String(),
	}, nil
}
