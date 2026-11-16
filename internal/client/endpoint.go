package client

import (
	"errors"
	"fmt"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// endpoint separates the physical UDP/TCP destination from its
// authenticated tenant identity. A pinned connect_ip never changes SNI.
type endpoint struct {
	dialAddress string
	serverName  string
	requestURL  string
}

// planClientEndpoint accepts exactly one configuration model:
// server = tenant DNS name[:port], path = optional canonical CONNECT path,
// connect_ip = optional literal underlay destination.
func planClientEndpoint(server, path, connectIP string) (endpoint, error) {
	if server == "" || strings.ContainsAny(server, "/?#@\\%") || strings.Contains(server, "://") {
		return endpoint{}, errors.New("server must be an authenticated DNS hostname[:port] (use path separately)")
	}
	// An unbracketed IPv6 literal has no port; otherwise use the
	// standard URL authority representation with bracketed IPv6.
	if ip, err := netip.ParseAddr(server); err == nil && ip.Is6() {
		server = "[" + ip.String() + "]"
	}
	u, err := url.Parse("https://" + server)
	if err != nil || u.Host == "" || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return endpoint{}, errors.New("server must be a DNS hostname[:port]")
	}
	host := strings.ToLower(u.Hostname())
	if err := validateClientIdentity(host); err != nil {
		return endpoint{}, err
	}
	if strings.HasSuffix(u.Host, ":") {
		return endpoint{}, errors.New("server port cannot be empty")
	}
	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return endpoint{}, fmt.Errorf("invalid server port %q", port)
		}
	} else {
		port = "443"
	}
	if path == "" {
		path = vpnwire.DefaultPath
	}
	if err := vpnwire.ValidateMASQUEPath(path); err != nil {
		return endpoint{}, err
	}
	dialHost := host
	if connectIP != "" {
		ip, err := netip.ParseAddr(connectIP)
		if err != nil || !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return endpoint{}, fmt.Errorf("invalid connect_ip %q: expected unicast IP literal", connectIP)
		}
		dialHost = ip.String()
	}
	authority := net.JoinHostPort(host, port)
	return endpoint{
		dialAddress: net.JoinHostPort(dialHost, port),
		serverName:  host,
		requestURL:  (&url.URL{Scheme: "https", Host: authority, Path: path}).String(),
	}, nil
}

// A literal IP is a TLS verification identity only when the peer presents
// a matching x509 IP SAN; Go deliberately omits SNI for IP literals.
func validateClientIdentity(host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("invalid server IP identity %q", host)
		}
		return nil
	}
	if err := vpnwire.ValidateSNI(host); err != nil {
		return fmt.Errorf("server DNS identity: %w", err)
	}
	return nil
}
