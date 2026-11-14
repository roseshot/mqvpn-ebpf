//go:build linux

package dnspush

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"
)

// ErrCleanup means the previous resolver state could not be restored. The
// Client reconnect supervisor must not start another network session.
var ErrCleanup = errors.New("VPN DNS configuration cleanup failed")

// errResolvedUnavailable permits the per-interface resolvconf fallback
// only when systemd-resolved or its D-Bus transport is genuinely absent.
// Permission errors and incorrect per-link state must not be bypassed.
var errResolvedUnavailable = errors.New("systemd-resolved unavailable")

const (
	resolvedService = "org.freedesktop.resolve1"
	managerPath     = dbus.ObjectPath("/org/freedesktop/resolve1")
	managerIface    = "org.freedesktop.resolve1.Manager"
	linkIface       = "org.freedesktop.resolve1.Link"
)

// D-Bus types are defined by systemd-resolved. DNSEx preserves custom
// port/TLS identity for a pre-existing TUN instead of losing that metadata.
type dnsRecord struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}
type domainRecord struct {
	Domain      string
	RoutingOnly bool
}
type linkState struct {
	DNS          []dnsRecord
	Domains      []domainRecord
	DefaultRoute bool
}

type resolverBackend interface {
	Read() (linkState, error)
	SetDNS([]dnsRecord) error
	SetDomains([]domainRecord) error
	SetDefaultRoute(bool) error
	Close() error
}

type resolvedBackend struct {
	conn *dbus.Conn
	link dbus.BusObject
}

func openResolver(ifname string) (resolverBackend, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("DNS TUN %q: %w", ifname, err)
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("%w: system D-Bus: %v", errResolvedUnavailable, err)
	}
	var path dbus.ObjectPath
	err = conn.Object(resolvedService, managerPath).Call(managerIface+".GetLink", 0, int32(iface.Index)).Store(&path)
	if err != nil {
		_ = conn.Close()
		var dbusErr *dbus.Error
		if errors.As(err, &dbusErr) {
			switch dbusErr.Name {
			case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner":
				return nil, fmt.Errorf("%w: %v", errResolvedUnavailable, err)
			}
		}
		return nil, fmt.Errorf("query systemd-resolved VPN TUN %q: %w", ifname, err)
	}
	return &resolvedBackend{conn: conn, link: conn.Object(resolvedService, path)}, nil
}

func (r *resolvedBackend) Read() (linkState, error) {
	var state linkState
	if err := r.link.StoreProperty(linkIface+".DNSEx", &state.DNS); err != nil {
		return linkState{}, fmt.Errorf("read existing per-link DNSEx: %w", err)
	}
	if err := r.link.StoreProperty(linkIface+".Domains", &state.Domains); err != nil {
		return linkState{}, fmt.Errorf("read existing per-link DNS domains: %w", err)
	}
	if err := r.link.StoreProperty(linkIface+".DefaultRoute", &state.DefaultRoute); err != nil {
		return linkState{}, fmt.Errorf("read existing per-link DNS default route: %w", err)
	}
	return state, nil
}
func (r *resolvedBackend) SetDNS(servers []dnsRecord) error {
	if servers == nil {
		servers = []dnsRecord{}
	}
	return r.link.Call(linkIface+".SetDNSEx", 0, servers).Err
}
func (r *resolvedBackend) SetDomains(domains []domainRecord) error {
	if domains == nil {
		domains = []domainRecord{}
	}
	return r.link.Call(linkIface+".SetDomains", 0, domains).Err
}
func (r *resolvedBackend) SetDefaultRoute(enabled bool) error {
	return r.link.Call(linkIface+".SetDefaultRoute", 0, enabled).Err
}
func (r *resolvedBackend) Close() error { return r.conn.Close() }

// Lease owns exactly one authenticated VPN session's resolver settings.
// Only the three DNS fields touched by this module are restored, and only
// if they still match our last applied state (to avoid overwriting another
// network manager's intervening changes).
type Lease struct {
	backend         resolverBackend
	fallback        *interfaceResolverLease
	before, applied linkState
	mu              sync.Once
	closeErr        error
}

func Apply(tunName string, servers []netip.Addr) (*Lease, error) {
	if len(servers) == 0 {
		return nil, nil
	}
	if _, err := Parse(addressStrings(servers)); err != nil {
		return nil, err
	}
	return applyWithResolvers(tunName, servers, openResolver, applyInterfaceResolver)
}

// Resolver failover is intentionally narrow: do not hide an authorization
// error from an active systemd-resolved daemon by using a second backend.
func applyWithResolvers(tunName string, servers []netip.Addr, openResolved func(string) (resolverBackend, error), openInterface func(string, []netip.Addr) (*Lease, error)) (*Lease, error) {
	b, err := openResolved(tunName)
	if err != nil {
		if errors.Is(err, errResolvedUnavailable) {
			return openInterface(tunName, servers)
		}
		return nil, err
	}
	return applyWithBackend(b, servers)
}

func addressStrings(servers []netip.Addr) []string {
	items := make([]string, len(servers))
	for i, ip := range servers {
		items[i] = ip.String()
	}
	return items
}

func toRecords(servers []netip.Addr) []dnsRecord {
	out := make([]dnsRecord, 0, len(servers))
	for _, ip := range servers {
		family := int32(syscall.AF_INET6)
		if ip.Is4() {
			family = syscall.AF_INET
		}
		out = append(out, dnsRecord{Family: family, Address: ip.AsSlice(), Port: 53})
	}
	return out
}

func addRootDomain(domains []domainRecord) []domainRecord {
	copyDomains := append([]domainRecord(nil), domains...)
	for _, entry := range copyDomains {
		if entry.Domain == "." && entry.RoutingOnly {
			return copyDomains
		}
	}
	return append(copyDomains, domainRecord{Domain: ".", RoutingOnly: true})
}

func applyWithBackend(b resolverBackend, servers []netip.Addr) (*Lease, error) {
	before, err := b.Read()
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	// Changing link DNS is a transaction from the Client's viewpoint. A
	// partial failure is rolled back before a new reconnect is permitted.
	if err := b.SetDNS(toRecords(servers)); err != nil {
		return nil, rollbackFailure(b, before, fmt.Errorf("set VPN link DNS: %w", err))
	}
	if err := b.SetDomains(addRootDomain(before.Domains)); err != nil {
		return nil, rollbackFailure(b, before, fmt.Errorf("set VPN DNS ~. routing domain: %w", err))
	}
	if err := b.SetDefaultRoute(true); err != nil {
		return nil, rollbackFailure(b, before, fmt.Errorf("set VPN DNS default route: %w", err))
	}
	applied, err := b.Read()
	if err != nil {
		return nil, rollbackFailure(b, before, fmt.Errorf("verify VPN DNS settings: %w", err))
	}
	// An external network manager might have refused/overwritten the values
	// without signalling an error. Require the requested settings to appear.
	if !recordsEqual(applied.DNS, toRecords(servers)) ||
		!domainsEqual(applied.Domains, addRootDomain(before.Domains)) ||
		!applied.DefaultRoute {
		return nil, rollbackFailure(b, before, errors.New("VPN DNS settings not applied as requested"))
	}
	return &Lease{backend: b, before: before, applied: applied}, nil
}

func recordsEqual(a, b []dnsRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Family != b[i].Family || a[i].Port != b[i].Port || a[i].Name != b[i].Name ||
			!reflect.DeepEqual(a[i].Address, b[i].Address) {
			return false
		}
	}
	return true
}
func domainsEqual(a, b []domainRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func restore(b resolverBackend, s linkState) error {
	// Restore all three fields even if one operation fails. A failure is
	// fatal to reconnect because it leaves partially changed resolver state.
	return errors.Join(
		b.SetDomains(s.Domains),
		b.SetDefaultRoute(s.DefaultRoute),
		b.SetDNS(s.DNS),
	)
}
func rollbackFailure(b resolverBackend, original linkState, reason error) error {
	cleanupErr := restore(b, original)
	_ = b.Close()
	if cleanupErr != nil {
		return errors.Join(reason, fmt.Errorf("%w: restore DNS after partial setup: %v", ErrCleanup, cleanupErr))
	}
	return reason
}

func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Do(func() {
		if l.fallback != nil {
			l.closeErr = l.fallback.Close()
			return
		}
		defer func() { l.closeErr = errors.Join(l.closeErr, l.backend.Close()) }()
		current, err := l.backend.Read()
		if err != nil {
			l.closeErr = fmt.Errorf("%w: inspect link DNS before restore: %v", ErrCleanup, err)
			return
		}
		if !recordsEqual(current.DNS, l.applied.DNS) ||
			!domainsEqual(current.Domains, l.applied.Domains) ||
			current.DefaultRoute != l.applied.DefaultRoute {
			l.closeErr = fmt.Errorf("%w: link DNS changed by another manager; refusing to overwrite newer settings", ErrCleanup)
			return
		}
		if err := restore(l.backend, l.before); err != nil {
			l.closeErr = fmt.Errorf("%w: restore original VPN link DNS: %v", ErrCleanup, err)
		}
	})
	return l.closeErr
}
