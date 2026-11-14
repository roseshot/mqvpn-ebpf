//go:build linux

package dnspush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var interfaceDNSCounter atomic.Uint64

// resolvconf is an interface-aware DNS aggregator (openresolv or the
// resolvconf package). Linux has no kernel setting for interface DNS:
// this backend registers only the VPN interface with the host resolver.
// A unique per-session key avoids overwriting an administrator's entries.
type interfaceResolverLease struct {
	id         string
	executable string
	run        resolvconfRunner
}

type resolvconfRunner func(string, []string, []byte) error

func runResolvconf(executable string, args []string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if len(message) > 400 {
			message = message[:400]
		}
		return fmt.Errorf("resolvconf %v: %w (%s)", args, err, message)
	}
	return nil
}

func applyInterfaceResolver(ifname string, servers []netip.Addr) (*Lease, error) {
	if _, err := net.InterfaceByName(ifname); err != nil {
		return nil, fmt.Errorf("fallback DNS interface %q: %w", ifname, err)
	}
	exe, err := exec.LookPath("resolvconf")
	if err != nil {
		return nil, fmt.Errorf("systemd-resolved is not running and resolvconf is not installed: %w", err)
	}
	return applyWithResolvconf(ifname, servers, exe, runResolvconf)
}

func applyWithResolvconf(ifname string, servers []netip.Addr, executable string, runner resolvconfRunner) (*Lease, error) {
	if ifname == "" || strings.HasPrefix(ifname, "-") || strings.ContainsAny(ifname, "/\n\r\t ") {
		return nil, errors.New("invalid resolvconf interface name")
	}
	// resolvconf accepts an interface.source name. Each Client attempt
	// owns a distinct source and deletes only that entry at shutdown.
	id := ifname + ".mqvpn-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(interfaceDNSCounter.Add(1), 10)
	var b strings.Builder
	for _, ip := range servers {
		b.WriteString("nameserver ")
		b.WriteString(ip.String())
		b.WriteByte('\n')
	}
	if err := runner(executable, []string{"-a", id}, []byte(b.String())); err != nil {
		// -a might fail after a partial write; always attempt cleanup.
		rollback := runner(executable, []string{"-d", id}, nil)
		if rollback != nil {
			return nil, errors.Join(fmt.Errorf("register VPN interface DNS: %w", err),
				fmt.Errorf("%w: remove partial resolvconf entry %q: %v", ErrCleanup, id, rollback))
		}
		return nil, fmt.Errorf("register VPN interface DNS: %w", err)
	}
	return &Lease{fallback: &interfaceResolverLease{id: id, executable: executable, run: runner}}, nil
}

func (l *interfaceResolverLease) Close() error {
	if err := l.run(l.executable, []string{"-d", l.id}, nil); err != nil {
		return fmt.Errorf("%w: deregister VPN interface DNS %q: %v", ErrCleanup, l.id, err)
	}
	return nil
}
