package cluster

import (
	"context"
	"errors"
	"fmt"
)

// LocalProbe is executed on the Server that owns the resource. Callers may
// supply probes for the configured QUIC/TCP listeners, TUN interfaces, WAN
// paths, local forwarding/routing and locally loaded PKI/CRLs. No ClusterStore
// call or cross-node status replication is needed to inspect these resources.
type LocalProbe struct {
	Name  string
	Check func(context.Context) error
}

// CheckNodeLocal evaluates only node-owned runtime facts. The caller selects
// required probes for the enabled instances and transport modes; missing or
// invalid probe definitions fail closed. This is not authorization to allocate
// an IP address, elect a peer owner or advertise shared cluster policy.
func CheckNodeLocal(ctx context.Context, probes []LocalProbe) error {
	if len(probes) == 0 {
		return fmt.Errorf("%w: no local health probes registered", ErrNotReady)
	}
	seen := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validID(probe.Name) || probe.Check == nil {
			return fmt.Errorf("%w: invalid local probe", ErrNotReady)
		}
		if _, exists := seen[probe.Name]; exists {
			return fmt.Errorf("%w: duplicate local probe %q", ErrNotReady, probe.Name)
		}
		seen[probe.Name] = struct{}{}
		if err := probe.Check(ctx); err != nil {
			return fmt.Errorf("%w: local probe %s: %w", ErrNotReady, probe.Name, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrNotReady, err)
	}
	return nil
}
