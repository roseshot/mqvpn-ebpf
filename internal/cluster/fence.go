// Package cluster contains node-count-independent, local fail-closed guards
// for ownership records issued by a future quorum-backed HA control plane.
//
// This package is NOT a consensus implementation or a distributed lease
// allocator. In particular, Apply must only consume authenticated, committed
// records from an external linearizable store; callers must not invent epochs.
package cluster

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	Tenant string
	ID     string
}

// Record describes one quorum-issued ownership epoch. OwnerNode empty means
// that the prior epoch was fenced, not that another Server may take ownership.
// MembershipRevision binds observations to a committed membership generation.
type Record struct {
	ClusterID          string
	Peer               Peer
	OwnerNode          string
	Epoch              uint64
	MembershipRevision uint64
	TunnelIP           netip.Addr
	ValidUntil         time.Time
}

// Fence is a local verification barrier. It keeps tombstones (epoch numbers)
// even after revocation so a late or replayed owner record cannot resurrect.
// It never mints an epoch, elects an owner, or contacts another node.
type Fence struct {
	mu                 sync.RWMutex
	clusterID          string
	localNode          string
	maxTTL             time.Duration
	membershipRevision uint64
	members            map[string]struct{}
	records            map[Peer]Record
}

func NewFence(clusterID, localNode string, maxTTL time.Duration) (*Fence, error) {
	if !validID(clusterID) || !validID(localNode) {
		return nil, errors.New("cluster ID and local node ID must be nonempty, stable identifiers")
	}
	if maxTTL < time.Second || maxTTL > 2*time.Minute {
		return nil, errors.New("ownership maxTTL must be between 1s and 2m")
	}
	return &Fence{
		clusterID: clusterID, localNode: localNode, maxTTL: maxTTL,
		members: make(map[string]struct{}), records: make(map[Peer]Record),
	}, nil
}

func validID(s string) bool {
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// SetMembers consumes a quorum-committed membership list. The number of
// Servers is independent from the number of voters in the consensus backend.
// Replays of an identical generation are idempotent; conflicts and rollback
// are rejected. A removed owner is immediately fenced locally, including
// after that node ID later rejoins with the same spelling.
func (f *Fence) SetMembers(clusterID string, revision uint64, nodeIDs []string) error {
	if clusterID != f.clusterID {
		return errors.New("membership belongs to another cluster")
	}
	if revision == 0 || len(nodeIDs) < 2 {
		return errors.New("HA membership requires a positive revision and at least two Servers")
	}
	next := make(map[string]struct{}, len(nodeIDs))
	for _, node := range nodeIDs {
		if !validID(node) {
			return fmt.Errorf("invalid Server node ID %q", node)
		}
		if _, exists := next[node]; exists {
			return fmt.Errorf("duplicate Server node ID %q", node)
		}
		next[node] = struct{}{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if revision < f.membershipRevision {
		return errors.New("stale cluster membership revision")
	}
	if revision == f.membershipRevision {
		if maps.Equal(next, f.members) {
			return nil
		}
		return errors.New("conflicting cluster membership at the same revision")
	}
	for peer, old := range f.records {
		if old.OwnerNode == "" {
			continue
		}
		if _, present := next[old.OwnerNode]; !present {
			old.OwnerNode = ""
			old.TunnelIP = netip.Addr{}
			old.ValidUntil = time.Time{}
			f.records[peer] = old
		}
	}
	f.members = next
	f.membershipRevision = revision
	return nil
}

// Apply observes an externally authorized record. A transfer from node A to
// B MUST pass through a separate, higher-epoch tombstone before B can acquire
// the peer. New epochs require quorum CAS and old-node ingress/egress fencing
// outside this package. Neither an expired lease nor membership change alone
// grants new ownership.
func (f *Fence) Apply(next Record, now time.Time) error {
	if next.ClusterID != f.clusterID {
		return errors.New("owner record belongs to another cluster")
	}
	if !validID(next.Peer.Tenant) || !validID(next.Peer.ID) || next.Epoch == 0 {
		return errors.New("invalid tenant, peer or owner epoch")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.membershipRevision == 0 || next.MembershipRevision != f.membershipRevision {
		return errors.New("ownership record does not match committed membership revision")
	}
	if next.OwnerNode == "" {
		if next.TunnelIP.IsValid() || !next.ValidUntil.IsZero() {
			return errors.New("fence tombstone must not carry an IP lease or expiry")
		}
	} else {
		if !validID(next.OwnerNode) {
			return errors.New("invalid owner node identity")
		}
		if _, present := f.members[next.OwnerNode]; !present {
			return errors.New("ownership record names a nonmember Server")
		}
		ip := next.TunnelIP.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return errors.New("ownership record requires a valid unicast tunnel IP")
		}
		next.TunnelIP = ip
		if !next.ValidUntil.After(now) || next.ValidUntil.After(now.Add(f.maxTTL)) {
			return errors.New("owner lease is expired or exceeds maximum TTL")
		}
	}
	if previous, exists := f.records[next.Peer]; exists {
		if next.Epoch < previous.Epoch {
			return errors.New("stale owner epoch")
		}
		if next.Epoch == previous.Epoch {
			if previous.OwnerNode == "" || next.OwnerNode != previous.OwnerNode ||
				next.TunnelIP != previous.TunnelIP || !now.Before(previous.ValidUntil) ||
				!next.ValidUntil.After(previous.ValidUntil) {
				return errors.New("same owner epoch may only extend a live identical lease")
			}
		} else if previous.OwnerNode != "" && next.OwnerNode != "" &&
			(previous.OwnerNode != next.OwnerNode || previous.TunnelIP != next.TunnelIP) {
			return errors.New("owner transfer or tunnel IP change requires an intervening fence tombstone")
		}
	}
	if next.OwnerNode != "" {
		for peer, current := range f.records {
			if peer != next.Peer && peer.Tenant == next.Peer.Tenant &&
				current.OwnerNode != "" && current.TunnelIP == next.TunnelIP {
				return fmt.Errorf("tunnel IP %s is already leased to peer %s", next.TunnelIP, peer.ID)
			}
		}
	}
	f.records[next.Peer] = next
	return nil
}

// Allowed is the last local ingress/egress authorization check. It fails
// closed for unknown members/peers, revoked or expired leases, stale epochs,
// incorrect IPs, and nodes excluded by a new membership generation.
func (f *Fence) Allowed(peer Peer, epoch uint64, tunnelIP netip.Addr, now time.Time) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, member := f.members[f.localNode]; !member {
		return false
	}
	record, found := f.records[peer]
	return found && record.OwnerNode == f.localNode && record.Epoch == epoch &&
		record.TunnelIP == tunnelIP.Unmap() && now.Before(record.ValidUntil)
}

// Revision exposes only the locally observed membership generation, never a
// claim that the backing consensus quorum is currently reachable.
func (f *Fence) Revision() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.membershipRevision
}
