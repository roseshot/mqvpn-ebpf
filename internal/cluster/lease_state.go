package cluster

import (
	"fmt"
	"maps"
	"net/netip"
	"sync"
	"time"
)

// LeaseStateMachine applies a single ordered stream of committed lease
// operations. It enforces atomic (tenant, IP) uniqueness and per-peer epoch
// compare-and-swap independently from low-frequency policy snapshots.
//
// THIS IS NOT A CONSENSUS BACKEND. A production caller MUST execute commands
// only after quorum commit in a durable, authenticated Raft state machine.
// Direct calls on multiple Servers are NOT safe and must never be used for
// independent allocations or as proof of distributed ownership.
type LeaseStateMachine struct {
	mu         sync.Mutex
	clusterID  string
	maxTTL     time.Duration
	grace      time.Duration
	revision   uint64
	members    map[string]struct{}
	records    map[Peer]Record
	inUse      map[leaseIPKey]Peer
	holdPeer   map[Peer]time.Time
	holdIP     map[leaseIPKey]time.Time
	lastCommit time.Time
}

type leaseIPKey struct {
	tenant string
	ip     netip.Addr
}

// NewLeaseStateMachine creates an in-process deterministic command applier.
// The grace interval is a minimum additional delay AFTER the previous
// owner's ValidUntil before reuse. It MUST cover worst-case clock error and
// packet/route drain budgets; a real backend also needs external fencing.
func NewLeaseStateMachine(clusterID string, maxTTL, grace time.Duration) (*LeaseStateMachine, error) {
	if !validID(clusterID) || maxTTL < time.Second || maxTTL > 2*time.Minute ||
		grace < time.Second || grace > 2*time.Minute {
		return nil, fmt.Errorf("%w: invalid cluster ID, lease TTL or fencing grace", ErrInvalid)
	}
	return &LeaseStateMachine{
		clusterID: clusterID, maxTTL: maxTTL, grace: grace,
		members: make(map[string]struct{}), records: make(map[Peer]Record),
		inUse: make(map[leaseIPKey]Peer), holdPeer: make(map[Peer]time.Time),
		holdIP: make(map[leaseIPKey]time.Time),
	}, nil
}

// SetMembers installs one already-committed membership generation. Removing
// an owner requires an explicit committed Revoke first; expiry alone does
// not silently release IPs or resurrect owners on node rejoin.
func (s *LeaseStateMachine) SetMembers(revision uint64, members []string) error {
	next, err := memberSet(members)
	if err != nil || revision == 0 {
		return fmt.Errorf("%w: invalid membership generation: %v", ErrInvalid, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision < s.revision {
		return ErrConflict
	}
	if revision == s.revision {
		if maps.Equal(s.members, next) {
			return nil
		}
		return ErrConflict
	}
	for _, record := range s.records {
		if record.OwnerNode != "" {
			if _, ok := next[record.OwnerNode]; !ok {
				return fmt.Errorf("%w: revoke live owner %s before membership removal", ErrConflict, record.OwnerNode)
			}
		}
	}
	s.members = next
	s.revision = revision
	return nil
}

// Claim grants one new ownership epoch after a committed absent/tombstoned
// state. expectedEpoch=0 means a first-ever claim; otherwise it MUST exactly
// match the previously committed tombstone epoch. There is no implicit
// takeover on timeout: first Revoke, then wait until old expiry + grace.
func (s *LeaseStateMachine) Claim(peer Peer, owner string, ip netip.Addr, expectedEpoch uint64, until, at time.Time) (Record, error) {
	ip = ip.Unmap()
	if !validPeerIdentity(peer.Tenant) || !validPeerIdentity(peer.ID) ||
		!validID(owner) || !validLeaseIP(ip) ||
		!validLeaseTime(at, until, s.maxTTL) {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCommitTime(at); err != nil {
		return Record{}, err
	}
	if s.revision == 0 {
		return Record{}, ErrMissing
	}
	if _, ok := s.members[owner]; !ok {
		return Record{}, fmt.Errorf("%w: unknown Server owner", ErrInvalid)
	}
	old, exists := s.records[peer]
	if !exists && expectedEpoch != 0 {
		return Record{}, ErrConflict
	}
	if exists && (old.OwnerNode != "" || old.Epoch != expectedEpoch) {
		return Record{}, ErrConflict
	}
	if expectedEpoch == ^uint64(0) {
		return Record{}, fmt.Errorf("%w: owner epoch overflow", ErrInvalid)
	}
	if at.Before(s.holdPeer[peer]) {
		return Record{}, fmt.Errorf("%w: previous owner fencing grace has not elapsed", ErrConflict)
	}
	key := leaseIPKey{tenant: peer.Tenant, ip: ip}
	if at.Before(s.holdIP[key]) {
		return Record{}, fmt.Errorf("%w: tunnel IP is still fenced", ErrConflict)
	}
	if current, found := s.inUse[key]; found && current != peer {
		return Record{}, fmt.Errorf("%w: tunnel IP already assigned to peer %s", ErrConflict, current.ID)
	}
	next := Record{
		ClusterID: s.clusterID, Peer: peer, OwnerNode: owner,
		Epoch: expectedEpoch + 1, MembershipRevision: s.revision,
		TunnelIP: ip, ValidUntil: until,
	}
	s.records[peer] = next
	s.inUse[key] = peer
	delete(s.holdPeer, peer)
	delete(s.holdIP, key)
	s.lastCommit = at
	return next, nil
}

// Renew keeps the same epoch, owner and IP; only the authorized, unexpired
// owner can increase its TTL. Renewal is a committed keyed CAS operation.
func (s *LeaseStateMachine) Renew(peer Peer, owner string, ip netip.Addr, expectedEpoch uint64, until, at time.Time) (Record, error) {
	ip = ip.Unmap()
	if !validLeaseIP(ip) || !validLeaseTime(at, until, s.maxTTL) {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCommitTime(at); err != nil {
		return Record{}, err
	}
	old, ok := s.records[peer]
	if !ok || old.OwnerNode != owner || owner == "" || old.TunnelIP != ip ||
		old.Epoch != expectedEpoch || !at.Before(old.ValidUntil) ||
		!until.After(old.ValidUntil) {
		return Record{}, ErrConflict
	}
	if _, member := s.members[owner]; !member {
		return Record{}, ErrConflict
	}
	old.ValidUntil = until
	old.MembershipRevision = s.revision
	s.records[peer] = old
	s.lastCommit = at
	return old, nil
}

// Revoke writes a new-epoch tombstone, dropping ownership but retaining the
// old IP/peer reservations until previous.ValidUntil + grace. Failed or
// expired owners may be revoked; expiry alone never frees their address.
func (s *LeaseStateMachine) Revoke(peer Peer, expectedEpoch uint64, at time.Time) (Record, error) {
	if at.IsZero() {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCommitTime(at); err != nil {
		return Record{}, err
	}
	old, ok := s.records[peer]
	if !ok || old.OwnerNode == "" || old.Epoch != expectedEpoch {
		return Record{}, ErrConflict
	}
	if old.Epoch == ^uint64(0) {
		return Record{}, fmt.Errorf("%w: owner epoch overflow", ErrInvalid)
	}
	key := leaseIPKey{tenant: peer.Tenant, ip: old.TunnelIP}
	next := Record{
		ClusterID: s.clusterID, Peer: peer, Epoch: old.Epoch + 1,
		MembershipRevision: s.revision,
	}
	s.records[peer] = next
	delete(s.inUse, key)
	s.holdPeer[peer] = old.ValidUntil.Add(s.grace)
	s.holdIP[key] = old.ValidUntil.Add(s.grace)
	s.lastCommit = at
	return next, nil
}

// Observed returns a local diagnostic copy, not proof of a current quorum
// or a lease authorization. Data-plane decisions must use the local Fence
// after authenticated, quorum-committed updates have been applied.
func (s *LeaseStateMachine) Observed(peer Peer) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[peer]
	return record, ok
}

func validLeaseIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && ip.Zone() == ""
}

func validLeaseTime(at, until time.Time, maxTTL time.Duration) bool {
	return !at.IsZero() && until.After(at) && !until.After(at.Add(maxTTL))
}

func (s *LeaseStateMachine) checkCommitTime(at time.Time) error {
	if at.IsZero() || (!s.lastCommit.IsZero() && at.Before(s.lastCommit)) {
		return fmt.Errorf("%w: non-monotonic committed lease timestamp", ErrInvalid)
	}
	return nil
}
