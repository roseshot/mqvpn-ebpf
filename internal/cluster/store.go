package cluster

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
)

// Store is the Phase B control-plane contract. Every successful read MUST
// be linearizable and every CompareAndSwap MUST be one quorum-committed
// transaction. A backend must return ErrUnavailable when it cannot establish
// quorum; it must never fall back to stale local data or local-only writes.
//
// A store does not authenticate clients or move existing QUIC sessions.
// The separate peer/IP lease allocator must provide its own atomic address
// uniqueness and owner-epoch fencing (see Fence).
type Store interface {
	Read(ctx context.Context, clusterID string) (ControlSnapshot, error)
	CompareAndSwap(ctx context.Context, clusterID string, expectedRevision uint64, desired ControlSnapshot) (ControlSnapshot, error)
}

var (
	ErrUnavailable = errors.New("cluster quorum unavailable")
	ErrConflict    = errors.New("cluster revision conflict")
	ErrMissing     = errors.New("cluster not initialized")
	ErrInvalid     = errors.New("invalid cluster control snapshot")
)

// PolicyReference references a separately staged, fully validated, immutable
// bundle. Digest must cover the entire tenant policy, CA trust and signed CRL
// manifest. CRLDigest separately pins the revocation manifest (empty only if
// no CRLs are configured). Neither digest stores signing keys or QUIC secrets.
type PolicyReference struct {
	Revision  uint64
	Digest    string
	CRLDigest string
}

// ControlSnapshot is the committed Phase B policy and membership header.
// Revision is a global CAS generation, independent of MembershipRevision
// and Policy.Revision. Server node count N is NOT the number Q of consensus
// voters. A two-Server snapshot may be stored by three independent voters.
//
// The Members slice is a value: implementations must copy it on read/write.
// No Server may advertise this snapshot as applied until all referenced
// policy and CRL bytes were independently validated and activated.
type ControlSnapshot struct {
	ClusterID          string
	Revision           uint64
	MembershipRevision uint64
	Members            []string
	Policy             PolicyReference
}

// validDigest ensures the reference has an unambiguous canonical encoding.
// It does not check the digest against the bytes: the reconciler must do so.
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func memberSet(members []string) (map[string]struct{}, error) {
	if len(members) < 2 {
		return nil, errors.New("HA requires at least two VPN Server nodes")
	}
	set := make(map[string]struct{}, len(members))
	for _, node := range members {
		if !validID(node) {
			return nil, fmt.Errorf("invalid Server ID %q", node)
		}
		if _, ok := set[node]; ok {
			return nil, fmt.Errorf("duplicate Server ID %q", node)
		}
		set[node] = struct{}{}
	}
	return set, nil
}

// validateControlTransition enforces semantic versioning even for a backend
// that simply calls a transactional compare-and-swap primitive. The external
// consensus adapter must additionally ensure authenticated writes, quorum,
// durable linearizable reads, and no ABA after restart.
func validateControlTransition(previous *ControlSnapshot, expected uint64, next ControlSnapshot) error {
	if !validID(next.ClusterID) || next.MembershipRevision == 0 || next.Policy.Revision == 0 ||
		!validDigest(next.Policy.Digest) ||
		(next.Policy.CRLDigest != "" && !validDigest(next.Policy.CRLDigest)) {
		return fmt.Errorf("%w: bad cluster identity, generation or policy digest", ErrInvalid)
	}
	updatedMembers, err := memberSet(next.Members)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if expected == ^uint64(0) || next.Revision != expected+1 {
		return fmt.Errorf("%w: control revision must increment by one", ErrInvalid)
	}
	if previous == nil {
		if expected != 0 || next.Revision != 1 ||
			next.MembershipRevision != 1 || next.Policy.Revision != 1 {
			return fmt.Errorf("%w: first commit must initialize generation 1", ErrInvalid)
		}
		return nil
	}
	if next.ClusterID != previous.ClusterID || previous.Revision != expected {
		return fmt.Errorf("%w: cluster identity or base revision mismatch", ErrInvalid)
	}
	if next.MembershipRevision < previous.MembershipRevision ||
		next.Policy.Revision < previous.Policy.Revision {
		return fmt.Errorf("%w: membership or policy rollback", ErrInvalid)
	}
	oldMembers, err := memberSet(previous.Members)
	if err != nil {
		return fmt.Errorf("%w: stored membership invalid: %v", ErrInvalid, err)
	}
	if next.MembershipRevision == previous.MembershipRevision && !maps.Equal(oldMembers, updatedMembers) {
		return fmt.Errorf("%w: membership changed without revision advance", ErrInvalid)
	}
	if next.Policy.Revision == previous.Policy.Revision && next.Policy != previous.Policy {
		return fmt.Errorf("%w: policy or CRL changed without revision advance", ErrInvalid)
	}
	return nil
}

// copyControl prevents a caller from mutating committed member slices.
func copyControl(s ControlSnapshot) ControlSnapshot {
	s.Members = append([]string(nil), s.Members...)
	return s
}
