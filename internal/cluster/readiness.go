package cluster

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotReady means a node has not yet applied the currently committed
// authenticated membership and policy/CRL manifest.
var ErrNotReady = errors.New("cluster control state not applied")

// AppliedState must be produced by a trusted Server-side reconciler only
// AFTER it validates and atomically activates the exact policy/CRL bytes.
// It is never a claim from a Client, a live socket, or an arbitrary YAML field.
type AppliedState struct {
	ClusterID          string
	NodeID             string
	MembershipRevision uint64
	Policy             PolicyReference
}

// CheckApplied is a security-critical admission prerequisite, not a /readyz
// check. It must read the current committed generation through a real quorum
// backend; local process health is deliberately outside this function.
func CheckApplied(ctx context.Context, store Store, applied AppliedState) error {
	if store == nil || !validID(applied.ClusterID) || !validID(applied.NodeID) ||
		applied.MembershipRevision == 0 || applied.Policy.Revision == 0 ||
		!validDigest(applied.Policy.Digest) ||
		(applied.Policy.CRLDigest != "" && !validDigest(applied.Policy.CRLDigest)) {
		return fmt.Errorf("%w: missing store or verified local policy/node identity", ErrNotReady)
	}
	committed, err := store.Read(ctx, applied.ClusterID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	if committed.ClusterID != applied.ClusterID ||
		committed.MembershipRevision != applied.MembershipRevision ||
		committed.Policy != applied.Policy {
		return fmt.Errorf("%w: committed membership or policy/CRL differs", ErrNotReady)
	}
	for _, member := range committed.Members {
		if member == applied.NodeID {
			return nil
		}
	}
	return fmt.Errorf("%w: Server is no longer a member", ErrNotReady)
}
