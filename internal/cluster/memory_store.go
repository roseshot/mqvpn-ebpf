package cluster

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is an in-process transactional reference implementation for
// deterministic tests. It is NOT a Raft backend, is not durable, authenticates
// no nodes, and MUST NOT be used for multi-Server production coordination.
// It uses the same Store contract intended for a real consensus adapter.
type MemoryStore struct {
	mu        sync.Mutex
	available bool
	clusters  map[string]ControlSnapshot
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		available: true,
		clusters:  make(map[string]ControlSnapshot),
	}
}

// SetAvailable models quorum unavailability for single-process contract
// testing only. This does not simulate a real Raft election or network split.
func (s *MemoryStore) SetAvailable(available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.available = available
}

func (s *MemoryStore) Read(ctx context.Context, clusterID string) (ControlSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ControlSnapshot{}, err
	}
	if !validID(clusterID) {
		return ControlSnapshot{}, fmt.Errorf("%w: invalid cluster ID", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ControlSnapshot{}, err
	}
	if !s.available {
		return ControlSnapshot{}, ErrUnavailable
	}
	value, ok := s.clusters[clusterID]
	if !ok {
		return ControlSnapshot{}, ErrMissing
	}
	return copyControl(value), nil
}

func (s *MemoryStore) CompareAndSwap(ctx context.Context, clusterID string, expectedRevision uint64, next ControlSnapshot) (ControlSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ControlSnapshot{}, err
	}
	if !validID(clusterID) || next.ClusterID != clusterID {
		return ControlSnapshot{}, fmt.Errorf("%w: cluster identity mismatch", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ControlSnapshot{}, err
	}
	if !s.available {
		return ControlSnapshot{}, ErrUnavailable
	}
	current, exists := s.clusters[clusterID]
	if !exists {
		if expectedRevision != 0 {
			return ControlSnapshot{}, fmt.Errorf("%w: initial expected revision must be zero", ErrConflict)
		}
		if err := validateControlTransition(nil, expectedRevision, next); err != nil {
			return ControlSnapshot{}, err
		}
	} else {
		if current.Revision != expectedRevision {
			return ControlSnapshot{}, ErrConflict
		}
		if err := validateControlTransition(&current, expectedRevision, next); err != nil {
			return ControlSnapshot{}, err
		}
	}
	committed := copyControl(next)
	s.clusters[clusterID] = committed
	return copyControl(committed), nil
}
