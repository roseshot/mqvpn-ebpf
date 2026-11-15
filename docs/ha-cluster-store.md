# HA Phase B: pluggable, quorum-backed ClusterStore contract

**Development status:** The interface and a test-only in-memory reference
implementation have landed in a development PR. This does **not** enable
distributed HA, run embedded Raft or deploy etcd. Cross-Server policy/CRL
replication, P2MP forwarding, and distributed tunnel-IP leasing are not
implemented by this PR.

## No mandatory etcd dependency

The Go `internal/cluster.Store` interface defines the minimum **committed
control-plane snapshot** contract. Different backends may implement it:

- **Embedded Raft (intended default):** VPN deployments can bootstrap a
  separately sized quorum of 3 or 5 Raft voters, possibly co-located with
  Servers. Durable log, snapshots, node identity, transport mTLS, joint
  membership changes, recovery, and linearizable reads are prerequisites.
  **This backend is not implemented.**
- **External etcd/Consul (optional):** implement the same guarantees through
  their documented quorum/CAS and watch semantics. **No adapter is wired.**
- **MemoryStore (tests only):** process-local mutex CAS, no persistence,
  authentication, or real quorum; not usable for multi-Server deployments.

**N VPN Server nodes and Q consensus voters are independent.** A two-Server
VPN cluster can use a three-voter state service; a five-Server pool may also
use three voters. No fixed A/B pair, mandatory etcd, or two-node quorum
fallback is assumed.

## Required operations

```go
type Store interface {
    Read(ctx context.Context, clusterID string) (ControlSnapshot, error)
    CompareAndSwap(ctx context.Context, clusterID string,
        expectedRevision uint64,
        desired ControlSnapshot) (ControlSnapshot, error)
}
```

A backend MUST give each successful `Read` a quorum-backed linearizable
snapshot, and MUST execute `CompareAndSwap` as one durable transaction on a
majority. If it cannot establish the required quorum it returns
`ErrUnavailable`, not a cached stale value. Competing writers using an old
global revision receive `ErrConflict`. The bootstrap transaction expects
global revision 0 and commits revision 1. All updates increment the global
revision exactly once. The global revision is not the Raft term.

`ControlSnapshot` carries:
- `cluster_id` and a global transaction `revision`;
- versioned **Server** membership (N >= 2 and unique stable node IDs);
- a separately versioned policy/PKI **digest**;
- a separately pinned signed-CRL-manifest digest.

Digest references are SHA-256 lowercase hex. The policy digest must cover the
entire signed CRL manifest and tenant policy in an immutable staged bundle;
the independent CRL digest makes CRL drift observable. The store commits
**references**, not a CA signing key, Client private key or QUIC traffic
secret. Before considering a node applied/ready, the reconciler must verify
the referenced bundle and actual CRL bytes, validate CA trust and policy,
then atomically activate them; this is future integration work.

A membership change without a higher `MembershipRevision`, or a
policy/CRL change without a higher `Policy.Revision`, is rejected. Neither
member nor policy revision can go backwards. Exposing a read-only `Revision`
is **not** proof that the local Server has applied that revision or is safe to
receive a new connection.

## Safety and performance boundaries

The interface covers **low-frequency Phase B policy and membership
manifests**, not a global CAS of every live Client session. Phase C needs a
separate **keyed, linearizable lease allocator** with atomic uniqueness over
`(tenant, tunnel_IP)`, per-peer epoch fencing and grace periods. Serializing
all Client session renewals through this single control snapshot would
introduce unnecessary contention. The existing local `Fence` only checks
quorum-issued records and cannot replace that distributed lease allocator.

The test fake's `SetAvailable(false)` exercises a fail-closed API contract;
it does **not** simulate actual Raft voting, network partitions, disk
persistence, split-brain prevention or reconfiguration.

A generic `CheckApplied` helper performs a **fresh** store read to compare
a current member's locally applied membership, policy and CRL revisions
against the committed snapshot. It fails closed on missing/quorum-lost state,
stale policy/CRL or removed members. The `AppliedState` input is trusted
only if a future reconciler independently verified and activated those
bytes; passing arbitrary YAML as "applied" would be unsafe. This helper is
**not yet connected to the Server's local `/readyz` or Client admission**.

No `ha.backend` Server config flag is introduced by this PR: advertising a
nonfunctional backend mode would be dangerous. Production HA readiness and
Client admission must remain unavailable until a real backend is integrated
and its current committed policy is applied locally.

## Acceptance tests for later implementation

A production backend must demonstrate linearizable reads after leader
failover, concurrent CAS, no rollback after restart/snapshot restore, stale
watch rejection, 3/5-voter majority/minority partition isolation, and 2/3/5
Server membership changes independent from voter count. CRL revocation must
reject the same Client on every Server before the new policy is advertised
as ready; a minority partition must not mint peer ownership or tunnel IPs.

See [Issue #43](https://github.com/roseshot/mqvpn-ebpf/issues/43) and
[HA synchronization contract](ha-cluster-state-sync.md).
