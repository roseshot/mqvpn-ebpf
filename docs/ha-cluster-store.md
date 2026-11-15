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

## Node-local observations versus globally committed state

A VPN Server **reads its own live operational state**; it must not replicate
transient telemetry as consensus data or issue remote quorum reads each time
a local health endpoint is queried. The existing `GET /livez` and `GET
/readyz` already read local process state. Their present readiness check
proves only local listener/configuration startup, **not** that consensus,
routing or peer ownership is healthy.

| Node reads locally (not synchronized) | Cluster coordination (quorum required) |
| --- | --- |
| Listener socket binding, TUN device, network interfaces/WAN carrier, local Linux FIB, forwarding capability | Committed Server membership and desired policy revision |
| Process load, packet/drop counters, observed RTT/loss, live QUIC path health | Tenant/peer authorization policy digests, CA/CRL manifest revisions |
| Whether **this node** validated and activated policy/CRL bytes; local certificate expiry | Unique tunnel-IP leases, peer-owner epochs and fencing tokens |
| Per-node health and capacity metrics | Authoritative owner lookup for inter-Server forwarding |

The `CheckNodeLocal` primitive invokes caller-supplied node-local probes
for configured resources. It does not depend on a `ClusterStore`, and
different nodes may legitimately report different WAN, TUN or route health.
Actual network/TUN probe implementations and Server manager hooks are
separate work; the existing `/readyz` has **not** been modified here.

`LocalControlView.Refresh` is designed for a background worker to perform
a **fresh linearizable** `Store.Read` and retain the last committed policy,
CRL and membership snapshot for a **bounded maximum age** (up to 30 seconds).
`CheckAppliedLocal` compares a node's independently validated/applied state
against this observation **without any network call**. An unavailable or
contradictory refresh immediately invalidates this local view; a stalled
worker allows the view to expire and fail closed. Removed members, changed
policy and changed CRL are rejected once their new committed snapshot is
observed. Local status and local observation may be evaluated on separate
schedules.

**Security boundary:** bounded-age observations are suitable only for local
operational readiness/diagnostics; they cannot guarantee instantaneous
revocation and **cannot authorize a new tunnel lease, peer ownership change
or security-critical Client admission**. A policy update could commit between
refreshes. For such decisions, `CheckApplied` still performs an authoritative
quorum-backed read and a separate committed lease/fencing check remains
necessary. The admission/reconciliation implementation must define the
maximum tolerated revocation delay and prevent stale nodes from accepting
new sessions when that policy cannot be met. No offline fallback should mint
leases or bypass fencing. Verified `AppliedState` must come from a trusted
reconciler, never arbitrary YAML or Client data.

The local probes, control-view cache and strict `CheckApplied` are reusable
components, but none is yet connected to live Server `/readyz`, Client
admission, or a production Raft backend.

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
