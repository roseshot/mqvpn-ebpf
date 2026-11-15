# HA architecture: local operation, shared policy, fenced ownership

**Implemented:** standalone Server-local readiness, a backend-neutral
`cluster.Store` contract, and a **local-only** `cluster.Fence` verifier.

**Not implemented:** a production Raft/etcd backend, cross-Server policy/CRL
reconciliation, distributed IP leases, inter-Server forwarding, or live
encrypted-session takeover. Do not interpret the contract as a deployed
N-node HA feature.

## Three responsibilities, no extra state framework

| Responsibility | Who owns it | Implementation boundary |
| --- | --- | --- |
| **Node-local operation**: TUN state, listeners, WAN health, local routing/FIB, resource metrics | Each Server reads its own kernel and process | `internal/app/server_health.go`; no cluster package or quorum dependency |
| **Shared desired configuration**: Server membership and policy/PKI/CRL manifest generations | One quorum-backed control plane | `internal/cluster.Store`; real backend and reconciler pending |
| **Exclusive peer/IP ownership**: tunnel-IP allocation and monotonically fenced peer epoch | Quorum-backed keyed lease authority | `internal/cluster.Fence` is a local verifier only; allocator and datapath integration pending |

Standalone deployments run entirely without Raft, etcd, Consul, quorum
voters, or ClusterStore reads. Existing `/livez` and `/readyz` operate on
local state. The Server manager samples every required local TUN's UP bit,
host IP and MTU and initialized listeners every two seconds, independent of
YAML reload polling. HTTP reads only the last atomic result. Failure of a
single WAN is not automatically failure of the entire MPQUIC Server.
Route/FIB convergence, packet-loss synthesis, actual listener traffic
probe and resource-pressure alarms are **not** covered by this readiness
endpoint.

In a future HA deployment, **N VPN Server nodes and Q voters are independent**;
N can be 2, 3, 5 or more while Q is chosen separately (typically 3 or 5
voters across failure domains). No mandatory etcd or two-Server limit.
To minimize operational and implementation burden, implement and validate
**one** production consensus backend first. Do not expose a selectable
backend in YAML before a working implementation exists. Optional adapters
for external etcd or Consul are deferred until justified by deployments.

## ClusterStore remains deliberately narrow

```go
type Store interface {
    Read(ctx context.Context, clusterID string) (ControlSnapshot, error)
    CompareAndSwap(ctx context.Context, clusterID string,
        expectedRevision uint64,
        desired ControlSnapshot) (ControlSnapshot, error)
}
```

A production implementation must guarantee linearizable reads and durable,
quorum-committed compare-and-swap. The global `Revision` increments by
exactly one, with independently monotonic `MembershipRevision` and
`Policy.Revision`; an unchanged policy or member revision cannot hide a
change to that field. `ControlSnapshot` pins immutable SHA-256 policy and
signed-CRL-manifest digests instead of private signing keys or QUIC secrets.
On a stale writer, return `ErrConflict`; without quorum, return
`ErrUnavailable`, never a stale successful read or local-only write.

`MemoryStore` has been moved into `memory_store_test.go`: it is a
deterministic single-process test fake, is **not compiled into production**,
and does not provide Raft elections, durable recovery or partition safety.

`CheckApplied` is a small, as-yet-unwired strict verification helper for a
future security-critical admission path. It compares a Server's trusted,
locally validated and activated policy/CRL/membership generations against
a **fresh authoritative** `Store.Read`. The actual reconciler, authentication,
and Server admission wiring are not implemented. `/readyz` never invokes
`CheckApplied` or `Store.Read`.

There is no `LocalControlView` cache or generic `CheckNodeLocal` registry:
neither was used by the running Server. Avoid reintroducing caches or probe
abstractions until a concrete consumer requires them.

## IP leases must not share a giant manifest transaction

The `Store` snapshot is for **low-frequency** policy and membership
changes. Session creation and renewal needs a separate **keyed**, linearizable
lease operation with atomic uniqueness for `(tenant, tunnel_IP)`,
monotonic owner epochs, explicit revocation/tombstone and fencing at both
TUN ingress and egress. The local `Fence` cannot issue ownership or prove
quorum, and there is no safely supported active/active session allocator.

Local TUN health **must not** imply permission to assign an IP or accept a
Client when shared policy/CRL requirements cannot be verified. During
quorum loss, no new conflicting owner/IP leases or security-sensitive
admission may be authorized through stale local state. A revoked peer
cannot be made safe merely by caching a recent policy digest.

## End-to-end exit criterion

Before claiming distributed HA: prove N=2/3/5 Server configurations
independent of Q=3/5 voters, signed policy/CRL convergence, failure-domain
partitions, no epoch rollback after restart, no duplicate IP allocation,
fenced owner cutover, and inter-Server forwarding across real QUIC/TUN
paths. Do not equate load-balancer failover with live QUIC session transfer.

A deterministic, **non-distributed** keyed lease-command implementation
(`LeaseStateMachine`) now enforces owner epochs, explicit tombstones, per-tenant
IP uniqueness and a safety grace interval; see [keyed lease semantics](ha-keyed-lease-state.md).
It is not a durable backend and is not connected to Server admission.

See [HA state sync](ha-cluster-state-sync.md),
[local ownership fence](ha-ownership-fence.md), and
[tracking issue #43](https://github.com/roseshot/mqvpn-ebpf/issues/43).
