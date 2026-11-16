# N-node HA ownership fencing: local verification primitive

[Documentation index](README.md) · [HA control-plane design](README.md#high-availability-control-plane-design-and-local-primitives)

> **Document scope:** **Local safety verifier, not distributed fencing.** The owner-epoch checks cannot enforce cluster-wide exclusivity until an authenticated quorum commits and delivers ownership state.

This is a **local implementation building block**, not an end-to-end HA
cluster. The Go package at [internal/cluster](../internal/cluster) holds a
node-count-independent local state machine for **quorum-issued** peer-owner
epochs. It has no network listener, does not contact etcd, and is not yet wired
into the P2MP hub. The existing Server health check still
reports **local-only** readiness and dynamic tunnel pools are **not** safe to
share across independent Servers.

## Invariants implemented by the local guard

- Accept authenticated, committed membership generations for any configured
  **N >= 2** Server node IDs; N does not equal the number of Raft voters.
- Reject duplicate, malformed, conflicting or rolled-back membership lists.
  Identical delivery of a committed revision is safe to replay.
- Observe a per-(tenant, peer) monotonic **owner epoch** and a finite lease
  bounded by an operator-chosen maximum TTL (1 second to 2 minutes).
- A higher epoch can renew the same owner's lease. A different Server or
  tunnel IP **cannot take over directly**: an explicit higher-epoch fencing
  tombstone must retire the previous owner first.
- An old or revoked owner cannot inject traffic once a newer epoch is observed.
  Removing a Server from membership locally retires its current ownership;
  re-adding the same node ID never resurrects old epochs.
- For a tenant, a tunnel IP cannot be assigned to a second peer until the
  first peer's ownership record has been fenced, even if the old lease expired.
  Different tenants may independently use overlapping private addresses.
- A local authorization check requires **exactly** the current owner, epoch,
  intended tunnel IP, live TTL and valid membership. Missing/unknown state
  denies access.
- `WithAuthorized` holds an in-process read barrier around a caller's final
  packet write/enqueue. A concurrent local tombstone or membership update must
  wait until that authorized action completes, and later actions are rejected.
  Callbacks must never re-enter membership/owner mutation while holding it.

The in-memory mutex prevents races inside **one process**. It does **not**
create a distributed linearizable register, prove quorum, fence a disconnected
old Server, or safely arbitrate simultaneous claims across machines.

A separate [keyed lease state machine](ha-keyed-lease-state.md) now models
atomic per-peer epoch CAS, tenant/IP uniqueness, revoke-before-transfer and
expiry-plus-grace handoff. It is an **in-process deterministic command
applier**, not a distributed quorum, and remains disconnected from the
running Server.

## Control-plane integration required before production HA

The future consensus-backed adapter must authenticate the node to etcd/Consul
over dedicated mTLS, verify a committed membership/owner record and apply it
to the guard. The adapter must use CAS for leases, monotonic generations, a
quorum policy, deadline/clock-skew bounds and persistent fencing tokens. It
must **not** call the local guard with caller-invented epochs or untrusted
network messages.

The Server manager must then gate **new Client admission** and local
`/readyz` on committed current policy/CRL and lease authority. The P2MP
path must check the ownership epoch **at final TUN ingress and egress**, and
the old owner must be fenced before a new owner is admitted. Rejected/stale
updates must not accidentally mark a Server ready. Only after those hooks and
the external store integration exist can the local guard be used to enforce
cluster ownership in production.

This primitive does not migrate QUIC/TLS crypto state or remove the need for
a reconnect after an owner failover.

## Test coverage

`go test ./internal/cluster -race` covers N=2/3/5/8 membership, scale-out,
membership rollback and revision collision, concurrent owner conflicts,
lease renewal/replay, IP reuse, explicit fencing, stale owner denial,
node removal/rejoin, and cross-tenant overlap. Network-partition tests must
be added with a **real** quorum-backed store, at least N=3/5 independent
Server processes and authenticated inter-Server packet forwarding before
claiming Phase B/C complete. See [Issue #43](https://github.com/roseshot/mqvpn-ebpf/issues/43).

## Related documentation

- [Keyed lease semantics](ha-keyed-lease-state.md)
- [ClusterStore contract](ha-cluster-store.md)
- [HA deployment](high-availability.md)
