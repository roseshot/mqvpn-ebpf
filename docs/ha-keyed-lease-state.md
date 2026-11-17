# Keyed peer/IP lease state machine (Phase C foundation)

[Documentation index](README.md) · [HA control-plane design](README.md#high-availability-control-plane-design-and-local-primitives)

> **Document scope:** **Local deterministic lease-model reference.** This in-process state machine is not durable quorum storage and is not connected to Server admission.

**Status: deterministic local state-machine implementation only. Not distributed
HA, not a Raft voter, not a persistent lease store and not connected to the
live Server/P2MP data path.** The API is not a safe fallback for a lost quorum.

The committed control manifest in [ClusterStore](ha-cluster-store.md) remains
small and low-frequency. Peer/IP ownership is instead modeled by
`internal/cluster.LeaseStateMachine`, which tracks individual
`(tenant, peer)` records and a unique `(tenant, tunnel IP)` index.
It does **not** copy transient WAN, TUN or routing metrics into consensus.

## Committed command sequence

1. A configured Server member proposes `Claim(peer, owner, ip,
   expectedEpoch=0, expiry, commitTime)`; a never-owned peer receives epoch 1.
   The chosen IP must be unclaimed **within its tenant**. Different tenants
   may use overlapping private addresses.
2. The same owner may `Renew` its unexpired record, retaining its epoch
   and IP and strictly extending its expiry. Expiry alone **cannot**
   transfer ownership or free an IP.
3. `Revoke(peer, expectedEpoch, commitTime)` atomically changes that peer
   to a higher-epoch tombstone and reserves both the peer and former IP until
   `old.ValidUntil + grace`.
4. After that deadline, `Claim` using the **exact tombstone epoch** issues
   another higher epoch to the new owner (or the same owner after restart).
   The new committed record can be distributed to all node-local `Fence`
   guards. An isolated old owner is denied after its old TTL expires, even
   before it learns about the new epoch.

Any stale expected epoch, duplicate IP, removed/nonmember owner, stale
renewal, unsupported timestamp, or pre-grace transfer is rejected. Updating
Server membership requires revoking any departing node's owner leases first;
an unchanged membership revision must not change its member set. N Server
nodes are independent of Q Raft voters.

## Required production execution model

A future Raft backend MUST append **the entire lease command including the
trusted commit timestamp** to a quorum-committed, durable replicated log,
and only then apply it exactly once in log order. A failed quorum check MUST
return `ErrUnavailable` and MUST NOT mutate lease state. Backend snapshots
must persist peer records, owner epochs, IP reservations, grace deadlines,
membership revisions and last accepted command timestamp. Restore/replay
must not roll back epochs, silently reclaim an expired IP or bypass a
previously committed tombstone.

The in-process mutex ensures deterministic **single-process** CAS for tests
only; it does not prove consensus, survive a crash or prevent two disconnected
Servers from applying separate local commands. It must **not** be invoked
directly by a running Server to allocate production HA tunnel IPs.

A Raft cluster must separately authenticate Server/voter identities with
mTLS, protect logs/snapshots, implement joint voter reconfiguration and
linearizable reads, and set bounded lease TTLs and grace according to
measured maximum clock skew, packet drain and route-convergence behavior.
Client-supplied clocks or arbitrary user-provided `commitTime` values
cannot be trusted. In particular, a committed record does not establish
that the old process has stopped emitting traffic; the data plane still
needs ingress/egress `Fence.WithAuthorized` integration and expiry checks
on every forwarded packet.

**Single-Server standalone operation remains unchanged.** No extra
YAML fields, user-visible backend selection, implicit quorum requirement
or Client changes were introduced.

## Tests and missing acceptance criteria

- N=2/3/5/8 Server membership, concurrent distinct-peer claims on one
  IP (single winner), tenant isolation and incompatible membership removal
- Renewal/epoch CAS, expired-owner denial, tombstone/grace handoff,
  rollback/replay rejection and invalid time/IP/member inputs
- Local two-Server `Fence` handoff, plus old isolated guard denial after
  TTL expiry

This is **not** a Q=3/Q=5 majority/minority partition test. Such tests
require a real multi-process consensus backend and injected failures.
Also pending: durable FSM snapshots, authenticated commit delivery, WAN
fault injection, P2MP session admission and actual cross-Server forwarding.

See [HA ownership fence](ha-ownership-fence.md) and
[tracking issue #43](https://github.com/roseshot/mqvpn-ebpf/issues/43).

## Related documentation

- [ClusterStore boundary](ha-cluster-store.md)
- [Ownership fencing](ha-ownership-fence.md)
- [Cluster acceptance plan](ha-cluster-state-sync.md)
