# HA cluster synchronization: implementation contract

**Status:** Architecture and acceptance criteria. Server-only readiness/VIP
handling is in PR #41; CN authorization, per-Peer policy inheritance and
instance CRL checks are in the dependent PKI PR. **This page does not claim
cross-node replication is already running.** A working VRRP address alone
is not a distributed session database.

## What must be synchronized?

| State | Consistency | Proposed authoritative owner | What standby does |
| --- | --- | --- | --- |
| Tenant configuration, per-peer CN/URI identity rules, network prefixes, route/DNS pushes | Immutable revision, monotonically advancing generation | Raft-backed configuration store (etcd/Consul) or GitOps controller publishing validated atomic snapshots | Validates exact generation, certificate trust and config digest before advertising readiness |
| CA trust bundles, signed CRLs and Server certificate identity | Signed PKI artifacts plus consistent manifest revision | PKI issuer and cluster policy controller | Refuses new Client authentication when required CRL is missing, expired or mismatched; retires impacted sessions after rotation |
| Dynamic tunnel IP leases | Linearizable **compare-and-swap** allocation, unique (tenant, address) key | Single lease allocator in quorum store | Never issues an address independently during network partition; owner lease expires only after fencing/grace |
| Session ownership (tenant, Client CN, epoch, owner node, transport, granted tunnel IP, last-seen) | Versioned epoch with leader-fenced writes | Active Server + quorum-backed ownership record | May know where the session lived; **does not pretend to own its encrypted QUIC connection** |
| P2MP destination route ownership and cross-node forwarding | Every owner swap gated by a fencing token and updated Linux FIB / inter-Server forwarding | Elected owner + routing control plane | Forwards only after the previous owner is fenced; never injects packets into stale TUN or duplicate sessions |
| QUIC/TLS connection secrets, packet numbers, CIDs, ACK/replay windows, MPQUIC path state | Transport-engine, packet-level atomic state | Active QUIC stack | **Not implemented**; requires transport support, audit and continuous sequencing; until then Client reconnect establishes a new session |

Refer to [RFC 9308 `11](https://www.rfc-editor.org/rfc/rfc9308.html#section-11)
for backend affinity and to [strongSwan HA](https://docs.strongswan.org/docs/latest/features/highAvailability.html)
for why encrypted-session synchronization includes cryptographic state,
sequence numbers and replay windows.

## Recommended Server-only architecture

```text
              Client (unchanged DNS/VIP + mTLS)
                            |
                   QUIC-aware ingress / VIP
                        /        \
              Server A             Server B
              P2MP + TUN           P2MP + TUN
                 |                     |
                 +--- mTLS cluster ---+
                             |
           Raft consensus state, 3 or 5 voters
           * desired policy + PKI manifest generation
           * lease CAS + ownership epochs
           * session metadata / current owner
                   [not QUIC crypto keys]
```

A two-node deployment should not use a naive 2-voter quorum with split-brain
fallback. Use an external 3-voter state service (or a witness with carefully
defined failure and fencing semantics). If quorum is unavailable, nodes must
**fail closed for new leases and peer owner elections**, not locally re-elect
a second active owner. A previously active Server may continue sessions only
under an explicitly documented, time-bounded lease and network policy; the
standby must not take its sessions without fencing.

The configuration should be *declarative*: the control plane stores a validated
bundle and revision, each Server reconciles that revision into its existing
instance/peer reload code, and its local \`/readyz\` must eventually depend on
**committed revision, current CRL and ownership readiness**. A file copied
from one node to another is not a safe quorum protocol.

## Identity and Client overrides

Within a Server instance the default identity key is its verified Client
certificate **CN**. Only CN values explicitly present in the Peer policy are
authorized. A Peer may use \`certificate_cn\` when the internal friendly
\`id\` differs from the certificate CN. CN is not a TLS server-name verifier
and is not globally unique: an instance's CA trust store should be dedicated
to the tenant, and a CA must enforce unique Client identities and issuance
permissions. The forward-compatible cluster identity can use a **URI SAN**
(SPIFFE-compatible) instead of relying on CN.

An instance sets defaults for \`push_routes\` and \`push_dns\`; a Peer may
override either or inherit an omitted field. An explicit empty \`[]\`
disables that push for that Peer. Static Peer \`routes\` specify destination
ownership and cannot be blindly inherited by all peers because duplicate
address ownership would be ambiguous.

Server options for each instance:
- \`client_revocation.mode: crl\` with \`crl_file\` for strict CRL checks.
- \`client_revocation.mode: off\` to disable **only** CRL checks, never mTLS.
- CN lookup after verified Client cert chain and \`clientAuth\` EKU.

In a cluster all nodes must consume the *same committed policy and CRL
generation* before advertising the same public VIP. A stale standby
must not become active simply because its local UDP socket still listens.

## Transaction and fencing protocol (planned)

1. Controller validates a *complete* revision of tenant YAML, Peer identity
   map, signed CRLs, CA material and tunnel-IP policy. It publishes
   \`{cluster_id,revision,digest,not_before}\` by a quorum CAS transaction.
2. Each node stages and validates that exact revision, then reports its
   applied digest. Incompatible or partial revisions **cannot** be served.
3. Each authenticated Client admission allocates a session owner epoch using
   a conditional transaction. Active owners periodically renew their lease.
4. On disconnect or peer revocation, the Server retires the epoch and
   releases ownership only after TUN/route egress fences and lease grace.
5. On crash, VIP ingress and route control fence the old owner; only then
   can a standby claim a larger epoch. With no live QUIC crypto state, the
   returning Client creates a new QUIC/TLS connection to the same VIP.
6. For multi-Server active/active, every inner packet addressed to a Peer
   on a different Server needs an encrypted **inter-Server P2MP forwarding**
   path and session-owner lookup, with loop and anti-replay prevention.
   Generic HAProxy TCP round-robin alone cannot supply this routing layer.

The synchronization channel must itself use mTLS with **distinct node
identities**, strict role authorization and auditable configuration version
changes. It must never expose CA signing keys, private Client keys, TLS
traffic key logs or unfenced lease writes to a replica.

## Acceptance matrix for implementation

| Test | Required assertion |
| --- | --- |
| Config revision published while both nodes healthy | Both report identical revision and apply matching Peer policy before ingress considers them ready |
| Policy/CA/CRL rotation | Revoked Client disconnects and cannot authenticate to **either** Server, including QUIC/TCP fallback |
| Issuer cert issued with reused CN or unknown Peer CN | No access unless the instance's CA/identity policy explicitly authorizes it |
| CRL stale/unavailable with \`mode: crl\` | New Client authentication fails on each node |
| Concurrent dynamic lease requests on two nodes | Exactly one unique address owner; no duplicate lease after crash/recovery |
| Partition/no cluster quorum | No divergent session owner epoch, duplicate route injection or active-active lease allocation |
| Active Server crash with VIP | Existing Client configuration remains identical; Client reconnects to Server with higher fenced owner epoch |
| Active/active cross-Server Client-to-Client | Bidirectional 20/20 Linux FIB/OSPF/BGP forwarding over an encrypted inter-Server route |
| 1–8 WAN randomized five-site test | Same Client identity and policy across failover, no split connection across QUIC backend nodes |
| QUIC crypto-state transfer | **Not supported until** the transport library exposes safe, tested, reproducible session snapshots |

## Delivery phases

- **Phase A — PKI/authorization:** CN Peer lookup, explicit per-Peer policy
  inheritance and optional fail-closed CRL validation. No Client HA changes.
- **Phase B — Policy replication:** consensus-backed revisioned manifest,
  authenticated node watch and \`/readyz\` generation gate; no shared Client
  crypto secrets.
- **Phase C — Ownership:** distributed unique tunnel leases, epoch fencing,
  session ownership and inter-Server P2MP route synchronization.
- **Phase D — Active/active QUIC:** CID-aware MPQUIC ingress, dynamic routing
  and tested Client reconnect. Any *truly seamless* encrypted state takeover
  needs transport-stack modifications and cryptographic review first.

Do not mark a phase as supported until its corresponding network-partition,
certificate-revocation and multi-WAN integration tests pass.
