# HA cluster synchronization: implementation contract

**Status:** Architecture and acceptance criteria. Server-only readiness/VIP
handling is in PR #41; CN authorization, per-Peer policy inheritance and
instance CRL checks are in the dependent PKI PR. **This page does not claim
cross-node replication is already running.** A working VRRP address alone
is not a distributed session database.

For the minimal Phase B quorum/CAS interface (no required etcd), see
[ClusterStore contract](ha-cluster-store.md). Its in-memory store is
compiled only in Go tests; the policy verification helper remains
unwired to Server admission. There is no production consensus backend.

## What is local (never replicated by Raft)?

**Per-node observed runtime status** is owned and read by each mqvpn Server:
WAN/interface carrier and path loss/RTT, listener binding, TUN readiness,
Linux route/FIB/FRR convergence, packet and flow counters, current CPU and
memory pressure, and local policy/CRL validation results. These are not
globally authoritative facts; nodes can legitimately disagree about their
own health. Use local probes and health controllers, not quorum CAS for
every observed metric or a synchronous cluster request on every `/readyz`.

Quorum coordination is reserved for **desired or globally unique state**:
membership, immutable policy/PKI/CRL manifest revisions, peer owner epoch,
and tunnel IP lease allocation. A Server separately confirms it has locally
applied the required committed manifest. A node may be locally healthy but
**not authorized** to admit new Clients or change global ownership if its
committed policy is stale or it lacks quorum. Local `/readyz` does
not cache or authorize global leases, and a local health observation
cannot replace authoritative, linearizable admission/fencing.
See [ClusterStore contract](ha-cluster-store.md).

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

## Cluster size and failure-domain model (N Server nodes)

**N is the number of mqvpn Server/data-plane nodes, not the number of Raft
voters.** The target architecture supports a dynamically configured set of
**N >= 2 Servers** (for example 2, 3, 5, 8 or more), without a hard-coded
two-Server topology, paired-primary/standby IDs, or all-to-all session state.
A single Server remains a valid non-HA deployment. The practical maximum N
will be governed by measured throughput, control-plane load and deployment
limits, not an arbitrary "2" in the cluster protocol.

**Q is the number of consensus voters**, which may run on separate machines
from the mqvpn Servers. Prefer 3 or 5 independent voters in distinct failure
domains. A majority of `floor(Q / 2) + 1` voters is required to commit
ownership/policy changes (3 voters -> 2 votes; 5 -> 3). Never use a
two-voter split-brain fallback. N and Q are independent: a two-Server VPN
deployment can use an external three-voter store, while five or more VPN
Servers may share a suitably sized three- or five-voter control plane.
Adding VPN Servers must not implicitly add consensus voters or change quorum.

Example with **five** data-plane Servers and **three** separate voters:

```text
      Unchanged Clients: single DNS identity + mTLS
                          |
             CID-aware ingress / VIP
                          |
           +--------------+--------------+
           |       |      |       |      |
         VPN A   VPN B  VPN C   VPN D  VPN E    (... VPN N)
          TUN     TUN    TUN     TUN    TUN
           |       |      |       |      |
           +-------+------+-------+------+
                          |
         Authenticated cluster control + forwarding
                          |
               etcd / Raft voters Q=3
             voter 1 -- voter 2 -- voter 3
               (2 of 3 required for writes)
```

The diagram is an **implementation target**, not a claim that replicated
leases, cross-node forwarding, or CID-aware QUIC ingress already exist.

Each Server has a **stable, unique node identity** and an authenticated
membership record. Admission, leases, peer-session owner epochs and policy
revisions are keyed by `cluster_id`, tenant and peer/address identity,
not by "primary" or "secondary" slots. Nodes independently watch the same
committed state and stage validated snapshots before accepting new sessions.
On scale-out, a new node cannot serve traffic until its policy/CRL revision
is current and ownership/fencing checks pass; on scale-in, a draining node
stops admitting sessions, relinquishes fenced ownership, and is removed only
after old epochs are retired. Rejoining with a reused node ID must never
resurrect an old session or owner epoch.

Forwarding must resolve the current owner **across all N nodes**, not only
the opposite member of a pair. An authenticated direct overlay or a
controlled inter-Server routing fabric may be used, provided it has loop
protection, tenant isolation, bounded hop count, and epoch checks at TUN
ingress/egress. Membership and route updates must not require every Server
to hold every Client's live QUIC secrets or imply an O(N²) transport mesh.

If quorum is unavailable, nodes must **fail closed for new leases and peer
owner elections**; minority partitions must not allocate duplicate tunnel
IPs. A previously active Server may continue existing sessions only within
an explicitly defined, time-bounded ownership lease and ingress-fencing
policy. Merely copying a peer map or receiving traffic on a VIP never
authorizes a node to take over an encrypted QUIC session.

The configuration should be declarative: a controller publishes a validated
bundle and revision, each Server reconciles the revision into its existing
instance/peer reload code, and local `/readyz` must eventually depend on
committed revision, current CRL and ownership readiness. A file copied
between Servers is not a quorum protocol.

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
2. Each of the N Server nodes stages and validates that exact revision,
   then reports its applied digest. Incompatible or partial revisions **cannot** be served.
3. Each authenticated Client admission allocates a session owner epoch using
   a conditional transaction. Active owners periodically renew their lease.
4. On disconnect or peer revocation, the Server retires the epoch and
   releases ownership only after TUN/route egress fences and lease grace.
5. On crash, ingress and route control fence the old owner; only then
   can an eligible member of the N-node cluster claim a larger epoch. With no live QUIC crypto state, the
   returning Client creates a new QUIC/TLS connection to the same VIP.
6. For N-node active/active, every inner packet addressed to a Peer
   on another Server needs an encrypted **inter-Server P2MP forwarding**
   path and session-owner lookup, with loop and anti-replay prevention.
   Generic HAProxy TCP round-robin alone cannot supply this routing layer.

The synchronization channel must itself use mTLS with **distinct node
identities**, strict role authorization and auditable configuration version
changes. It must never expose CA signing keys, private Client keys, TLS
traffic key logs or unfenced lease writes to a replica.

## Acceptance matrix for implementation

| Test | Required assertion |
| --- | --- |
| Config revision published with N healthy Servers (N=2,3,5) | Every admitted node reports the same committed revision and applies matching Peer policy before ingress considers it ready |
| Policy/CA/CRL rotation | Revoked Client disconnects and cannot authenticate to **any** Server node, including QUIC/TCP fallback |
| Issuer cert issued with reused CN or unknown Peer CN | No access unless the instance's CA/identity policy explicitly authorizes it |
| CRL stale/unavailable with \`mode: crl\` | New Client authentication fails on every stale node; a fresh node cannot inherit a stale node's readiness |
| Concurrent dynamic lease requests on N nodes | Exactly one unique address owner across the entire cluster; no duplicate lease after crash/recovery |
| Majority/minority partition (Q=3 and Q=5), with N=2,3,5 Servers | No divergent session owner epoch, duplicate route injection or active-active lease allocation, even when all reachable VPN Servers are in the minority partition |
| Active Server crash, drain and member rejoin among N nodes | Existing Client configuration remains identical; Client reconnects to a live, fenced session owner with a higher epoch; a stale node cannot reclaim ownership |
| N-node active/active cross-Server Client-to-Client (N=3,5) | Bidirectional 20/20 Linux FIB/OSPF/BGP forwarding via authenticated owner resolution, tenant isolation and loop-free inter-Server transport |
| 1–8 WAN randomized five-site test across N=2,3,5 Servers | Same Client identity and policy across failover, no split connection across QUIC backend nodes |
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
