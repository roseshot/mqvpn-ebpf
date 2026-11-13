// SPDX-License-Identifier: GPL-2.0
// Shared server-side XDP dispatcher: one program per physical WAN interface.
// The Go control plane hot-updates instance_ports when server instances change.
// This is a strict, statistics-only XDP program. All VPN traffic goes
// through the Linux UDP stack; no dormant AF_XDP/XSKMAP scaffolding.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);     // Host-byte-order destination UDP port.
    __type(value, __u8);    // Nonzero means the port belongs to an instance.
} instance_ports SEC(".maps");

// Per-CPU counters keep the XDP fast path free of global atomics.
// This dispatcher never blocks unrelated WAN traffic.
struct xdp_counters {
    __u64 packets;
    __u64 bytes;
    __u64 matched_udp;
    __u64 matched_bytes;
    __u64 vlan;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_counters);
} xdp_stats SEC(".maps");

struct vlan_header {
    __be16 tci;
    __be16 proto;
};

static __always_inline int dispatch_udp(void *l4, void *end, struct xdp_md *ctx,
                                        struct xdp_counters *stats) {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > end)
        return XDP_PASS;
    __u16 dport = bpf_ntohs(udp->dest);
    __u8 *enabled = bpf_map_lookup_elem(&instance_ports, &dport);
    if (!enabled || !*enabled)
        return XDP_PASS;
    if (stats) {
        stats->matched_udp++;
        stats->matched_bytes += (__u64)((long)ctx->data_end - (long)ctx->data);
    }

    // The XDP data plane measures the encrypted WAN packet; Go owns
    // the QUIC UDP socket and is solely responsible for RX/TX.
    return XDP_PASS;
}

SEC("xdp")
int xdp_mqvpn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u32 stats_key = 0;
    struct xdp_counters *stats = bpf_map_lookup_elem(&xdp_stats, &stats_key);
    if (stats) {
        stats->packets++;
        stats->bytes += (__u64)((long)end - (long)data);
    }
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return XDP_PASS;

    __be16 proto = eth->h_proto;
    void *l3 = eth + 1;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) &&
            proto != bpf_htons(ETH_P_8021AD))
            break;
        struct vlan_header *v = l3;
        if (stats)
            stats->vlan++;
        if ((void *)(v + 1) > end)
            return XDP_PASS;
        proto = v->proto;
        l3 = v + 1;
    }

    void *l4;
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > end || ip->version != 4 ||
            ip->ihl < 5 || ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        // IP fragmentation is handled by the kernel stack.
        if (ip->frag_off & bpf_htons(0x3fff))
            return XDP_PASS;
        l4 = (void *)ip + ip->ihl * 4;
        if (l4 > end)
            return XDP_PASS;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > end || ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS; // IPv6 extension headers stay on kernel path.
        l4 = ip6 + 1;
    } else {
        return XDP_PASS;
    }
    return dispatch_udp(l4, end, ctx, stats);
}

char LICENSE[] SEC("license") = "GPL";
