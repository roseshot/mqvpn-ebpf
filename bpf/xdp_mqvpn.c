// SPDX-License-Identifier: GPL-2.0
// EXPERIMENTAL XDP redirect stage for Intel I226 / igc.
// This object is NOT attached by the Go UDP backend.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef MQVPN_UDP_PORT
#define MQVPN_UDP_PORT 4433
#endif

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct vlan_header { __be16 tci; __be16 proto; };

static __always_inline int check_udp(void *l4, void *end) {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > end) return XDP_PASS;
    // Incoming server traffic has destination port 4433;
    // incoming client traffic normally has source port 4433.
    if (udp->source != bpf_htons(MQVPN_UDP_PORT) &&
        udp->dest != bpf_htons(MQVPN_UDP_PORT)) return XDP_PASS;
    return 0;
}

SEC("xdp")
int xdp_mqvpn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    __be16 proto = eth->h_proto;
    void *l3 = eth + 1;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) &&
            proto != bpf_htons(ETH_P_8021AD)) break;
        struct vlan_header *v = l3;
        if ((void *)(v + 1) > end) return XDP_PASS;
        proto = v->proto;
        l3 = v + 1;
    }

    void *l4;
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > end || ip->version != 4 ||
            ip->ihl < 5 || ip->protocol != IPPROTO_UDP) return XDP_PASS;
        // IPv4 fragments remain in the kernel slow path.
        if (ip->frag_off & bpf_htons(0x3fff)) return XDP_PASS;
        l4 = (void *)ip + ip->ihl * 4;
        if (l4 > end) return XDP_PASS;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > end ||
            ip6->nexthdr != IPPROTO_UDP) return XDP_PASS;
        // IPv6 extension headers are not redirected.
        l4 = ip6 + 1;
    } else return XDP_PASS;

    if (check_udp(l4, end) != 0) return XDP_PASS;
    // The XSK must be bound to this device AND rx_queue_index.
    // Missing XSK -> XDP_PASS, not silent drop.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
