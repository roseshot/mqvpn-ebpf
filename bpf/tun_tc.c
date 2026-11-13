// SPDX-License-Identifier: GPL-2.0
// Linux TCX (6.6+) on L3 TUN: packet data starts at an IPv4/IPv6 header.
// Two independent attachment points cover both Go->Linux (ingress) and
// Linux->Go (egress). No Ethernet header parsing, no route changes.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define DIR_INGRESS 0
#define DIR_EGRESS 1
#define MAX_EXT_HEADERS 6
#define MAX_TCP_OPT_BYTES 40

struct tun_settings {
    __u32 mtu;
    __u16 mss4;
    __u16 mss6;
    __u32 clamp;
};

struct tun_counters {
    __u64 packets;
    __u64 bytes;
    __u64 ipv4;
    __u64 ipv6;
    __u64 syn;
    __u64 clamped;
    __u64 oversize;
    __u64 parse_errors;
    __u64 checksum_errors;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tun_settings);
} tun_config SEC(".maps");

// One object per instance means each TUN gets independent configuration
// and counters; no user-controlled peer/session IDs in BPF.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct tun_counters);
} tun_stats SEC(".maps");

static __always_inline int load(struct __sk_buff *skb, __u32 off, void *dst, __u32 n) {
    if (off > skb->len || n > skb->len - off)
        return -1;
    return bpf_skb_load_bytes(skb, off, dst, n);
}

static __always_inline int ip_to_tcp(struct __sk_buff *skb, __u32 *offset,
                                     __u16 *max_mss, __u16 mss4, __u16 mss6,
                                     struct tun_counters *stats) {
    __u8 version;
    if (load(skb, 0, &version, sizeof(version)) < 0)
        return -1;
    switch (version >> 4) {
    case 4: {
        struct iphdr ip;
        if (load(skb, 0, &ip, sizeof(ip)) < 0 || ip.ihl < 5)
            return -1;
        __u32 hlen = (__u32)ip.ihl * 4;
        if (hlen > skb->len)
            return -1;
        stats->ipv4++;
        // Never mutate IP fragments (including first fragments).
        if (bpf_ntohs(ip.frag_off) & 0x3fff || ip.protocol != IPPROTO_TCP)
            return 0;
        *offset = hlen;
        *max_mss = mss4;
        return 1;
    }
    case 6: {
        struct ipv6hdr ip6;
        if (load(skb, 0, &ip6, sizeof(ip6)) < 0)
            return -1;
        stats->ipv6++;
        __u8 next = ip6.nexthdr;
        __u32 off = sizeof(ip6);
#pragma unroll
        for (int i = 0; i < MAX_EXT_HEADERS; i++) {
            if (next == IPPROTO_TCP) {
                *offset = off;
                *max_mss = mss6;
                return 1;
            }
            // Skip Fragment and ESP: no fragment reassembly or plaintext
            // inspection in TC. Unknown extension headers fail open.
            if (next == IPPROTO_FRAGMENT || next == IPPROTO_ESP)
                return 0;
            if (next != IPPROTO_HOPOPTS && next != IPPROTO_ROUTING &&
                next != IPPROTO_DSTOPTS && next != IPPROTO_AH)
                return 0;
            __u8 hdr[2];
            if (load(skb, off, hdr, 2) < 0)
                return -1;
            __u32 length = next == IPPROTO_AH ?
                           ((__u32)hdr[1] + 2) * 4 :
                           ((__u32)hdr[1] + 1) * 8;
            if (length < 8 || length > 2048 ||
                off > skb->len || length > skb->len - off)
                return -1;
            next = hdr[0];
            off += length;
        }
        return 0;
    }
    default:
        return 0;
    }
}

// Modifies only existing TCP MSS options in SYN / SYN-ACK. Never inserts
// options, never increases MSS, never rewrites payload, and fails open
// on malformed or non-TCP traffic. Unrecoverable checksum write failure
// drops the packet rather than forwarding it corrupted.
static __always_inline int clamp_syn(struct __sk_buff *skb, __u32 tcp_off,
                                      __u16 limit, struct tun_counters *stats) {
    __u8 tcp[20];
    if (load(skb, tcp_off, tcp, sizeof(tcp)) < 0) {
        stats->parse_errors++;
        return TC_ACT_OK;
    }
    if (!(tcp[13] & 0x02))
        return TC_ACT_OK;
    stats->syn++;
    __u32 header_len = (__u32)(tcp[12] >> 4) * 4;
    if (header_len < 20 || header_len > 60 ||
        tcp_off > skb->len || header_len > skb->len - tcp_off) {
        stats->parse_errors++;
        return TC_ACT_OK;
    }
    __u32 pos = tcp_off + 20;
    __u32 remaining = header_len - 20;
#pragma unroll
    for (int i = 0; i < MAX_TCP_OPT_BYTES; i++) {
        if (!remaining)
            break;
        __u8 kind;
        if (load(skb, pos, &kind, 1) < 0) {
            stats->parse_errors++;
            break;
        }
        if (kind == 0)
            break;
        if (kind == 1) {
            pos++;
            remaining--;
            continue;
        }
        if (remaining < 2) {
            stats->parse_errors++;
            break;
        }
        __u8 length;
        if (load(skb, pos + 1, &length, 1) < 0 ||
            length < 2 || length > remaining) {
            stats->parse_errors++;
            break;
        }
        if (kind == 2 && length == 4) {
            __be16 old_mss;
            if (load(skb, pos + 2, &old_mss, sizeof(old_mss)) < 0) {
                stats->parse_errors++;
                break;
            }
            if (bpf_ntohs(old_mss) <= limit)
                break;
            __be16 updated = bpf_htons(limit);
            // Incremental TCP checksum helper also handles CHECKSUM_PARTIAL
            // skb states; no userland checksum logic or netfilter rules.
            if (bpf_l4_csum_replace(skb, tcp_off + 16,
                                    old_mss, updated, sizeof(updated)) < 0) {
                stats->checksum_errors++;
                return TC_ACT_SHOT;
            }
            if (bpf_skb_store_bytes(skb, pos + 2, &updated, sizeof(updated), 0) < 0) {
                stats->checksum_errors++;
                return TC_ACT_SHOT;
            }
            stats->clamped++;
            break;
        }
        pos += length;
        remaining -= length;
    }
    return TC_ACT_OK;
}

static __always_inline int run_tun(struct __sk_buff *skb, __u32 direction) {
    struct tun_counters *stats = bpf_map_lookup_elem(&tun_stats, &direction);
    if (!stats)
        return TC_ACT_OK;
    stats->packets++;
    stats->bytes += skb->len;
    __u32 index = 0;
    struct tun_settings *conf = bpf_map_lookup_elem(&tun_config, &index);
    if (!conf)
        return TC_ACT_OK;
    if (conf->mtu && skb->len > conf->mtu)
        stats->oversize++;
    __u32 off = 0;
    __u16 limit = 0;
    int result = ip_to_tcp(skb, &off, &limit, conf->mss4, conf->mss6, stats);
    if (result < 0) {
        stats->parse_errors++;
        return TC_ACT_OK;
    }
    if (result == 0 || !conf->clamp || limit == 0)
        return TC_ACT_OK;
    return clamp_syn(skb, off, limit, stats);
}

SEC("tc")
int tc_mqvpn_ingress(struct __sk_buff *skb) {
    return run_tun(skb, DIR_INGRESS);
}
SEC("tc")
int tc_mqvpn_egress(struct __sk_buff *skb) {
    return run_tun(skb, DIR_EGRESS);
}
char LICENSE[] SEC("license") = "GPL";
