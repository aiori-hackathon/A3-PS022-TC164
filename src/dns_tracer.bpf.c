// dns_tracer.bpf.c
//
// XDP DNS flood limiter. For every packet:
//   P1  bounded parse   Ethernet -> IPv4 -> UDP:53 -> 12-byte DNS header
//   P2  per-source      token bucket per source IPv4 address (LRU hash)
//   P3  global          one token bucket shared by all port-53 queries
//   P4  verdict         XDP_PASS, or XDP_DROP before any skb is allocated
// Non-DNS traffic is passed untouched. Every verdict bumps a per-CPU counter.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define DNS_PORT     53
#define DNS_FLAG_QR  0x8000

// DNS wire header (RFC 1035 section 4.1.1)
struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

// ---------------------------------------------------------------------------
// Token bucket (lazy refill, fixed-point, no timers)
//
// Tokens are stored in units of 1e-9 token, so refill is simply
// elapsed_ns * rate_per_sec with no division and no lost remainder.
// One packet costs TOKEN_SCALE.
// ---------------------------------------------------------------------------

#define TOKEN_SCALE    1000000000ULL
#define MAX_REFILL_NS  (60 * 1000000000ULL)   // cap idle time credited at once

// Per-source state. Lives in an LRU hash, which does not support
// bpf_spin_lock, so updates are lock-free: two CPUs racing on the same
// source can at worst admit a packet or two extra.
struct src_bucket {
    __u64 tokens;
    __u64 last_update;
};

// Global state. Lives in an array map, so it can use a spin lock; every CPU
// touches this one entry, so exact accounting matters here.
struct global_bucket {
    __u64 tokens;
    __u64 last_update;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RATE_CFG_MAX);
    __type(key, __u32);
    __type(value, struct rate_config);
} rate_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);                 // source IPv4 address
    __type(value, struct src_bucket);
} src_token_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_bucket);
} global_token_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &idx);
    if (count)
        (*count)++;
}

// Refill the bucket for the time elapsed since last_update, then try to
// spend one token. Returns 1 if the packet is allowed.
static __always_inline int bucket_take(__u64 *tokens, __u64 *last_update,
                                       __u64 now,
                                       const struct rate_config *cfg)
{
    __u64 cap = cfg->burst * TOKEN_SCALE;
    __u64 delta = now > *last_update ? now - *last_update : 0;
    if (delta > MAX_REFILL_NS)
        delta = MAX_REFILL_NS;

    __u64 t = *tokens + delta * cfg->rate;
    if (t > cap)
        t = cap;
    *last_update = now;

    if (t >= TOKEN_SCALE) {
        *tokens = t - TOKEN_SCALE;
        return 1;
    }
    *tokens = t;
    return 0;
}

static __always_inline int src_allow(__u32 saddr, __u64 now,
                                     const struct rate_config *cfg)
{
    struct src_bucket *b = bpf_map_lookup_elem(&src_token_map, &saddr);
    if (!b) {
        // First packet from this source: start with a full bucket.
        struct src_bucket init = {
            .tokens = cfg->burst * TOKEN_SCALE,
            .last_update = now,
        };
        bpf_map_update_elem(&src_token_map, &saddr, &init, BPF_NOEXIST);
        b = bpf_map_lookup_elem(&src_token_map, &saddr);
        if (!b)
            return 1;       // fail open
    }
    return bucket_take(&b->tokens, &b->last_update, now, cfg);
}

static __always_inline int global_allow(__u64 now,
                                        const struct rate_config *cfg)
{
    __u32 key = 0;
    struct global_bucket *g = bpf_map_lookup_elem(&global_token_map, &key);
    if (!g)
        return 1;           // fail open

    int allowed;
    bpf_spin_lock(&g->lock);
    if (g->last_update == 0)    // first use: start full
        g->tokens = cfg->burst * TOKEN_SCALE;
    allowed = bucket_take(&g->tokens, &g->last_update, now, cfg);
    bpf_spin_unlock(&g->lock);
    return allowed;
}

SEC("xdp")
int xdp_dns_parser(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL_PACKETS);

    // ---- P1: bounded parse; every read is checked against data_end ----
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < (int)sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(DNS_PORT))
        return XDP_PASS;

    // From here on the packet is DNS-bound: a bad one is dropped and counted.
    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end ||
        (dns->flags & bpf_htons(DNS_FLAG_QR)) ||    // a query must have QR=0
        dns->qdcount == 0) {                        // ... and QDCOUNT >= 1
        inc_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    __u64 now = bpf_ktime_get_ns();

    // ---- P2: per-source limit ----
    __u32 idx = RATE_CFG_SRC;
    const struct rate_config *src_cfg = bpf_map_lookup_elem(&rate_config_map, &idx);
    if (src_cfg && !src_allow(ip->saddr, now, src_cfg)) {
        inc_stat(STAT_DROP_SRC_LIMIT);
        return XDP_DROP;
    }

    // ---- P3: global limit ----
    idx = RATE_CFG_GLOBAL;
    const struct rate_config *glob_cfg = bpf_map_lookup_elem(&rate_config_map, &idx);
    if (glob_cfg && !global_allow(now, glob_cfg)) {
        inc_stat(STAT_DROP_GLOBAL_LIMIT);
        return XDP_DROP;
    }

    // ---- P4: verdict ----
    inc_stat(STAT_DNS_PASSED);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";