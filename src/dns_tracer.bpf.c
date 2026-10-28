// dns_tracer.bpf.c
//
// XDP DNS flood limiter. For every packet:
//   P1  bounded parse   Ethernet -> IPv4 -> UDP:53 -> 12-byte DNS header
//   P2  per-source      token bucket per source IPv4 address (LRU hash),
//                       optionally driven by the adaptive state machine
//                       NORMAL -> THROTTLED -> BLOCKED -> PROBATION
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

// Per-source state: the token bucket plus the adaptive state machine.
// Lives in an LRU hash, which does not support bpf_spin_lock, so updates are
// lock-free: two CPUs racing on the same source can at worst admit a packet
// or two extra, or delay a state transition by one epoch. LRU eviction drops
// a source's state, which resets its penalty.
enum src_state_id {
    SRC_NORMAL = 0,
    SRC_THROTTLED,
    SRC_BLOCKED,
    SRC_PROBATION,
};

struct src_state {
    __u64 tokens;
    __u64 last_update;
    __u64 epoch_start;
    __u64 blocked_until;
    __u32 epoch_total;      // packets seen this epoch
    __u32 epoch_dropped;    // ... of which dropped by this source's bucket
    __u32 score;            // EWMA of the per-epoch drop ratio, per-mille
    __u8  state;            // enum src_state_id
    __u8  k;                // THROTTLED backoff level
    __u8  block_level;      // BLOCKED duration doubles with each level
    __u8  clean_epochs;     // consecutive clean PROBATION epochs
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct adaptive_config);
} adaptive_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);                 // source IPv4 address
    __type(value, struct src_state);
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

// ---------------------------------------------------------------------------
// Per-source adaptive state machine
// ---------------------------------------------------------------------------

#define MAX_BLOCK_LEVEL   15    // BLOCKED duration doubles at most this many times
#define MAX_IDLE_EPOCHS   3     // quiet epochs credited at once after a gap

static __always_inline __u64 probation_burst(const struct adaptive_config *a)
{
    return a->probation_rate ? a->probation_rate : 1;   // one second's worth
}

static __always_inline void enter_normal(struct src_state *s)
{
    s->state = SRC_NORMAL;
    s->k = 0;
    s->score = 0;
    s->block_level = 0;
    s->clean_epochs = 0;
    inc_stat(STAT_ENTER_NORMAL);
}

static __always_inline void enter_blocked(struct src_state *s,
                                          const struct adaptive_config *a,
                                          __u64 now)
{
    __u32 lvl = s->block_level & MAX_BLOCK_LEVEL;
    __u64 t = a->block_ns << lvl;

    if (t > a->block_max_ns)
        t = a->block_max_ns;            // capped backoff: never permanent
    if (lvl < MAX_BLOCK_LEVEL)
        s->block_level = lvl + 1;
    s->state = SRC_BLOCKED;
    s->blocked_until = now + t;
    inc_stat(STAT_ENTER_BLOCKED);
}

static __always_inline void enter_probation(struct src_state *s,
                                            const struct adaptive_config *a,
                                            __u64 now)
{
    s->state = SRC_PROBATION;
    s->clean_epochs = 0;
    s->score = 0;
    s->k = 0;
    s->tokens = probation_burst(a) * TOKEN_SCALE;   // start full
    s->last_update = now;
    s->epoch_start = now;
    s->epoch_total = 0;
    s->epoch_dropped = 0;
    inc_stat(STAT_ENTER_PROBATION);
}

// Close one epoch: update the EWMA score from its drop ratio, then apply
// the transition. theta_r < theta_t gives hysteresis: a score between the two
// holds the current level.
static __always_inline void epoch_step(struct src_state *s,
                                       const struct adaptive_config *a,
                                       __u32 total, __u32 dropped, __u64 now)
{
    __u32 alpha = a->alpha_pct > 100 ? 100 : a->alpha_pct;
    __u32 ratio = total ? (__u32)(((__u64)dropped * 1000) / total) : 0;

    s->score = (s->score * (100 - alpha) + ratio * alpha) / 100;

    switch (s->state) {
    case SRC_NORMAL:
        if (s->score > a->theta_t_pct * 10) {
            s->state = SRC_THROTTLED;
            s->k = 1;
            inc_stat(STAT_ENTER_THROTTLED);
        }
        break;
    case SRC_THROTTLED:
        if (s->score > a->theta_t_pct * 10) {           // bad epoch: back off
            if (s->k + 1 >= a->k_max)
                enter_blocked(s, a, now);
            else
                s->k++;
        } else if (s->score < a->theta_r_pct * 10) {    // good epoch: recover
            if (s->k > 1)
                s->k--;
            else
                enter_normal(s);
        }
        break;
    case SRC_PROBATION:
        if (++s->clean_epochs >= a->probation_epochs)
            enter_normal(s);
        break;
    }
}

enum src_verdict {
    SRC_ALLOW = 0,
    SRC_DROP_LIMIT,
    SRC_DROP_BLOCKED,
};

static __always_inline int src_allow(__u32 saddr, __u64 now,
                                     const struct rate_config *cfg,
                                     const struct adaptive_config *a)
{
    struct src_state *s = bpf_map_lookup_elem(&src_token_map, &saddr);
    if (!s) {
        // First packet from this source: start NORMAL with a full bucket.
        struct src_state init = {
            .tokens = cfg->burst * TOKEN_SCALE,
            .last_update = now,
            .epoch_start = now,
        };
        bpf_map_update_elem(&src_token_map, &saddr, &init, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&src_token_map, &saddr);
        if (!s)
            return SRC_ALLOW;   // fail open
    }

    if (!a || !a->enabled)      // static mode: plain token bucket
        return bucket_take(&s->tokens, &s->last_update, now, cfg)
                   ? SRC_ALLOW : SRC_DROP_LIMIT;

    // BLOCKED: drop everything until the timer expires, then PROBATION.
    if (s->state == SRC_BLOCKED) {
        if (now < s->blocked_until)
            return SRC_DROP_BLOCKED;
        enter_probation(s, a, now);
    }

    // Lazy epoch rollover, evaluated by whichever packet arrives next.
    __u64 elapsed = now - s->epoch_start;
    if (a->epoch_ns && now > s->epoch_start && elapsed >= a->epoch_ns) {
        __u64 whole = elapsed / a->epoch_ns;

        epoch_step(s, a, s->epoch_total, s->epoch_dropped, now);
        #pragma unroll
        for (int i = 1; i <= MAX_IDLE_EPOCHS; i++)
            if (i < whole && s->state != SRC_BLOCKED)
                epoch_step(s, a, 0, 0, now);        // quiet epoch: ratio 0
        s->epoch_start = now;
        s->epoch_total = 0;
        s->epoch_dropped = 0;
        if (s->state == SRC_BLOCKED)
            return SRC_DROP_BLOCKED;
    }

    // Effective bucket for the current state.
    struct rate_config eff = *cfg;
    if (s->state == SRC_THROTTLED) {
        __u32 sh = s->k * a->decay_shift;
        if (sh > 63)
            sh = 63;
        eff.rate = cfg->rate >> sh;
        eff.burst = cfg->burst >> sh;
        if (!eff.burst)
            eff.burst = 1;
    } else if (s->state == SRC_PROBATION) {
        eff.rate = a->probation_rate;
        eff.burst = probation_burst(a);
    }

    int allowed = bucket_take(&s->tokens, &s->last_update, now, &eff);

    s->epoch_total++;
    if (!allowed) {
        s->epoch_dropped++;
        if (s->state == SRC_PROBATION)      // any violation on probation
            enter_blocked(s, a, now);
        return SRC_DROP_LIMIT;
    }
    return SRC_ALLOW;
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
    if (src_cfg) {
        __u32 zero = 0;
        const struct adaptive_config *adapt =
            bpf_map_lookup_elem(&adaptive_config_map, &zero);
        int v = src_allow(ip->saddr, now, src_cfg, adapt);

        if (v != SRC_ALLOW) {
            inc_stat(v == SRC_DROP_BLOCKED ? STAT_DROP_BLOCKED
                                           : STAT_DROP_SRC_LIMIT);
            return XDP_DROP;
        }
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