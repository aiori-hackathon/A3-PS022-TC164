#ifndef DNS_TRACER_COMMON_H
#define DNS_TRACER_COMMON_H

// Definitions shared by the BPF program (dns_tracer.bpf.c) and the
// user-space controller (dns_tracer.c). Plain types only -- no maps, no
// BPF helpers -- so it compiles on both sides.

#include <linux/types.h>

// Per-CPU packet counters (index into the "stats" map).
enum stat_key {
    STAT_TOTAL_PACKETS = 0,     // every packet seen by the XDP program
    STAT_DNS_PASSED,            // port-53 queries that passed both limiters
    STAT_DROP_MALFORMED,        // malformed port-53 packets
    STAT_DROP_SRC_LIMIT,        // dropped by the per-source bucket
    STAT_DROP_GLOBAL_LIMIT,     // dropped by the global bucket
    STAT_MAX
};

// Token-bucket parameters, written by user space into "rate_config_map".
struct rate_config {
    __u64 rate;     // sustained rate, tokens (packets) per second
    __u64 burst;    // bucket capacity, tokens
};

enum rate_config_idx {
    RATE_CFG_SRC = 0,       // per-source bucket
    RATE_CFG_GLOBAL = 1,    // global bucket
    RATE_CFG_MAX
};

// Sanity limits so the fixed-point arithmetic in the BPF program cannot
// overflow a u64 (see bucket_take() in dns_tracer.bpf.c).
#define RATE_MAX   100000000ULL     // 100M packets/s
#define BURST_MAX  1000000000ULL    // 1G tokens

#endif // DNS_TRACER_COMMON_H