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
    STAT_DROP_SRC_LIMIT,        // dropped by a per-source bucket
    STAT_DROP_GLOBAL_LIMIT,     // dropped by the global bucket
    STAT_DROP_BLOCKED,          // dropped because the source is BLOCKED
    STAT_ENTER_THROTTLED,       // state transitions (adaptive mode)
    STAT_ENTER_BLOCKED,
    STAT_ENTER_PROBATION,
    STAT_ENTER_NORMAL,          // recoveries back to NORMAL
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

// Per-source adaptive layer, written by user space into "adaptive_config_map".
//
//   NORMAL     -- rate R
//   THROTTLED  -- rate R / 2^(k * decay_shift)
//   BLOCKED    -- everything dropped until a timer expires
//   PROBATION  -- small fixed rate; any violation -> BLOCKED with timeout x2
//
// Time is divided into epochs of epoch_ns, evaluated lazily by the next
// packet (no timers). Each epoch's drop ratio feeds an EWMA "score".
struct adaptive_config {
    __u64 epoch_ns;             // epoch length
    __u64 probation_rate;       // PROBATION rate, packets per second
    __u64 block_ns;             // first BLOCKED duration (doubles on repeat)
    __u64 block_max_ns;         // cap on the BLOCKED duration
    __u32 enabled;              // 0 = plain static token bucket per source
    __u32 alpha_pct;            // EWMA weight of the newest epoch, 1..100
    __u32 theta_t_pct;          // score above this  -> bad epoch (throttle harder)
    __u32 theta_r_pct;          // score below this  -> good epoch (recover); < theta_t
    __u32 k_max;                // reaching this backoff level -> BLOCKED
    __u32 decay_shift;          // each backoff level divides the rate by 2^decay_shift
    __u32 probation_epochs;     // clean PROBATION epochs needed to return to NORMAL
    __u32 pad;
};

// Sanity limits so the fixed-point arithmetic in the BPF program cannot
// overflow a u64 (see bucket_take() in dns_tracer.bpf.c).
#define RATE_MAX        100000000ULL     // 100M packets/s
#define BURST_MAX       1000000000ULL    // 1G tokens
#define K_MAX_LIMIT     16
#define DECAY_SHIFT_MAX 8
#define BLOCK_MAX_NS    (100ULL * 1000000000ULL)   // 100 s

#endif // DNS_TRACER_COMMON_H