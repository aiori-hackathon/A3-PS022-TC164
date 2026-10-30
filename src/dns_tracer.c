// dns_tracer.c -- user-space controller for the XDP DNS rate limiter.
//
// Loads the BPF program, writes the token-bucket and adaptive parameters
// into the config maps, attaches XDP to an interface, and on exit prints the
// summed per-CPU counters.

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "dns_tracer.skel.h"

#define XDP_MODE XDP_FLAGS_SKB_MODE     // generic mode; XDP_FLAGS_DRV_MODE for native
#define MS_TO_NS 1000000ULL

// Defaults -- placeholders, tune for the lab.
static struct rate_config cfg[RATE_CFG_MAX] = {
    [RATE_CFG_SRC]    = { .rate = 1000,  .burst = 100  },
    [RATE_CFG_GLOBAL] = { .rate = 20000, .burst = 1000 },
};

static struct adaptive_config acfg = {
    .enabled          = 0,
    .epoch_ns         = 1000 * MS_TO_NS,
    .alpha_pct        = 50,
    .theta_t_pct      = 30,
    .theta_r_pct      = 10,
    .k_max            = 4,
    .decay_shift      = 1,
    .probation_rate   = 10,
    .probation_epochs = 3,
    .block_ns         = 5000 * MS_TO_NS,
    .block_max_ns     = 60000 * MS_TO_NS,
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s [options] <iface> [src_rate src_burst global_rate global_burst]\n"
        "\n"
        "Rates are packets per second, bursts are packets.\n"
        "Defaults: src 1000/100, global 20000/1000.\n"
        "\n"
        "Adaptive per-source state machine (off by default):\n"
        "  --adaptive             enable NORMAL/THROTTLED/BLOCKED/PROBATION\n"
        "  --epoch-ms N           epoch length                     (1000)\n"
        "  --alpha PCT            EWMA weight of newest epoch      (50)\n"
        "  --theta-t PCT          score above this = bad epoch     (30)\n"
        "  --theta-r PCT          score below this = good epoch    (10, < theta-t)\n"
        "  --k-max N              backoff level that blocks        (4)\n"
        "  --decay-shift N        rate / 2^(k*N) per level         (1)\n"
        "  --probation-rate N     PROBATION rate, pkt/s            (10)\n"
        "  --probation-epochs N   clean epochs to return to NORMAL (3)\n"
        "  --block-ms N           first block duration, doubles    (5000)\n"
        "  --block-max-ms N       block duration cap               (60000)\n",
        prog);
}

// Parse a decimal integer in [min, max].
static int parse_u64(const char *s, __u64 min, __u64 max, __u64 *out)
{
    char *end;

    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *end || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

static int parse_u32(const char *name, const char *s, __u64 min, __u64 max, __u32 *out)
{
    __u64 v;

    if (parse_u64(s, min, max, &v)) {
        fprintf(stderr, "Invalid %s '%s' (expected %llu..%llu)\n", name, s,
                (unsigned long long)min, (unsigned long long)max);
        return -1;
    }
    *out = (__u32)v;
    return 0;
}

static int parse_ms(const char *name, const char *s, __u64 min_ms, __u64 max_ms, __u64 *ns)
{
    __u64 v;

    if (parse_u64(s, min_ms, max_ms, &v)) {
        fprintf(stderr, "Invalid %s '%s' (expected %llu..%llu ms)\n", name, s,
                (unsigned long long)min_ms, (unsigned long long)max_ms);
        return -1;
    }
    *ns = v * MS_TO_NS;
    return 0;
}

static int parse_config(char **argv)
{
    if (parse_u64(argv[0], 0, RATE_MAX,  &cfg[RATE_CFG_SRC].rate)     ||
        parse_u64(argv[1], 0, BURST_MAX, &cfg[RATE_CFG_SRC].burst)    ||
        parse_u64(argv[2], 0, RATE_MAX,  &cfg[RATE_CFG_GLOBAL].rate)  ||
        parse_u64(argv[3], 0, BURST_MAX, &cfg[RATE_CFG_GLOBAL].burst)) {
        fprintf(stderr, "Invalid rate/burst (rate <= %llu, burst <= %llu)\n",
                (unsigned long long)RATE_MAX, (unsigned long long)BURST_MAX);
        return -1;
    }
    return 0;
}

enum {
    OPT_ADAPTIVE = 256, OPT_EPOCH_MS, OPT_ALPHA, OPT_THETA_T, OPT_THETA_R,
    OPT_K_MAX, OPT_DECAY_SHIFT, OPT_PROB_RATE, OPT_PROB_EPOCHS,
    OPT_BLOCK_MS, OPT_BLOCK_MAX_MS,
};

static const struct option long_opts[] = {
    { "adaptive",          no_argument,       NULL, OPT_ADAPTIVE },
    { "epoch-ms",          required_argument, NULL, OPT_EPOCH_MS },
    { "alpha",             required_argument, NULL, OPT_ALPHA },
    { "theta-t",           required_argument, NULL, OPT_THETA_T },
    { "theta-r",           required_argument, NULL, OPT_THETA_R },
    { "k-max",             required_argument, NULL, OPT_K_MAX },
    { "decay-shift",       required_argument, NULL, OPT_DECAY_SHIFT },
    { "probation-rate",    required_argument, NULL, OPT_PROB_RATE },
    { "probation-epochs",  required_argument, NULL, OPT_PROB_EPOCHS },
    { "block-ms",          required_argument, NULL, OPT_BLOCK_MS },
    { "block-max-ms",      required_argument, NULL, OPT_BLOCK_MAX_MS },
    { "help",              no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

// Returns 0 on success, 1 for --help, -1 on a bad option.
static int parse_options(int argc, char **argv)
{
    int opt;
    __u64 v;

    while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        int bad = 0;

        switch (opt) {
        case OPT_ADAPTIVE:  acfg.enabled = 1; break;
        case OPT_EPOCH_MS:  bad = parse_ms("--epoch-ms", optarg, 1, 3600000, &acfg.epoch_ns); break;
        case OPT_ALPHA:     bad = parse_u32("--alpha", optarg, 1, 100, &acfg.alpha_pct); break;
        case OPT_THETA_T:   bad = parse_u32("--theta-t", optarg, 1, 100, &acfg.theta_t_pct); break;
        case OPT_THETA_R:   bad = parse_u32("--theta-r", optarg, 0, 99, &acfg.theta_r_pct); break;
        case OPT_K_MAX:     bad = parse_u32("--k-max", optarg, 2, K_MAX_LIMIT, &acfg.k_max); break;
        case OPT_DECAY_SHIFT: bad = parse_u32("--decay-shift", optarg, 1, DECAY_SHIFT_MAX, &acfg.decay_shift); break;
        case OPT_PROB_RATE:
            bad = parse_u64(optarg, 1, RATE_MAX, &v);
            if (bad)
                fprintf(stderr, "Invalid --probation-rate '%s'\n", optarg);
            else
                acfg.probation_rate = v;
            break;
        case OPT_PROB_EPOCHS: bad = parse_u32("--probation-epochs", optarg, 1, 1000, &acfg.probation_epochs); break;
        case OPT_BLOCK_MS:  bad = parse_ms("--block-ms", optarg, 1, BLOCK_MAX_NS / MS_TO_NS, &acfg.block_ns); break;
        case OPT_BLOCK_MAX_MS: bad = parse_ms("--block-max-ms", optarg, 1, BLOCK_MAX_NS / MS_TO_NS, &acfg.block_max_ns); break;
        case 'h': return 1;
        default:  return -1;
        }
        if (bad)
            return -1;
    }

    if (acfg.theta_r_pct >= acfg.theta_t_pct) {
        fprintf(stderr, "--theta-r (%u) must be below --theta-t (%u)\n",
                acfg.theta_r_pct, acfg.theta_t_pct);
        return -1;
    }
    if (acfg.block_max_ns < acfg.block_ns) {
        fprintf(stderr, "--block-max-ms must be >= --block-ms\n");
        return -1;
    }
    return 0;
}

static void print_stats(int fd)
{
    static const char *names[STAT_MAX] = {
        [STAT_TOTAL_PACKETS]     = "total_packets",
        [STAT_DNS_PASSED]        = "dns_passed",
        [STAT_DROP_MALFORMED]    = "drop_malformed",
        [STAT_DROP_SRC_LIMIT]    = "drop_src_limit",
        [STAT_DROP_GLOBAL_LIMIT] = "drop_global_limit",
        [STAT_DROP_BLOCKED]      = "drop_blocked",
        [STAT_ENTER_THROTTLED]   = "enter_throttled",
        [STAT_ENTER_BLOCKED]     = "enter_blocked",
        [STAT_ENTER_PROBATION]   = "enter_probation",
        [STAT_ENTER_NORMAL]      = "enter_normal",
    };

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0)
        return;

    uint64_t *vals = calloc(ncpu, sizeof(*vals));
    if (!vals)
        return;

    printf("\n---------- stats ----------\n");
    for (uint32_t k = 0; k < STAT_MAX; k++) {
        if (bpf_map_lookup_elem(fd, &k, vals))
            continue;

        uint64_t sum = 0;
        for (int i = 0; i < ncpu; i++)
            sum += vals[i];
        printf("  %-18s %llu\n", names[k], (unsigned long long)sum);
    }
    printf("---------------------------\n");

    free(vals);
}

int main(int argc, char **argv)
{
    int rc = parse_options(argc, argv);
    if (rc) {
        usage(argv[0]);
        return rc > 0 ? 0 : 1;
    }

    int nargs = argc - optind;
    if (nargs != 1 && nargs != 5) {
        usage(argv[0]);
        return 1;
    }
    const char *ifname = argv[optind];

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interface '%s' not found: %s\n", ifname, strerror(errno));
        return 1;
    }
    if (nargs == 5 && parse_config(argv + optind + 1))
        return 1;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct dns_tracer_bpf *obj = dns_tracer_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }

    int err = 0;
    int cfg_fd = bpf_map__fd(obj->maps.rate_config_map);
    for (uint32_t i = 0; i < RATE_CFG_MAX; i++) {
        if (bpf_map_update_elem(cfg_fd, &i, &cfg[i], BPF_ANY)) {
            err = -errno;
            fprintf(stderr, "Failed to write rate config: %s\n", strerror(-err));
            goto out;
        }
    }

    uint32_t zero = 0;
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.adaptive_config_map),
                            &zero, &acfg, BPF_ANY)) {
        err = -errno;
        fprintf(stderr, "Failed to write adaptive config: %s\n", strerror(-err));
        goto out;
    }

    err = bpf_set_link_xdp_fd(ifindex, 
                          bpf_program__fd(obj->progs.xdp_dns_parser), 
                          XDP_MODE);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n", ifname, strerror(-err));
        goto out;
    }

    printf("XDP attached to %s\n", ifname);
    printf("  per-source: %llu pkt/s, burst %llu\n",
           (unsigned long long)cfg[RATE_CFG_SRC].rate,
           (unsigned long long)cfg[RATE_CFG_SRC].burst);
    printf("  global    : %llu pkt/s, burst %llu\n",
           (unsigned long long)cfg[RATE_CFG_GLOBAL].rate,
           (unsigned long long)cfg[RATE_CFG_GLOBAL].burst);
    if (acfg.enabled)
        printf("  adaptive  : on  epoch=%llums alpha=%u%% theta_t=%u%% theta_r=%u%% "
               "k_max=%u decay=1/2^%u per level\n"
               "              probation=%llu pkt/s x%u clean epochs, "
               "block=%llums (cap %llums)\n",
               (unsigned long long)(acfg.epoch_ns / MS_TO_NS), acfg.alpha_pct,
               acfg.theta_t_pct, acfg.theta_r_pct, acfg.k_max, acfg.decay_shift,
               (unsigned long long)acfg.probation_rate, acfg.probation_epochs,
               (unsigned long long)(acfg.block_ns / MS_TO_NS),
               (unsigned long long)(acfg.block_max_ns / MS_TO_NS));
    else
        printf("  adaptive  : off (static token bucket per source)\n");
    printf("Press Ctrl+C to stop.\n");

    while (!exiting)
        sleep(1);

    print_stats(bpf_map__fd(obj->maps.stats));
    bpf_set_link_xdp_fd(ifindex, -1, XDP_MODE);

out:
    dns_tracer_bpf__destroy(obj);
    return err ? 1 : 0;
}