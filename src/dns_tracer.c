// dns_tracer.c -- user-space controller for the XDP DNS rate limiter.
//
// Loads the BPF program, writes the token-bucket parameters into the config
// map, attaches XDP to an interface, and on exit prints the summed per-CPU
// counters.
//
//   sudo ./dns_tracer <iface> [src_rate src_burst global_rate global_burst]
//
// Rates are packets per second, bursts are packets.

#include <errno.h>
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

// Defaults -- placeholders, tune for the lab.
static struct rate_config cfg[RATE_CFG_MAX] = {
    [RATE_CFG_SRC]    = { .rate = 1000,  .burst = 100  },
    [RATE_CFG_GLOBAL] = { .rate = 20000, .burst = 1000 },
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static int parse_u64(const char *s, __u64 max, __u64 *out)
{
    char *end;

    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *end || v > max)
        return -1;
    *out = v;
    return 0;
}

static int parse_config(char **argv)
{
    if (parse_u64(argv[0], RATE_MAX,  &cfg[RATE_CFG_SRC].rate)     ||
        parse_u64(argv[1], BURST_MAX, &cfg[RATE_CFG_SRC].burst)    ||
        parse_u64(argv[2], RATE_MAX,  &cfg[RATE_CFG_GLOBAL].rate)  ||
        parse_u64(argv[3], BURST_MAX, &cfg[RATE_CFG_GLOBAL].burst)) {
        fprintf(stderr, "Invalid rate/burst (rate <= %llu, burst <= %llu)\n",
                (unsigned long long)RATE_MAX, (unsigned long long)BURST_MAX);
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
    if (argc != 2 && argc != 6) {
        fprintf(stderr,
                "Usage: sudo %s <iface> [src_rate src_burst global_rate global_burst]\n",
                argv[0]);
        return 1;
    }

    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Interface '%s' not found: %s\n", argv[1], strerror(errno));
        return 1;
    }
    if (argc == 6 && parse_config(argv + 2))
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

    err = bpf_xdp_attach(ifindex, bpf_program__fd(obj->progs.xdp_dns_parser),
                         XDP_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n", argv[1], strerror(-err));
        goto out;
    }

    printf("XDP attached to %s\n", argv[1]);
    printf("  per-source: %llu pkt/s, burst %llu\n",
           (unsigned long long)cfg[RATE_CFG_SRC].rate,
           (unsigned long long)cfg[RATE_CFG_SRC].burst);
    printf("  global    : %llu pkt/s, burst %llu\n",
           (unsigned long long)cfg[RATE_CFG_GLOBAL].rate,
           (unsigned long long)cfg[RATE_CFG_GLOBAL].burst);
    printf("Press Ctrl+C to stop.\n");

    while (!exiting)
        sleep(1);

    print_stats(bpf_map__fd(obj->maps.stats));
    bpf_xdp_detach(ifindex, XDP_MODE, NULL);

out:
    dns_tracer_bpf__destroy(obj);
    return err ? 1 : 0;
}