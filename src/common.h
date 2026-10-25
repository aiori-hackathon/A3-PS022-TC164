#ifndef DNS_TRACER_COMMON_H
#define DNS_TRACER_COMMON_H

// common.h
//
// Shared, hook-agnostic definitions used by both the XDP reader
// (xdp.h / xdp_dns_parser) and the TC latency tracker (tc.h /
// tc_dns_egress, tc_dns_ingress). Anything that both sides need
// identically lives here so it's defined exactly once.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define MAX_DNS_NAME_LEN 256

// ---------------------------------------------------------------------------
// DNS wire-format header (12 bytes, RFC 1035 section 4.1.1)
// Used to overlay directly on packet bytes in both XDP and TC.
// ---------------------------------------------------------------------------

struct DNSHeader {
    __be16 id;         // Transaction ID
    __be16 flags;      // Flags and codes
    __be16 qdcount;    // Question count
    __be16 ancount;    // Answer count
    __be16 nscount;    // Authority count
    __be16 arcount;    // Additional count
} __attribute__((packed));

// ---------------------------------------------------------------------------
// Shared enums
// ---------------------------------------------------------------------------

enum DNSType {
    DNS_TYPE_A     = 1,   // IPv4 address record
    DNS_TYPE_AAAA  = 28,  // IPv6 address record
    DNS_TYPE_CNAME = 5,   // Canonical name (alias)
    DNS_TYPE_MX    = 15,  // Mail exchange record
    DNS_TYPE_TXT   = 16,  // Text record
    DNS_TYPE_NS    = 2,   // Name server record
    DNS_TYPE_SOA   = 6,   // Start of authority
    DNS_TYPE_PTR   = 12,  // Pointer record (reverse DNS)
};

enum DNSRespCode {
    DNS_RCODE_NOERROR  = 0,  // No error
    DNS_RCODE_FORMERR  = 1,  // Format error
    DNS_RCODE_SERVFAIL = 2,  // Server failure
    DNS_RCODE_NXDOMAIN = 3,  // Non-existent domain
    DNS_RCODE_REFUSED  = 5,  // Query refused
};

// NOTE: this is a plain C enum (compiled by clang as C, not C++), so
// members are referenced unscoped, e.g. STAT_TOTAL_PACKETS -- never
// StatKeys::STAT_TOTAL_PACKETS. The '::' scope operator doesn't exist
// in C and won't compile.
enum StatKeys {
    STAT_TOTAL_PACKETS = 0,
    STAT_DNS_QUERIES,
    STAT_DNS_RESPONSES,
    STAT_PARSE_ERRORS,
    STAT_TRUNCATED,
    STAT_NXDOMAIN,
    STAT_RINGBUF_DROPS,
};

// ---------------------------------------------------------------------------
// Global packet statistics
//
// PERCPU_ARRAY instead of a plain ARRAY: a plain array shared across cores
// means every packet, on every CPU, does an atomic increment against the
// same cache line -- heavy contention under real traffic. PERCPU_ARRAY
// gives each core its own private slot (plain, non-atomic ++), and
// userspace sums the per-CPU values on read.
// ---------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &idx);
    if (count)
        (*count)++;
}

// ---------------------------------------------------------------------------
// Shared DNS name parser
//
// Parses a DNS name in wire format (length-prefixed labels, terminated by
// a zero-length label) starting at dns_start into a dotted string. Stops
// at the first compression pointer rather than following it. Bounded to
// 64 labels for the verifier. Used by both xdp_dns_parser (on every
// packet) and tc_dns_egress (to fill in query_info.name so tc_dns_ingress
// has something real to report instead of the uninitialized field the
// previous version left behind).
//
// Returns the number of bytes consumed from the DNS message, or -1 on
// a malformed / out-of-bounds name.
// ---------------------------------------------------------------------------

static __always_inline int parse_dns_name_from_packet(
    void *data,
    void *data_end,
    void *dns_start,
    char *out_buf,
    int max_len
) {
    /*
     * Temporary placeholder.
     *
     * DNS name parsing is disabled for now because the bounded
     * parser causes excessive verifier state explosion on the
     * CloudLab 5.15 kernel.
     *
     * We will move DNS name parsing to userspace later.
     */

    if (max_len > 0)
        out_buf[0] = '\0';

    return 0;
}

#endif // DNS_TRACER_COMMON_H
