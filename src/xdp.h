#ifndef DNS_TRACER_XDP_H
#define DNS_TRACER_XDP_H

// xdp.h
//
// Definitions specific to the XDP read path (xdp_dns_parser). Everything
// shared with the TC path lives in common.h instead.

#include "common.h"

// Parsed DNS event for userspace consumption -- one per packet seen by
// xdp_dns_parser (both queries and responses).
struct DNSQueryEvent {
    __u64 timestamp;           // Capture timestamp
    __u32 src_ip;              // Source IP address
    __u32 dst_ip;              // Destination IP address
    __u16 src_port;            // Source port
    __u16 dst_port;            // Destination port
    __u16 query_id;            // DNS transaction ID
    __u16 query_type;          // Query type (A, AAAA, etc.)
    __u16 query_class;         // Query class (usually IN)
    __u8  is_response;         // 0 = query, 1 = response
    __u8  rcode;                // Response code
    __u16 answer_count;        // Number of answers in response
    __u8  truncated;            // TC flag - message truncated
    __u8  authoritative;        // AA flag - authoritative answer
    __u8  raw_payload[512];   // Raw DNS payload, parsed on egress
};

// Ring buffer carrying DNSQueryEvent records to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB ring buffer
} dns_events SEC(".maps");

#endif // DNS_TRACER_XDP_H
