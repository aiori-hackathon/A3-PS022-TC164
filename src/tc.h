#ifndef DNS_TRACER_TC_H
#define DNS_TRACER_TC_H

// tc.h
//
// Definitions specific to the TC latency path: tc_dns_egress stamps a
// query's send time (plus name/type, parsed with the shared
// parse_dns_name_from_packet from common.h) into pending_queries;
// tc_dns_ingress looks it up by transaction ID on the matching response,
// computes latency, and emits a latency_event.

#include "common.h"

// Key structure for the query tracking map -- uniquely identifies a
// DNS transaction between a given client and the resolver.
struct query_key {
    __u16 query_id;      // DNS transaction ID
    __u32 client_ip;     // Client IP address
    __u16 client_port;   // Client source port
    __u16 padding;       // Alignment padding
};

// Value structure storing query metadata, captured on egress and read
// back on the matching ingress response.
struct query_info {
    __u8 raw_payload[512];   // Raw DNS payload, parsed on egress
    __u64 start_ts;                 // Timestamp when query was sent
    __u32 server_ip;
    __u16 query_type;               // DNS query type, parsed on egress
};

// Scratch map to prevent overflowing stack in TC
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct query_info);
    __uint(max_entries, 1);
} scratch_info SEC(".maps");

// Latency event sent to userspace once a response matches a pending query.
struct latency_event {
    __u64 timestamp;           // Event timestamp
    __u64 latency_ns;          // Round-trip latency in nanoseconds
    __u32 client_ip;           // Client IP address
    __u32 server_ip;           // DNS server IP
    __u16 client_port;         // Client Port
    __u16 query_id;            // Transaction ID
    __u16 query_type;          // Query type (A, AAAA, etc.)
    __u8  rcode;                // Response code
    __u8  is_timeout;           // 1 if this is a timeout event
    __u16 answer_count;        // Number of answers
    __u8 raw_payload[512];   // Raw DNS payload, parsed on ingress
};

// Hash map tracking in-flight DNS queries between egress and ingress.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct query_key);
    __type(value, struct query_info);
} pending_queries SEC(".maps");

// Ring buffer carrying latency_event records to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} latency_events SEC(".maps");

#endif // DNS_TRACER_TC_H
