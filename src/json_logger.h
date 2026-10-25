#ifndef JSON_LOGGER_H
#define JSON_LOGGER_H

#include <stddef.h>
#include <stdint.h>

/*
 * These structures MUST remain layout-compatible with
 * xdp.h and tc.h.
 *
 * They are kept here so dns_tracer.c and json_logger.c
 * share the exact same userspace event definitions.
 */

#define JSON_LOGGER_DNS_PAYLOAD_MAX 512

struct DNSQueryEvent {
    uint64_t timestamp;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint16_t query_id;
    uint16_t query_type;
    uint16_t query_class;

    uint8_t  is_response;
    uint8_t  rcode;

    uint16_t answer_count;

    uint8_t  truncated;
    uint8_t  authoritative;

    uint8_t  raw_payload[JSON_LOGGER_DNS_PAYLOAD_MAX];
};

struct latency_event {
    uint64_t timestamp;
    uint64_t latency_ns;

    uint32_t client_ip;
    uint32_t server_ip;

    uint16_t client_port;

    uint16_t query_id;
    uint16_t query_type;

    uint8_t  rcode;
    uint8_t  is_timeout;

    uint16_t answer_count;

    uint8_t  raw_payload[JSON_LOGGER_DNS_PAYLOAD_MAX];
};


/*
 * Start a new JSON file for this tracer run.
 *
 * Example:
 *
 *     json/run_20260907_173012_12345.json
 */
int json_logger_init(const char *interface_name);


/*
 * Record an XDP event.
 *
 * Both QUERY and RESPONSE events are accepted.
 */
void json_logger_record_xdp(const struct DNSQueryEvent *event);


/*
 * Record a TC latency event.
 */
void json_logger_record_latency(const struct latency_event *event);


/*
 * Finish the JSON document and close the file.
 *
 * Must be called before the tracer exits.
 */
void json_logger_close(void);

#endif /* JSON_LOGGER_H */