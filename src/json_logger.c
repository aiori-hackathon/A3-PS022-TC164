#include "json_logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "dns_parser.h"

#define JSON_DIRECTORY "json"
#define MAX_PENDING_TRANSACTIONS 4096

/* ============================================================================
 * JSON logger state
 * ========================================================================== */

static FILE *json_file = NULL;
static bool first_query = true;
static char json_filename[PATH_MAX];

/* ============================================================================
 * Transaction correlation
 * ========================================================================== */

struct pending_transaction {
    bool used;

    /*
     * Normalized DNS transaction identity:
     *
     *   query_id + client_ip + client_port + server_ip
     */
    uint16_t query_id;
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t server_ip;

    /*
     * XDP sees only the DNS response.
     */
    bool have_xdp_response;
    struct DNSQueryEvent xdp_response;

    /*
     * TC latency event contains:
     *   - the original DNS query payload
     *   - the measured latency
     */
    bool have_latency;
    struct latency_event latency;
};

static struct pending_transaction pending[MAX_PENDING_TRANSACTIONS];

/* ============================================================================
 * Basic helpers
 * ========================================================================== */

static void ip_to_string(uint32_t ip, char *buf, size_t len)
{
    if (!inet_ntop(AF_INET, &ip, buf, len))
        snprintf(buf, len, "?");
}

static const char *query_type_name(uint16_t type)
{
    return dns_type_name(type);
}

/*
 * Find an existing transaction.
 */
static struct pending_transaction *
find_transaction(uint16_t query_id,
                 uint32_t client_ip,
                 uint16_t client_port,
                 uint32_t server_ip)
{
    for (size_t i = 0; i < MAX_PENDING_TRANSACTIONS; i++) {
        if (!pending[i].used)
            continue;

        if (pending[i].query_id != query_id)
            continue;

        if (pending[i].client_ip != client_ip)
            continue;

        if (pending[i].client_port != client_port)
            continue;

        if (pending[i].server_ip != server_ip)
            continue;

        return &pending[i];
    }

    return NULL;
}

/*
 * Allocate a new transaction slot.
 */
static struct pending_transaction *allocate_transaction(void)
{
    for (size_t i = 0; i < MAX_PENDING_TRANSACTIONS; i++) {
        if (!pending[i].used) {
            memset(&pending[i], 0, sizeof(pending[i]));
            pending[i].used = true;
            return &pending[i];
        }
    }

    return NULL;
}

/* ============================================================================
 * JSON helpers
 * ========================================================================== */

static void json_escape(FILE *f, const char *s)
{
    fputc('"', f);

    if (s) {
        for (; *s; s++) {
            unsigned char c = (unsigned char)*s;

            switch (c) {
            case '"':
                fputs("\\\"", f);
                break;

            case '\\':
                fputs("\\\\", f);
                break;

            case '\b':
                fputs("\\b", f);
                break;

            case '\f':
                fputs("\\f", f);
                break;

            case '\n':
                fputs("\\n", f);
                break;

            case '\r':
                fputs("\\r", f);
                break;

            case '\t':
                fputs("\\t", f);
                break;

            default:
                if (c < 0x20)
                    fprintf(f, "\\u%04x", c);
                else
                    fputc(c, f);
                break;
            }
        }
    }

    fputc('"', f);
}

/*
 * Write raw DNS bytes as one continuous hex string.
 */
static void json_raw_payload(FILE *f,
                             const uint8_t *payload,
                             size_t len)
{
    fputc('"', f);

    for (size_t i = 0; i < len; i++)
        fprintf(f, "%02x", payload[i]);

    fputc('"', f);
}

/* ============================================================================
 * DNS parsed-message JSON
 * ========================================================================== */

static void json_rr(FILE *f, const struct dns_rr *rr)
{
    fprintf(f, "{\"name\":");
    json_escape(f, rr->name);

    fprintf(f,
            ",\"type\":%u,"
            "\"type_name\":",
            rr->type);

    json_escape(f, dns_type_name(rr->type));

    fprintf(f,
            ",\"class\":%u,"
            "\"class_name\":",
            rr->rrclass);

    json_escape(f, dns_class_name(rr->rrclass));

    fprintf(f,
            ",\"ttl\":%u,"
            "\"rdlength\":%u,"
            "\"rdata\":",
            rr->ttl,
            rr->rdlength);

    json_escape(f, rr->rdata);

    fputc('}', f);
}

static void json_rr_array(FILE *f,
                          const struct dns_rr *records,
                          size_t count)
{
    fputc('[', f);

    for (size_t i = 0; i < count; i++) {
        if (i)
            fputc(',', f);

        json_rr(f, &records[i]);
    }

    fputc(']', f);
}

static void json_dns_message(FILE *f,
                             const struct dns_message *m)
{
    fprintf(f,
            "{"
            "\"id\":%u,"
            "\"flags\":%u,"
            "\"qr\":%u,"
            "\"opcode\":%u,"
            "\"aa\":%u,"
            "\"tc\":%u,"
            "\"rd\":%u,"
            "\"ra\":%u,"
            "\"ad\":%u,"
            "\"cd\":%u,"
            "\"rcode\":%u,"
            "\"rcode_name\":",
            m->id,
            m->flags,
            m->qr,
            m->opcode,
            m->aa,
            m->tc,
            m->rd,
            m->ra,
            m->ad,
            m->cd,
            m->rcode);

    json_escape(f, dns_rcode_name(m->rcode));

    fprintf(f,
            ",\"counts\":{"
            "\"questions\":%u,"
            "\"answers\":%u,"
            "\"authority\":%u,"
            "\"additional\":%u},"
            "\"questions\":[",
            m->qdcount,
            m->ancount,
            m->nscount,
            m->arcount);

    for (size_t i = 0; i < m->question_count; i++) {
        if (i)
            fputc(',', f);

        fprintf(f, "{\"name\":");
        json_escape(f, m->questions[i].name);

        fprintf(f,
                ",\"type\":%u,"
                "\"type_name\":",
                m->questions[i].type);

        json_escape(f, dns_type_name(m->questions[i].type));

        fprintf(f,
                ",\"class\":%u,"
                "\"class_name\":",
                m->questions[i].qclass);

        json_escape(f, dns_class_name(m->questions[i].qclass));

        fputc('}', f);
    }

    fprintf(f, "],\"answers\":");
    json_rr_array(f, m->answers, m->answer_count);

    fprintf(f, ",\"authority\":");
    json_rr_array(f, m->authority, m->authority_count);

    fprintf(f, ",\"additional\":");
    json_rr_array(f, m->additional, m->additional_count);

    fprintf(f,
            ",\"parse_ok\":%s,"
            "\"parsed_len\":%zu,"
            "\"truncated_by_capture\":%s",
            m->parse_ok ? "true" : "false",
            m->parsed_len,
            m->truncated_by_capture ? "true" : "false");

    fputc('}', f);
}

/*
 * Parse a captured DNS payload.
 *
 * The BPF event contains a fixed 512-byte payload buffer. The parser
 * determines how many bytes form the DNS message.
 */
static size_t parse_payload(const uint8_t *payload,
                            struct dns_message *message,
                            bool *parse_ok)
{
    memset(message, 0, sizeof(*message));
    *parse_ok = false;

    if (!payload)
        return 0;

    if (dns_parse_message(payload,
                          JSON_LOGGER_DNS_PAYLOAD_MAX,
                          message) == 0) {
        *parse_ok = true;

        if (message->parsed_len <= JSON_LOGGER_DNS_PAYLOAD_MAX)
            return message->parsed_len;
    }

    return message->parsed_len;
}

/* ============================================================================
 * Query JSON
 * ========================================================================== */

static void json_query(FILE *f,
                       const struct latency_event *event)
{
    struct dns_message query;
    bool parse_ok;

    size_t dns_len =
        parse_payload(event->raw_payload,
                       &query,
                       &parse_ok);

    fprintf(f,
            "{"
            "\"raw_payload_len\":%zu,"
            "\"raw_payload_hex\":",
            dns_len);

    json_raw_payload(f,
                     event->raw_payload,
                     dns_len);

    fprintf(f, ",\"parsed\":");

    if (parse_ok)
        json_dns_message(f, &query);
    else
        fputs("null", f);

    fputc('}', f);
}

/* ============================================================================
 * Response JSON
 * ========================================================================== */

static void json_response(FILE *f,
                          const struct DNSQueryEvent *event)
{
    struct dns_message response;
    bool parse_ok;

    size_t dns_len =
        parse_payload(event->raw_payload,
                       &response,
                       &parse_ok);

    fprintf(f,
            "{"
            "\"timestamp_ns\":%llu,"
            "\"raw_payload_len\":%zu,"
            "\"raw_payload_hex\":",
            (unsigned long long)event->timestamp,
            dns_len);

    json_raw_payload(f,
                     event->raw_payload,
                     dns_len);

    fprintf(f, ",\"parsed\":");

    if (parse_ok)
        json_dns_message(f, &response);
    else
        fputs("null", f);

    fputc('}', f);
}

/* ============================================================================
 * Latency JSON
 * ========================================================================== */

static void json_latency(FILE *f,
                         const struct latency_event *event)
{
    fprintf(f,
            "{"
            "\"timestamp_ns\":%llu,"
            "\"latency_ns\":%llu,"
            "\"latency_ms\":%.3f,"
            "\"is_timeout\":%s"
            "}",
            (unsigned long long)event->timestamp,
            (unsigned long long)event->latency_ns,
            (double)event->latency_ns / 1000000.0,
            event->is_timeout ? "true" : "false");
}

/* ============================================================================
 * Write complete transaction
 * ========================================================================== */

static void write_transaction(struct pending_transaction *tx)
{
    if (!json_file)
        return;

    /*
     * IMPORTANT:
     * Only this function controls commas between query objects.
     * Every query object is opened with '{' and closed with '}' here.
     */
    if (!first_query)
        fputc(',', json_file);

    first_query = false;

    char client[INET_ADDRSTRLEN];
    char server[INET_ADDRSTRLEN];

    ip_to_string(tx->client_ip,
                 client,
                 sizeof(client));

    ip_to_string(tx->server_ip,
                 server,
                 sizeof(server));

    fprintf(json_file,
            "{"
            "\"query_id\":%u,"
            "\"client\":{"
            "\"ip\":",
            tx->query_id);

    json_escape(json_file, client);

    fprintf(json_file,
            ",\"port\":%u"
            "},"
            "\"server\":{"
            "\"ip\":",
            tx->client_port);

    json_escape(json_file, server);

    fprintf(json_file,
            ",\"port\":53"
            "},"
            "\"query\":");

    if (tx->have_latency)
        json_query(json_file, &tx->latency);
    else
        fputs("null", json_file);

    fprintf(json_file, ",\"response\":");

    if (tx->have_xdp_response)
        json_response(json_file, &tx->xdp_response);
    else
        fputs("null", json_file);

    fprintf(json_file, ",\"latency\":");

    if (tx->have_latency)
        json_latency(json_file, &tx->latency);
    else
        fputs("null", json_file);

    /*
     * Close exactly one transaction object.
     */
    fputc('}', json_file);

    fflush(json_file);
}

/*
 * A transaction is complete when we have:
 *
 *     XDP response
 *     latency event
 *
 * The latency event contains the original DNS query.
 */
static void try_complete_transaction(struct pending_transaction *tx)
{
    if (!tx)
        return;

    if (!tx->have_xdp_response)
        return;

    if (!tx->have_latency)
        return;
    
    if (!tx->latency.is_timeout && !tx->have_xdp_response)
    return;

    write_transaction(tx);

    memset(tx, 0, sizeof(*tx));
}

/* ============================================================================
 * XDP correlation
 * ========================================================================== */

void json_logger_record_xdp(const struct DNSQueryEvent *event)
{
    if (!json_file || !event)
        return;

    /*
     * XDP is used only for DNS responses.
     *
     * Response direction:
     *
     *     server -> client
     *
     * Normalize it to:
     *
     *     client_ip
     *     client_port
     *     server_ip
     */
    if (!event->is_response)
        return;

    struct pending_transaction *tx =
        find_transaction(event->query_id,
                         event->dst_ip,
                         event->dst_port,
                         event->src_ip);

    if (!tx)
        tx = allocate_transaction();

    if (!tx)
        return;

    tx->query_id = event->query_id;
    tx->client_ip = event->dst_ip;
    tx->client_port = event->dst_port;
    tx->server_ip = event->src_ip;

    memcpy(&tx->xdp_response,
           event,
           sizeof(*event));

    tx->have_xdp_response = true;

    try_complete_transaction(tx);
}

/* ============================================================================
 * Latency correlation
 * ========================================================================== */

void json_logger_record_latency(const struct latency_event *event)
{
    if (!json_file || !event)
        return;

    struct pending_transaction *tx =
        find_transaction(event->query_id,
                         event->client_ip,
                         event->client_port,
                         event->server_ip);

    if (!tx)
        tx = allocate_transaction();

    if (!tx)
        return;

    tx->query_id = event->query_id;
    tx->client_ip = event->client_ip;
    tx->client_port = event->client_port;
    tx->server_ip = event->server_ip;

    memcpy(&tx->latency,
           event,
           sizeof(*event));

    tx->have_latency = true;

    try_complete_transaction(tx);
}

/* ============================================================================
 * Initialization
 * ========================================================================== */

int json_logger_init(const char *interface_name)
{
    memset(pending, 0, sizeof(pending));
    first_query = true;
    json_file = NULL;
    json_filename[0] = '\0';

    /*
     * Create json/ if it doesn't exist.
     */
    if (mkdir(JSON_DIRECTORY, 0755) < 0 &&
        errno != EEXIST) {
        fprintf(stderr,
                "JSON logger: failed to create '%s': %s\n",
                JSON_DIRECTORY,
                strerror(errno));
        return -1;
    }

    /*
     * Timestamp + nanoseconds gives us a unique run filename.
     */
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        fprintf(stderr,
                "JSON logger: clock_gettime failed: %s\n",
                strerror(errno));
        return -1;
    }

    struct tm tm_now;

    if (!localtime_r(&ts.tv_sec, &tm_now)) {
        fprintf(stderr,
                "JSON logger: localtime_r failed\n");
        return -1;
    }

    char timestamp[64];

    strftime(timestamp,
             sizeof(timestamp),
             "%Y-%m-%d_%H-%M-%S",
             &tm_now);

    /*
     * Example:
     *
     *     json/exp1_2026-09-07_17-53-12_123456789.json
     */
    snprintf(json_filename,
             sizeof(json_filename),
             "%s/exp1_%s_%09ld.json",
             JSON_DIRECTORY,
             timestamp,
             ts.tv_nsec);

    json_file = fopen(json_filename, "w");

    if (!json_file) {
        fprintf(stderr,
                "JSON logger: failed to open '%s': %s\n",
                json_filename,
                strerror(errno));
        return -1;
    }

    /*
     * Start the JSON document.
     */
    fprintf(json_file,
            "{"
            "\"run\":{"
            "\"pid\":%d,"
            "\"interface\":",
            (int)getpid());

    json_escape(json_file,
                interface_name ? interface_name : "");

    fprintf(json_file,
            ",\"started_at\":\"%s.%09ld\""
            "},"
            "\"queries\":[",
            timestamp,
            ts.tv_nsec);

    fflush(json_file);

    printf("JSON output : %s\n", json_filename);

    return 0;
}

/* ============================================================================
 * Shutdown
 * ========================================================================== */

void json_logger_close(void)
{
    if (!json_file)
        return;

    /*
     * Write incomplete transactions too.
     *
     * This preserves a transaction even if the tracer is stopped before
     * all corresponding events arrive.
     */
    for (size_t i = 0; i < MAX_PENDING_TRANSACTIONS; i++) {
        if (!pending[i].used)
            continue;

        write_transaction(&pending[i]);

        memset(&pending[i],
               0,
               sizeof(pending[i]));
    }

    /*
     * Finish:
     *
     *     "queries":[ ... ]
     * }
     */
    fprintf(json_file,
            "]"
            "}\n");

    fflush(json_file);

    fclose(json_file);
    json_file = NULL;
}
