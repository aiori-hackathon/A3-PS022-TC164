#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dns_tracer.skel.h"
#include "dns_parser.h"
#include "json_logger.h"

#define DNS_PAYLOAD_MAX 512
#define MAX_DNS_NAME_LEN 256

/* ============================================================================
 * Event structures
 * ============================================================================
 *
 * These MUST match xdp.h and tc.h exactly.
 *
 * We do NOT include xdp.h/tc.h here because they contain BPF helper
 * definitions which conflict with the userspace libbpf headers.
 */

// ******************************
// DNSQueryEvent
// latency_event
// Should be added in a separate file or smthing

static void print_latency_event(const struct latency_event *event);

struct pq_key  { 
    uint16_t query_id; 
    uint32_t client_ip;
    uint16_t client_port; 
    uint16_t padding; 
};
struct pq_info { 
    uint8_t raw_payload[512]; 
    uint64_t start_ts;
    uint32_t server_ip; 
    uint16_t query_type; 
};

#define QUERY_TIMEOUT_NS 5000000000ULL   /* 5 s */

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   /* same clock as bpf_ktime_get_ns */
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sweep_timeouts(int fd)
{
    struct pq_key key, next;
    struct pq_info info;
    uint64_t now = mono_ns();

    int rc = bpf_map_get_next_key(fd, NULL, &key);
    while (rc == 0) {
        int more = bpf_map_get_next_key(fd, &key, &next); /* fetch BEFORE delete */

        if (bpf_map_lookup_elem(fd, &key, &info) == 0 &&
            now - info.start_ts >= QUERY_TIMEOUT_NS) {

            struct latency_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.timestamp   = now;
            ev.latency_ns  = now - info.start_ts;
            ev.client_ip   = key.client_ip;
            ev.server_ip   = info.server_ip;
            ev.client_port = key.client_port;
            ev.query_id    = key.query_id;
            ev.query_type  = info.query_type;
            ev.is_timeout  = 1;
            memcpy(ev.raw_payload, info.raw_payload, sizeof(ev.raw_payload));

            print_latency_event(&ev);          /* print "[TIMEOUT]" when is_timeout */
            json_logger_record_latency(&ev);
            bpf_map_delete_elem(fd, &key);
        }
        if (more) break;
        key = next;
    }
}


/* ============================================================================
 * Global state
 * ========================================================================== */

static volatile sig_atomic_t exiting = 0;


/* ============================================================================
 * Signal handling
 * ========================================================================== */

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}


/* ============================================================================
 * libbpf logging
 * ========================================================================== */

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level == LIBBPF_WARN || level == LIBBPF_INFO)
        vfprintf(stderr, format, args);

    return 0;
}


/* ============================================================================
 * Basic formatting helpers
 * ========================================================================== */

static void ip_to_string(uint32_t ip, char *buf, size_t len)
{
    if (!inet_ntop(AF_INET, &ip, buf, len))
        snprintf(buf, len, "?");
}


/* ============================================================================
 * DNS parsing
 * ========================================================================== */

/*
 * The BPF event contains a fixed 512-byte raw_payload.
 *
 * There is no payload-length field in the event, so we determine how much
 * of the buffer is actually a DNS message by parsing it.
 *
 * On success:
 *
 *     parsed->parsed_len
 *
 * gives the amount of DNS data consumed.
 *
 * On malformed/truncated input, the parser's parsed_len gives us the furthest
 * safe position reached.
 */
static size_t useful_dns_length(const uint8_t *payload,
                                size_t cap,
                                int *parse_ok,
                                struct dns_message *parsed)
{
    if (parse_ok)
        *parse_ok = 0;

    if (!payload || !parsed || cap < 12)
        return 0;

    memset(parsed, 0, sizeof(*parsed));

    if (dns_parse_message(payload, cap, parsed) == 0) {
        if (parse_ok)
            *parse_ok = 1;

        if (parsed->parsed_len <= cap)
            return parsed->parsed_len;

        return cap;
    }

    /*
     * Parsing failed.
     *
     * parsed_len represents the furthest safe location reached by
     * the parser. Never use more than that.
     */
    if (parsed->parsed_len >= 12 &&
        parsed->parsed_len <= cap)
        return parsed->parsed_len;

    return cap;
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


/*
 * Write the fully parsed DNS message as JSON.
 *
 * This gives us a machine-readable representation that can later be used
 * directly for Experiment 1 analysis.
 */
static void json_dns_message(FILE *f,
                             const struct dns_message *m)
{
    fprintf(f,
            "{"
            "\"dns\":{"
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

        json_escape(f,
                    dns_type_name(m->questions[i].type));

        fprintf(f,
                ",\"class\":%u,"
                "\"class_name\":",
                m->questions[i].qclass);

        json_escape(f,
                    dns_class_name(m->questions[i].qclass));

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

    fprintf(f, "}}");
}


/* ============================================================================
 * Detailed human-readable DNS output
 * ========================================================================== */

static void print_question(const struct dns_question *q,
                           size_t index)
{
    printf("    Question %zu:\n", index + 1);
    printf("      Name  : %s\n", q->name);
    printf("      Type  : %u (%s)\n",
           q->type,
           dns_type_name(q->type));
    printf("      Class : %u (%s)\n",
           q->qclass,
           dns_class_name(q->qclass));
}


static void print_rr(const struct dns_rr *rr,
                     size_t index,
                     const char *section)
{
    printf("    %s %zu:\n",
           section,
           index + 1);

    printf("      Name     : %s\n",
           rr->name);

    printf("      Type     : %u (%s)\n",
           rr->type,
           dns_type_name(rr->type));

    printf("      Class    : %u (%s)\n",
           rr->rrclass,
           dns_class_name(rr->rrclass));

    printf("      TTL      : %u\n",
           rr->ttl);

    printf("      RDLength : %u\n",
           rr->rdlength);

    printf("      RDATA    : %s\n",
           rr->rdata);
}


/*
 * Print all information extracted by dns_parser.c.
 *
 * This is deliberately verbose. For Experiment 1, having the complete
 * decoded DNS message is much more useful than printing only:
 *
 *     name / type / latency
 */
static void print_dns_details(const struct dns_message *m)
{
    printf("\n");
    printf("  ---------------- DNS DETAILS ----------------\n");

    printf("  Header:\n");

    printf("    ID      : %u\n", m->id);
    printf("    Flags   : 0x%04x\n", m->flags);

    printf("    QR      : %u\n", m->qr);
    printf("    Opcode  : %u\n", m->opcode);

    printf("    AA      : %u\n", m->aa);
    printf("    TC      : %u\n", m->tc);

    printf("    RD      : %u\n", m->rd);
    printf("    RA      : %u\n", m->ra);

    printf("    AD      : %u\n", m->ad);
    printf("    CD      : %u\n", m->cd);

    printf("    RCODE   : %u (%s)\n",
           m->rcode,
           dns_rcode_name(m->rcode));

    printf("\n");

    printf("  Counts:\n");
    printf("    Questions  : %u\n", m->qdcount);
    printf("    Answers    : %u\n", m->ancount);
    printf("    Authority  : %u\n", m->nscount);
    printf("    Additional : %u\n", m->arcount);

    printf("\n");

    /*
     * Questions
     */
    if (m->question_count > 0) {
        printf("  Questions:\n");

        for (size_t i = 0; i < m->question_count; i++)
            print_question(&m->questions[i], i);
    }

    /*
     * Answers
     */
    if (m->answer_count > 0) {
        printf("\n");
        printf("  Answers:\n");

        for (size_t i = 0; i < m->answer_count; i++)
            print_rr(&m->answers[i], i, "Answer");
    }

    /*
     * Authority
     */
    if (m->authority_count > 0) {
        printf("\n");
        printf("  Authority:\n");

        for (size_t i = 0; i < m->authority_count; i++)
            print_rr(&m->authority[i], i, "Authority");
    }

    /*
     * Additional
     */
    if (m->additional_count > 0) {
        printf("\n");
        printf("  Additional:\n");

        for (size_t i = 0; i < m->additional_count; i++)
            print_rr(&m->additional[i], i, "Additional");
    }

    printf("\n");

    printf("  Parser:\n");
    printf("    Parse OK             : %s\n",
           m->parse_ok ? "yes" : "no");

    printf("    Parsed length        : %zu bytes\n",
           m->parsed_len);

    printf("    Truncated by capture : %s\n",
           m->truncated_by_capture ? "yes" : "no");

    printf("  ---------------------------------------------\n");
}


/* ============================================================================
 * XDP event
 * ========================================================================== */

static void print_xdp_event(const struct DNSQueryEvent *event)
{
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    struct dns_message msg;

    int parse_ok = 0;

    size_t dns_len;

    ip_to_string(event->src_ip,
                 src,
                 sizeof(src));

    ip_to_string(event->dst_ip,
                 dst,
                 sizeof(dst));

    /*
     * Parse the exact payload copied by the BPF program.
     */
    dns_len = useful_dns_length(event->raw_payload,
                                DNS_PAYLOAD_MAX,
                                &parse_ok,
                                &msg);

    const char *type = "UNKNOWN";
    const char *name = "<unknown>";

    if (msg.question_count > 0) {
        type = dns_type_name(msg.questions[0].type);
        name = msg.questions[0].name;
    } else if (event->query_type != 0) {
        /*
         * Fallback to the value supplied by BPF.
         */
        type = dns_type_name(event->query_type);
    }

    printf(
        "[XDP] %-8s "
        "%s:%u -> %s:%u "
        "id=%u "
        "type=%s "
        "name=%s "
        "rcode=%u(%s) "
        "answers=%u "
        "authority=%u "
        "additional=%u",
        event->is_response ? "RESPONSE" : "QUERY",

        src,
        event->src_port,

        dst,
        event->dst_port,

        event->query_id,

        type,
        name,

        event->rcode,
        dns_rcode_name(event->rcode),

        event->answer_count,

        msg.nscount,
        msg.arcount
    );

    if (event->truncated)
        printf(" [TC]");

    if (event->authoritative)
        printf(" [AA]");

    printf("\n");

    /*
     * Detailed userspace parse.
     */
    if (parse_ok)
        print_dns_details(&msg);
    else
        printf("  DNS parser: incomplete/malformed packet "
               "(safe length=%zu bytes)\n",
               dns_len);

    fflush(stdout);
}


/* ============================================================================
 * Latency event
 * ========================================================================== */

static void print_latency_event(const struct latency_event *event)
{
    char client[INET_ADDRSTRLEN];
    char server[INET_ADDRSTRLEN];

    struct dns_message query;

    int parse_ok = 0;

    size_t dns_len;

    ip_to_string(event->client_ip,
                 client,
                 sizeof(client));

    ip_to_string(event->server_ip,
                 server,
                 sizeof(server));

    /*
     * IMPORTANT:
     *
     * The latency_event contains the ORIGINAL QUERY payload.
     *
     * The BPF program copies:
     *
     *     info->raw_payload
     *
     * into:
     *
     *     event->raw_payload
     *
     * when the response arrives.
     *
     * Therefore we can fully parse the original query here.
     */
    dns_len = useful_dns_length(event->raw_payload,
                                DNS_PAYLOAD_MAX,
                                &parse_ok,
                                &query);

    fprintf(stderr, "\n========== DEBUG ==========\n");

fprintf(stderr, "BPF event->query_type = %u\n",
        event->query_type);

fprintf(stderr, "parser parse_ok = %d\n",
        parse_ok);

fprintf(stderr, "parser parsed_len = %zu\n",
        query.parsed_len);

fprintf(stderr, "parser qdcount = %u\n",
        query.qdcount);

fprintf(stderr, "parser question_count = %zu\n",
        query.question_count);

if (query.question_count > 0) {
    fprintf(stderr, "parser QTYPE = %u\n",
            query.questions[0].type);

    fprintf(stderr, "parser QCLASS = %u\n",
            query.questions[0].qclass);

    fprintf(stderr, "parser QNAME = %s\n",
            query.questions[0].name);
}

fprintf(stderr, "RAW DNS PAYLOAD:\n");

for (size_t i = 0; i < dns_len; i++) {
    fprintf(stderr, "%02x ", event->raw_payload[i]);

    if ((i + 1) % 16 == 0)
        fprintf(stderr, "\n");
}

fprintf(stderr, "\n===========================\n");

    const char *type = "UNKNOWN";
    const char *name = "<unknown>";

    if (query.question_count > 0) {
        type = dns_type_name(query.questions[0].type);
        name = query.questions[0].name;
    } else if (event->query_type != 0) {
        type = dns_type_name(event->query_type);
    }

    printf(
        "[%s] %s:%u -> %s:53 "
        "id=%u "
        "type=%s "
        "name=%s "
        "latency=%.3f ms "
        "response_rcode=%u(%s) "
        "response_answers=%u\n",

        event->is_timeout ? "TIMEOUT" : "RESPONSE",
        client,
        event->client_port,
        server,

        event->query_id,

        type,
        name,

        (double)event->latency_ns / 1000000.0,

        event->rcode,
        dns_rcode_name(event->rcode),

        event->answer_count
    );

    /*
     * Print the complete QUERY message.
     *
     * Note:
     *
     *     query.* = original outgoing DNS query
     *
     * while:
     *
     *     event->rcode
     *     event->answer_count
     *
     * come from the matched response.
     */
    if (parse_ok)
        print_dns_details(&query);
    else
        printf("  DNS parser: incomplete/malformed packet "
               "(safe length=%zu bytes)\n",
               dns_len);

    fflush(stdout);
}


/* ============================================================================
 * Ring-buffer callbacks
 * ========================================================================== */

static int handle_dns_event(void *ctx,
                            void *data,
                            size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct DNSQueryEvent))
        return 0;

    print_xdp_event(
        (const struct DNSQueryEvent *)data
    );

    json_logger_record_xdp(
        (const struct DNSQueryEvent *)data
    );

    return 0;
}


static int handle_latency_event(void *ctx,
                                void *data,
                                size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct latency_event))
        return 0;

    print_latency_event(
        (const struct latency_event *)data
    );

    json_logger_record_latency(
        (const struct latency_event *)data
    );

    return 0;
}


/* ============================================================================
 * TC attachment
 * ========================================================================== */

static int attach_tc_program(struct bpf_program *prog,
                             int ifindex,
                             enum bpf_tc_attach_point attach_point,
                             struct bpf_tc_hook *hook,
                             struct bpf_tc_opts *opts)
{
    int err;

    memset(hook, 0, sizeof(*hook));
    memset(opts, 0, sizeof(*opts));

    hook->sz = sizeof(*hook);
    hook->ifindex = ifindex;
    hook->attach_point = attach_point;

    err = bpf_tc_hook_create(hook);

    if (err && err != -EEXIST) {
        fprintf(stderr,
                "bpf_tc_hook_create(%s) failed: %d (%s)\n",
                attach_point == BPF_TC_INGRESS
                    ? "ingress"
                    : "egress",
                err,
                strerror(-err));

        return err;
    }

    opts->sz = sizeof(*opts);
    opts->prog_fd = bpf_program__fd(prog);

    if (attach_point == BPF_TC_INGRESS) {
        opts->handle = 1;
        opts->priority = 1;
    } else {
        opts->handle = 2;
        opts->priority = 1;
    }

    err = bpf_tc_attach(hook, opts);

    if (err) {
        fprintf(stderr,
                "bpf_tc_attach(%s) failed: %d (%s)\n",
                attach_point == BPF_TC_INGRESS
                    ? "ingress"
                    : "egress",
                err,
                strerror(-err));

        return err;
    }

    printf("  TC %s attached: "
           "handle=%u priority=%u\n",
           attach_point == BPF_TC_INGRESS
               ? "ingress"
               : "egress",
           opts->handle,
           opts->priority);

    return 0;
}


static int detach_tc_program(struct bpf_tc_hook *hook,
                             struct bpf_tc_opts *opts)
{
    struct bpf_tc_opts detach_opts = {};

    detach_opts.sz = sizeof(detach_opts);

    /*
     * For libbpf 0.5.0:
     *
     * detach requires only handle + priority.
     */
    detach_opts.handle = opts->handle;
    detach_opts.priority = opts->priority;

    int err = bpf_tc_detach(hook, &detach_opts);

    if (err == -ENOENT)
        return 0;

    if (err) {
        fprintf(stderr,
                "Warning: bpf_tc_detach failed: "
                "%d (%s)\n",
                err,
                strerror(-err));
    }

    return err;
}

static void print_stats(int fd)
{
    /* order MUST match enum StatKeys in common.h */
    static const char *names[] = {
        "total_packets", "dns_queries", "dns_responses",
        "parse_errors",  "truncated",   "nxdomain",
        "ringbuf_drops"
    };
    const uint32_t n = sizeof(names) / sizeof(names[0]);

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0)
        return;

    uint64_t *vals = calloc(ncpu, sizeof(*vals));
    if (!vals)
        return;

    printf("\n---------- BPF stats ----------\n");
    for (uint32_t k = 0; k < n; k++) {
        if (bpf_map_lookup_elem(fd, &k, vals))
            continue;

        uint64_t sum = 0;
        for (int i = 0; i < ncpu; i++)
            sum += vals[i];

        printf("  %-14s %llu\n", names[k], (unsigned long long)sum);
    }
    printf("-------------------------------\n");

    free(vals);
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv)
{
    const char *ifname;
    unsigned int ifindex;

    struct dns_tracer_bpf *obj = NULL;

    struct ring_buffer *rb = NULL;

    bool xdp_attached = false;

    struct bpf_tc_hook tc_ingress_hook;
    struct bpf_tc_opts tc_ingress_opts;

    struct bpf_tc_hook tc_egress_hook;
    struct bpf_tc_opts tc_egress_opts;

    bool tc_ingress_attached = false;
    bool tc_egress_attached = false;

    int err = 0;

    memset(&tc_ingress_hook,
           0,
           sizeof(tc_ingress_hook));

    memset(&tc_ingress_opts,
           0,
           sizeof(tc_ingress_opts));

    memset(&tc_egress_hook,
           0,
           sizeof(tc_egress_hook));

    memset(&tc_egress_opts,
           0,
           sizeof(tc_egress_opts));


    /* ------------------------------------------------------------------------
     * Argument validation
     * --------------------------------------------------------------------- */

    if (argc != 2) {
        fprintf(stderr,
                "Usage: sudo %s <interface>\n",
                argv[0]);

        fprintf(stderr,
                "Example: sudo %s enp1s0f0np0\n",
                argv[0]);

        return 1;
    }

    ifname = argv[1];

    ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr,
                "Interface '%s' not found: %s\n",
                ifname,
                strerror(errno));

        return 1;
    }

    if (json_logger_init(ifname) != 0) {
        fprintf(stderr, "Failed to initialize JSON logger\n");
        return 1;
    }


    /* ------------------------------------------------------------------------
     * Signals / libbpf
     * --------------------------------------------------------------------- */

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);


    /* ------------------------------------------------------------------------
     * Startup information
     * --------------------------------------------------------------------- */

    printf("============================================\n");
    printf(" DNS Tracer\n");
    printf("============================================\n");

    printf("Interface : %s\n",
           ifname);

    printf("Ifindex   : %u\n\n",
           ifindex);


    /* ------------------------------------------------------------------------
     * Open skeleton
     * --------------------------------------------------------------------- */

    obj = dns_tracer_bpf__open();

    if (!obj) {
        fprintf(stderr,
                "Failed to open BPF skeleton\n");

        return 1;
    }


    /* ------------------------------------------------------------------------
     * Configure TC programs for libbpf 0.5.0
     * --------------------------------------------------------------------- */

    /*
     * The BPF source uses:
     *
     *     SEC("classifier")
     *
     * for the TC programs.
     *
     * Explicitly mark them as SCHED_CLS.
     */
    bpf_program__set_type(
        obj->progs.tc_dns_egress,
        BPF_PROG_TYPE_SCHED_CLS
    );

    bpf_program__set_type(
        obj->progs.tc_dns_ingress,
        BPF_PROG_TYPE_SCHED_CLS
    );


    /* ------------------------------------------------------------------------
     * Load BPF object
     * --------------------------------------------------------------------- */

    err = dns_tracer_bpf__load(obj);

    if (err) {
        fprintf(stderr,
                "Failed to load BPF object: %d\n",
                err);

        goto cleanup;
    }

    printf("BPF object loaded.\n");


    /* ------------------------------------------------------------------------
     * Attach XDP
     * --------------------------------------------------------------------- */

    printf("Attaching XDP in generic/SKB mode...\n");

    int prog_fd =
        bpf_program__fd(obj->progs.xdp_dns_parser);

    if (prog_fd < 0) {
        err = prog_fd;

        fprintf(stderr,
                "Failed to get XDP program FD: %d\n",
                err);

        goto cleanup;
    }

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);

    if (err) {
        fprintf(stderr,
                "Failed to attach XDP in generic mode: "
                "%d (%s)\n",
                err,
                strerror(-err));

        goto cleanup;
    }

    xdp_attached = true;

    printf("  XDP attached in generic/SKB mode.\n");


    /* ------------------------------------------------------------------------
     * Attach TC ingress
     * --------------------------------------------------------------------- */

    printf("Attaching TC ingress...\n");

    err = attach_tc_program(
        obj->progs.tc_dns_ingress,
        (int)ifindex,
        BPF_TC_INGRESS,
        &tc_ingress_hook,
        &tc_ingress_opts
    );

    if (err) {
        fprintf(stderr,
                "Failed to attach TC ingress.\n");

        goto cleanup;
    }

    tc_ingress_attached = true;


    /* ------------------------------------------------------------------------
     * Attach TC egress
     * --------------------------------------------------------------------- */

    printf("Attaching TC egress...\n");

    err = attach_tc_program(
        obj->progs.tc_dns_egress,
        (int)ifindex,
        BPF_TC_EGRESS,
        &tc_egress_hook,
        &tc_egress_opts
    );

    if (err) {
        fprintf(stderr,
                "Failed to attach TC egress.\n");

        goto cleanup;
    }

    tc_egress_attached = true;


    /* ------------------------------------------------------------------------
     * Ring buffer
     * --------------------------------------------------------------------- */

    printf("Creating ring-buffer manager...\n");

    /*
     * Both XDP and TC events are consumed through one ring-buffer manager.
     */
    rb = ring_buffer__new(
        bpf_map__fd(obj->maps.dns_events),
        handle_dns_event,
        NULL,
        NULL
    );

    if (!rb) {
        err = -errno;

        fprintf(stderr,
                "Failed to create XDP ring buffer: "
                "%d (%s)\n",
                err,
                strerror(-err));

        goto cleanup;
    }


    /*
     * Add latency ring buffer to the same manager.
     */
    err = ring_buffer__add(
        rb,
        bpf_map__fd(obj->maps.latency_events),
        handle_latency_event,
        NULL
    );

    if (err) {
        fprintf(stderr,
                "Failed to add TC latency ring buffer: "
                "%d\n",
                err);

        goto cleanup;
    }

    printf("  XDP ring buffer added.\n");
    printf("  TC  ring buffer added.\n\n");


    /* ------------------------------------------------------------------------
     * Run
     * --------------------------------------------------------------------- */

    printf("============================================\n");
    printf(" Tracer running\n");
    printf("============================================\n");

    printf("Listening for DNS events on %s...\n",
           ifname);

    printf("Press Ctrl+C to stop.\n\n");

    uint64_t last_sweep = 0; 

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR)
            break;

        if (err < 0) {
            fprintf(stderr,
                    "ring_buffer__poll failed: "
                    "%d (%s)\n",
                    err,
                    strerror(-err));

            goto cleanup;
        }

        uint64_t t = mono_ns();
        if (t - last_sweep > 1000000000ULL) {
            sweep_timeouts(bpf_map__fd(obj->maps.pending_queries));
            last_sweep = t;
        }
    }

    print_stats(bpf_map__fd(obj->maps.stats));
    err = 0;


/* ============================================================================
 * Cleanup
 * ========================================================================== */

cleanup:

    if (rb)
        ring_buffer__free(rb);


    /*
     * TC filters must be explicitly detached with the old libbpf API.
     */
    if (tc_egress_attached)
        detach_tc_program(
            &tc_egress_hook,
            &tc_egress_opts
        );

    if (tc_ingress_attached)
        detach_tc_program(
            &tc_ingress_hook,
            &tc_ingress_opts
        );


    /*
     * Detach XDP from generic/SKB mode.
     */
    if (xdp_attached) {
        int xdp_err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        if (xdp_err && xdp_err != -ENOENT) {
            fprintf(stderr,
                    "Warning: failed to detach XDP: "
                    "%d (%s)\n",
                    xdp_err,
                    strerror(-xdp_err));
        }
    }


    /*
     * Destroy TC hooks after filters have been detached.
     */
    if (tc_egress_attached) {
        int tc_err =
            bpf_tc_hook_destroy(&tc_egress_hook);

        if (tc_err && tc_err != -ENOENT) {
            fprintf(stderr,
                    "Warning: failed to destroy "
                    "TC egress hook: %d\n",
                    tc_err);
        }
    }

    if (tc_ingress_attached) {
        int tc_err =
            bpf_tc_hook_destroy(&tc_ingress_hook);

        if (tc_err && tc_err != -ENOENT) {
            fprintf(stderr,
                    "Warning: failed to destroy "
                    "TC ingress hook: %d\n",
                    tc_err);
        }
    }

    json_logger_close();


    /*
     * Destroy skeleton.
     */
    if (obj)
        dns_tracer_bpf__destroy(obj);


    if (err)
        fprintf(stderr,
                "\nTracer exited with error %d.\n",
                err);
    else
        printf("\nTracer stopped.\n");


    return err ? 1 : 0;
}
