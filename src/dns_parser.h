#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define DNS_MAX_NAME       256
#define DNS_MAX_QUESTIONS  16
#define DNS_MAX_RR         64
#define DNS_MAX_RDATA_TEXT 512

/* ------------------------------------------------------------
 * DNS Question
 * ------------------------------------------------------------ */

struct dns_question {
    char name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t qclass;
};

/* ------------------------------------------------------------
 * DNS Resource Record
 * ------------------------------------------------------------ */

struct dns_rr {
    char name[DNS_MAX_NAME];

    uint16_t type;
    uint16_t rrclass;
    uint32_t ttl;
    uint16_t rdlength;

    /*
     * Human-readable RDATA.
     *
     * Examples:
     *   A      -> "14.139.196.75"
     *   AAAA   -> "2001:db8::1"
     *   CNAME  -> "example.com"
     *   MX     -> "10 mail.example.com"
     *   SOA    -> "ns.example.com hostmaster.example.com ..."
     *
     * Unknown types fall back to hexadecimal.
     */
    char rdata[DNS_MAX_RDATA_TEXT];
};

/* ------------------------------------------------------------
 * DNS Message
 * ------------------------------------------------------------ */

struct dns_message {
    int parse_ok;
    int truncated_by_capture;

    /* Header */
    uint16_t id;
    uint16_t flags;

    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t ad;
    uint8_t cd;
    uint8_t rcode;

    /* Section counts from DNS header */
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    /* Number of bytes successfully consumed */
    size_t parsed_len;

    /* Question section */
    size_t question_count;
    struct dns_question questions[DNS_MAX_QUESTIONS];

    /* Answer section */
    size_t answer_count;
    struct dns_rr answers[DNS_MAX_RR];

    /* Authority section */
    size_t authority_count;
    struct dns_rr authority[DNS_MAX_RR];

    /* Additional section */
    size_t additional_count;
    struct dns_rr additional[DNS_MAX_RR];
};

/* ------------------------------------------------------------
 * Lookup helpers
 * ------------------------------------------------------------ */

const char *dns_type_name(uint16_t type);
const char *dns_class_name(uint16_t qclass);
const char *dns_rcode_name(uint8_t rcode);

/* ------------------------------------------------------------
 * Main parser
 * ------------------------------------------------------------ */

int dns_parse_message(const uint8_t *packet,
                      size_t len,
                      struct dns_message *msg);

/* ------------------------------------------------------------
 * DNS name parser
 *
 * Supports normal DNS labels and RFC 1035 compression pointers.
 *
 * On success:
 *   - out contains the decoded name
 *   - offset is advanced past the name in the original stream
 *
 * Returns:
 *    0 on success
 *   -1 on malformed/truncated input
 * ------------------------------------------------------------ */

int dns_parse_name(const uint8_t *packet,
                   size_t len,
                   size_t *offset,
                   char *out,
                   size_t out_len);

#endif