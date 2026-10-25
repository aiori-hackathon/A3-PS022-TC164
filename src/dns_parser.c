#include "dns_parser.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* ============================================================
 * Basic byte readers
 * ============================================================ */

static uint16_t read_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) |
           (uint16_t)p[1];
}

static uint32_t read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

/* ============================================================
 * DNS type names
 * ============================================================ */

const char *dns_type_name(uint16_t type)
{
    switch (type) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 41:  return "OPT";
    case 43:  return "DS";
    case 46:  return "RRSIG";
    case 47:  return "NSEC";
    case 48:  return "DNSKEY";
    case 50:  return "NSEC3";
    case 64:  return "SVCB";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    default:  return "UNKNOWN";
    }
}

/* ============================================================
 * DNS class names
 * ============================================================ */

const char *dns_class_name(uint16_t qclass)
{
    switch (qclass) {
    case 1:   return "IN";
    case 3:   return "CH";
    case 4:   return "HS";
    case 255: return "ANY";
    default:  return "UNKNOWN";
    }
}

/* ============================================================
 * DNS RCODE names
 * ============================================================ */

const char *dns_rcode_name(uint8_t rcode)
{
    switch (rcode) {
    case 0:  return "NOERROR";
    case 1:  return "FORMERR";
    case 2:  return "SERVFAIL";
    case 3:  return "NXDOMAIN";
    case 4:  return "NOTIMP";
    case 5:  return "REFUSED";
    case 6:  return "YXDOMAIN";
    case 7:  return "YXRRSET";
    case 8:  return "NXRRSET";
    case 9:  return "NOTAUTH";
    case 10: return "NOTZONE";
    default: return "UNKNOWN";
    }
}

/* ============================================================
 * DNS name parsing
 *
 * Handles:
 *
 *   example.com
 *   www.example.com
 *   compression pointers
 *   mixed labels + compression
 *
 * Safety:
 *   - bounds checks
 *   - label length <= 63
 *   - pointer must be inside packet
 *   - maximum pointer jumps
 * ============================================================ */

int dns_parse_name(const uint8_t *packet,
                   size_t len,
                   size_t *offset,
                   char *out,
                   size_t out_len)
{
    size_t pos;
    size_t next = 0;
    size_t outpos = 0;

    int jumped = 0;
    unsigned jumps = 0;

    if (!packet || !offset || !out || out_len == 0)
        return -1;

    out[0] = '\0';

    pos = *offset;

    while (pos < len) {
        uint8_t c = packet[pos];

        /* End of DNS name */
        if (c == 0) {
            if (!jumped)
                next = pos + 1;

            /* Root name */
            if (outpos == 0) {
                if (out_len < 2)
                    return -1;

                out[0] = '.';
                out[1] = '\0';
            } else {
                /* Remove final '.' */
                out[outpos - 1] = '\0';
            }

            *offset = next;
            return 0;
        }

        /* Compression pointer */
        if ((c & 0xc0) == 0xc0) {
            uint16_t ptr;

            if (pos + 1 >= len)
                return -1;

            ptr = (uint16_t)(((c & 0x3f) << 8) |
                             packet[pos + 1]);

            if (!jumped) {
                next = pos + 2;
                jumped = 1;
            }

            /*
             * Limit jumps to prevent malformed pointer loops.
             */
            if (++jumps > 128)
                return -1;

            if (ptr >= len)
                return -1;

            pos = ptr;
            continue;
        }

        /*
         * RFC 1035:
         * ordinary DNS label length is at most 63.
         */
        if (c > 63)
            return -1;

        if (pos + 1 + c > len)
            return -1;

        if (outpos + c + 1 >= out_len)
            return -1;

        memcpy(out + outpos,
               packet + pos + 1,
               c);

        outpos += c;

        out[outpos++] = '.';
        out[outpos] = '\0';

        pos += 1 + c;
    }

    return -1;
}

/* ============================================================
 * RDATA formatting
 *
 * This converts raw RDATA into something useful for JSON.
 * ============================================================ */

static void format_rdata(const uint8_t *packet,
                         size_t len,
                         size_t rdata_off,
                         uint16_t type,
                         uint16_t rdlen,
                         char *out,
                         size_t out_len)
{
    size_t end = rdata_off + rdlen;

    if (!out || out_len == 0)
        return;

    out[0] = '\0';

    if (rdata_off > len || rdlen > len - rdata_off) {
        snprintf(out, out_len, "<truncated>");
        return;
    }

    /* --------------------------------------------------------
     * A
     * -------------------------------------------------------- */

    switch (type) {

    case 1: /* A */
        if (rdlen == 4) {
            if (!inet_ntop(AF_INET,
                           packet + rdata_off,
                           out,
                           out_len)) {
                snprintf(out, out_len, "<invalid>");
            }
            return;
        }
        break;

    /* --------------------------------------------------------
     * AAAA
     * -------------------------------------------------------- */

    case 28: /* AAAA */
        if (rdlen == 16) {
            if (!inet_ntop(AF_INET6,
                           packet + rdata_off,
                           out,
                           out_len)) {
                snprintf(out, out_len, "<invalid>");
            }
            return;
        }
        break;

    /* --------------------------------------------------------
     * Domain-name based RDATA
     *
     * NS
     * CNAME
     * PTR
     * -------------------------------------------------------- */

    case 2:   /* NS */
    case 5:   /* CNAME */
    case 12:  /* PTR */
    {
        size_t tmp = rdata_off;

        if (dns_parse_name(packet,
                           len,
                           &tmp,
                           out,
                           out_len) == 0)
            return;

        break;
    }

    /* --------------------------------------------------------
     * MX
     *
     * preference + exchange
     * -------------------------------------------------------- */

    case 15: /* MX */
        if (rdlen >= 3) {
            uint16_t pref;
            size_t tmp;
            char target[DNS_MAX_NAME];

            pref = read_u16(packet + rdata_off);
            tmp = rdata_off + 2;

            if (dns_parse_name(packet,
                               len,
                               &tmp,
                               target,
                               sizeof(target)) == 0) {

                snprintf(out,
                         out_len,
                         "%u %s",
                         (unsigned)pref,
                         target);

                return;
            }
        }

        break;

    /* --------------------------------------------------------
     * SOA
     *
     * MNAME
     * RNAME
     * SERIAL
     * REFRESH
     * RETRY
     * EXPIRE
     * MINIMUM
     * -------------------------------------------------------- */

    case 6: /* SOA */
    {
        size_t tmp = rdata_off;

        char mname[DNS_MAX_NAME];
        char rname[DNS_MAX_NAME];

        if (dns_parse_name(packet,
                           len,
                           &tmp,
                           mname,
                           sizeof(mname)) == 0 &&
            dns_parse_name(packet,
                           len,
                           &tmp,
                           rname,
                           sizeof(rname)) == 0 &&
            tmp <= end &&
            end - tmp >= 20) {

            snprintf(out,
                     out_len,
                     "%s %s %u %u %u %u %u",
                     mname,
                     rname,
                     (unsigned)read_u32(packet + tmp),
                     (unsigned)read_u32(packet + tmp + 4),
                     (unsigned)read_u32(packet + tmp + 8),
                     (unsigned)read_u32(packet + tmp + 12),
                     (unsigned)read_u32(packet + tmp + 16));

            return;
        }

        break;
    }

    /* --------------------------------------------------------
     * TXT
     * -------------------------------------------------------- */

    case 16: /* TXT */
    {
        size_t p = rdata_off;
        size_t w = 0;

        while (p < end) {
            uint8_t n = packet[p++];

            if (p + n > end)
                break;

            if (w != 0) {
                if (w + 1 >= out_len)
                    break;

                out[w++] = ' ';
            }

            if (w + n + 2 >= out_len)
                break;

            out[w++] = '"';

            for (uint8_t i = 0; i < n; i++) {
                unsigned char ch = packet[p + i];

                out[w++] =
                    (ch >= 32 && ch <= 126)
                    ? (char)ch
                    : '.';
            }

            out[w++] = '"';

            p += n;
        }

        out[w] = '\0';

        if (p == end)
            return;

        break;
    }

    /* --------------------------------------------------------
     * Unknown / not-yet-decoded RDATA
     *
     * Keep a hex representation rather than losing data.
     * -------------------------------------------------------- */

    default:
        break;
    }

    {
        size_t w = 0;
        size_t limit = rdlen < 64 ? rdlen : 64;

        for (size_t i = 0;
             i < limit && w + 3 < out_len;
             i++) {

            int written = snprintf(out + w,
                                   out_len - w,
                                   "%02x",
                                   packet[rdata_off + i]);

            if (written < 0)
                break;

            w += (size_t)written;
        }

        if (limit < rdlen && w + 4 < out_len)
            snprintf(out + w,
                     out_len - w,
                     "...");
    }
}

/* ============================================================
 * Generic Resource Record parser
 *
 * Parses:
 *
 *   NAME
 *   TYPE
 *   CLASS
 *   TTL
 *   RDLENGTH
 *   RDATA
 * ============================================================ */

static int parse_rr(const uint8_t *packet,
                    size_t len,
                    size_t *offset,
                    struct dns_rr *rr)
{
    size_t pos;
    uint16_t type;
    uint16_t rrclass;
    uint16_t rdlen;

    if (!packet || !offset || !rr)
        return -1;

    memset(rr, 0, sizeof(*rr));

    pos = *offset;

    /* NAME */
    if (dns_parse_name(packet,
                       len,
                       &pos,
                       rr->name,
                       sizeof(rr->name)) < 0)
        return -1;

    /*
     * TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
     */
    if (pos > len || len - pos < 10)
        return -1;

    type = read_u16(packet + pos);
    rrclass = read_u16(packet + pos + 2);

    rr->ttl = read_u32(packet + pos + 4);

    rdlen = read_u16(packet + pos + 8);

    pos += 10;

    if (rdlen > len - pos)
        return -1;

    rr->type = type;
    rr->rrclass = rrclass;
    rr->rdlength = rdlen;

    format_rdata(packet,
                 len,
                 pos,
                 type,
                 rdlen,
                 rr->rdata,
                 sizeof(rr->rdata));

    pos += rdlen;

    *offset = pos;

    return 0;
}

/* ============================================================
 * Header parser
 * ============================================================ */

static int parse_header(const uint8_t *packet,
                        size_t len,
                        struct dns_message *msg)
{
    if (!packet || !msg)
        return -1;

    if (len < 12)
        return -1;

    msg->id = read_u16(packet);
    msg->flags = read_u16(packet + 2);

    msg->qdcount = read_u16(packet + 4);
    msg->ancount = read_u16(packet + 6);
    msg->nscount = read_u16(packet + 8);
    msg->arcount = read_u16(packet + 10);

    msg->qr = (msg->flags >> 15) & 1;
    msg->opcode = (msg->flags >> 11) & 0xf;
    msg->aa = (msg->flags >> 10) & 1;
    msg->tc = (msg->flags >> 9) & 1;
    msg->rd = (msg->flags >> 8) & 1;
    msg->ra = (msg->flags >> 7) & 1;
    msg->ad = (msg->flags >> 5) & 1;
    msg->cd = (msg->flags >> 4) & 1;
    msg->rcode = msg->flags & 0xf;

    return 0;
}

/* ============================================================
 * Question parser
 * ============================================================ */

static int parse_question(const uint8_t *packet,
                          size_t len,
                          size_t *offset,
                          struct dns_question *question)
{
    size_t pos;

    if (!packet || !offset || !question)
        return -1;

    pos = *offset;

    if (dns_parse_name(packet,
                       len,
                       &pos,
                       question->name,
                       sizeof(question->name)) < 0)
        return -1;

    if (pos > len || len - pos < 4)
        return -1;

    question->type = read_u16(packet + pos);
    question->qclass = read_u16(packet + pos + 2);

    pos += 4;

    *offset = pos;

    return 0;
}

/* ============================================================
 * Question section
 * ============================================================ */

static int parse_question_section(const uint8_t *packet,
                                  size_t len,
                                  size_t *offset,
                                  struct dns_message *msg)
{
    for (uint16_t i = 0; i < msg->qdcount; i++) {

        struct dns_question question;

        if (parse_question(packet,
                           len,
                           offset,
                           &question) < 0)
            return -1;

        if (msg->question_count < DNS_MAX_QUESTIONS)
            msg->questions[msg->question_count++] = question;
    }

    return 0;
}

/* ============================================================
 * Answer section
 * ============================================================ */

static int parse_answer_section(const uint8_t *packet,
                                size_t len,
                                size_t *offset,
                                struct dns_message *msg)
{
    for (uint16_t i = 0; i < msg->ancount; i++) {

        struct dns_rr rr;

        if (parse_rr(packet,
                     len,
                     offset,
                     &rr) < 0)
            return -1;

        if (msg->answer_count < DNS_MAX_RR)
            msg->answers[msg->answer_count++] = rr;
    }

    return 0;
}

/* ============================================================
 * Authority section
 * ============================================================ */

static int parse_authority_section(const uint8_t *packet,
                                   size_t len,
                                   size_t *offset,
                                   struct dns_message *msg)
{
    for (uint16_t i = 0; i < msg->nscount; i++) {

        struct dns_rr rr;

        if (parse_rr(packet,
                     len,
                     offset,
                     &rr) < 0)
            return -1;

        if (msg->authority_count < DNS_MAX_RR)
            msg->authority[msg->authority_count++] = rr;
    }

    return 0;
}

/* ============================================================
 * Additional section
 * ============================================================ */

static int parse_additional_section(const uint8_t *packet,
                                    size_t len,
                                    size_t *offset,
                                    struct dns_message *msg)
{
    for (uint16_t i = 0; i < msg->arcount; i++) {

        struct dns_rr rr;

        if (parse_rr(packet,
                     len,
                     offset,
                     &rr) < 0)
            return -1;

        if (msg->additional_count < DNS_MAX_RR)
            msg->additional[msg->additional_count++] = rr;
    }

    return 0;
}

/* ============================================================
 * Main DNS message parser
 * ============================================================ */

int dns_parse_message(const uint8_t *packet,
                      size_t len,
                      struct dns_message *msg)
{
    size_t offset = 0;

    if (!msg)
        return -1;

    memset(msg, 0, sizeof(*msg));

    /* --------------------------------------------------------
     * Header
     * -------------------------------------------------------- */

    if (parse_header(packet, len, msg) < 0)
        goto fail;

    offset = 12;

    /* --------------------------------------------------------
     * Question
     * -------------------------------------------------------- */

    if (parse_question_section(packet,
                               len,
                               &offset,
                               msg) < 0)
        goto fail;

    /* --------------------------------------------------------
     * Answer
     * -------------------------------------------------------- */

    if (parse_answer_section(packet,
                             len,
                             &offset,
                             msg) < 0)
        goto fail;

    /* --------------------------------------------------------
     * Authority
     * -------------------------------------------------------- */

    if (parse_authority_section(packet,
                                len,
                                &offset,
                                msg) < 0)
        goto fail;

    /* --------------------------------------------------------
     * Additional
     * -------------------------------------------------------- */

    if (parse_additional_section(packet,
                                 len,
                                 &offset,
                                 msg) < 0)
        goto fail;

    msg->parsed_len = offset;
    msg->parse_ok = 1;

    /*
     * If the DNS packet itself has TC=1, the server says the
     * response was truncated.
     */
    msg->truncated_by_capture = (msg->tc != 0);

    return 0;

fail:

    msg->parsed_len = offset;
    msg->parse_ok = 0;

    /*
     * TC means DNS-level truncation.
     *
     * offset >= len means we ran out of captured bytes while
     * parsing the message.
     */
    msg->truncated_by_capture =
        (msg->tc != 0 || offset >= len);

    return -1;
}