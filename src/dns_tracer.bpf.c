// dns_tracer.bpf.c
//
// Two-hook DNS monitor:
//   XDP -> xdp_dns_parser   reads every DNS packet (query or response)
//                            seen on the wire and emits a DNSQueryEvent.
//   TC  -> tc_dns_egress /   track a query's send time on the way out,
//          tc_dns_ingress    match it against the response on the way
//                            in, and emit a latency_event.
//
// Per instructions.txt #9, uprobe/kprobe hooks are intentionally excluded
// from this build.
//
// Logging: bpf_printk() writes to the shared kernel trace pipe --
//     sudo cat /sys/kernel/debug/tracing/trace_pipe | grep dns_tracer

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "xdp.h"
#include "tc.h"

// ---------------------------------------------------------------------------
// TC egress: outgoing DNS query. Stamps send time + parses name/qtype into
// pending_queries, keyed by transaction ID + client 4-tuple.
// ---------------------------------------------------------------------------

SEC("classifier")
int tc_dns_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != 53)
        return TC_ACT_OK;

    bpf_printk("dns_tracer: tc_dns_egress: udp/53 candidate\n");

    struct DNSHeader *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return TC_ACT_OK;

    __u16 flags = bpf_ntohs(dns->flags);
    if (flags & 0x8000)  // QR bit set = response, not a query
        return TC_ACT_OK;

    struct query_key key = {};

    key.query_id = bpf_ntohs(dns->id);
    key.client_ip = ip->saddr;
    key.client_port = bpf_ntohs(udp->source);
    key.padding = 0;

    __u32 zero = 0;
    struct query_info *info = bpf_map_lookup_elem(&scratch_info, &zero);
    if (!info)
        return TC_ACT_OK;

    __builtin_memset(info, 0, sizeof(*info));
    info->start_ts = bpf_ktime_get_ns();
    info->server_ip = ip->daddr;

    /*
    * Save the complete DNS message into query_info.
    * At the same time, find QTYPE from the DNS question.
    *
    * DNS format:
    *   DNS header (12 bytes)
    *   QNAME (variable length)
    *   QTYPE (2 bytes)
    *   QCLASS (2 bytes)
    */
    __u8 *dns_ptr = (__u8 *)dns;
    __u16 qtype = 0;

    /*
    * First find QTYPE.
    *
    * We only need to walk until the end of QNAME.
    * Once QTYPE is found, stop this small parsing loop.
    */
    #pragma clang loop unroll(disable)
    for (int i = sizeof(struct DNSHeader);
        i < sizeof(info->raw_payload);
        i++) {

        if ((void *)(dns_ptr + i + 1) > data_end)
            break;

        if (dns_ptr[i] == 0) {
            if ((void *)(dns_ptr + i + 3) > data_end)
                break;

            qtype = ((__u16)dns_ptr[i + 1] << 8) |
                    (__u16)dns_ptr[i + 2];

            break;
        }
    }

    /*
    * Now copy the COMPLETE DNS payload.
    *
    * Do not stop at QNAME. Continue until:
    *   - packet ends, or
    *   - raw_payload reaches 512 bytes.
    */
    #pragma clang loop unroll(disable)
    for (int i = 0; i < sizeof(info->raw_payload); i++) {
        if ((void *)(dns_ptr + i + 1) > data_end)
            break;

        info->raw_payload[i] = dns_ptr[i];
    }

    info->query_type = qtype;


    bpf_map_update_elem(&pending_queries, &key, info, BPF_ANY);
    return TC_ACT_OK;
}

// ---------------------------------------------------------------------------
// TC ingress: incoming DNS response. Matches against pending_queries,
// computes latency, updates the histogram, and emits a latency_event.
// ---------------------------------------------------------------------------

SEC("classifier")
int tc_dns_ingress(struct __sk_buff *skb)
{
    /*
     * Make Ethernet + minimum IPv4 + UDP headers accessible
     * in the linear portion of the skb.
     */
    if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) +
                               sizeof(struct iphdr) +
                               sizeof(struct udphdr) +
                               sizeof(struct DNSHeader)) < 0)
        return TC_ACT_OK;

    /*
     * IMPORTANT:
     * Reload data/data_end after bpf_skb_pull_data().
     */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end){
        bpf_printk("UDP BOUNDS FAIL skb_len=%u\n", skb->len);
        return TC_ACT_OK;
    }

    if (bpf_ntohs(udp->source) != 53)
        return TC_ACT_OK;

    struct DNSHeader *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return TC_ACT_OK;

    __u16 flags = bpf_ntohs(dns->flags);
    if (!(flags & 0x8000))  // QR bit not set = query, not a response
        return TC_ACT_OK;

    bpf_printk("dns_tracer: tc_dns_ingress: udp/53 response id=%u\n",
               bpf_ntohs(dns->id));

    struct query_key key = {};

    key.query_id = bpf_ntohs(dns->id);
    key.client_ip = ip->daddr;
    key.client_port = bpf_ntohs(udp->dest);
    key.padding = 0;

    struct query_info *info = bpf_map_lookup_elem(&pending_queries, &key);
    if (!info) {
        bpf_printk("dns_tracer: tc_dns_ingress: no pending query for id=%u\n",
                   key.query_id);
        return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_ns = now - info->start_ts;

    struct latency_event *event;
    event = bpf_ringbuf_reserve(&latency_events, sizeof(*event), 0);
    if (event) {
        event->timestamp = now;
        event->latency_ns = latency_ns;
        event->client_ip = ip->daddr;
        event->server_ip = ip->saddr;
        event->query_id = key.query_id;
        event->query_type = info->query_type;
        event->rcode = flags & 0x0F;
        event->is_timeout = 0;
        event->answer_count = bpf_ntohs(dns->ancount);
        event->client_port = key.client_port;

        __builtin_memcpy(event->raw_payload, info->raw_payload, sizeof(event->raw_payload));

        bpf_ringbuf_submit(event, 0);
        bpf_printk("dns_tracer: tc_dns_ingress: id=%u latency_ns=%llu\n",
                   key.query_id, latency_ns);
    } else {                                 
        inc_stat(STAT_RINGBUF_DROPS);
    }

    bpf_map_delete_elem(&pending_queries, &key);

    return TC_ACT_OK;
}

// ---------------------------------------------------------------------------
// XDP: reads every DNS packet on the wire (query or response) and emits
// a DNSQueryEvent. Independent of the TC latency path above.
// ---------------------------------------------------------------------------

SEC("xdp")
int xdp_dns_parser(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL_PACKETS);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);

    if (sport != 53 && dport != 53)
        return XDP_PASS;

    bpf_printk("dns_tracer: xdp_dns_parser: udp/53 candidate\n");

    struct DNSHeader *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;
    }

    __u16 flags = bpf_ntohs(dns->flags);
    __u8 qr = (flags >> 15) & 0x1;      // Query (0) or Response (1)
    __u8 aa = (flags >> 10) & 0x1;      // Authoritative Answer
    __u8 tc = (flags >> 9) & 0x1;       // Truncated
    __u8 rcode = flags & 0xF;           // Response Code

    if (qr == 0)
        inc_stat(STAT_DNS_QUERIES);
    else
        inc_stat(STAT_DNS_RESPONSES);

    if (tc)
        inc_stat(STAT_TRUNCATED);

    if (rcode == DNS_RCODE_NXDOMAIN)
        inc_stat(STAT_NXDOMAIN);

    struct DNSQueryEvent *event;
    event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
    if (!event){
        inc_stat(STAT_RINGBUF_DROPS);
        return XDP_PASS;
    }

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = sport;
    event->dst_port = dport;
    event->query_id = bpf_ntohs(dns->id);
    event->is_response = qr;
    event->rcode = rcode;
    event->answer_count = bpf_ntohs(dns->ancount);
    event->truncated = tc;
    event->authoritative = aa;

    __u8 *dns_ptr = (__u8 *)dns;
    #pragma unroll
    for (int i = 0; i < sizeof(event->raw_payload); i++) {
        if ((void *)(dns_ptr + i + 1) > data_end)
            break;
        event->raw_payload[i] = dns_ptr[i];
    }

    bpf_printk("dns_tracer: xdp_dns_parser: id=%u qr=%u rcode=%u submitted\n",
               event->query_id, qr, rcode);
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
