// +build ignore

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "parsing_helpers.h"

#define MAX_MAP_ENTRIES 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct event
{
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int
parse_event(struct xdp_md *ctx, struct event *evt)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return -1;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	struct iphdr *iph;
	nh_type = parse_iphdr(&nh, data_end, &iph);
	if (nh_type < 0)
		return -1;

	__u16 sport = 0;
	__u16 dport = 0;
	if (nh_type == IPPROTO_UDP)
	{
		struct udphdr *udph;
		nh_type = parse_udphdr(&nh, data_end, &udph);
		if (nh_type < 0)
			return -1;
		sport = bpf_ntohs(udph->source);
		dport = bpf_ntohs(udph->dest);
	}

	if (nh_type == IPPROTO_TCP)
	{
		struct tcphdr *tcph;
		nh_type = parse_tcphdr(&nh, data_end, &tcph);
		if (nh_type < 0)
			return -1;
		sport = bpf_ntohs(tcph->source);
		dport = bpf_ntohs(tcph->dest);
	}

	evt->saddr = bpf_ntohl(iph->saddr);
	evt->daddr = bpf_ntohl(iph->daddr);
	evt->sport = sport;
	evt->dport = dport;

	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
	struct event evt;
	if (parse_event(ctx, &evt) < 0)
		return XDP_PASS;

	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e)
		return XDP_PASS;

	*e = evt;
	bpf_ringbuf_submit(e, 0);

	return XDP_PASS;
}
