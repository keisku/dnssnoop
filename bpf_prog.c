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

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
	{
		return 0;
	}
	__u16 sport = 0;
	__u16 dport = 0;
	if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 2);
		if (udph + 1 > (struct udphdr *)data_end)
		{
			return 0;
		}
		sport = bpf_ntohs(udph->source);
		dport = bpf_ntohs(udph->dest);
	}
	if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
		if (tcph + 1 > (struct tcphdr *)data_end)
		{
			return 0;
		}
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
	if (!parse_event(ctx, &evt))
	{
		return XDP_PASS;
	}
	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e)
	{
		return XDP_PASS;
	}
	*e = evt;
	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}
