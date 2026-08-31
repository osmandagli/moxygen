#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/in.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct _vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	__u32 index = ctx->rx_queue_index;
  void* data = (void *)(long)ctx->data;
  void* data_end = (void *)(long)ctx->data_end;
  __u16 nh_off;
  __u16 h_proto;
  int iphdr_len;

  // parse eth header
  nh_off = ETH_HLEN;
  struct ethhdr *eth = (void *)data;
  if (data + ETH_HLEN > data_end) {
    return XDP_PASS;
  }
  
  h_proto = eth->h_proto;

  if (bpf_ntohs(h_proto) < ETH_P_802_3_MIN)
    return XDP_PASS; // non-Ethernet II unsupported
  
  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    struct _vlan_hdr *vhdr;
    vhdr = (struct _vlan_hdr *)(data + nh_off);
    nh_off += sizeof(struct _vlan_hdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }
    h_proto = vhdr->h_vlan_encapsulated_proto;
  }

  if (h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph;
  iph = (struct iphdr *)(data + nh_off);
  if ((void *)(iph + 1) > data_end) {
      return XDP_PASS;
  }
  iphdr_len = iph->ihl * 4;
  if (iphdr_len < (int)sizeof(struct iphdr))
    return XDP_PASS;
  nh_off += iphdr_len;
  if ((void *)iph + iphdr_len > data_end)
    return XDP_PASS;
  

  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;
  
  struct udphdr *udp = NULL;
  udp = (struct udphdr *)(data + nh_off);
  nh_off += sizeof(struct udphdr);
  if (data + nh_off > data_end)
    return XDP_PASS;
  
  if (udp->dest != bpf_htons(4433))
    return XDP_PASS;

	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, XDP_PASS);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
