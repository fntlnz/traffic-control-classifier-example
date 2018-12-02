#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include "bpf_endian.h"
#include <bits/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include "xdp-utils.h"
#define SEC(NAME) __attribute__((section(NAME), used))

struct http_payload {
  int method;
};

static inline int is_http(struct __sk_buff *skb, __u64 nh_off);
static inline int http(struct __sk_buff *skb);

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

SEC("classifier")
int imain(struct __sk_buff *skb) { return http(skb); }

static inline int http(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;

  int rc = TC_ACT_OK;
  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  if (data + nh_off > data_end) {
    return rc;
  }

  h_proto = eth->h_proto;

  if (h_proto == bpf_htons(ETH_P_IP)) {
    if (is_http(skb, nh_off) == 1) {
      trace_printk("oh, yes, HTTP\n");
    }
  }

  return rc;
}

static inline int is_http(struct __sk_buff *skb, __u64 nh_off) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = data + nh_off;

  if (iph + 1 > data_end) {
    return 0;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return 0;
  }
  __u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u32 ip_total_length = iph->tot_len;

  ip_hlen = iph->ihl << 2;

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);

  if (tcph + 1 > data_end) {
    return 0;
  }

  tcp_hlen = tcph->doff << 2;

  poffset = ETH_HLEN + ip_hlen + tcp_hlen;
  plength = ip_total_length - ip_hlen - tcp_hlen;
  if (plength >= 7) {
    unsigned long p[7];
    int i = 0;
    for (i = 0; i < 7; i++) {
      p[i] = load_byte(skb, poffset + i);
    }
    int *value;
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
      return 1;
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
