#ifndef _NET_AH_H
#define _NET_AH_H

#include <linux/skbuff.h>

struct crypto_ahash;

struct ah_data {
	// 初始化向量完整长度
	int			icv_full_len;
	// 初始化向量截断长度
	int			icv_trunc_len;
	// HASH算法
	struct crypto_ahash	*ahash;
};

struct ip_auth_hdr;

static inline struct ip_auth_hdr *ip_auth_hdr(const struct sk_buff *skb)
{
	return (struct ip_auth_hdr *)skb_transport_header(skb);
}

#endif
