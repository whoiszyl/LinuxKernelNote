#ifndef _NET_AH_H
#define _NET_AH_H

#include <linux/skbuff.h>

struct crypto_ahash;

struct ah_data {
	// ��ʼ��������������
	int			icv_full_len;
	// ��ʼ�������ضϳ���
	int			icv_trunc_len;
	// HASH�㷨
	struct crypto_ahash	*ahash;
};

struct ip_auth_hdr;

static inline struct ip_auth_hdr *ip_auth_hdr(const struct sk_buff *skb)
{
	return (struct ip_auth_hdr *)skb_transport_header(skb);
}

#endif
