#ifndef _UAPI_NF_CONNTRACK_COMMON_H
#define _UAPI_NF_CONNTRACK_COMMON_H
/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */
enum ip_conntrack_info {
	/* Part of an established connection (either direction). */
	IP_CT_ESTABLISHED,

	/* Like NEW, but related to an existing connection, or ICMP error
	   (in either direction). */
	IP_CT_RELATED,

	/* Started a new connection to track (only
           IP_CT_DIR_ORIGINAL); may be a retransmission. */
	IP_CT_NEW,

	/* >= this indicates reply direction */
	IP_CT_IS_REPLY,

	IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY,
	IP_CT_RELATED_REPLY = IP_CT_RELATED + IP_CT_IS_REPLY,
	IP_CT_NEW_REPLY = IP_CT_NEW + IP_CT_IS_REPLY,	
	/* Number of distinct IP_CT types (no NEW in reply dirn). */
	IP_CT_NUMBER = IP_CT_IS_REPLY * 2 - 1
};

#define NF_CT_STATE_INVALID_BIT			(1 << 0)
#define NF_CT_STATE_BIT(ctinfo)			(1 << ((ctinfo) % IP_CT_IS_REPLY + 1))
#define NF_CT_STATE_UNTRACKED_BIT		(1 << (IP_CT_NUMBER + 1))

/* Bitset representing status of connection. */
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,  /* 表示该连接是个子连接 */
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1, /* 表示该连接上双方向上都有数据包了 */
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,  /* TCP：在三次握手建立完连接后即设定该标志。
	                         UDP：如果在该连接上的两个方向都有数据包通过，则再有数据包在该连接上通过时，就设定该标志。
							 ICMP：不设置该标志 */
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,  /* 表示该连接已被添加到net->ct.hash表中 */
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,   /*在POSTROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,  /* 在PREROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7,  /* 在POSTROUTING处，已被SNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8, /* 在PREROUTING处，已被DNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,  /* 表示该连接正在被释放，内核通过该标志保证正在被释放的ct不会被其它地方再次引用。有了这个标志，当某个连接要被删除时，即使它还在net->ct.hash中，也不会再次被引用。*/
	IPS_DYING = (1 << IPS_DYING_BIT),

	/* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT_BIT = 10, /* 固定连接超时时间，这将不根据状态修改连接超时时间。通过函数nf_ct_refresh_acct()修改超时时间时检查该标志。 */
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),

	/* Conntrack is a template */
	IPS_TEMPLATE_BIT = 11,  /* 由CT target进行设置（这个target只能用在raw表中，用于为数据包构建指定ct，并打上该标志），用于表明这个ct是由CT target创建的 */
	IPS_TEMPLATE = (1 << IPS_TEMPLATE_BIT),

	/* Conntrack is a fake untracked entry */
	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),

	/* Conntrack got a helper explicitly attached via CT target. */
	IPS_HELPER_BIT = 13,
	IPS_HELPER = (1 << IPS_HELPER_BIT),
};

/* Connection tracking event types */
enum ip_conntrack_events {
	IPCT_NEW,		/* new conntrack */
	IPCT_RELATED,		/* related conntrack */
	IPCT_DESTROY,		/* destroyed conntrack */
	IPCT_REPLY,		/* connection has seen two-way traffic */
	IPCT_ASSURED,		/* connection status has changed to assured */
	IPCT_PROTOINFO,		/* protocol information has changed */
	IPCT_HELPER,		/* new helper has been set */
	IPCT_MARK,		/* new mark has been set */
	IPCT_SEQADJ,		/* sequence adjustment has changed */
	IPCT_NATSEQADJ = IPCT_SEQADJ,
	IPCT_SECMARK,		/* new security mark has been set */
	IPCT_LABEL,		/* new connlabel has been set */
};

enum ip_conntrack_expect_events {
	IPEXP_NEW,		/* new expectation */
	IPEXP_DESTROY,		/* destroyed expectation */
};

/* expectation flags */
#define NF_CT_EXPECT_PERMANENT		0x1
#define NF_CT_EXPECT_INACTIVE		0x2
#define NF_CT_EXPECT_USERSPACE		0x4


#endif /* _UAPI_NF_CONNTRACK_COMMON_H */
