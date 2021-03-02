/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#include <linux/skbuff.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#endif
#include <linux/netdevice.h>

/* This is one larger than the largest protocol value that can be
 * found in an ipv4 or ipv6 header.  Since in both cases the protocol
 * value is presented in a __u8, this is defined to be 256.
 */
#define MAX_INET_PROTOS		256

/* 
 * inet_add_protocol函数用于将上述结构的实例(指针)
 * 存储到inet_protos 数组中
 * update:
 *  net_protocol是一个非常重要的结构，定义了协议族中支持的
 * 传输层协议以及传输层的报文接收实例。此结构是网络层和
 * 传输层之间的桥梁，当网络数据包从网络层流向传输层时，
 * 会调用此结构中的传输层协议数据时，会调用此结构中的传输层
 * 协议数据报接收处理函数。注意：此处说"传输层"并不准确，
 * 事实上包括ICMP和IGMP协议。
 *
 * 内核中为Internet协议族定义了4个net_protocol结构实例---
 * icmp_protocol、udp_protocol、tcp_protocol和igmp_protocol
 * ,分别与ICMP、UDP、TCP和IGMP协议一一对应。在Internet协议族
 * 初始化时，调用inet_add_protocol()将它们注册到net_protocol
 * 结构指针数组inet_protos[MAX_INET_PROTOS]中。在系统运行
 * 过程中，随时可以用内核模块加载/卸载方式，调用函数inet_add_protocol()
 * /inet_del_protocol()将net_protocol结构实例注册到inet_protos[]数组中，
 * 或从中删除。
 *///ops = rcu_dereference(inet_protos[proto]);通过该函数获取对应的协议ops
struct net_protocol {
	void			(*early_demux)(struct sk_buff *skb);
	/* 分组将传递到该函数进行进一步处理*/
    /*
     * 传输层协议数据包接收处理函数指针，当网络层接收IP数据包
     * 之后，根据IP数据包所指示传输层协议，调用对应传输层
     * net_protocol结构的该例程接收报文。
     * TCP协议的接收函数为tcp_v4_rcv()，UDP协议的接收函数为
     * udp_rcv()，IGMP协议为igmp_rcv()，ICMP协议为icmp_rcv()。
     */
	int			(*handler)(struct sk_buff *skb);
       /* 
        * 在接收到ICMP错误信息并需要传递到更高层时，
        * 调用该函数
        */
    /*
     * 在ICMP模块中接收到差错报文后，会解析差错报文，并根据
     * 差错报文中原始的IP首部，调用对应传输层的异常处理
     * 函数err_handler。TCP协议为tcp_v4_err()，UDP为
     * udp_err()，IGMP则无。
     */
	void			(*err_handler)(struct sk_buff *skb, u32 info);
    /*
     * GSO是网络设备支持传输层的一个功能。
     * 当GSO数据包输出时到达网络设备，如果网络设备不支持GSO的
     * 情况，则需要传输层对输出的数据包重新进行GSO分段和
     * 校验和计算。因此需要网络层提供接口给设备层，能够
     * 访问传输层的GSO分段和校验和的计算功能，对输出的数据包
     * 进行分段和执行校验和。
     * gso_send_check接口就是回调传输层在分段之前对伪首部
     * 进行校验和的计算。
     * gso_segment接口就是回调传输层GSO分段方法对大段进行分段。
     * TCP中实现的函数为tcp_v4_gso_send_check()和tcp_tso_segment()。
     * UDP不支持GSO。
     */
    /*
     * no_policy标识在路由时是否进行策略路由。TCP和UDP默认不进行
     * 策略路由。
     */
	unsigned int		no_policy:1,
				netns_ok:1,
				/* does the protocol do more stringent
				 * icmp tag validation than simple
				 * socket lookup?
				 */
				icmp_strict_tag_validation:1;
};

#if IS_ENABLED(CONFIG_IPV6)
struct inet6_protocol {
	void	(*early_demux)(struct sk_buff *skb);

	int	(*handler)(struct sk_buff *skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       u8 type, u8 code, int offset,
			       __be32 info);
	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
#endif

struct net_offload {
	struct offload_callbacks callbacks;
	unsigned int		 flags;	/* Flags used by IPv6 for now */
};
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x1

/* This is used to register socket interfaces for IP protocols.  */
struct inet_protosw {
	struct list_head list;

        /* These two fields form the lookup key.  */
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). 见sock_type与应用程序创建套接字sock函数的第二个参数一致 */
	unsigned short	 protocol; /* This is the L4 protocol number.IPPROTO_TCP UDP等  */

	struct proto	 *prot;//套接口网络层接口，对应tcp_prot  udp_prot  raw_prot
	const struct proto_ops *ops; //套接口传输层接口。TCP为inet_stream_ops UDP为inet_dgram_ops 原始套接口则为inet_sockraw_ops
  
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */  //传输控制块的ICSK中使用
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable?  端口重用*/
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. 协议不能被替换和卸载  有该标识的套接口不能允许inet_unregister_protosw*/
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? 表示是否是连接类型的套接口*/

//参考初始化在inet_init，在函数rcu_dereference(inet_protos[hash]);中获取对应protocol(tcp_protocol udp_protocol raw_protocol)
extern const struct net_protocol __rcu *inet_protos[MAX_INET_PROTOS];
extern const struct net_offload __rcu *inet_offloads[MAX_INET_PROTOS];
extern const struct net_offload __rcu *inet6_offloads[MAX_INET_PROTOS];

#if IS_ENABLED(CONFIG_IPV6)
extern const struct inet6_protocol __rcu *inet6_protos[MAX_INET_PROTOS];
#endif

int inet_add_protocol(const struct net_protocol *prot, unsigned char num);
int inet_del_protocol(const struct net_protocol *prot, unsigned char num);
int inet_add_offload(const struct net_offload *prot, unsigned char num);
int inet_del_offload(const struct net_offload *prot, unsigned char num);
void inet_register_protosw(struct inet_protosw *p);
void inet_unregister_protosw(struct inet_protosw *p);

int  udp_add_offload(struct udp_offload *prot);
void udp_del_offload(struct udp_offload *prot);

#if IS_ENABLED(CONFIG_IPV6)
int inet6_add_protocol(const struct inet6_protocol *prot, unsigned char num);
int inet6_del_protocol(const struct inet6_protocol *prot, unsigned char num);
int inet6_register_protosw(struct inet_protosw *p);
void inet6_unregister_protosw(struct inet_protosw *p);
#endif
int inet6_add_offload(const struct net_offload *prot, unsigned char num);
int inet6_del_offload(const struct net_offload *prot, unsigned char num);

#endif	/* _PROTOCOL_H */
