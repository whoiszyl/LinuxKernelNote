#ifndef _UAPI__LINUX_NETFILTER_H
#define _UAPI__LINUX_NETFILTER_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>


/* Responses from hook functions. */
#define NF_DROP 0  				//丢弃该数据包
#define NF_ACCEPT 1				//保留该数据包 这个返回值告诉 Netfilter：到目前为止,该数据包还是
								//被接受的并且该数据包应当被递交到网络协议栈的下一个阶段。
#define NF_STOLEN 2				//忘掉该数据包 该回调函数将从此开始对数据包的处理，并且Netfilter
								//应当放弃对该数据包做任何的处理。但是，这并不意味着该数据包的资源
								//已经被释放。这个数据包以及它独自的sk_buff数据结构仍然有效，只是
								//回调函数从Netfilter 获取了该数据包的所有权。
#define NF_QUEUE 3 				//将该数据包插入到用户空间 对该数据报进行排队(通常用于将数据报给用户空间的进程进行处理)
#define NF_REPEAT 4 			//再次调用该hook函数 应当谨慎使用这个值，以免造成死循环。
#define NF_STOP 5 				//一旦挂接链表中某个hook节点返回NF_STOP,
								//该skb包就立即结束检查而接收,不再进入链表中后续的hook节点,
								//而NF_ACCEPT则还需要进入后续hook点检查。
#define NF_MAX_VERDICT NF_STOP  //

/* we overload the higher bits for encoding auxiliary data such as the queue
 * number or errno values. Not nice, but better than additional function
 * arguments. */
#define NF_VERDICT_MASK 0x000000ff

/* extra verdict flags have mask 0x0000ff00 */
#define NF_VERDICT_FLAG_QUEUE_BYPASS	0x00008000

/* queue number (NF_QUEUE) or errno (NF_DROP) */
#define NF_VERDICT_QMASK 0xffff0000
#define NF_VERDICT_QBITS 16

#define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)

#define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)

/* only for userspace compatibility */
#ifndef __KERNEL__
/* Generic cache responses from hook functions.
   <= 0x2000 is used for protocol-flags. */
#define NFC_UNKNOWN 0x4000
#define NFC_ALTERED 0x8000

/* NF_VERDICT_BITS should be 8 now, but userspace might break if this changes */
#define NF_VERDICT_BITS 16
#endif

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};

enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_INET   =  1,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

union nf_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};

#endif /* _UAPI__LINUX_NETFILTER_H */
