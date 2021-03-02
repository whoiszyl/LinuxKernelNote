/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/memcontrol.h>
#include <linux/res_counter.h>
#include <linux/static_key.h>
#include <linux/aio.h>
#include <linux/sched.h>

#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include <linux/poll.h>

#include <linux/atomic.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <net/tcp_states.h>
#include <linux/net_tstamp.h>

struct cgroup;
struct cgroup_subsys;
#ifdef CONFIG_NET
int mem_cgroup_sockets_init(struct mem_cgroup *memcg, struct cgroup_subsys *ss);
void mem_cgroup_sockets_destroy(struct mem_cgroup *memcg);
#else
static inline
int mem_cgroup_sockets_init(struct mem_cgroup *memcg, struct cgroup_subsys *ss)
{
	return 0;
}
static inline
void mem_cgroup_sockets_destroy(struct mem_cgroup *memcg)
{
}
#endif
/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
/* Validate arguments and do nothing */
static inline __printf(2, 3)
void SOCK_DEBUG(const struct sock *sk, const char *msg, ...)
{
}
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
 
/*
 * 实现控制用户进程和下半部 (例如应用程序发送数据的时候，然后进入系统调度到内核部分，这时候，内核又收到了对方来的数据，就好产生硬件中断，硬件中断上半部执行完后，执行下半部的时候就会用到刚才被抢走的发送数据的sock，从而会访问相同的数据空间，所以需要枷锁)
 以及下半部之间(例如内核硬件中断接收数据后进入软中断处理过程中，又收到了对方来的数据产生中断。)
 * 间同步锁都是由socket_lock_t结构描述的
 */
typedef struct {
       /*
        * 用来实现下半部间的同步锁,同时也用于保护owned的写操作
        */
    spinlock_t      slock;
       /* 
        * 设置owned时需要通过自旋锁slock来保护，
        * 为0表示未被用户进程锁定，为1表示
        * 被用户进程确定
        */
    int         owned;
       /*
        * 等待队列。当进程调用lock_sock对传输控制块进行上锁时，
        * 如果此时传输控制块已被软中断锁定，则此时进程只能
        * 睡眠，并将进程信息添加到此队列中，当软中断解锁
        * 传输控制块时，会唤醒此队列上的进程
        */
    wait_queue_head_t   wq;
    /*
     * We express the mutex-alike socket_lock semantics
     * to the lock validator by explicitly managing
     * the slock as a lock variant (in addition to
     * the slock itself):
     */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

struct sock;
struct proto;
struct net;

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_daddr: Foreign IPv4 addr
 *	@skc_rcv_saddr: Bound local IPv4 addr
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_u16hashes: two u16 hash values used by UDP lookup tables
 *	@skc_dport: placeholder for inet_dport/tw_dport
 *	@skc_num: placeholder for inet_num/tw_num
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_reuseport: %SO_REUSEPORT setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_portaddr_node: second hash linkage for UDP/UDP-Lite protocol
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for TCP/UDP/UDP-Lite protocol
 *	@skc_tx_queue_mapping: tx queue number for this connection
 *	@skc_refcnt: reference count
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
/* 套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
 * 以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
 * 以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
 * 以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
 * struct sock里面包含struct sock_common
 * tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)
 */

/*
 * 该结构是传输控制块信息的最小集合，由sock和inet_timewait_sock结构
 * 前面相同部分单独构成，因此只用来构成这两种结构
 */
//tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
//tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
//sock_common是传输控制块信息最小集合 struct sock是比较通用的网络层描述块，与具体的协议族无关，他描述个各个不同协议族传输层的公共信息
struct sock_common {
    /*
     * first fields are not copied in sock_copy()
     */
    /*
     * TCP维护一个所有TCP传输控制块的散列表tcp_hashinfo,
     * 而skc_node用来将所属TCP传输控制块链接到该散列表，
	 * udp的hashinfo为udp_table
     */
    union { //udp没有加入到这里面任何一个list中     本段为服务器端的时候tcp和raw在listen的时候调用inet_csk_listen_start把struct sock添加到对应协议的struct proto对应的h成员(hashinfo)中
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;// 外部/目的IPV4地址
			__be32	skc_rcv_saddr;// 本地绑定IPV4地址
		};
	};
	union  {
		unsigned int	skc_hash;//根据协议查找表获取的哈希值
		__u16		skc_u16hashes[2];//2个16位哈希值，UDP专用
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;// inet_dport占位符
			__u16	skc_num;// inet_num占位符
		};
	};

	unsigned short		skc_family;// 网络地址family
	volatile unsigned char	skc_state;// 连接状态
	unsigned char		skc_reuse:4; // SO_REUSEADDR 标记位
	unsigned char		skc_reuseport:1;// SO_REUSEPORT 标记位
	unsigned char		skc_ipv6only:1;// IPV6标记位
	int			skc_bound_dev_if;// 绑定设备索引
	union {
		struct hlist_node	skc_bind_node;// 不同协议查找表组成的绑定哈希表
		struct hlist_nulls_node skc_portaddr_node;// UDP/UDP-Lite protocol二级哈希表
	};
	struct proto		*skc_prot;// 协议回调函数，根据协议不同而不同
#ifdef CONFIG_NET_NS
	struct net	 	*skc_net;
#endif

#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr		skc_v6_daddr;
	struct in6_addr		skc_v6_rcv_saddr;
#endif

	/*
	 * fields between dontcopy_begin/dontcopy_end
	 * are not copied in sock_copy()
	 */
	/* private: */
	int			skc_dontcopy_begin[0];
	/* public: */
	union {
		struct hlist_node	skc_node;// 不同协议查找表组成的主哈希表
		struct hlist_nulls_node skc_nulls_node;// UDP/UDP-Lite protocol主哈希表
	};
	int			skc_tx_queue_mapping;// 该连接的传输队列
	atomic_t		skc_refcnt;// 套接字引用计数
	/* private: */
	int                     skc_dontcopy_end[0];
	/* public: */
};

struct cg_proto;
/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early demux
  *	@sk_dst_cache: destination cache
  *	@sk_dst_lock: destination cache lock
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_napi_id: id of the last napi context to receive data for sk
  *	@sk_ll_usec: usecs to busypoll when there is no data
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_max_pacing_rate: Maximum pacing rate (%SO_MAX_PACING_RATE)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,
  *		   %SO_OOBINLINE settings, %SO_TIMESTAMPING settings
  *	@sk_no_check_tx: %SO_NO_CHECK setting, set checksum in TX packets
  *	@sk_no_check_rx: allow zero checksum in RX packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_cgrp_prioidx: socket group's priority map index
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_rxhash: flow hash received from netif layer
  *	@sk_txhash: computed flow hash for use on transmit
  *	@sk_filter: socket filtering instructions
  *	@sk_protinfo: private area, net family specific, when not using slab
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_tsflags: SO_TIMESTAMPING socket options
  *	@sk_tskey: counter to disambiguate concurrent tstamp requests
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_classid: this socket's cgroup classid
  *	@sk_cgrp: this socket's cgroup-specific proto data
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
 */
//这个struct sock最后根据不同协议分别添加到raw_hashinfo   tcp_hashinfo 做客户端的时候是在connect的时候，通过sk_bind_node成员加入，做服务器端的时候通过
//sk_node或者sk_nulls_node加入到

//inet = inet_sk(sk);tp = tcp_sk(sk);  
struct sock { //TCP情况下的struct sock包括两种，一种称为"父"，另一种为"子"，当应用层调用sock函数的时候，内核创建的是父，当三次握手成功的第三步后会创建新的struct sock,accept的时候会取走这个sock，这个是子
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;// 网络层套接字通用结构体
#define sk_node			__sk_common.skc_node //raw通过raw_hash_sk  sk->sk_node加入到raw_hashinfo的ht,相当于struct sock连接到了raw_hashinfo中
#define sk_nulls_node		__sk_common.skc_nulls_node //tcp通过inet_hash把sk->skc_nulls_node加入到tcp_hashinfo结构中的listening_hash。见__sk_nulls_add_node_rcu
#define sk_refcnt		__sk_common.skc_refcnt// 引用计数
#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping

#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
#define sk_hash			__sk_common.skc_hash
#define sk_portpair		__sk_common.skc_portpair
#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
#define sk_addrpair		__sk_common.skc_addrpair
#define sk_daddr		__sk_common.skc_daddr // dip，Foreign IPv4 addr
#define sk_rcv_saddr		__sk_common.skc_rcv_saddr  // 记录套接字所绑定的地址 Bound local IPv4 addr
#define sk_family		__sk_common.skc_family// 协议族，例如PF_INET

//sk_flags取值为sock_flags， 状态装换图为前面的sk_state，取值为TCP_SYN_RECV等          sk_state在tcp_set_state中赋值
#define sk_state		__sk_common.skc_state //创建sk的时候，默认为TCP_CLOSE sock_init_data
#define sk_reuse		__sk_common.skc_reuse// 地址是否可重用，只有RAW才使用
#define sk_reuseport		__sk_common.skc_reuseport
#define sk_ipv6only		__sk_common.skc_ipv6only
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if //Bound device index if != 0

//客户端tcp在conncet的时候把sk通过inet_bind_bucket加入到tcp_hashinfo中       inet_bind_bucket也被添加到inet_connection_sock中的icsk_bind_hash 
//参考  sk_add_bind_node
#define sk_bind_node		__sk_common.skc_bind_node //见inet_bind_hash    struct sock被添加到inet_bind_bucket结构的owners链表中(inet_bind_hash)，然后该inet_bind_bucket通过node节点加入到tcp_hashinfo中
/* 指向网络接口层的指针,如果是TCP套接字，为tcp_prot
 * 如果是UDP套接字为udp_prot。raw_prot
 */
#define sk_prot			__sk_common.skc_prot // 例如指向tcp_prot
#define sk_net			__sk_common.skc_net
#define sk_v6_daddr		__sk_common.skc_v6_daddr // dip，Foreign IPv6 addr
#define sk_v6_rcv_saddr	__sk_common.skc_v6_rcv_saddr // 记录套接字所绑定的地址 Bound local IPv6 addr

    /*
     * 同步锁，其中包括了两种锁:一是用于用户进程读取数据
     * 和网络层向传输层传递数据之间的同步锁；二是控制Linux
     * 下半部访问本传输控制块的同步锁，以免多个下半部同
     * 时访问本传输控制块
     */
	socket_lock_t		sk_lock;// 锁标志， 每个socket都有一个自旋锁，该锁在用户上下文和软中断处理时提供了同步机制
	struct sk_buff_head	sk_receive_queue;// 接受队列
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 * Note : rmem_alloc is in this structure to fill a hole
	 * on 64bit arches, not because its logically part of
	 * backlog.
	 */
    /*
     * 后备接收队列，目前只用于TCP.传输控制块被上锁后(如应用层
     * 读取数据时),当有新的报文传递到传输控制块时，只能把报文
     * 放到后备接受队列中，之后有用户进程读取TCP数据时，再从
     * 该队列中取出复制到用户空间中.
     * 一旦用户进程解锁传输控制块，就会立即处理
     * 后备队列，将TCP段处理之后添加到接收队列中。
     */
	struct {
		atomic_t	rmem_alloc;// 接受队列中存放的数据的字节数
		int		len;
		struct sk_buff	*head;
		struct sk_buff	*tail;
	} sk_backlog;
//表示接收队列中所有skb的总长度，在sock_queue_rcv_skb函数的skb_set_owner_r中增加
#define sk_rmem_alloc sk_backlog.rmem_alloc
    /* 
     * 预分配缓存长度，这只是一个标识，目前 只用于TCP。
     * 当分配的缓存小于该值时，分配必然成功，否则需要
     * 重新确认分配的缓存是否有效。参见__sk_mem_schedule().
     * 在sk_clone()中，sk_forward_alloc被初始化为0.
     * 
     * update:sk_forward_alloc表示预分配长度。当我们第一次要为
     * 发送缓冲队列分配一个struct sk_buff时，我们并不是直接
     * 分配需要的内存大小，而是会以内存页为单位进行
     * 预分配(此时并不是真的分配内存)。当把这个新分配
     * 成功的struct sk_buff放入缓冲队列sk_write_queue后，从sk_forward_alloc
     * 中减去该sk_buff的truesize值。第二次分配struct sk_buff时，只要再
     * 从sk_forward_alloc中减去新的sk_buff的truesize即可，如果sk_forward_alloc
     * 已经小于当前的truesize，则将其再加上一个页的整数倍值，
     * 并累加如tcp_memory_allocated。
     
     *   也就是说，通过sk_forward_alloc使全局变量tcp_memory_allocated保存
     * 当前tcp协议总的缓冲区分配内存的大小，并且该大小是
     * 页边界对齐的。
     */ 
	 //这是本sock的缓存大小，如果要看整个tcp sock的缓存大小，要参考tcp_prot中的memory_allocated成员
     //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法 。  
	 //注意和上面的sk_wmem_alloc的区别
	int			sk_forward_alloc;//预分配剩余字节数,skb_entail中的sk_mem_charge里面会对新分配的SKB空间做一次减法，表示预分配缓存空间少了  
								 //在真正分配空间之前需要比较这个值，看内存空间释放使用达到限度
								 //在应用层send_msg的时候，会在函数__sk_mem_schedule中开辟空间，为sk_forward_alloc增加amt * SK_MEM_QUANTUM;如果发送的数据长度小于该值，肯定超过，若果大于该值
								 //则会增加sk_forward_alloc拥有的内存空间，见sk_wmem_schedule
								 //该变量表示的是当前sk的可用空间，预分配后的可用空间。例如应用层send，在内核分配ksb的时候空间做减法，表示可用空间少了这部分长度，
								 //当发送出去释放skb后，做加法，这时表示可用空间有多了
    
#ifdef CONFIG_RPS
	__u32			sk_rxhash;
#endif
	__u32			sk_txhash;
#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int		sk_napi_id;//接收sk数据的最后一个napi上下文的id
	unsigned int		sk_ll_usec;//当没有数据时使用busypoll
#endif
	atomic_t		sk_drops;
	/* 接收缓冲区大小的上限，默认值是sysctl_rmem_default(sock_init_data)，即32767， 也就是IP首部16位长度(最大65535)的一半*/
    //当sock接收到一个包的时候，会在sock_queue_rcv_skb中判断当前队列中已有的skb占用的buffer和这个新来的buff之后是否超过了sk_rcvbuf
	int			sk_rcvbuf;// 接受缓冲区的大小（按字节）
    /* 
     * 套接字过滤器。在传输层对输入的数据包通过BPF过滤代码进行过滤，
     * 只对设置了套接字过滤器的进程有效。
     */
	struct sk_filter __rcu	*sk_filter;
	struct socket_wq __rcu	*sk_wq; // 等待队列

#ifdef CONFIG_XFRM
    /* 与IPSee相关的传输策略 */
	struct xfrm_policy	*sk_policy[2];
#endif
    /*
     * 标志位，可能的取值参见枚举类型sock_flags.
     * 判断某个标志是否设置调用sock_flag函数来
     * 判断，而不是直接使用位操作。
     */
	unsigned long 		sk_flags;//sk_flags取值为sock_flags， 状态装换图为前面的sk_state，取值为TCP_SYN_RECV等
	struct dst_entry	*sk_rx_dst;
	/*
     * 目的路由项缓存，一般都是在创建传输控制块发送
     * 数据报文时，发现未设置该字段才从路由表或路由
     * 缓存中查询到相应的路由项来设置新字段，这样可以
     * 加速数据的输出，后续数据的输出不必再查询目的
     * 路由。某些情况下会刷新此目的路由缓存，比如断开
     * 连接、重新进行了连接、TCP重传、重新绑定端口
     * 等操作
     */
	struct dst_entry __rcu	*sk_dst_cache;// 目的地的路由缓存
	spinlock_t		sk_dst_lock;// 为该socket赋dst_entry值时的锁
    /* 所在传输控制块中，为发送而分配的所有SKB数据区的总长度。这个成员和
     * sk_wmem_queued不同，所有因为发送而分配的SKB数据区的内存都会统计到
     * sk_wmem_alloc成员中。例如，在tcp_transmit_skb()中会克隆发送队列中的
     * SKB，克隆出来的SKB所占的内存会统计到sk_wmem_alloc，而不是sk_wmem_queued中。
     *  
     * 释放sock结构时，会先将sk_wmem_alloc成员减1，如果为0，说明没有待
     * 发送的数据，才会真正释放。所以这里要先将其初始化为1   ,参见 
     * sk_alloc()。
     * 该成员在skb_set_owner_w()中会更新。
     */
	 //通过阅读函数sock_alloc_send_pskb可以理解改变量的作用  每开辟一个SKB的时候当应用程序通过套接口传数据的时候，最终会把数据传输到SKB中，
	 //然后把数据长度+header长度的值赋值给该变量中，表示当前该套接字中未发送的数据为多少
	 // 见sock_alloc_send_pskb中的skb_set_owner_w   在开辟空间前要和sk_sndbuf做比较
	 //在sk_alloc的时候初始化设置为1，然后在skb_set_owner_w加上SKB长度，当SKB发送出去后，在减去该SKB的长度，所以这个值当数据发送后其值始终是1，不会执行sock_wfree
	 //这个为发送队列(包括克隆的)分配的实际空间，sk_forward_alloc是提前预分配的，实际上并没有分片空间，只是说先确定下来可以用这么多空间，就是后面分片空间的时候最多可以分片这么多空间。
    atomic_t        sk_wmem_alloc; //这个只针对发送数据，接收数据对应的是sk_rmem_alloc，   //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
    /* 
     * 分配辅助缓冲区的上限，辅助数据包括进行设置选项、
     * 设置过滤时分配到的内存和组播设置等
     */
    atomic_t        sk_omem_alloc; // 在TCP分析中无须考虑 * "o" is "option" or "other" 
    /*
     * 发送缓冲区长度的上限，发送队列中报文数据总长度不能
     * 超过该值.默认值是sysctl_wmem_default，即32767。在通过setsockops设置时，其值最大为sysctl_wmem_max的两倍
     */ //发送缓冲区会根据该proto使用的内存情况，进行调整，见__sk_mem_schedule中的sk_stream_moderate_sndbuf        并能通过tcp_rmem调整。 
    int         sk_sndbuf; //setsockops中设置   这个是本sock发送缓存的最大值，整个tcp_prot或者udp_prot的内存情况比较，参考proto相关字段
    /*
     * 发送队列，在TCP中，此队列同时也是重传队列，
     * 在sk_send_head之前为重传队列，之后为发送
     * 队列，参见sk_send_head
     */ //这上面存的是发送SKB链表，即使调用了dev_queue_xmit后,该SKB海在该链表上面，知道收到对方ack。
     //图形化理解参考樊东东下P866
	struct sk_buff_head	sk_write_queue;// 发送队列
	kmemcheck_bitfield_begin(flags);
	/*
     * 关闭套接口的标志，下列值之一:
     * RCV_SHUTDOWN: 接收通道关闭，不允许继续接收数据  在接收到FIN并发送ACK的时候，接不能再接收数据了(一种是主动关闭端的第三步FIN和第四步ACK，另一种是被动接收到第一步FIN并发送ACK)。
     * SEND_SHUTDOWN: 发送通道关闭，不允许继续发送数据  在发送FIN并接收到ACK的时候，就不能再发送数据了。(一种是主动关闭的一段发送第一步FIN并受到ACK，另一种是被动端发送第三步FIN并受到ACK)
     * SHUTDOWN_MASK: 表示完全关闭
     */ 
	 //如果设置了RCV_SHUTDOWN，则不允许接收数据         如果设置了SEND_SHUTDOWN则不允许接收数据
     //实际起作用的地方是决定是否能接收发送数据
	unsigned int		sk_shutdown  : 2,// 判断该socket连接在某方向或者双向方向上都已经关闭
				//在setsockops中设置为SO_NO_CHECK的时候生效
				sk_no_check_tx : 1,
				sk_no_check_rx : 1,
				/*
				 * 包括如下几种值的组合，从而改变收包等操作的执行顺序
				 * #define SOCK_SNDBUF_LOCK 1
				 * #define SOCK_RCVBUF_LOCK 2
				 * #define SOCK_BINDADDR_LOCK 4
				 * #define SOCK_BINDPORT_LOCK 8
				 */
				sk_userlocks : 4,
				sk_protocol  : 8,//也就是应用层sock函数的第三个参数，表示协议类型，如果为netlink，也就是最大为32
#define SK_PROTOCOL_MAX U8_MAX
				/* 
				 * 所属的套接字类型，如SOCK_STREAM
				 */
				sk_type      : 16;
	kmemcheck_bitfield_end(flags);
	/* 发送队列中所有报文数据的总长度，目前只用于TCP 。这里
     * 统计的是发送队列中所有报文的长度，不包括因为发送而克隆
     * 出来的SKB占用的内存。是真正的占用空间的发送队列数据长度。见skb_entail
     * /
	int			sk_wmem_queued;// 传输队列大小,所有已经发送的数据的总字节数
	gfp_t			sk_allocation;// 分配该sock之skb时选择的模式，GFP_ATOMIC还是GFP_KERNEL等等
	u32			sk_pacing_rate; /* bytes per second */
	u32			sk_max_pacing_rate;//最大的速率
	/*
     * 目的路由网络设备的特性，在sk_setup_caps()中根据
     * net_device结构的features成员设置
     */ 
	//如果网口设备dev设置了dev->features |= NETIF_F_TSO，则支持TSO      参考e1000网卡的这里enic_ethtool_ops
	netdev_features_t	sk_route_caps;//路由能力,指示本sock用到的路由的信息
	netdev_features_t	sk_route_nocaps;//禁止路线能力
	/*
     * 传输层支持的GSO类型，如SKB_GSO_TCPV4等  默认该值为SKB_GSO_TCPV4
     */
	int			sk_gso_type;//L4协议期望底层支持的GSO技术
	/*
     * 这个成员在sk_setup_caps()中初始化，表示最大TCP分段的大小。
     * 注意，这个大小包括IP首部长度长度、IP选项长度及TCP首部和选项，
     * 另外还要减1(这个减1不知道是为什么。。。。)
     */
	unsigned int		sk_gso_max_size;
	u16			sk_gso_max_segs;
	int			sk_rcvlowat;/* 声明在开始发送 数据 (SO_SNDLOWAT) 或正在接收数据的用户 (SO_RCVLOWAT) 传递数据之
							 * 前缓冲区内的最小字节数. 在 Linux 中这两个值是不可改变的, 固定为 1 字节. */
	unsigned long	        sk_lingertime;// lingertime一起，指明了close()后保留的时间
	/* 
     * 错误链表，存放详细的出错信息。应用程序通过setsockopt
     * 系统调用设置IP_RECVERR选项，即需获取详细出错信息。当
     * 有错误发生时，可通过recvmsg()，参数flags为MSG_ERRQUEUE
     * 来获取详细的出错信息
     * update:
     * sk_error_queue用于保存错误消息，当ICMP接收到差错消息或者
     * UDP套接字和RAW套接字输出报文出错时，会产生描述错误信息的
     * SKB添加到该队列上。应用程序为能通过系统调用获取详细的
     * 错误消息，需要设置IP_RECVERR套接字选项，之后可通过参数
     * flags为MSG_ERRQUEUE的recvmsg系统调用来获取详细的出错
     * 信息。
     * UDP套接字和RAW套接字在调用recvmsg接收数据时，可以设置
     * MSG_ERRQUEUE标志，只从套接字的错误队列上接收错误而不
     * 接收其他数据。实现这个功能是通过ip_recv_error()来完成的。
     * 在基于连接的套接字上，IP_RECVERR意义则会有所不同。并不
     * 保存错误信息到错误队列中，而是立即传递所有收到的错误信息
     * 给用户进程。这对于基于短连接的TCP应用是很有用的，因为
     * TCP要求快速的错误处理。需要注意的是，TCP没有错误队列，
     * MSG_ERRQUEUE对于基于连接的套接字是无效的。
     * 错误信息传递给用户进程时，并不将错误信息作为报文的内容传递
     * 给用户进程，而是以错误信息块的形式保存在SKB控制块中，
     * 通常通过SKB_EXT_ERR来访问SKB控制块中的错误信息块。
     * 参见sock_exterr_skb结构。
     */
	struct sk_buff_head	sk_error_queue; //icmp差错信息会添加到该链表中 参考樊东东P229 P230
	/*
     * 原始网络协议块指针。因为传输控制块中的另一个网络
     * 协议块指针sk_prot在IPv6的IPV6_ADDRFORM套接字选项
     * 设置时被修改
     */
	struct proto		*sk_prot_creator;
	/*
     * 确保传输控制块中一些成员同步访问的锁。因为有些成员在软
     * 中断中被访问，存在异步访问的问题
     *
     */
	rwlock_t		sk_callback_lock; // sock相关函数内部操作的保护锁
	/*
     * 记录当前传输层中发生的最后一次致命错误的错误码，但
     * 应用层读取后会自动恢复为初始正常状态.
     * 错误码的设置是由tcp_v4_err()函数完成的。
     */
	int			sk_err,
	/*
     * 用于记录非致命性错误，或者用作在传输控制块被
     * 锁定时记录错误的后备成员
     */
				sk_err_soft;
	    /* 当前已建立的连接数 */  //表示套接口上可以排队等待连接的连接数门限值
    //在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
	//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
	//这个是从半连接队列取出request_sock后加入到已连接队列中的request_sock个数，sk_ack_backlog是已经完成了三次握手，但是还没有被accept系统调用处理的连接请求数量；
	//sk_max_ack_backlog就是我们经常熟悉的listen的参数。
	//建立连接的过程中加1，在reqsk_queue_add中赋值 减1在reqsk_queue_get_child
	/* 连接队列长度的上限 ，其值是用户指定的连接
     * 队列长度与/proc/sys/net/core/somaxconn(默认值是128)之间的较小值。表示该sock上面最多可以由多少个连接，见tcp_v4_conn_request中的sk_acceptq_is_full
     * 用这个变量的sk应该是accept前的那个sk
     */
	unsigned short		sk_ack_backlog;// 当前已经accept的数目
	unsigned short		sk_max_ack_backlog;// 当前listen sock能保留多少个待处理TCP连接.
	/* 用于设置由此套接字输出数据包的QoS类别 */
	__u32			sk_priority;/* Packet queueing priority，Used to set the TOS field. Packets with a higher priority may be processed first, depending on the device’s queueing discipline. See SO_PRIORITY */
#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
	__u32			sk_cgrp_prioidx;
#endif
	struct pid		*sk_peer_pid;
	const struct cred	*sk_peer_cred;
    /* 
     * 套接字层接收超时，初始值为MAX_SCHEDULE_TIMEOUT。
     * 可以通过套接字选项SO_RCVTIMEO来设置接收的超时时间。 sock_init_data设置为无限大，也就是accept的时候默认是无限阻塞的，见inet_csk_accept
     * 如果想设置为非阻塞，可以通过SO_RCVTIMEO参数设置
     */
	long			sk_rcvtimeo;// 接收时的超时设定, 并在超时时报错
	/* 
     * 套接字层发送超时,初始值为MAX_SCHEDULE_TIMEOUT。
     * 可以通过套接字选项SO_SNDTIMEO来设置发送的超时时间。 connect的时候判断是否connect超时用的就是这个值  使用该值的地方在sock_sndtimeo
     */
	long			sk_sndtimeo;// 发送时的超时设定, 并在超时时报错
	/* 
     * 传输控制块存放私有数据的指针
     */
	void			*sk_protinfo;
    /*
     * 通过TCP的不同状态，来实现连接定时器、FIN_WAIT_2定时器(该定时器在TCP四次挥手过程中结束，见tcp_rcv_state_process)以及
     * TCP保活定时器，在tcp_keepalive_timer中实现
     * 定时器处理函数为tcp_keepalive_timer(),参见tcp_v4_init_sock()
     * 和tcp_init_xmit_timers()。
     */
    struct timer_list   sk_timer;//inet_csk_init_xmit_timers  sock_init_data
    /* 
     * 在未启用SOCK_RCVTSTAMP套接字选项时，记录报文接收数据到
     * 应用层的时间戳。在启用SOCK_RCVTSTAMP套接字选项时，接收
     * 数据到应用层的时间戳记录在SKB的tstamp中
     */
    ktime_t         sk_stamp;
	u16			sk_tsflags;
	u32			sk_tskey;
	struct socket		*sk_socket;// 对应的socket
	/* RPC层存放私有数据的指针 ，IPv4中未使用 */
	void			*sk_user_data;
	struct page_frag	sk_frag;//页缓存碎片
	/*
     * 指向sk_write_queue队列中第一个未发送的结点，如果sk_send_head
     * 为空则表示发送队列是空的，发送队列上的报文已全部发送。
     */
	struct sk_buff		*sk_send_head;//表示sk_write_queue队列中还未调用dev_queue_xmit的最前面一个SKB的地方
	/* 
     * 表示数据尾端在最后一页分片内的页内偏移，
     * 新的数据可以直接从这个位置复制到该分片中
     */ 
	 //在tcp_sendmsg中开辟空间后，并复制，见里面的TCP_OFF(sk) = off + copy;
	__s32			sk_peek_off;
	/* 标识有数据即将写入套接口，
     * 也就是有写数据的请求
	 */
	int			sk_write_pending;
#ifdef CONFIG_SECURITY
	/* 指向sk_security_struct结构，安全模块使用*/
	void			*sk_security;
#endif
	__u32			sk_mark;
	u32			sk_classid;
	struct cg_proto		*sk_cgrp;
	/*
     * 当传输控制块的状态发生变化时，唤醒哪些等待本套接字的进程。
     * 在创建套接字时初始化，IPv4中为sock_def_wakeup()  通常当传输 状态发生变化时调用
     */
	void			(*sk_state_change)(struct sock *sk);
	/*
     * 当有数据到达接收处理时，唤醒或发送信号通知准备读本套接字的
     * 进程。在创建套接字时被初始化，IPv4中为sock_def_readable()。如果
     * 是netlink套接字，则为netlink_data_ready()。 通常当传输控制块接收到数据包，存在可读的数据之后被调用
     */
	void			(*sk_data_ready)(struct sock *sk); //内核创建netlink sock的时候，对应的是netlink_kernel_create->netlink_data_ready
	/*
     * 在发送缓存大小发生变化或套接字被释放时，唤醒因等待本套接字而
     * 处于睡眠状态的进程，包括sk_sleep队列以及fasync_list队列上的
     * 进程。创建套接字时初始化，IPv4中默认为sock_def_write_space(),
     * TCP中为sk_stream_write_space().   进程处于休眠状态的地方在sock_alloc_send_pskb里面的sock_wait_for_wmem
     */
	void			(*sk_write_space)(struct sock *sk); //该函数在释放SKB的时候执行，见sock_wfree sock_rfree
	/*
     * 报告错误的回调函数，如果等待该传输控制块的进程正在睡眠，
     * 则将其唤醒(例如MSG_ERRQUEUE).在创建套接字时被初始化，
     * IPv4中为sock_def_error_report(). 通常当传输控制块发生错误时被调用
     */
	void			(*sk_error_report)(struct sock *sk);
	/*
     * 用于TCP和PPPoE中。在TCP中，用于接收预备队列和后备队列中的
     * TCP段，TCP的sk_backlog_rcv接口为tcp_v4_do_rcv()。如果预备
     * 队列中还存在TCP段，则调用tcp_prequeue_process()预处理，在
     * 该函数中会回调sk_backlog_rcv()。如果后备队列中还存在TCP段，
     * 则调用release_sock()处理，也会回调sk_backlog_rcv()。该函数
     * 指针在创建套接字的传输控制块时由传输层backlog_rcv接口初始化
     */
	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);
	/*
     * 进行传输控制块的销毁，在释放传输控制块前释放一些其他资源，在
     * sk_free()释放传输控制块时调用。当传输控制块的引用计数器为0时，
     * 才真正释放。IPv4中为inet_sock_destruct().
     */
	void                    (*sk_destruct)(struct sock *sk);
};


#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)	rcu_dereference(__sk_user_data((sk)))
#define rcu_assign_sk_user_data(sk, ptr)	rcu_assign_pointer(__sk_user_data((sk)), ptr)

/*
 * SK_CAN_REUSE and SK_NO_REUSE on a socket mean that the socket is OK
 * or not whether his port will be reused by someone else. SK_FORCE_REUSE
 * on a socket means that the socket will reuse everybody else's port
 * without looking at the other's sk_reuse value.
 */

#define SK_NO_REUSE	0
#define SK_CAN_REUSE	1
#define SK_FORCE_REUSE	2

static inline int sk_peek_offset(struct sock *sk, int flags)
{
	if ((flags & MSG_PEEK) && (sk->sk_peek_off >= 0))
		return sk->sk_peek_off;
	else
		return 0;
}

static inline void sk_peek_offset_bwd(struct sock *sk, int val)
{
	if (sk->sk_peek_off >= 0) {
		if (sk->sk_peek_off >= val)
			sk->sk_peek_off -= val;
		else
			sk->sk_peek_off = 0;
	}
}

static inline void sk_peek_offset_fwd(struct sock *sk, int val)
{
	if (sk->sk_peek_off >= 0)
		sk->sk_peek_off += val;
}

/*
 * Hashed lists helper routines
 */
static inline struct sock *sk_entry(const struct hlist_node *node)
{
	return hlist_entry(node, struct sock, sk_node);
}

static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *__sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_entry(head->first, struct sock, sk_nulls_node);
}

static inline struct sock *sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL : __sk_nulls_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return sk->sk_node.next ?
		hlist_entry(sk->sk_node.next, struct sock, sk_node) : NULL;
}

static inline struct sock *sk_nulls_next(const struct sock *sk)
{
	return (!is_a_nulls(sk->sk_nulls_node.next)) ?
		hlist_nulls_entry(sk->sk_nulls_node.next,
				  struct sock, sk_nulls_node) :
		NULL;
}

static inline bool sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline bool sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static inline void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static inline void sk_nulls_node_init(struct hlist_nulls_node *node)
{
	node->pprev = NULL;
}

static inline void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static inline bool __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return true;
	}
	return false;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static inline bool sk_del_node_init(struct sock *sk)
{
	bool rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)

static inline bool __sk_nulls_del_node_init_rcu(struct sock *sk)
{
	if (sk_hashed(sk)) {
		hlist_nulls_del_init_rcu(&sk->sk_nulls_node);
		return true;
	}
	return false;
}

static inline bool sk_nulls_del_node_init_rcu(struct sock *sk)
{
	bool rc = __sk_nulls_del_node_init_rcu(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static inline void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static inline void sk_add_node_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	hlist_add_head_rcu(&sk->sk_node, list);
}

static inline void __sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&sk->sk_nulls_node, list);
}

static inline void sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	sock_hold(sk);
	__sk_nulls_add_node_rcu(sk, list);
}

static inline void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static inline void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)

/**
 * sk_nulls_for_each_entry_offset - iterate over a list at a given struct offset
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @offset:	offset of hlist_node within the struct.
 *
 */
#define sk_nulls_for_each_entry_offset(tpos, pos, head, offset)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = pos->next)

static inline struct user_namespace *sk_user_ns(struct sock *sk)
{
	/* Careful only use this in a context where these parameters
	 * can not change and must all be valid, such as recvmsg from
	 * userspace.
	 */
	return sk->sk_socket->file->f_cred->user_ns;
}

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,/* 连接已断开，套接字即将关闭  //tcp_close里面的sock_orphan执行这个*/
	SOCK_DONE,/* 标识TCP会话即将结束，在接收到FIN报文时设置*/
	SOCK_URGINLINE,/* 带外数据放入正常数据流，在普通数据流中接收带外数据*/
	SOCK_KEEPOPEN,/* 启用TCP传输层的保活定时*/
	/* 关闭套接字前发送剩余数据的时间，如果设置了该标记，应用层CLOSE的时候不会立马返回，
     * 会等待设置该标志的时候携带的等待时间后才返回，如果这个时间大于0，则会等待，等待过程中，缓冲区的数据就可以发送出去，
     * 如果等待时间为0，则直接删除未发送的数据，见inet_release   tcp_close
     */
	SOCK_LINGER,
	SOCK_DESTROY,/* 协议控制块已经释放，IPv4协议族未使用 */
	SOCK_BROADCAST,/* 套接口支持收发广播报文*/
	SOCK_TIMESTAMP,/* 标识是否启用段的接收时间作为时间戳*/
	SOCK_ZAPPED,/* 在ax25和ipx协议族中标识建立了连接。IPv4协议族未使用*/
	/* 
	 * 标识是否初始化了传输控制块中的sk_write_space()指针，这样在
	 * sock_wfree()中sk_write_space可以被调用
	 */
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	/* 记录套接字的调试信息*/
	SOCK_DBG, /* %SO_DEBUG setting */
	/* 数据包的接收时间作为时间戳*/
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	/* 使用本地路由表还是策略路由表*/
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	/* 发送队列的缓存区最近是否缩小过 */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
	SOCK_MEMALLOC, /* VM depends on this socket for swapping */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY, /* buffers from userspace */
	SOCK_WIFI_STATUS, /* push wifi status to userspace */
	SOCK_NOFCS, /* Tell NIC not to do the Ethernet FCS.
		     * Will use last 4 bytes of packet sent from
		     * user-space instead.
		     */
	SOCK_FILTER_LOCKED, /* Filter cannot be changed anymore */
	SOCK_SELECT_ERR_QUEUE, /* Wake select on error queue */
};

#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

#ifdef CONFIG_NET
extern struct static_key memalloc_socks;
static inline int sk_memalloc_socks(void)
{
	return static_key_false(&memalloc_socks);
}
#else

static inline int sk_memalloc_socks(void)
{
	return 0;
}

#endif

static inline gfp_t sk_gfp_atomic(struct sock *sk, gfp_t gfp_mask)
{
	return GFP_ATOMIC | (sk->sk_allocation & __GFP_MEMALLOC);
}
//在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

//在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

//sk_ack_backlog是已经完成了三次握手，但是还没有被accept系统调用处理的连接请求数量是否已经达到最大限制
static inline bool sk_acceptq_is_full(const struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(const struct sock *sk)
{
	return sk->sk_wmem_queued >> 1;
}

static inline int sk_stream_wspace(const struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

void sk_stream_write_space(struct sock *sk);

/* OOB backlog add */
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* dont let skb dst not refcounted, we are going to leave rcu lock */
	skb_dst_force_safe(skb);

	if (!sk->sk_backlog.tail)
		sk->sk_backlog.head = skb;
	else
		sk->sk_backlog.tail->next = skb;

	sk->sk_backlog.tail = skb;
	skb->next = NULL;
}

/*
 * Take into account size of receive queue and backlog queue
 * Do not take into account this skb truesize,
 * to allow even a single big packet to come.
 */
static inline bool sk_rcvqueues_full(const struct sock *sk, unsigned int limit)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize > limit;
}

/* The per-socket spinlock must be held here. */
static inline __must_check int sk_add_backlog(struct sock *sk, struct sk_buff *skb,
					      unsigned int limit)
{
	if (sk_rcvqueues_full(sk, limit))
		return -ENOBUFS;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC))
		return -ENOMEM;

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
	return 0;
}

int __sk_backlog_rcv(struct sock *sk, struct sk_buff *skb);

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (sk_memalloc_socks() && skb_pfmemalloc(skb))
		return __sk_backlog_rcv(sk, skb);

	return sk->sk_backlog_rcv(sk, skb);
}

static inline void sock_rps_record_flow_hash(__u32 hash)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_record_sock_flow(sock_flow_table, hash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_reset_flow_hash(__u32 hash)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_reset_sock_flow(sock_flow_table, hash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_record_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	sock_rps_record_flow_hash(sk->sk_rxhash);
#endif
}

static inline void sock_rps_reset_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	sock_rps_reset_flow_hash(sk->sk_rxhash);
#endif
}

static inline void sock_rps_save_rxhash(struct sock *sk,
					const struct sk_buff *skb)
{
#ifdef CONFIG_RPS
	if (unlikely(sk->sk_rxhash != skb->hash)) {
		sock_rps_reset_flow(sk);
		sk->sk_rxhash = skb->hash;
	}
#endif
}

static inline void sock_rps_reset_rxhash(struct sock *sk)
{
#ifdef CONFIG_RPS
	sock_rps_reset_flow(sk);
	sk->sk_rxhash = 0;
#endif
}

#define sk_wait_event(__sk, __timeo, __condition)			\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		}							\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
void sk_stream_wait_close(struct sock *sk, long timeo_p);
int sk_stream_error(struct sock *sk, int flags, int err);
void sk_stream_kill_queues(struct sock *sk);
void sk_set_memalloc(struct sock *sk);
void sk_clear_memalloc(struct sock *sk);

int sk_wait_data(struct sock *sk, long *timeo);

struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;
struct raw_hashinfo;
struct module;

/*
 * caches using SLAB_DESTROY_BY_RCU should let .next pointer from nulls nodes
 * un-modified. Special care is taken when initializing object to zero.
 */
static inline void sk_prot_clear_nulls(struct sock *sk, int size)
{
	if (offsetof(struct sock, sk_node.next) != 0)
		memset(sk, 0, offsetof(struct sock, sk_node.next));
	memset(&sk->sk_node.pprev, 0,
	       size - offsetof(struct sock, sk_node.pprev));
}

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */
 //网络层接口，对应tcp_prot  udp_prot  raw_prot
 //struct inet_protosw结构中有结构
struct proto {
	void			(*close)(struct sock *sk,
					long timeout);
	int			(*connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept)(struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk); /* 传输层初始化接口，在创建套接口时，在inet_create中调用 */
	void			(*destroy)(struct sock *sk); /* 关闭套接口的时候调用 */
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					int __user *option);
#ifdef CONFIG_COMPAT
	int			(*compat_setsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*compat_getsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int __user *option);
	int			(*compat_ioctl)(struct sock *sk,
					unsigned int cmd, unsigned long arg);
#endif
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					   size_t len, int noblock, int flags,
					   int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk,
					struct sockaddr *uaddr, int addr_len);


/* 引入这个后备队列的原因:例如TCP段接收过程中，如果传输控制块未被用户进程上锁，则将TCP段输入到接收队列中，
 * 否则接收到后备队列中,如果没有后备队列，如过用户进程在recv数据的时候，进入系统内核调度中执行，如果这时候驱动接收到数据
 * 执行完硬件中断开始执行下半部的时候，如果直接用已有队列就会对共享内存数据造成影响
 */
	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb); /* 用于接收预备队列和后备队列中的数据 */

	void		(*release_cb)(struct sock *sk);

    /* 
     * hash为添加到管理传输控制块散列表的接口，unhash为从管理传输控制块散列表中删除的接口。由于不同的传输层协议组织管理传输控制块也不一样，
     * 因此需要提供不同的方法，比如,在TCP中实现接口函数分别为inet_hash和inet_unhash。而UDP传输控制块的管理相对比较简单，只有绑定端口的传输
     * 控制块才会添加到散列表中，这由绑定过程来完成，因此不需要实现hash接口，只需实现unhash接口即可(2.6.32中是udp_lib_hash和udp_lib_unhash，
     参见udp_prot)
     */
	/* Keeping track of sk's, looking them up, and port selection methods. */
	void			(*hash)(struct sock *sk); //将该传输控制块socket添加到tcp_hashinfo的ehash中
	void			(*unhash)(struct sock *sk);
	void			(*rehash)(struct sock *sk);

	/*
	 * 实现地址与端口的绑定。参数sk为进行绑定操作的传输控制块，snum为进行绑定的端口号(如果为0，端口号在绑定时自动选择)。TCP中为 inet_csk_get_port,UDP中为udp_v4_get_port。
	 */
	int			(*get_port)(struct sock *sk, unsigned short snum);
	void			(*clear_sk)(struct sock *sk, int size);

	/* Keeping track of sockets in use */
#ifdef CONFIG_PROC_FS
	unsigned int		inuse_idx;
#endif

	bool			(*stream_memory_free)(const struct sock *sk);
    /*
     * 目前只有TCP使用，当前整个TCP传输层中为缓冲区分配的内存超过tcp_mem[1]，便进入了警告状态，会调用此接口设置警告状态。在TCP中它指向tcp_enter_memory_pressure.
     */
	/* Memory pressure */
	void			(*enter_memory_pressure)(struct sock *sk);

	/*
     * 目前只有TCP使用，表示当前整个TCP传输层中为缓冲区分配的内存 (包括输入缓冲队列)。在TCP中它指向变量tcp_memory_allocated
     * 
     * update:如果是TCP层，它指向变量tcp_memory_allocated，表示当前整个TCP传输层为缓冲区分配的内存页面数，是系统中
     * 所有TCP传输块的sk_forward_alloc的总和，并不是所有传输控制块的发送和接收缓冲区综合，切记!
     */
     /*
 	  * 无论是为发送而分配SKB，还是将报文接收到TCP
 	  * 传输层，都需要对新进入传输控制块的缓存进行
 	  * 确认。确认时如果套接字缓存中的数据长度大于
 	  * 预分配量，则需进行全面的确认，这个过程由
 	  * __sk_mem_schedule()实现。
 	  * @size:要确认的缓存长度
 	  * @kind:类型，0为发送缓存，1为接收缓存。
 	  */
     //当tcp_memory_allocated大于sysctl_tcp_mem[1]时，TCP缓存管理进入警告状态，tcp_memory_pressure置为1。 这几个变量存到proto中的对应变量中。
	 //当tcp_memory_allocated小于sysctl_tcp_mem[0]时，TCP缓存管理退出警告状态，tcp_memory_pressure置为0。 
	atomic_long_t		*memory_allocated;	/* Current allocated memory. */
	/*
     * 表示当前整个TCP传输层中已创建的套接字的数目。目前只在TCP中使用，它指向变量tcp_sockets_allocated
     */
	struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	/*
	 * 目前只有TCP使用，在TCP传输层中缓冲大小进入警告状态时，它置为1，
	 * 否则置为0.目前只在TCP中使用，它指向变量tcp_memory_pressure.
	 */
	 //当tcp_memory_allocated大于tcp_mem[1]时，TCP缓存管理进入警告状态，tcp_memory_pressure置为1。 这几个变量存到proto中的对应变量中。
	 //当tcp_memory_allocated小于tcp_mem[0]时，TCP缓存管理退出警告状态，tcp_memory_pressure置为0。 
	 //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*memory_pressure;
    /* 指向sysctl_tcp_mem数组，参见sysctl_tcp_mem系统参数 */
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	long			*sysctl_mem;
    /* 指向sysctl_tcp_wmem数组，参见sysctl_tcp_wmem系统参数 */
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*sysctl_wmem;
    /* 指向sysctl_tcp_rmem数组，参见sysctl_tcp_rmem系统参数 */
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*sysctl_rmem;
    /* 目前只有TCP使用，TCP首部的最大长度，考虑了所有的选项  值为MAX_TCP_HEADER*/
	int			max_header;
	bool			no_autobind;
	/* 用于分配传输控制块的slab高速缓存，在注册对应传输层协议时建立 */
	struct kmem_cache	*slab;
	 /*
     * 标识传输控制块的大小，如果在初始化时建立分配传输控制块的slab
     * 缓存失败，则通过kmalloc分配obj_size大小的空间来完成传输控制
     * 块的分配。见inet_init中的proto_register
     */
	unsigned int		obj_size;
	int			slab_flags;
     /*
     * 目前只在TCP中使用，表示整个TCP传输层中待销毁的套接字的数目。在TCP中，它指向变量tcp_orphan_count.
     *///在tcp_close的时候要判断这个值是否超过阀值sysctl_tcp_max_orphans，见tcp_too_many_orphans
	struct percpu_counter	*orphan_count;
    /*
     * 目前只在TCP中使用，指向连接请求处理接口集合，包括 发送SYN+ACK等实现
     */
	struct request_sock_ops	*rsk_prot;
	/*
     * 目前只在TCP中使用，指向timewait控制块操作接口，TCP中的实例为tcp_timewait_sock_ops.timewait_sock_ops结构提供
     * 了两个操作接口，tcp_twsk_unique()用于检测被timewait控制块绑定的端口是否可用，而tcp_twsk_destructor用于在释放
     * timewait控制块时，在启用MD5数字签名的情况下做一些清理工作
     */
	struct timewait_sock_ops *twsk_prot;

	union {
		struct inet_hashinfo	*hashinfo; //tcp_hashinfo
		struct udp_table	*udp_table; //udp_table
		struct raw_hashinfo	*raw_hash; //raw_v4_hashinfo
	} h;

	struct module		*owner;

    /* 标识传输层的名称，TCP协议为"TCP",UDP协议则为"UDP" */
	char			name[32];

    /* 通过node注册到proto_list中 */
	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
#ifdef CONFIG_MEMCG_KMEM
	/*
	 * cgroup specific init/deinit functions. Called once for all
	 * protocols that implement it, from cgroups populate function.
	 * This function has to setup any files the protocol want to
	 * appear in the kmem cgroup filesystem.
	 */
	int			(*init_cgroup)(struct mem_cgroup *memcg,
					       struct cgroup_subsys *ss);
	void			(*destroy_cgroup)(struct mem_cgroup *memcg);
	struct cg_proto		*(*proto_cgroup)(struct mem_cgroup *memcg);
#endif
};

/*
 * Bits in struct cg_proto.flags
 */
enum cg_proto_flags {
	/* Currently active and new sockets should be assigned to cgroups */
	MEMCG_SOCK_ACTIVE,
	/* It was ever activated; we must disarm static keys on destruction */
	MEMCG_SOCK_ACTIVATED,
};

struct cg_proto {
	struct res_counter	memory_allocated;	/* Current allocated memory. */
	struct percpu_counter	sockets_allocated;	/* Current number of sockets. */
	int			memory_pressure;
	long			sysctl_mem[3];
	unsigned long		flags;
	/*
	 * memcg field is used to find which memcg we belong directly
	 * Each memcg struct can hold more than one cg_proto, so container_of
	 * won't really cut.
	 *
	 * The elegant solution would be having an inverse function to
	 * proto_cgroup in struct proto, but that means polluting the structure
	 * for everybody, instead of just for memcg users.
	 */
	struct mem_cgroup	*memcg;
};

int proto_register(struct proto *prot, int alloc_slab);
void proto_unregister(struct proto *prot);

static inline bool memcg_proto_active(struct cg_proto *cg_proto)
{
	return test_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
}

static inline bool memcg_proto_activated(struct cg_proto *cg_proto)
{
	return test_bit(MEMCG_SOCK_ACTIVATED, &cg_proto->flags);
}

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (atomic_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, atomic_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_NET)
extern struct static_key memcg_socket_limit_enabled;
static inline struct cg_proto *parent_cg_proto(struct proto *proto,
					       struct cg_proto *cg_proto)
{
	return proto->proto_cgroup(parent_mem_cgroup(cg_proto->memcg));
}
#define mem_cgroup_sockets_enabled static_key_false(&memcg_socket_limit_enabled)
#else
#define mem_cgroup_sockets_enabled 0
static inline struct cg_proto *parent_cg_proto(struct proto *proto,
					       struct cg_proto *cg_proto)
{
	return NULL;
}
#endif

static inline bool sk_stream_memory_free(const struct sock *sk)
{
	if (sk->sk_wmem_queued >= sk->sk_sndbuf)
		return false;

	return sk->sk_prot->stream_memory_free ?
		sk->sk_prot->stream_memory_free(sk) : true;
}

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	return sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
	       sk_stream_memory_free(sk);
}


static inline bool sk_has_memory_pressure(const struct sock *sk)
{
	return sk->sk_prot->memory_pressure != NULL;
}

static inline bool sk_under_memory_pressure(const struct sock *sk)
{
	if (!sk->sk_prot->memory_pressure)
		return false;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
		return !!sk->sk_cgrp->memory_pressure;

	return !!*sk->sk_prot->memory_pressure;
}

static inline void sk_leave_memory_pressure(struct sock *sk)
{
	int *memory_pressure = sk->sk_prot->memory_pressure;

	if (!memory_pressure)
		return;

	if (*memory_pressure)
		*memory_pressure = 0;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		struct cg_proto *cg_proto = sk->sk_cgrp;
		struct proto *prot = sk->sk_prot;

		for (; cg_proto; cg_proto = parent_cg_proto(prot, cg_proto))
			cg_proto->memory_pressure = 0;
	}

}

static inline void sk_enter_memory_pressure(struct sock *sk)
{
	if (!sk->sk_prot->enter_memory_pressure)
		return;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		struct cg_proto *cg_proto = sk->sk_cgrp;
		struct proto *prot = sk->sk_prot;

		for (; cg_proto; cg_proto = parent_cg_proto(prot, cg_proto))
			cg_proto->memory_pressure = 1;
	}

	sk->sk_prot->enter_memory_pressure(sk);
}

static inline long sk_prot_mem_limits(const struct sock *sk, int index)
{
	long *prot = sk->sk_prot->sysctl_mem;
	if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
		prot = sk->sk_cgrp->sysctl_mem;
	return prot[index];
}

static inline void memcg_memory_allocated_add(struct cg_proto *prot,
					      unsigned long amt,
					      int *parent_status)
{
	struct res_counter *fail;
	int ret;

	ret = res_counter_charge_nofail(&prot->memory_allocated,
					amt << PAGE_SHIFT, &fail);
	if (ret < 0)
		*parent_status = OVER_LIMIT;
}

static inline void memcg_memory_allocated_sub(struct cg_proto *prot,
					      unsigned long amt)
{
	res_counter_uncharge(&prot->memory_allocated, amt << PAGE_SHIFT);
}

static inline u64 memcg_memory_allocated_read(struct cg_proto *prot)
{
	u64 ret;
	ret = res_counter_read_u64(&prot->memory_allocated, RES_USAGE);
	return ret >> PAGE_SHIFT;
}

static inline long
sk_memory_allocated(const struct sock *sk)
{
	struct proto *prot = sk->sk_prot;
	if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
		return memcg_memory_allocated_read(sk->sk_cgrp);

	return atomic_long_read(prot->memory_allocated);
}

static inline long
sk_memory_allocated_add(struct sock *sk, int amt, int *parent_status)
{
	struct proto *prot = sk->sk_prot;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		memcg_memory_allocated_add(sk->sk_cgrp, amt, parent_status);
		/* update the root cgroup regardless */
		atomic_long_add_return(amt, prot->memory_allocated);
		return memcg_memory_allocated_read(sk->sk_cgrp);
	}

	return atomic_long_add_return(amt, prot->memory_allocated);
}

static inline void
sk_memory_allocated_sub(struct sock *sk, int amt)
{
	struct proto *prot = sk->sk_prot;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
		memcg_memory_allocated_sub(sk->sk_cgrp, amt);

	atomic_long_sub(amt, prot->memory_allocated);
}

static inline void sk_sockets_allocated_dec(struct sock *sk)
{
	struct proto *prot = sk->sk_prot;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		struct cg_proto *cg_proto = sk->sk_cgrp;

		for (; cg_proto; cg_proto = parent_cg_proto(prot, cg_proto))
			percpu_counter_dec(&cg_proto->sockets_allocated);
	}

	percpu_counter_dec(prot->sockets_allocated);
}

static inline void sk_sockets_allocated_inc(struct sock *sk)
{
	struct proto *prot = sk->sk_prot;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		struct cg_proto *cg_proto = sk->sk_cgrp;

		for (; cg_proto; cg_proto = parent_cg_proto(prot, cg_proto))
			percpu_counter_inc(&cg_proto->sockets_allocated);
	}

	percpu_counter_inc(prot->sockets_allocated);
}

static inline int
sk_sockets_allocated_read_positive(struct sock *sk)
{
	struct proto *prot = sk->sk_prot;

	if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
		return percpu_counter_read_positive(&sk->sk_cgrp->sockets_allocated);

	return percpu_counter_read_positive(prot->sockets_allocated);
}

static inline int
proto_sockets_allocated_sum_positive(struct proto *prot)
{
	return percpu_counter_sum_positive(prot->sockets_allocated);
}

static inline long
proto_memory_allocated(struct proto *prot)
{
	return atomic_long_read(prot->memory_allocated);
}

static inline bool
proto_memory_pressure(struct proto *prot)
{
	if (!prot->memory_pressure)
		return false;
	return !!*prot->memory_pressure;
}


#ifdef CONFIG_PROC_FS
/* Called with local bh disabled */
void sock_prot_inuse_add(struct net *net, struct proto *prot, int inc);
int sock_prot_inuse_get(struct net *net, struct proto *proto);
#else
static inline void sock_prot_inuse_add(struct net *net, struct proto *prot,
		int inc)
{
}
#endif


/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline void __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	sk->sk_prot->hash(sk);
}

void sk_prot_clear_portaddr_nulls(struct sock *sk, int size);

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

/* 表示完全关闭 */
#define SHUTDOWN_MASK	3  //tcp_close应用程序调用close肯定是完全关闭，如果是shutdown则可选半关闭还是完全关闭
/* 接收通道关闭，不允许继续接收数据*/
#define RCV_SHUTDOWN	1
/* 发送通道关闭，不允许继续发送数据*/
#define SEND_SHUTDOWN	2

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/* sock_iocb: used to kick off async processing of socket ios */
struct sock_iocb {
	struct list_head	list;

	int			flags;
	int			size;
	struct socket		*sock;
	struct sock		*sk;
	struct scm_cookie	*scm;
	struct msghdr		*msg, async_msg;
	struct kiocb		*kiocb;
};

static inline struct sock_iocb *kiocb_to_siocb(struct kiocb *iocb)
{
	return (struct sock_iocb *)iocb->private;
}

static inline struct kiocb *siocb_to_kiocb(struct sock_iocb *si)
{
	return si->kiocb;
}
/*
 * 套接口文件系统inode结点和套接口是一一对应的，因此套接口文件系统的i结点和分配是比较特殊的，分配的并不是一个单纯的i结点，而是i结点和
 * socket结构的组合体，即socket_calloc结构，这样可以使套接口的分配及与之绑定的套接口文件的i结点的分配同时进行。在应用层访问套接口要通过文件描述符,
 * 这样就可以快速地通过文件描述符定位与之绑定的套接口。
 */
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

/*
 * Functions for memory accounting
 */
int __sk_mem_schedule(struct sock *sk, int size, int kind);
void __sk_mem_reclaim(struct sock *sk);

#define SK_MEM_QUANTUM ((int)PAGE_SIZE)
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

static inline bool sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

static inline bool sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline bool
sk_rmem_schedule(struct sock *sk, struct sk_buff *skb, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size<= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV) ||
		skb_pfmemalloc(skb);
}

/*
 * 在多种情况下会调用sk_mem_reclaim()来回收缓存，如在
 * 断开连接、释放传输控制块、关闭TCP套接字时释放
 * 发送或接收队列中的SKB。sk_mem_reclaim()只在预分配量
 * 大于一个页面时，才调用__sk_mem_reclaim()进行真正的
 * 缓存回收。
 */
static inline void sk_mem_reclaim(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}
//skb_entail会把skb添加到sk的发送队列尾部，然后调用sk_mem_charge调整sk_wmem_quequed和sk_forward_alloc。前则将增加该skb中数据的长度，而后则则减少该skb中数据的长度
//在发送时会调用skb_set_owner_w设置该skb的宿主，同时设置释放是的回调函数为sock_wfree，最后sk_wmem_alloc将增加该skb中数据的长度。
static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
}

static inline void sk_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
 
/*
 * 软中断在访问传输控制块时需要通过sock_owned_by_user
 * 宏来检测该控制块是否已经被进程锁定，如果没有
 * 锁定，则可直接访问而无需通过lock_sock来上锁。因为
 * 软中断的优先级比进程的优先级高得多，只有软中断
 * 能中断进程的执行，而进程决不能中断软中断的执行。
 * 例如，在TCP段接收过程中，如果传输控制块未被用户
 * 进程上锁，则将TCP段输入到接收队列中，否则接收
 * 到后备队列中        内核调度优先级参考:http://blog.csdn.net/allen6268198/article/details/7567679
 */
#define sock_owned_by_user(sk)	((sk)->sk_lock.owned)

static inline void sock_release_ownership(struct sock *sk)
{
	sk->sk_lock.owned = 0;
}

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

void lock_sock_nested(struct sock *sk, int subclass);

/*
 * 用于进程加锁传输控制块，当进程调用网络相关的
 * 系统调用时，在访问传输控制块之前都会调用此函数，
 * 加锁传输控制块。
 * 注意这里在lock_sock_nested()中只是先获取了自旋锁，然后设置owned成员
 * 表示当前传输块被用户进程锁定，然后又释放了自旋锁。所以在
 * 软中断处理中(例如tcp_v4_rcv())会先获取锁，然后检查owned成员是否设置
 * 即传输控制块是否被用户进程锁定。
 */

/*
 * 实现控制用户进程和下半部 (例如应用程序发送数据的时候，然后进入系统调度到内核部分，这时候，内核又收到了对方来的数据，就好产生硬件中断，硬件中断上半部执行完后，执行下半部的时候就会用到刚才被抢走的发送数据的sock，从而会访问相同的数据空间，所以需要枷锁)
 以及下半部之间(例如多核环境下，内核硬件中断接收数据后进入软中断处理过程中，又收到了对方来的数据产生中断。)
 * 间同步锁都是由socket_lock_t结构描述的
 */
static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

void release_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

bool lock_sock_fast(struct sock *sk);
/**
 * unlock_sock_fast - complement of lock_sock_fast
 * @sk: socket
 * @slow: slow mode
 *
 * fast unlock socket for user context.
 * If slow mode is on, we call regular release_sock()
 */
static inline void unlock_sock_fast(struct sock *sk, bool slow)
{
	if (slow)
		release_sock(sk);
	else
		spin_unlock_bh(&sk->sk_lock.slock);
}


struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot);
void sk_free(struct sock *sk);
void sk_release_kernel(struct sock *sk);
struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority);

struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,
			     gfp_t priority);
void sock_wfree(struct sk_buff *skb);
void skb_orphan_partial(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);
void sock_efree(struct sk_buff *skb);
#ifdef CONFIG_INET
void sock_edemux(struct sk_buff *skb);
#else
#define sock_edemux(skb) sock_efree(skb)
#endif

int sock_setsockopt(struct socket *sock, int level, int op,
		    char __user *optval, unsigned int optlen);

int sock_getsockopt(struct socket *sock, int level, int op,
		    char __user *optval, int __user *optlen);
struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
				    int noblock, int *errcode);
struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock,
				     int *errcode, int max_page_order);
void *sock_kmalloc(struct sock *sk, int size, gfp_t priority);
void sock_kfree_s(struct sock *sk, void *mem, int size);
void sk_send_sigurg(struct sock *sk);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
int sock_no_bind(struct socket *, struct sockaddr *, int);
int sock_no_connect(struct socket *, struct sockaddr *, int, int);
int sock_no_socketpair(struct socket *, struct socket *);
int sock_no_accept(struct socket *, struct socket *, int);
int sock_no_getname(struct socket *, struct sockaddr *, int *, int);
unsigned int sock_no_poll(struct file *, struct socket *,
			  struct poll_table_struct *);
int sock_no_ioctl(struct socket *, unsigned int, unsigned long);
int sock_no_listen(struct socket *, int);
int sock_no_shutdown(struct socket *, int);
int sock_no_getsockopt(struct socket *, int , int, char __user *, int __user *);
int sock_no_setsockopt(struct socket *, int, int, char __user *, unsigned int);
int sock_no_sendmsg(struct kiocb *, struct socket *, struct msghdr *, size_t);
int sock_no_recvmsg(struct kiocb *, struct socket *, struct msghdr *, size_t,
		    int);
int sock_no_mmap(struct file *file, struct socket *sock,
		 struct vm_area_struct *vma);
ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
			 size_t size, int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
int sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags);
int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, unsigned int optlen);
int compat_sock_common_getsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int __user *optlen);
int compat_sock_common_setsockopt(struct socket *sock, int level,
		int optname, char __user *optval, unsigned int optlen);

void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */

/* Initialise core socket variables */
void sock_init_data(struct socket *sock, struct sock *sk);

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}
/* Generic version of sock_put(), dealing with all sockets
 * (TCP_TIMEWAIT, ESTABLISHED...)
 */
void sock_gen_put(struct sock *sk);

int sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested);

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	sk->sk_tx_queue_mapping = tx_queue;
}

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = -1;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	return sk ? sk->sk_tx_queue_mapping : -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk_tx_queue_clear(sk);
	sk->sk_socket = sock;
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct socket_wq, wait) != 0);
	return &rcu_dereference_raw(sk->sk_wq)->wait;
}
/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_wq = parent->wq;
	parent->sk = sk;
	sk_set_socket(sk, parent);
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

kuid_t sock_i_uid(struct sock *sk);
unsigned long sock_i_ino(struct sock *sk);

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache, sock_owned_by_user(sk) ||
						       lockdep_is_held(&sk->sk_lock.slock));
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	dst = rcu_dereference(sk->sk_dst_cache);
	if (dst && !atomic_inc_not_zero(&dst->__refcnt))
		dst = NULL;
	rcu_read_unlock();
	return dst;
}

static inline void dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_tx_queue_clear(sk);
		}
	}
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	/*
	 * This can be called while sk is owned by the caller only,
	 * with no state that can be checked in a rcu_dereference_check() cond
	 */
	old_dst = rcu_dereference_raw(sk->sk_dst_cache);
	rcu_assign_pointer(sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	old_dst = xchg((__force struct dst_entry **)&sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	sk_dst_set(sk, NULL);
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

bool sk_mc_loop(struct sock *sk);
////TSO是tcp segment offload的缩写，GSO是 generic segmentation offload 的缩写。 通过命令ethtool -k eth0查看是否支持gso或者tso 。参考skb_shared_info
static inline bool sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_nocaps_add(struct sock *sk, netdev_features_t flags)
{
	sk->sk_route_nocaps |= flags;
	sk->sk_route_caps &= ~flags;
}

static inline int skb_do_copy_data_nocache(struct sock *sk, struct sk_buff *skb,
					   char __user *from, char *to,
					   int copy, int offset)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		__wsum csum = csum_and_copy_from_user(from, to, copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, offset);
	} else if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY) {
		if (!access_ok(VERIFY_READ, from, copy) ||
		    __copy_from_user_nocache(to, from, copy))
			return -EFAULT;
	} else if (copy_from_user(to, from, copy))
		return -EFAULT;

	return 0;
}

static inline int skb_add_data_nocache(struct sock *sk, struct sk_buff *skb,
				       char __user *from, int copy)
{
	int err, offset = skb->len;

	err = skb_do_copy_data_nocache(sk, skb, from, skb_put(skb, copy),
				       copy, offset);
	if (err)
		__skb_trim(skb, offset);

	return err;
}

static inline int skb_copy_to_page_nocache(struct sock *sk, char __user *from,
					   struct sk_buff *skb,
					   struct page *page,
					   int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);
	if (err)
		return err;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk_mem_charge(sk, copy);
	return 0;
}

static inline int skb_copy_to_page(struct sock *sk, char __user *from,
				   struct sk_buff *skb, struct page *page,
				   int off, int copy)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		__wsum csum = csum_and_copy_from_user(from,
						     page_address(page) + off,
							    copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, skb->len);
	} else if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk_mem_charge(sk, copy);
	return 0;
}

/**
 * sk_wmem_alloc_get - returns write allocations
 * @sk: socket
 *
 * Returns sk_wmem_alloc minus initial offset of one
 */
static inline int sk_wmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_wmem_alloc) - 1;
}

/**
 * sk_rmem_alloc_get - returns read allocations
 * @sk: socket
 *
 * Returns sk_rmem_alloc
 */
static inline int sk_rmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc);
}

/**
 * sk_has_allocations - check if allocations are outstanding
 * @sk: socket
 *
 * Returns true if socket has write or read allocations
 */
static inline bool sk_has_allocations(const struct sock *sk)
{
	return sk_wmem_alloc_get(sk) || sk_rmem_alloc_get(sk);
}

/**
 * wq_has_sleeper - check if there are any waiting processes
 * @wq: struct socket_wq
 *
 * Returns true if socket_wq has waiting processes
 *
 * The purpose of the wq_has_sleeper and sock_poll_wait is to wrap the memory
 * barrier call. They were added due to the race found within the tcp code.
 *
 * Consider following tcp code paths:
 *
 * CPU1                  CPU2
 *
 * sys_select            receive packet
 *   ...                 ...
 *   __add_wait_queue    update tp->rcv_nxt
 *   ...                 ...
 *   tp->rcv_nxt check   sock_def_readable
 *   ...                 {
 *   schedule               rcu_read_lock();
 *                          wq = rcu_dereference(sk->sk_wq);
 *                          if (wq && waitqueue_active(&wq->wait))
 *                              wake_up_interruptible(&wq->wait)
 *                          ...
 *                       }
 *
 * The race for tcp fires when the __add_wait_queue changes done by CPU1 stay
 * in its cache, and so does the tp->rcv_nxt update on CPU2 side.  The CPU1
 * could then endup calling schedule and sleep forever if there are no more
 * data on the socket.
 *
 */
static inline bool wq_has_sleeper(struct socket_wq *wq)
{
	/* We need to be sure we are in sync with the
	 * add_wait_queue modifications to the wait queue.
	 *
	 * This memory barrier is paired in the sock_poll_wait.
	 */
	smp_mb();
	return wq && waitqueue_active(&wq->wait);
}

/**
 * sock_poll_wait - place memory barrier behind the poll_wait call.
 * @filp:           file
 * @wait_address:   socket wait queue
 * @p:              poll_table
 *
 * See the comments in the wq_has_sleeper function.
 */
static inline void sock_poll_wait(struct file *filp,
		wait_queue_head_t *wait_address, poll_table *p)
{
	if (!poll_does_not_wait(p) && wait_address) {
		poll_wait(filp, wait_address, p);
		/* We need to be sure we are in sync with the
		 * socket flags modification.
		 *
		 * This memory barrier is paired in the wq_has_sleeper.
		 */
		smp_mb();
	}
}

static inline void skb_set_hash_from_sk(struct sk_buff *skb, struct sock *sk)
{
	if (sk->sk_txhash) {
		skb->l4_hash = 1;
		skb->hash = sk->sk_txhash;
	}
}

/*
 *	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 *	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
/* 
 * 每个用于输出的SKB都要关联到一个传输控制块上，
 * 这样可以调整该传输控制块为发送而分配的所有
 * SKB数据区的总大小，并设置此SKB的销毁函数。
 */
 //套接字发送数据的时候，struct sock和SKB的关系可以通过sock_alloc_send_pskb(UDP和RAW套接字用这个)函数详细了解。TCP在构造SYN+ACK时使用sock_wmalloc，发送用户数据时通常使用sk_stream_alloc_skb()分配发送缓存
//TCP在连接建立后发送数据的时候在tcp_transmit_skb中调用该函数，而在TCP构造过程中通过sock_wmalloc调用该函数，UDP和RAW则在sock_alloc_send_pskb中调用该函数

//skb_entail会把skb添加到sk的发送队列尾部，然后调用sk_mem_charge调整sk_wmem_quequed和sk_forward_alloc。前则将增加该skb中数据的长度，而后则则减少该skb中数据的长度
//在发送时会调用skb_set_owner_w设置该skb的宿主，同时设置释放是的回调函数为sock_wfree，最后sk_wmem_alloc将增加该skb中数据的长度。
static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_wfree;//在sk_alloc的时候初始化设置为1，然后在skb_set_owner_w加上SKB长度，当SKB发送出去后，在减去该SKB的长度，所以这个值当数据发送后其值始终是1，不会执行sock_wfree
	skb_set_hash_from_sk(skb, sk);
	/*
	 * We used to take a refcount on sk, but following operation
	 * is enough to guarantee sk_free() wont free this sock until
	 * all in-flight packets are completed
	 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

/*
 * 当TCP段的SKB传递到TCP传输控制块中，便会调用
 * sk_stream_set_owner_r()设置该SKB的宿主，并设置此SKB
 * 的销毁函数，还要更新接收队列中所有报文数据
 * 的总长度，以及预分配缓存长度
 */
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
}

void sk_reset_timer(struct sock *sk, struct timer_list *timer,
		    unsigned long expires);

void sk_stop_timer(struct sock *sk, struct timer_list *timer);

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);
struct sk_buff *sock_dequeue_err_skb(struct sock *sk);

/*
 *	Recover an error report and clear atomically
 */

static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
		if (amt < 0)
			amt = 0;
	}
	return amt;
}

/*
 * 用来将SIGIO或SIGURG信号发送给该套接字上的进程，
 * 通知该进程可以对该文件进行读或写。
 *
 * @sk: 通知进程可运行I/O处理的传输控制块
 * @how: 通知进程方式，取值为SOCK_WAKE_IO等
 * @band:  通知进程的I/O读写类型，取值为POLL_IN等
 */

//执行该函数sk_wake_async(将SIGIO或SIGURG信号发送给该套接字上的进程,这是异步I/O机制)的地方有sk_send_sigurg(接收到带外数据)，sock_def_write_space和sk_stream_write_space(发送缓冲区发生变化)，有新的数据到来(sock_def_readable)
//sock_def_error_report传输控制块发生某种错误，sock_def_wakeup传输状态发生变化, tcp_fin
static inline void sk_wake_async(struct sock *sk, int how, int band)
{
	if (sock_flag(sk, SOCK_FASYNC))
		sock_wake_async(sk->sk_socket, how, band);
}

/* Since sk_{r,w}mem_alloc sums skb->truesize, even a small frame might
 * need sizeof(sk_buff) + MTU + padding, unless net driver perform copybreak.
 * Note: for send buffers, TCP works better if we can build two skbs at
 * minimum.
 */
#define TCP_SKB_MIN_TRUESIZE	(2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))

#define SOCK_MIN_SNDBUF		(TCP_SKB_MIN_TRUESIZE * 2)
#define SOCK_MIN_RCVBUF		 TCP_SKB_MIN_TRUESIZE

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
		sk->sk_sndbuf = max_t(u32, sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp);

/**
 * sk_page_frag - return an appropriate page_frag
 * @sk: socket
 *
 * If socket allocation mode allows current thread to sleep, it means its
 * safe to use the per task page_frag instead of the per socket one.
 */
static inline struct page_frag *sk_page_frag(struct sock *sk)
{
	if (sk->sk_allocation & __GFP_WAIT)
		return &current->task_frag;

	return &sk->sk_frag;
}

bool sk_page_frag_refill(struct sock *sk, struct page_frag *pfrag);

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline bool sock_writeable(const struct sock *sk)
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf >> 1);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

/*
 * 根据是否设置MSG_WAITALL标志来确定本次调用需要接收数据的长度.如果设置了MSG_WAITALL标志,则读取数据长度为用户调用时的输入参数len.
 */
static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
			   struct sk_buff *skb);
void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
			     struct sk_buff *skb);

static inline void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	ktime_t kt = skb->tstamp;
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	/*
	 * generate control messages if
	 * - receive time stamping in software requested
	 * - software time stamp available and wanted
	 * - hardware time stamps available and wanted
	 */
	if (sock_flag(sk, SOCK_RCVTSTAMP) ||
	    (sk->sk_tsflags & SOF_TIMESTAMPING_RX_SOFTWARE) ||
	    (kt.tv64 && sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE) ||
	    (hwtstamps->hwtstamp.tv64 &&
	     (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE)))
		__sock_recv_timestamp(msg, sk, skb);
	else
		sk->sk_stamp = kt;

	if (sock_flag(sk, SOCK_WIFI_STATUS) && skb->wifi_acked_valid)
		__sock_recv_wifi_status(msg, sk, skb);
}

void __sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
			      struct sk_buff *skb);

static inline void sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
					  struct sk_buff *skb)
{
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP))
#define TSFLAGS_ANY	  (SOF_TIMESTAMPING_SOFTWARE			| \
			   SOF_TIMESTAMPING_RAW_HARDWARE)

	if (sk->sk_flags & FLAGS_TS_OR_DROPS || sk->sk_tsflags & TSFLAGS_ANY)
		__sock_recv_ts_and_drops(msg, sk, skb);
	else
		sk->sk_stamp = skb->tstamp;
}

void __sock_tx_timestamp(const struct sock *sk, __u8 *tx_flags);

/**
 * sock_tx_timestamp - checks whether the outgoing packet is to be time stamped
 * @sk:		socket sending this packet
 * @tx_flags:	completed with instructions for time stamping
 *
 * Note : callers should take care of initial *tx_flags value (usually 0)
 */
static inline void sock_tx_timestamp(const struct sock *sk, __u8 *tx_flags)
{
	if (unlikely(sk->sk_tsflags))
		__sock_tx_timestamp(sk, tx_flags);
	if (unlikely(sock_flag(sk, SOCK_WIFI_STATUS)))
		*tx_flags |= SKBTX_WIFI_STATUS;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}

static inline
void sock_net_set(struct sock *sk, struct net *net)
{
	write_pnet(&sk->sk_net, net);
}

/*
 * Kernel sockets, f.e. rtnl or icmp_socket, are a part of a namespace.
 * They should not hold a reference to a namespace in order to allow
 * to stop it.
 * Sockets after sk_change_net should be released using sk_release_kernel
 */
static inline void sk_change_net(struct sock *sk, struct net *net)
{
	struct net *current_net = sock_net(sk);

	if (!net_eq(current_net, net)) {
		put_net(current_net);
		sock_net_set(sk, hold_net(net));
	}
}

static inline struct sock *skb_steal_sock(struct sk_buff *skb)
{
	if (skb->sk) {
		struct sock *sk = skb->sk;

		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	return NULL;
}

/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait or request socket.
 */
static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}

void sock_enable_timestamp(struct sock *sk, int flag);
int sock_get_timestamp(struct sock *, struct timeval __user *);
int sock_get_timestampns(struct sock *, struct timespec __user *);
int sock_recv_errqueue(struct sock *sk, struct msghdr *msg, int len, int level,
		       int type);

bool sk_ns_capable(const struct sock *sk,
		   struct user_namespace *user_ns, int cap);
bool sk_capable(const struct sock *sk, int cap);
bool sk_net_capable(const struct sock *sk, int cap);

/*
 *	Enable debug/info messages
 */
extern int net_msg_warn;
#define NETDEBUG(fmt, args...) \
	do { if (net_msg_warn) printk(fmt,##args); } while (0)

#define LIMIT_NETDEBUG(fmt, args...) \
	do { if (net_msg_warn && net_ratelimit()) printk(fmt,##args); } while(0)

//下面这两个值的初始化在sk_init函数中，其值会收内存的影响，默认值可能不一样
extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

/* 用于控制传输控制块分配的选项缓存，该值为辅助缓冲区的上限值*/
extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;//发送缓冲区默认值 SK_WMEM_MAX
extern __u32 sysctl_rmem_default;// 接收缓冲区大小的上限为SK_RMEM_MAX，默认值是sysctl_rmem_default，即32767也就是IP首部16位长度(最大65535)的一半

#endif	/* _SOCK_H */
