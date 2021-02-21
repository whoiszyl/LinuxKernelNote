/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

int sysctl_ip_default_ttl __read_mostly = IPDEFTTL;
EXPORT_SYMBOL(sysctl_ip_default_ttl);

/* Generate a checksum for an outgoing IP datagram. */
void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}
EXPORT_SYMBOL(ip_send_check);
//当IP头部封装好后，调用__ip_local_out
int __ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, skb, NULL,
		       skb_dst(skb)->dev, dst_output);//通过dst_output最终会走到IP层输出函数dev_queue_xmit
}

//通过ip_local_out最终会走到IP层输出函数dev_queue_xmit
int ip_local_out_sk(struct sock *sk, struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output_sk(sk, skb);

	return err;
}
EXPORT_SYMBOL_GPL(ip_local_out_sk);

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = ip4_dst_hoplimit(dst);
	return ttl;
}

/*
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options_rcu *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = skb_rtable(skb);
	struct iphdr *iph;

	/* Build the IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->daddr    = (opt && opt->opt.srr ? opt->opt.faddr : daddr);
	iph->saddr    = saddr;
	iph->protocol = sk->sk_protocol;
	ip_select_ident(skb, sk);

	if (opt && opt->opt.optlen) {
		iph->ihl += opt->opt.optlen>>2;
		ip_options_build(skb, &opt->opt, daddr, rt, 0);
	}

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	/* Send it out. */
	return ip_local_out(skb);
}
EXPORT_SYMBOL_GPL(ip_build_and_send_pkt);

/*
 * 此函数通过邻居子系统将数据包输出
 * 到网络设备。
 */
static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	u32 nexthop;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTBCAST, skb->len);

	/* Be paranoid, rather than too clever. */
	/*
	 * 检测skb的前部空间是否还能存储链路层首部。
	 * 如果不够，则重新分配更大存储区的skb，
	 * 并释放原skb。
	 */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	rcu_read_lock_bh();
	/*
	 * 如果缓存了链路层的首部，则调用
	 * neigh_hh_output()输出数据包。否则，
	 * 若存在对应的邻居项，则通过
	 * 邻居项的输出方法输出数据包。
	 */ 
	 //最后调用二层函数dev_queue_xmit
	nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
	if (!IS_ERR(neigh)) {
		int res = dst_neigh_output(dst, neigh, skb);

		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	/*
	 * 如果既没有缓存链路层的首部，又
	 * 不存在对应的邻居项，在这种情况
	 * 下，不能输出，释放该数据包。
	 */
	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}

static int ip_finish_output_gso(struct sk_buff *skb)
{
	netdev_features_t features;
	struct sk_buff *segs;
	int ret = 0;

	/* common case: locally created skb or seglen is <= mtu */
	if (((IPCB(skb)->flags & IPSKB_FORWARDED) == 0) ||
	      skb_gso_network_seglen(skb) <= ip_skb_dst_mtu(skb))
		return ip_finish_output2(skb);

	/* Slowpath -  GSO segment length is exceeding the dst MTU.
	 *
	 * This can happen in two cases:
	 * 1) TCP GRO packet, DF bit not set
	 * 2) skb arrived via virtio-net, we thus get TSO/GSO skbs directly
	 * from host network stack.
	 */
	features = netif_skb_features(skb);
	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
	if (IS_ERR_OR_NULL(segs)) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	consume_skb(skb);

	do {
		struct sk_buff *nskb = segs->next;
		int err;

		segs->next = NULL;
		err = ip_fragment(segs, ip_finish_output2);

		if (err && ret == 0)
			ret = err;
		segs = nskb;
	} while (segs);

	return ret;
}

static int ip_finish_output(struct sk_buff *skb)
{
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm != NULL) { 			//仅经过ip_forward流程处理的报文携带该对象
		IPCB(skb)->flags |= IPSKB_REROUTED;		//该flag会影响后续报文的GSO处理
		return dst_output(skb); 				//由于SNAT等策略处理，需要再次调用xfrm4_output函数来发包
	}
#endif 
	if (skb_is_gso(skb))
		return ip_finish_output_gso(skb);
	
	//当报文的长度大于mtu会调用ip_fragment进行分片。否则就会调用ip_finish_output2把数据发送出去。
	if (skb->len > ip_skb_dst_mtu(skb))
		return ip_fragment(skb, ip_finish_output2);

	return ip_finish_output2(skb);
}

int ip_mc_output(struct sock *sk, struct sk_buff *skb)
{
	struct rtable *rt = skb_rtable(skb);
	struct net_device *dev = rt->dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if (sk_mc_loop(sk)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    &&
		    ((rt->rt_flags & RTCF_LOCAL) ||
		     !(IPCB(skb)->flags & IPSKB_FORWARDED))
#endif
		   ) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING,
					newskb, NULL, newskb->dev,
					dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, newskb,
				NULL, newskb->dev, dev_loopback_xmit);
	}

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL,
			    skb->dev, ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * 对于单播数据包，目的路由缓存项中的输出接口是ip_output().
 */
int ip_output(struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	/*统计发送出去的数据包*/
	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	/*具体选择从哪个网卡设备上发送出去IP报文*/
	skb->dev = dev;
	/* 指定报文类型为IP packet.*/
	skb->protocol = htons(ETH_P_IP);

	/*
	 * 经netfilter处理后，调用ip_finish_output()继续IP数据包的输出
	 */
	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * copy saddr and daddr, possibly using 64bit load/stores
 * Equivalent to :
 *   iph->saddr = fl4->saddr;
 *   iph->daddr = fl4->daddr;
 */
static void ip_copy_addrs(struct iphdr *iph, const struct flowi4 *fl4)
{
	BUILD_BUG_ON(offsetof(typeof(*fl4), daddr) !=
		     offsetof(typeof(*fl4), saddr) + sizeof(fl4->saddr));
	memcpy(&iph->saddr, &fl4->saddr,
	       sizeof(fl4->saddr) + sizeof(fl4->daddr));
}

//对于IPv4包的发出, 通常出口函数其中一种是ip_queue_xmit，还没有进行路由选择
/* Note: skb->sk can be different from sk, in case of tunnels */
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	// 已经路由过的数据跳过路由查找过程
	rt = skb_rtable(skb);
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (rt == NULL) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ip_route_output_ports(sock_net(sk), fl4, sk,
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   RT_CONN_FLAGS(sk),
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);

packet_routed:
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);

	/* Transport layer set skb->h.foo itself. */

	if (inet_opt && inet_opt->opt.optlen) {
		iph->ihl += inet_opt->opt.optlen >> 2;
		ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
	}

	ip_select_ident_segs(skb, sk, skb_shinfo(skb)->gso_segs ?: 1);

	/* TODO : should we use skb->sk here instead of sk ? */
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	res = ip_local_out(skb);
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}
EXPORT_SYMBOL(ip_queue_xmit);


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_copy(to, from);
	to->dev = from->dev;
	to->mark = from->mark;

	skb_copy_hash(to, from);

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */
/*
 * 当要将一个IP数据包从本地发送或转发出去时，
 * 如果发现该IP数据包大于当前的MTU或路径MTU，
 * 则调用ip_fragment()将数据包分片后再发送出去。
 * @skb: 待分片后发送或转发的IP数据包，即原始
 *           数据包，该数据包应该包含已初始化的IP首部
 * @output:将完成分片输出的回调函数，IPv4中为
 *              ip_finish_output2().
 */
int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *))
{
	struct iphdr *iph;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	__be16 not_last_frag;
	/* 取得路由表 */
	struct rtable *rt = skb_rtable(skb);
	int err = 0;

	/* 网络设备 */
	dev = rt->dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	/* 得到IP报文头的指针 */
	iph = ip_hdr(skb);

	mtu = ip_skb_dst_mtu(skb);

	/*
	 * 判断DF位，知道如果df位被设置了话就表示不要被分片，
	 * 如果待分片IP数据包禁止分片，则调用
	 * icmp_send()向发送方发送一个原因为需要
	 * 分片而设置了不分片标志的目的不可达
	 * ICMP报文，并丢弃报文，即设置IP状态
	 * 为分片失败，释放skb，返回消息过长
	 * 错误码。
	 */
	if (unlikely(((iph->frag_off & htons(IP_DF)) && !skb->ignore_df) ||
		     (IPCB(skb)->frag_max_size &&
		      IPCB(skb)->frag_max_size > mtu))) {
		/* 禁止分片，增加错误计数 */
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	/* 得到IP报文总长度 */
	hlen = iph->ihl * 4;

	/* 这里的mtu为真正的MTU-IP报文头，即允许的最大IP数据长度 */
	mtu = mtu - hlen;	/* Size of data space */
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	if (skb->nf_bridge)
		mtu -= nf_bridge_mtu_reduction(skb);
#endif
	/*
	 * 在分片之前先给IP数据包的控制块设置
	 * IPSKB_FRAG_COMPLETE标志，标识完成分片。
	 */

	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	/*
	 * 如果4层将数据包分片了，那么就会把这些数据包放到skb的frag_list链表中，
	 * 因此这里首先先判断frag_list链表是否为空，为空的话将会进行slow 分片
	 */
	if (skb_has_frag_list(skb)) {
		/*
		 * 取得第一个数据报的len.当sk_write_queue队列被flush后，
		 * 除了第一个切好包的另外的包都会加入到frag_list中，而这里
		 * 需要得到的第一个包(也就是本身这个sk_buff）的长度。
		 */

		struct sk_buff *frag, *frag2;
		int first_len = skb_pagelen(skb);

		/*
		1.数据包的长度超过了MTU；
		2.数据包长度没有按8字节对齐；
		3.数据包设置了IP_MF或者IP_OFFSET位
		这样，进入slow_path
		*/

		/*
		 * 接下来的判断都是为了确定能进行fast分片。分片不能被共享，
		 * 这是因为在fast path 中，需要加给每个分片不同的ip头(而并
		 * 不会复制每个分片)。因此在fast path中是不可接受的。而在
		 * slow path中，就算有共享也无所谓，因为他会复制每一个分片，
		 * 使用一个新的buff。   
		 */
		
  		/*
		 * 判断第一个包长度是否符合一些限制(包括mtu，mf位等一些限制).
		 * 如果第一个数据报的len没有包含mtu的大小这里之所以要把第一个
		 * 切好片的数据包单独拿出来检测，是因为一些域是第一个包所独有
		 * 的(比如IP_MF要为1）。这里由于这个mtu是不包括hlen的mtu，因此
		 * 需要减去一个hlen。  
  		 */
		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    ip_is_fragment(iph) ||
		    skb_cloned(skb))
			goto slow_path;//跳到slow_path

		/* 遍历每一个分片 */
		skb_walk_frags(skb, frag) {
		/* Correct geometry. */
		/* 检查每个分片，如果有一个分片不符合要求，就只能使用slow path */
			
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
				goto slow_path_clean;

			/* Partially cloned skb? */
			/* 判断是否共享 */
			if (skb_shared(frag))
				goto slow_path_clean;

			BUG_ON(frag->sk);
			/* 进行socket的一些操作 */
			if (skb->sk) {
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			skb->truesize -= frag->truesize;
		}

		/* Everything is OK. Generate! */
		/* 现在可以进行fast path了*/

		err = 0;
		offset = 0;
		/* 拿到frag list */
		frag = skb_shinfo(skb)->frag_list;
		/* 重置原来的frag list，相当于从skb_buff上取走了frag list */
		skb_frag_list_init(skb);
		/* 得到实际的数据长度，置分片标志位和校验和 */
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		/* 设置mf位  */
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);

		/* 分别处理每一个分片 */
		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				/* 表示checksm已经算好*/
				frag->ip_summed = CHECKSUM_NONE;
				/* 设置传输层*/
				skb_reset_transport_header(frag);
			    /* 预留ddos header 空间 */
				__skb_push(frag, hlen);
				/* 设置网络层 */
				skb_reset_network_header(frag);
				/* 复制ip头 */
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				/* 将当前skb的一些属性付给将要传递的分片好的帧 */
				ip_copy_metadata(frag, skb);
				/* 处理ip_option  */
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				/* 设置位移 */
				iph->frag_off = htons(offset>>3);
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				/* 计算分片的校验和 */
				ip_send_check(iph);
			}

			/* 发送 */
			err = output(skb);

			if (!err)
				IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
			if (err || !frag)
				break;

			/* 处理链表中下一个buf */
			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		if (err == 0) {
			IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		/* 出错释放内存 */
		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		return err;

slow_path_clean:
	 	/* 清除shared sk_buff */
		skb_walk_frags(skb, frag2) {
			if (frag2 == frag)
				break;
			frag2->sk = NULL;
			frag2->destructor = NULL;
			skb->truesize += frag2->truesize;
		}
	}

slow_path:
	/* for offloaded checksums cleanup checksum before fragmentation */
	if ((skb->ip_summed == CHECKSUM_PARTIAL) && skb_checksum_help(skb))
		goto fail;
	iph = ip_hdr(skb);

	/* 分片的数据剩余长度 */
	left = skb->len - hlen;		/* Space per frame */
	/* 而ptr就是分片开始的数据指针 */
	ptr = hlen;		/* Where to start from */

	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header
	 */
	 /* 处理桥接、VLAN、PPPOE相关MTU */
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->dst.dev, nf_bridge_pad(skb));

	/*
	 *	Fragment the datagram.
	 */
	/* 得到偏移     取出ip offset域 */
	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	/* 通过IP_MF标志位，判断是否是最后一个分片 */
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */
	/* 开始为循环处理，每一个分片创建一个skb buffer */
	while (left > 0) {
		/* 计算分片长度 */
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		/* 如果len大于mtu，设置当前的将要分片的数据大小为mtu */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending up to and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			/* 长度对齐 */
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */

		/* malloc一个新的buff,它的大小包括ip payload,ip head,以及L2 head */
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */

		/* 调用ip_copy_metadata复制一些相同的值的域 */
		ip_copy_metadata(skb2, skb);
		/* 保留L2 header空间 */
		skb_reserve(skb2, ll_rs);
		/* 设置ip header & ddos header & ip paylod 空间 */
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		/* L4 header指针为ip header + ddos header数据偏移位置,用于复制原始payload */
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		/* 将每一个分片的ip包都关联到源包的socket */
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */
		/* 拷贝ip header */
		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		 /* 拷贝ip payload数据 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		/* 分片的数据剩余长度 */
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		 /* 填充网络层 */
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		/* 如果是第一个分片， 填充ip option */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		/* 不是最后一个包，因此设置mf位 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		/* 移动数据指针以及更改数据偏移 */
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		/* 更新包头的数据长度 */
		iph->tot_len = htons(len + hlen);

		/* 计算校验和 */
		ip_send_check(iph);

		/* 发送该分片 */
		err = output(skb2);
		if (err)
			goto fail;

		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
	}
	consume_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	 /* 释放sk_buff */
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
	return err;
}
EXPORT_SYMBOL(ip_fragment);

int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		__wsum csum = 0;
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}
EXPORT_SYMBOL(ip_generic_getfrag);

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	__wsum csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

static inline int ip_ufo_append_data(struct sock *sk,
			struct sk_buff_head *queue,
			int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int maxfraglen, unsigned int flags)
{
	struct sk_buff *skb;
	int err;

	/* There is support for UDP fragmentation offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */
	if ((skb = skb_peek_tail(queue)) == NULL) {
		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);

		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		skb_put(skb, fragheaderlen + transhdrlen);

		/* initialize network header pointer */
		skb_reset_network_header(skb);

		/* initialize protocol header pointer */
		skb->transport_header = skb->network_header + fragheaderlen;

		skb->csum = 0;


		__skb_queue_tail(queue, skb);
	} else if (skb_is_gso(skb)) {
		goto append;
	}

	skb->ip_summed = CHECKSUM_PARTIAL;
	/* specify the length of each IP datagram fragment */
	skb_shinfo(skb)->gso_size = maxfraglen - fragheaderlen;
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP;

append:
	return skb_append_datato_frags(sk, skb, getfrag, from,
				       (length - transhdrlen));
}

static int __ip_append_data(struct sock *sk,
			    struct flowi4 *fl4,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    struct page_frag *pfrag,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	struct ip_options *opt = cork->opt;
	int hh_len;
    /*
     * exthdrlen用于记录IPsec中扩展首部的长度，未启用IPsec时为0
     */
	int exthdrlen;
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt = (struct rtable *)cork->dst;
	u32 tskey = 0;

	/*这里skb有两种情况，如果队列为空，则skb = NULL，否则为尾部skb的指针 */
	skb = skb_peek_tail(queue);
	

	exthdrlen = !skb ? rt->dst.header_len : 0;
	mtu = cork->fragsize;
	if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
	    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
		tskey = sk->sk_tskey++;

	/*链路层首部长度 */
	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	/* IP首部（包括IP选项）长度 */
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	/* 最大IP首部长度,注意对齐 */
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
	maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

	if (cork->length + length > maxnonfragsize - fragheaderlen) {
		/*一个IP数据包最大大小不能超过64K */
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       mtu - (opt ? opt->optlen : 0));
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->dst.dev->features & NETIF_F_V4_CSUM &&
	    !exthdrlen)
	    /*由硬件执行校验和计算 */
		csummode = CHECKSUM_PARTIAL;

	/*更新数据长度 */
	cork->length += length;
	/* 对于UDP报文，新加的数据长度大于MTU，并且需要进行分片，则需要
     * 进行分片处理
     * 这里相当于《understand linux network internel》图21-11最左边的那条支线
     * 注意：这里需要加入判断skb是否为NULL
     */
	if ((skb && skb_is_gso(skb)) ||
	    (((length + fragheaderlen) > mtu) &&
	    (skb_queue_len(queue) <= 1) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->dst.dev->features & NETIF_F_UFO) && !rt->dst.header_len &&
	    (sk->sk_type == SOCK_DGRAM))) {
		err = ip_ufo_append_data(sk, queue, getfrag, from, length,
					 hh_len, fragheaderlen, transhdrlen,
					 maxfraglen, flags);
		if (err)
			goto error;
		return 0;
	}

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	if (!skb)
		goto alloc_new_skb;

	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
        /*
         * 检测待发送数据是否能全部复制到最后一个SKB的剩余空间中。如果可以，
         * 则说明是IP分片中的上一个分片，可以不用4字节对齐，否则需要4字节
         * 对齐，因此用8字节对齐后的MTU减去上一个SKB的数据长度，得到上一个
         * SKB的剩余空间大小，也就是本次复制数据的长度.
         * 当本次复制数据的长度copy小于等于0时，说明上一个SKB已经填满或
         * 空间不足8B，需要分配新的SKB。
         * 当copy大于0时，说明上一个SKB有剩余空间，数据可以复制到该SKB中去。
         *
         */
		copy = mtu - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;
        /*
         * 如果上一个SKB已经填满或空间不足8B，或者不存在上一个SKB，则将数据复制到
         * 新分配的SKB中去。
         */
		if (copy <= 0) {
			char *data;
            /*
             * 如果上一个SKB（通常是在调用ip_append_data()时，
             * 输出队列中最后一个SKB）中存在多余8字节对齐的MTU的数据，
             * 则这些数据需移动到当前SKB中，确保最后一个IP分片之外的
             * 数据能够4字节对齐，因此需计算移动到当前SKB的数据长度。
             */
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			/*需要计算从上一个skb中复制到新的新的skb中的数据长度 */
			if (skb_prev)
				/*明显就是copy取反 */
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
            /*
             * 如果剩余数据的长度超过MTU，则需要更多的分片。
             */
            /*
             * 计算需要复制到新SKB中的数据长度。因为如果前一个SKB
             * 还能容纳数据，则有一部分数据会复制到前一个SKB中。
             */
			datalen = length + fraggap;
            /*
             * 如果剩余的数据一个分片不够容纳，则根据MTU重新计算本次
             * 可发送的数据长度。
             */
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
            /*
             * 根据本次复制的数据长度以及IP首部长度，计算三层
             * 首部及其数据的总长度
             */
			fraglen = datalen + fragheaderlen;

            /*
             * 如果后续还有数据要输出且网络设备不支持聚合分散I/O，则将
             * MTU作为分配SKB的长度，使分片达到最长，为后续的数据
             * 预备空间。否则按数据的长度（包括IP首部）分配SKB的空间
             * 即可。
             */
			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else
				alloclen = fraglen;

			alloclen += exthdrlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
            /*
             * 如果是最后一个分片，且是根据目的路由启用IPsec的情况，
             * 则可能需要多分配一些空间来支持IPsec。
             */
			if (datalen == length + fraggap)
				alloclen += rt->dst.trailer_len;


            /*
             * 根据是否存在传输层首部，确定用何种方法分配SKB。
             * 如果存在传输层首部，则可以确定该分片为分片组中的
             * 第一个分片，因此在分配SKB时需要考虑更多的情况，如
             * 输出操作是否超时,传输层是否发生未处理的致命错误，
             * 发送通道是否已关闭等。当分片不是第一个分片时，
             * 则无需考虑以上情况
             */
			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk,
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
			}
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
            /*
             * 填充用于校验的控制信息
             */
			skb->ip_summed = csummode;
			skb->csum = 0;
            /*
             * 为数据包预留用于存放二层首部、三层首部和数据的空间，
             * 并设置SKB中指向三层和四层的指针。
             */
			skb_reserve(skb, hh_len);

			/* only the initial fragment is time stamped */
			skb_shinfo(skb)->tx_flags = cork->tx_flags;
			cork->tx_flags = 0;
			skb_shinfo(skb)->tskey = tskey;
			tskey = 0;

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen + exthdrlen);
			skb_set_network_header(skb, exthdrlen);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen + exthdrlen;

            /*
             * 如果上一个SKB的数据超过8字节对齐MTU，则将超出数据和
             * 传输层首部复制到当前SKB，重新计算校验和，并以8字节
             * 对齐MTU为长度截取上一个SKB的数据。
             */
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->dst.dev->features&NETIF_F_SG) &&
		    skb_tailroom(skb) >= copy) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;

			err = -ENOMEM;
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			atomic_add(copy, &sk->sk_wmem_alloc);
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error_efault:
	err = -EFAULT;
error:
	cork->length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static int ip_setup_cork(struct sock *sk, struct inet_cork *cork,
			 struct ipcm_cookie *ipc, struct rtable **rtp)
{
	struct ip_options_rcu *opt;
	struct rtable *rt;

	/*
	 * setup for corking.
	 */
	opt = ipc->opt;
	if (opt) {
		if (cork->opt == NULL) {
			cork->opt = kmalloc(sizeof(struct ip_options) + 40,
					    sk->sk_allocation);
			if (unlikely(cork->opt == NULL))
				return -ENOBUFS;
		}
		memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
		cork->flags |= IPCORK_OPT;
		cork->addr = ipc->addr;
	}
	rt = *rtp;
	if (unlikely(!rt))
		return -EFAULT;
	/*
	 * We steal reference to this route, caller should not release it
	 */
	*rtp = NULL;
	cork->fragsize = ip_sk_use_pmtu(sk) ?
			 dst_mtu(&rt->dst) : rt->dst.dev->mtu;
	cork->dst = &rt->dst;
	cork->length = 0;
	cork->ttl = ipc->ttl;
	cork->tos = ipc->tos;
	cork->priority = ipc->priority;
	cork->tx_flags = ipc->tx_flags;

	return 0;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
int ip_append_data(struct sock *sk, struct flowi4 *fl4,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue)) {
		err = ip_setup_cork(sk, &inet->cork.base, ipc, rtp);
		if (err)
			return err;
	} else {/*队列不为空，则使用上次的路由，IP选项，以及分片长度 */
		transhdrlen = 0;
	}

	return __ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
				sk_page_frag(sk), getfrag,
				from, length, transhdrlen, flags);
}

ssize_t	ip_append_page(struct sock *sk, struct flowi4 *fl4, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	struct inet_cork *cork;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap, maxnonfragsize;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	cork = &inet->cork.base;
	rt = (struct rtable *)cork->dst;
	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (!(rt->dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);
	mtu = cork->fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
	maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

	if (cork->length + size > maxnonfragsize - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       mtu - (opt ? opt->optlen : 0));
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	cork->length += size;
	if ((size + skb->len > mtu) &&
	    (skb_queue_len(&sk->sk_write_queue) == 1) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->dst.dev->features & NETIF_F_UFO)) {
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
	}


	while (size > 0) {
		int i;

		if (skb_is_gso(skb))
			len = size;
		else {

			/* Check if the remaining data fits into current packet. */
			len = mtu - skb->len;
			if (len < size)
				len = maxfraglen - skb->len;
		}
		if (len <= 0) {
			struct sk_buff *skb_prev;
			int alloclen;

			skb_prev = skb;
			fraggap = skb_prev->len - maxfraglen;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			skb_put(skb, fragheaderlen + fraggap);
			skb_reset_network_header(skb);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(skb_prev,
								   maxfraglen,
						    skb_transport_header(skb),
								   fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i-1], len);
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			__wsum csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		skb->truesize += len;
		atomic_add(len, &sk->sk_wmem_alloc);
		offset += len;
		size -= len;
	}
	return 0;

error:
	cork->length -= size;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void ip_cork_release(struct inet_cork *cork)
{
	cork->flags &= ~IPCORK_OPT;
	kfree(cork->opt);
	cork->opt = NULL;
	dst_release(cork->dst);
	cork->dst = NULL;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
struct sk_buff *__ip_make_skb(struct sock *sk,
			      struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)cork->dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;

	if ((skb = __skb_dequeue(queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));
	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	skb->ignore_df = ip_sk_ignore_df(sk);

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If ignore_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    inet->pmtudisc == IP_PMTUDISC_PROBE ||
	    (skb->len <= dst_mtu(&rt->dst) &&
	     ip_dont_fragment(sk, &rt->dst)))
		df = htons(IP_DF);

	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (cork->ttl != 0)
		ttl = cork->ttl;
	else if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->dst);

	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
	iph->frag_off = df;
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);
	ip_select_ident(skb, sk);

	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, cork->addr, rt, 0);
	}

	skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
	skb->mark = sk->sk_mark;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	cork->dst = NULL;
	skb_dst_set(skb, &rt->dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	ip_cork_release(cork);
out:
	return skb;
}

int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}

int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4)
{
	struct sk_buff *skb;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		return 0;

	/* Netfilter gets whole the not fragmented skb. */
	return ip_send_skb(sock_net(sk), skb);
}

/*
 *	Throw away all pending data on the socket.
 */
static void __ip_flush_pending_frames(struct sock *sk,
				      struct sk_buff_head *queue,
				      struct inet_cork *cork)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);

	ip_cork_release(cork);
}

void ip_flush_pending_frames(struct sock *sk)
{
	__ip_flush_pending_frames(sk, &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}

struct sk_buff *ip_make_skb(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    unsigned int flags)
{
	struct inet_cork cork;
	struct sk_buff_head queue;
	int err;

	if (flags & MSG_PROBE)
		return NULL;

	__skb_queue_head_init(&queue);

	cork.flags = 0;
	cork.addr = 0;
	cork.opt = NULL;
	err = ip_setup_cork(sk, &cork, ipc, rtp);
	if (err)
		return ERR_PTR(err);

	err = __ip_append_data(sk, fl4, &queue, &cork,
			       &current->task_frag, getfrag,
			       from, length, transhdrlen, flags);
	if (err) {
		__ip_flush_pending_frames(sk, &queue, &cork);
		return ERR_PTR(err);
	}

	return __ip_make_skb(sk, fl4, &queue, &cork);
}

/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
			      int len, int odd, struct sk_buff *skb)
{
	__wsum csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send some TCP resets/acks so far.
 */
void ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb,
			   const struct ip_options *sopt,
			   __be32 daddr, __be32 saddr,
			   const struct ip_reply_arg *arg,
			   unsigned int len)
{
	struct ip_options_data replyopts;
	struct ipcm_cookie ipc;
	struct flowi4 fl4;
	struct rtable *rt = skb_rtable(skb);
	struct net *net = sock_net(sk);
	struct sk_buff *nskb;
	int err;

	if (__ip_options_echo(&replyopts.opt.opt, skb, sopt))
		return;

	ipc.addr = daddr;
	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;

	if (replyopts.opt.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (replyopts.opt.opt.srr)
			daddr = replyopts.opt.opt.faddr;
	}

	flowi4_init_output(&fl4, arg->bound_dev_if,
			   IP4_REPLY_MARK(net, skb->mark),
			   RT_TOS(arg->tos),
			   RT_SCOPE_UNIVERSE, ip_hdr(skb)->protocol,
			   ip_reply_arg_flowi_flags(arg),
			   daddr, saddr,
			   tcp_hdr(skb)->source, tcp_hdr(skb)->dest);
	security_skb_classify_flow(skb, flowi4_to_flowi(&fl4));
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return;

	inet_sk(sk)->tos = arg->tos;

	sk->sk_priority = skb->priority;
	sk->sk_protocol = ip_hdr(skb)->protocol;
	sk->sk_bound_dev_if = arg->bound_dev_if;
	sk->sk_sndbuf = sysctl_wmem_default;
	err = ip_append_data(sk, &fl4, ip_reply_glue_bits, arg->iov->iov_base,
			     len, 0, &ipc, &rt, MSG_DONTWAIT);
	if (unlikely(err)) {
		ip_flush_pending_frames(sk);
		goto out;
	}

	nskb = skb_peek(&sk->sk_write_queue);
	if (nskb) {
		if (arg->csumoffset >= 0)
			*((__sum16 *)skb_transport_header(nskb) +
			  arg->csumoffset) = csum_fold(csum_add(nskb->csum,
								arg->csum));
		nskb->ip_summed = CHECKSUM_NONE;
		skb_set_queue_mapping(nskb, skb_get_queue_mapping(skb));
		ip_push_pending_frames(sk, &fl4);
	}
out:
	ip_rt_put(rt);
}

void __init ip_init(void)
{
	ip_rt_init();
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST)
	igmp_mc_init();
#endif
}
