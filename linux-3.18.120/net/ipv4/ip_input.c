/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;

	for (ra = rcu_dereference(ip_ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), dev_net(dev))) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

//从这里进入L4传输层
/*
 * ip_local_deliver_finish()将输入数据包从网络层传递
 * 到传输层。过程如下:
 * 1)首先，在数据包传递给传输层之前，去掉IP首部
 * 2)接着，如果是RAW套接字接收数据包，则需要
 * 复制一份副本，输入到接收该数据包的套接字。
 * 3)最后，通过传输层的接收例程，将数据包传递
 * 到传输层，由传输层进行处理。
 */
static int ip_local_deliver_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);

	/* 把skb->data指向L4协议头，更新skb->len */
	/* 赋值skb->transport_header */
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		int protocol = ip_hdr(skb)->protocol; /* L4协议号 */
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		/*
		 * 处理RAW套接字，先根据传输层协议号
		 * 得到哈希值，然后查看raw_v4_htable散列表
		 * 中以该值为关键字的哈希桶是否为空，
		 * 如果不为空，则说明创建了RAW套接字，
		 * 复制该数据包的副本输入到注册到
		 * 该桶中的所有套接字。
		 */
		/*
		 * ip_local_deliver_finish函数会先检查哈希表raw_v4_htable。因为在创建 socket时，inet_create会把协议号IPPROTO_ICMP的值赋给socket的成员num，
		 * 并以num为键值，把socket存入哈 项表raw_v4_htable，raw_v4_htable[IPPROTO_ICMP&(MAX_INET_PROTOS-1)]上即存放了 这个socket，实际上是一个socket的链表，
		 * 如果其它还有socket要处理这个回显应答，也会被放到这里，组成一个链 表，ip_local_deliver_finish收到数据报后，取出这个socket链表(目前实际上只有一项)，
		 * 调用raw_v4_input，把 skb交给每一个socket进行处理。然后，还需要把数据报交给inet_protos[IPPROTO_ICMP& (MAX_INET_PROTOS-1)]，即icmp_rcv处理，
		 * 因为对于icmp报文，每一个都是需要经过协议栈处理的，但对回显应 答，icmp_rcv只是简单丢弃，并未实际处理。
		 */
		 ////之前开巨帧的时候，icmp不通就是在这里面的函数中sock_queue_rcv_skb丢的
		raw = raw_local_deliver(skb, protocol); //如果是raw套接字，则则该函数里面会复制一份skb，然后送到，例如用ping 1.2.2.2的时候，会走这里面，不会走icmp_recv

		/* 从inet_protos数组中取出对应的net_protocol元素，TCP的为tcp_protocol */
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot != NULL) {
			int ret;

			/* 如果需要检查IPsec安全策略 */
			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			/* 调用L4协议的处理函数，对于TCP，调用tcp_protocol->handler，为tcp_v4_rcv() */
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			/*
			 * 如果没有响应的协议传输层接收该数据包，
			 * 则释放该数据包。在释放前，如果是RAW
			 * 套接字没有接收或接收异常，则还需产生
			 * 一个目的不可达ICMP报文给发送方。表示该包raw没有接收并且inet_protos中没有注册该协议
			 */
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 * 收集IP分片，然后调用ip_local_deliver_finish将一个完整的数据包传送给上层协议。
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	/*
     * 判断该IP数据包是否是一个分片，如果IP_MF置位，则表示该包是分片之一，其
     * 后还有更多分片，最后一个IP分片未置位IP_MF但是其offset是非0。
     * 如果是一个IP分片，则调用ip_defrag重新组织IP数据包。
     */
        /* 
         * frag_off是16位，其中高3位用作标志位，
         * 低13位才是真正的偏移量.
         * 内核可通过设置的分片标识位或非0
         * 的分片偏移量识别分片的分组。偏移
         * 量字段为0，表明这是分组的最后一个分片。
         * 
         * 如果接收到的IP数据包时分片，则调用
         * ip_defrag()进行重组，其标志位IP_DEFRAG_LOCAL_DELIVER。
         */
	if (ip_is_fragment(ip_hdr(skb))) {
       /*
        * 重新组合分片分组的各个部分。
        * 
        * 如果ip_defrag()返回非0，则表示IP数据包分片
        * 尚未到齐，重组没有完成，或者出错，直接
        * 返回。为0，则表示已完成IP数据包的重组，
        * 需要传递到传输层进行处理。
        */
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

    /*
     * 经过netfilter处理后，调用ip_local_deliver_finish()，
     * 将组装完成的IP数据包传送到传输层处理
     */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

int sysctl_ip_early_demux __read_mostly = 1;
EXPORT_SYMBOL(sysctl_ip_early_demux);

/*
 * ip_rcv_finish()在ip_rcv()中当IP数据包经过netfilter模块
 * 处理后被调用。完成的主要功能是，如果
 * 还没有为该数据包查找输入路由缓存，则
 * 调用ip_route_input()为其查找输入路由缓存。
 * 接着处理IP数据包首部中的选项，最后
 * 根据输入路由缓存输入到本地或抓发。
 */
static int ip_rcv_finish(struct sk_buff *skb)
{
	//根据套接字获得ip头
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	/*sysctl_ip_early_demux 是二进制值，该值用于对发往本地数据包的优化。当前仅对建立连接的套接字起作用。*/
	if (sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && ipprot->early_demux) {
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}


	  /*
     *  为数据包初始化虚拟路径缓存，它描述了数据包是如何在linux网络中传播的
     */
     //noted:通常从外界接收的数据包,skb->dst不会包含路由信息,暂时还不知道在何处会设置这个字段
     //ip_route_input函数会根据路由表设置路由信息
     //ip_route_input_noref查找路由信息
     //(kernel/include/net/route.h)ip_route_input_noref()--->(kernel/net/route.c)ip_route_input_common()
	if (!skb_dst(skb)) {
		/* 选择路由*/
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);//最终会调用ip_local_deliver
		if (unlikely(err)) {
			if (err == -EXDEV)
				//更新基于tcp/ip因特网的MIB（management information base）信息，RFC1213
				NET_INC_STATS_BH(dev_net(skb->dev),
						 LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

//noted:更新统计数据
#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	//如果IP头部大于20字节，则表示IP头部包含IP选项，需要进行选项处理
	//对套接字可选字段的处理。ip_rcv_options(skb)会调用ip_options_rcv_srr(skb)
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	//noted: skb_rtable函数等同于skb_dst函数，获取skb->dst 获得路由表
	rt = skb_rtable(skb);
	//多播和广播时的信息传递。
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
				skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
				skb->len);
    //noted: dst_input实际上会调用skb->dst->input(skb).input函数会根据路由信息设置为合适的
    //函数指针，如果是递交到本地的则为ip_local_deliver，若是转发则为ip_forward.
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	/* 
     * 当网卡处于混杂模式时，丢掉所有接收到的的垃圾数据，不要试图解析它
     */
    //noted: 其实也就是丢弃掉不是发往本地的数据包。网卡在混杂模式下会接收一切到达网卡的数据，不管目的地mac是否是本网卡
    //noted: 在调用ip_rcv之前，内核会将该数据包交给嗅探器，所以该函数仅丢弃该包
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	//noted:该宏用于内核做一些统计,关于网络层snmp统计的信息，也可以通过netstat 指令看到这些统计值
	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);
	
    //noted: ip_rcv是由netif_receive_skb函数调用，如果嗅探器或者其他的用户对数据包需要进
    //进行处理，则在调用ip_rcv之前，netif_receive_skb会增加skb的引用计数，既该引
    //用计数会大于1。若如此次，则skb_share_check会创建sk_buff的一份拷贝。
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		 //noted: SNMP所需要的统计数据，忽略
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}
	
    //noted:pskb_may_pull确保skb->data指向的内存包含的数据至少为IP头部大小，由于每个
    //IP数据包包括IP分片必须包含一个完整的IP头部。如果小于IP头部大小，则缺失
    //的部分将从数据分片中拷贝。这些分片保存在skb_shinfo(skb)->frags[]中。
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	//noted: pskb_may_pull可能会调整skb中的指针，所以需要重新定义IP头部
	iph = ip_hdr(skb);

	/*
     *  RFC1122: 3.2.1.2 必须默默地放弃任何IP帧校验和失败.
     *
     *  数据报可接收?
     *
     *  1.  长度至少是一个ip报头的大小
     *  2.  版本4
     *  3.  校验和正确。(速度优化后,跳过回路校验和)
     *  4.  没有虚假的长度
     */

	//noted: 检测ip首部长度及协议版本
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	IP_ADD_STATS_BH(dev_net(dev),
			IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	//noted: 确保IP完整的头部包括选项在内存中
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	//noted:验证IP头部的校验和
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	//noted:检测ip报文长度是否小于skb->len
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* 我们的传输介质可能填充缓冲区。现在我们知道这是 我们可以从此帧中削减的真实长度的ip帧
	 * 注意现在意味着skb->len包括ntohs(iph->tot_len)
	 */
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	//noted: 设置tcp报头指针
	skb->transport_header = skb->network_header + iph->ihl*4;

	/* 删除任何套接字控制块碎片 */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* 因为tproxy，现在必须丢掉socket */
    //noted: tproxy是iptables的一附加控件，在mangle表的PREROUTING链中使用，不修改数据包包头，
    //直接把数据传递给一个本地socket(即不对数据包进行任何nat操作)。
	skb_orphan(skb);

	//在完整校验之后，选路确定之前	
    //noted: 在做完基本的头校验等工作后，就交由NF_HOOK管理了
    //noted: NF_HOOK在做完PRE_ROUTING的筛选后，PRE_ROUTING点上注册的所有钩子都
    //返回NF_ACCEPT才会执行后面的ip_rcv_finish函数 ，然后继续执行路由等处理
    //如果是本地的就会交给更高层的协议进行处理，如果不是交由本地的就执行FORWARD
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
