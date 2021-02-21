/*
 *	NET3	IP device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Derived from the IP parts of dev.c 1.0.19
 * 		Authors:	Ross Biro
 *				Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *				Mark Evans, <evansmp@uhura.aston.ac.uk>
 *
 *	Additional Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *	Changes:
 *		Alexey Kuznetsov:	pa_* fields are replaced with ifaddr
 *					lists.
 *		Cyrus Durgin:		updated for kmod
 *		Matthias Andree:	in devinet_ioctl, compare label and
 *					address (4.4BSD alias style support),
 *					fall back to comparing just the label
 *					if no match found.
 */


#include <asm/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/slab.h>
#include <linux/hash.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <linux/kmod.h>
#include <linux/netconf.h>

#include <net/arp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/addrconf.h>

#include "fib_lookup.h"

static struct ipv4_devconf ipv4_devconf = {
	.data = {
		[IPV4_DEVCONF_ACCEPT_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SEND_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SECURE_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SHARED_MEDIA - 1] = 1,
		[IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL - 1] = 10000 /*ms*/,
		[IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL - 1] =  1000 /*ms*/,
	},
};

static struct ipv4_devconf ipv4_devconf_dflt = {
	.data = {
		[IPV4_DEVCONF_ACCEPT_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SEND_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SECURE_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SHARED_MEDIA - 1] = 1,
		[IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE - 1] = 1,
		[IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL - 1] = 10000 /*ms*/,
		[IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL - 1] =  1000 /*ms*/,
	},
};

#define IPV4_DEVCONF_DFLT(net, attr) \
	IPV4_DEVCONF((*net->ipv4.devconf_dflt), attr)

static const struct nla_policy ifa_ipv4_policy[IFA_MAX+1] = {
	[IFA_LOCAL]     	= { .type = NLA_U32 },
	[IFA_ADDRESS]   	= { .type = NLA_U32 },
	[IFA_BROADCAST] 	= { .type = NLA_U32 },
	[IFA_LABEL]     	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
	[IFA_CACHEINFO]		= { .len = sizeof(struct ifa_cacheinfo) },
	[IFA_FLAGS]		= { .type = NLA_U32 },
};

#define IN4_ADDR_HSIZE_SHIFT	8
#define IN4_ADDR_HSIZE		(1U << IN4_ADDR_HSIZE_SHIFT)

//http://www.linuxidc.com/Linux/2013-07/86999.htm如图 1中所示，
//Linux的网络子系统一共有3个通知链：表示ipv4地址发生变化时的inetaddr_chain；
//表示ipv6地址发生变化的inet6addr_chain；还有表示设备注册、状态变化的netdev_chain。
//static BLOCKING_NOTIFIER_HEAD(inetaddr_chain);
/*  
原子通知链（ Atomic notifier chains ）：通知链元素的回调函数（当事件发生时要执行的函数）在中断或原子操作上下文中运行，不允许阻塞。对应的链表头结构：
可阻塞通知链（ Blocking notifier chains ）：通知链元素的回调函数在进程上下文中运行，允许阻塞。对应的链表头：
原始通知链（ Raw notifierchains ）：对通知链元素的回调函数没有任何限制，所有锁和保护机制都由调用者维护。对应的链表头：
SRCU 通知链（ SRCU notifier chains ）：可阻塞通知链的一种变体。对应的链表头：

register_inetaddr_notifier和unregister_inetaddr_notifier配对
*/

static struct hlist_head inet_addr_lst[IN4_ADDR_HSIZE];

static u32 inet_addr_hash(struct net *net, __be32 addr)
{
	u32 val = (__force u32) addr ^ net_hash_mix(net);

	return hash_32(val, IN4_ADDR_HSIZE_SHIFT);
}

static void inet_hash_insert(struct net *net, struct in_ifaddr *ifa)
{
	u32 hash = inet_addr_hash(net, ifa->ifa_local);

	ASSERT_RTNL();
	hlist_add_head_rcu(&ifa->hash, &inet_addr_lst[hash]);
}

static void inet_hash_remove(struct in_ifaddr *ifa)
{
	ASSERT_RTNL();
	hlist_del_init_rcu(&ifa->hash);
}

/**
 * __ip_dev_find - find the first device with a given source address.
 * @net: the net namespace
 * @addr: the source address
 * @devref: if true, take a reference on the found device
 *
 * If a caller uses devref=false, it should be protected by RCU, or RTNL
 */
struct net_device *__ip_dev_find(struct net *net, __be32 addr, bool devref)
{
	u32 hash = inet_addr_hash(net, addr);
	struct net_device *result = NULL;
	struct in_ifaddr *ifa;

	rcu_read_lock();
	hlist_for_each_entry_rcu(ifa, &inet_addr_lst[hash], hash) {
		if (ifa->ifa_local == addr) {
			struct net_device *dev = ifa->ifa_dev->dev;

			if (!net_eq(dev_net(dev), net))
				continue;
			result = dev;
			break;
		}
	}
	if (!result) {
		struct flowi4 fl4 = { .daddr = addr };
		struct fib_result res = { 0 };
		struct fib_table *local;

		/* Fallback to FIB local table so that communication
		 * over loopback subnets work.
		 */
		local = fib_get_table(net, RT_TABLE_LOCAL);
		if (local &&
		    !fib_table_lookup(local, &fl4, &res, FIB_LOOKUP_NOREF) &&
		    res.type == RTN_LOCAL)
			result = FIB_RES_DEV(res);
	}
	if (result && devref)
		dev_hold(result);
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL(__ip_dev_find);

static void rtmsg_ifa(int event, struct in_ifaddr *, struct nlmsghdr *, u32);

static BLOCKING_NOTIFIER_HEAD(inetaddr_chain);
static void inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy);
#ifdef CONFIG_SYSCTL
static int devinet_sysctl_register(struct in_device *idev);
static void devinet_sysctl_unregister(struct in_device *idev);
#else
static int devinet_sysctl_register(struct in_device *idev)
{
	return 0;
}
static void devinet_sysctl_unregister(struct in_device *idev)
{
}
#endif

/* Locks all the inet devices. */

static struct in_ifaddr *inet_alloc_ifa(void)
{
	return kzalloc(sizeof(struct in_ifaddr), GFP_KERNEL);
}

static void inet_rcu_free_ifa(struct rcu_head *head)
{
	struct in_ifaddr *ifa = container_of(head, struct in_ifaddr, rcu_head);
	if (ifa->ifa_dev)
		in_dev_put(ifa->ifa_dev);
	kfree(ifa);
}

static void inet_free_ifa(struct in_ifaddr *ifa)
{
	call_rcu(&ifa->rcu_head, inet_rcu_free_ifa);
}

void in_dev_finish_destroy(struct in_device *idev)
{
	struct net_device *dev = idev->dev;

	WARN_ON(idev->ifa_list);
	WARN_ON(idev->mc_list);
	kfree(rcu_dereference_protected(idev->mc_hash, 1));
#ifdef NET_REFCNT_DEBUG
	pr_debug("%s: %p=%s\n", __func__, idev, dev ? dev->name : "NIL");
#endif
	dev_put(dev);
	if (!idev->dead)
		pr_err("Freeing alive in_device %p\n", idev);
	else
		kfree(idev);
}
EXPORT_SYMBOL(in_dev_finish_destroy);

 /*
  * inetdev_init()为通过参数指定的网络设备分配并绑定
  * IP配置块。
  */
static struct in_device *inetdev_init(struct net_device *dev)
{
	struct in_device *in_dev;
	int err = -ENOMEM;

	ASSERT_RTNL();

	 /*
	  * 分配一个IP配置块
	  */
	in_dev = kzalloc(sizeof(*in_dev), GFP_KERNEL);
	if (!in_dev)
		goto out;
	 /*
	  * 初始化IP配置块中的一些成员，包括
	  * IPv4配置的默认值，以及所属的网络设备。
	  */
	memcpy(&in_dev->cnf, dev_net(dev)->ipv4.devconf_dflt,
			sizeof(in_dev->cnf));
	in_dev->cnf.sysctl = NULL;
	in_dev->dev = dev;
	 /*
	  * 为IP配置块分配邻居协议参数配置块，
	  * 并根据ARP表初始化
	  */
	in_dev->arp_parms = neigh_parms_alloc(dev, &arp_tbl);
	if (!in_dev->arp_parms)
		goto out_kfree;
	if (IPV4_DEVCONF(in_dev->cnf, FORWARDING))
		dev_disable_lro(dev);
	/* Reference in_dev->dev */
	dev_hold(dev);
	/* Account for reference dev->ip_ptr (below) */
	in_dev_hold(in_dev);

	err = devinet_sysctl_register(in_dev);
	if (err) {
		in_dev->dead = 1;
		in_dev_put(in_dev);
		in_dev = NULL;
		goto out;
	}
	 /*
	  * 初始化IGMP模块
	  */
	ip_mc_init_dev(in_dev);
	 /*
	  * 如果网络设备已启用，则初始化该网络
	  * 设备上的组播消息，例如，将
	  * 该网络设备加入到224.0.0.1组播组等操作
	  */
	if (dev->flags & IFF_UP)
		ip_mc_up(in_dev);

	/* we can receive as soon as ip_ptr is set -- do this last */
	rcu_assign_pointer(dev->ip_ptr, in_dev);
 /*
  * 操作成功，返回分配并绑定成功的IP配置块，
  * 否则返回NULL。
  */
out:
	return in_dev ?: ERR_PTR(err);
out_kfree:
	kfree(in_dev);
	in_dev = NULL;
	goto out;
}

static void in_dev_rcu_put(struct rcu_head *head)
{
	struct in_device *idev = container_of(head, struct in_device, rcu_head);
	in_dev_put(idev);
}

 /*
  * inetdev_destroy()通常在设备注销时被调用，
  * 释放指定的IP配置块。
  */
static void inetdev_destroy(struct in_device *in_dev)
{
	struct in_ifaddr *ifa;
	struct net_device *dev;

	ASSERT_RTNL();

	dev = in_dev->dev;

	 /*
	  * 标识带释放的IP配置块正处在释放过程中。
	  */
	in_dev->dead = 1;

	 /*
	  * 销毁组播相关的配置，如停止相关定时器。
	  */
	ip_mc_destroy_dev(in_dev);

	 /*
	  * 删除并释放所有的IP地址块。
	  */
	while ((ifa = in_dev->ifa_list) != NULL) {
		inet_del_ifa(in_dev, &in_dev->ifa_list, 0);
		inet_free_ifa(ifa);
	}

	 /*
	  * 将网络设备指向IP配置块的指针设置为NULL。
	  */
	RCU_INIT_POINTER(dev->ip_ptr, NULL);
	 /*
	  * 注销邻居子系统相关的配置参数
	  */
	devinet_sysctl_unregister(in_dev);
	 /*
	  * 释放IP配置块中的邻居协议参数配置块。
	  */
	neigh_parms_release(&arp_tbl, in_dev->arp_parms);
	arp_ifdown(dev);

	 /*
	  * 通过RCU机制释放IP配置块。
	  */
	call_rcu(&in_dev->rcu_head, in_dev_rcu_put);
}

 /*
  * 根据指定网络设备的IP配置块，检查两个给定的
  * IP地址是否同属于一个子网
  */
int inet_addr_onlink(struct in_device *in_dev, __be32 a, __be32 b)
{
	rcu_read_lock();
	for_primary_ifa(in_dev) {
		if (inet_ifa_match(a, ifa)) {
			if (!b || inet_ifa_match(b, ifa)) {
				rcu_read_unlock();
				return 1;
			}
		}
	} endfor_ifa(in_dev);
	rcu_read_unlock();
	return 0;
}

static void __inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy, struct nlmsghdr *nlh, u32 portid)
{
	struct in_ifaddr *promote = NULL;
	struct in_ifaddr *ifa, *ifa1 = *ifap;
	struct in_ifaddr *last_prim = in_dev->ifa_list;
	struct in_ifaddr *prev_prom = NULL;
	int do_promote = IN_DEV_PROMOTE_SECONDARIES(in_dev);

	ASSERT_RTNL();

	if (in_dev->dead)
		goto no_promotions;

	/* 1. Deleting primary ifaddr forces deletion all secondaries
	 * unless alias promotion is set
	 **/

	 /*
	  * 如果删除的是主IP地址，则需对从属
	  * IP地址作相应的处理。如果没有启用
	  * promote_secondaries，则删除所有该主IP地址的
	  * 从属IP地址，否则选择一个从属IP地址，
	  * 升级为主IP地址。
	  */
	if (!(ifa1->ifa_flags & IFA_F_SECONDARY)) {
		struct in_ifaddr **ifap1 = &ifa1->ifa_next;

		while ((ifa = *ifap1) != NULL) {
			if (!(ifa->ifa_flags & IFA_F_SECONDARY) &&
			    ifa1->ifa_scope <= ifa->ifa_scope)
				last_prim = ifa;

			if (!(ifa->ifa_flags & IFA_F_SECONDARY) ||
			    ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa)) {
				ifap1 = &ifa->ifa_next;
				prev_prom = ifa;
				continue;
			}

			if (!do_promote) {
				inet_hash_remove(ifa);
				*ifap1 = ifa->ifa_next;

				rtmsg_ifa(RTM_DELADDR, ifa, nlh, portid);
				blocking_notifier_call_chain(&inetaddr_chain,
						NETDEV_DOWN, ifa);
				inet_free_ifa(ifa);
			} else {
				promote = ifa;
				break;
			}
		}
	}

	/* On promotion all secondaries from subnet are changing
	 * the primary IP, we must remove all their routes silently
	 * and later to add them back with new prefsrc. Do this
	 * while all addresses are on the device list.
	 */
	for (ifa = promote; ifa; ifa = ifa->ifa_next) {
		if (ifa1->ifa_mask == ifa->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, ifa))
			fib_del_ifaddr(ifa, ifa1);
	}

no_promotions:
	/* 2. Unlink it */

	 /*
	  * 先将待删除的IP地址块从链表中删除，
	  * 后续操作中再根据destroy作处理
	  */
	*ifap = ifa1->ifa_next;
	inet_hash_remove(ifa1);

	/* 3. Announce address deletion */

	/* Send message first, then call notifier.
	   At first sight, FIB update triggered by notifier
	   will refer to already deleted ifaddr, that could confuse
	   netlink listeners. It is not true: look, gated sees
	   that route deleted and if it still thinks that ifaddr
	   is valid, it will try to restore deleted routes... Grr.
	   So that, this order is correct.
	 */
	 /*
	  * 通过netlink发送RTM_DELADDR消息给感兴趣的
	  * 用户进程
	  */
	rtmsg_ifa(RTM_DELADDR, ifa1, nlh, portid);
	 /*
	  * 通过inetaddr_chain通知链发送删除IP地址事件
	  * 和IP地址信息给感兴趣的其他内核模块
	  */
	blocking_notifier_call_chain(&inetaddr_chain, NETDEV_DOWN, ifa1);

	 /*
	  * 如果启用了promote_secondaries，将选择到的
	  * 从属IP地址升级为主IP地址，发送从属
	  * IP地址升级为主IP地址消息。并通过
	  * fib_add_ifaddr()将从属IP地址相关的路由
	  * 表项添加到ip_fib_local_table路由表中。
	  */
	if (promote) {
		struct in_ifaddr *next_sec = promote->ifa_next;

		if (prev_prom) {
			prev_prom->ifa_next = promote->ifa_next;
			promote->ifa_next = last_prim->ifa_next;
			last_prim->ifa_next = promote;
		}

		promote->ifa_flags &= ~IFA_F_SECONDARY;
		rtmsg_ifa(RTM_NEWADDR, promote, nlh, portid);
		blocking_notifier_call_chain(&inetaddr_chain,
				NETDEV_UP, promote);
		for (ifa = next_sec; ifa; ifa = ifa->ifa_next) {
			if (ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa))
					continue;
			fib_add_ifaddr(ifa);
		}

	}
	
	 /*
	  * 如果根据destroy需要释放，则通过RCU机制
	  * 释放IP配置块。在删除掉最后一个地址后，
	  * 释放所有的IP配置块。
	  */
	if (destroy)
		inet_free_ifa(ifa1);
}

static void inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy)
{
	__inet_del_ifa(in_dev, ifap, destroy, NULL, 0);
}

static void check_lifetime(struct work_struct *work);

static DECLARE_DELAYED_WORK(check_lifetime_work, check_lifetime);

static int __inet_insert_ifa(struct in_ifaddr *ifa, struct nlmsghdr *nlh,
			     u32 portid)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct in_ifaddr *ifa1, **ifap, **last_primary;

	ASSERT_RTNL();

	if (!ifa->ifa_local) {
		inet_free_ifa(ifa);
		return 0;
	}

	 /*
	  * 先清除地址的从属标志，因为配置的地址
	  * 是主IP地址还是从属IP地址，并非根据标志
	  * 而是根据当前已配置的IP地址
	  */
	ifa->ifa_flags &= ~IFA_F_SECONDARY;
	last_primary = &in_dev->ifa_list;

	 /*
	  * 在所有主IP地址中查找，如果存在相同
	  * 寻址范围的地址，则本次添加的IP地址
	  * 为从属IP地址。而如果已配置了相同的
	  * 地址，则返回错误码-EEXIST。
	  */
	for (ifap = &in_dev->ifa_list; (ifa1 = *ifap) != NULL;
	     ifap = &ifa1->ifa_next) {
		if (!(ifa1->ifa_flags & IFA_F_SECONDARY) &&
		    ifa->ifa_scope <= ifa1->ifa_scope)
			last_primary = &ifa1->ifa_next;
		if (ifa1->ifa_mask == ifa->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, ifa)) {
			if (ifa1->ifa_local == ifa->ifa_local) {
				inet_free_ifa(ifa);
				return -EEXIST;
			}
			if (ifa1->ifa_scope != ifa->ifa_scope) {
				inet_free_ifa(ifa);
				return -EINVAL;
			}
			ifa->ifa_flags |= IFA_F_SECONDARY;
		}
	}

	 /*
	  * 如果配置的是第一个地址，则先添加
	  * 熵到伪随机数引擎中，然后将其地址
	  * 添加到IP配置块中。
	  */
	if (!(ifa->ifa_flags & IFA_F_SECONDARY)) {
		prandom_seed((__force u32) ifa->ifa_local);
		ifap = last_primary;
	}

	ifa->ifa_next = *ifap;
	*ifap = ifa;

	inet_hash_insert(dev_net(in_dev->dev), ifa);

	cancel_delayed_work(&check_lifetime_work);
	queue_delayed_work(system_power_efficient_wq, &check_lifetime_work, 0);

	/* Send message first, then call notifier.
	   Notifier will trigger FIB update, so that
	   listeners of netlink will know about new ifaddr */
	 /*
	  * 通过netlink发送RTM_NEWADDR消息给感兴趣的
	  * 用户进程。
	  */
	rtmsg_ifa(RTM_NEWADDR, ifa, nlh, portid);
	 /*
	  * 通过inetaddr_chain通知链发送添加IP地址事件
	  * 和IP地址消息给感兴趣的其他内核模块。
	  */
	blocking_notifier_call_chain(&inetaddr_chain, NETDEV_UP, ifa);

	return 0;
}

 /*
  * inet_insert_ifa()用来添加一个IP地址。
  * 通常在设置广播地址、点对点对端
  * 地址和地址掩码时，先调用inet_del_ifa()清除
  * 原有的信息，然后再调用inet_insert_ifa()进行
  * 设置
  */
static int inet_insert_ifa(struct in_ifaddr *ifa)
{
	return __inet_insert_ifa(ifa, NULL, 0);
}

static int inet_set_ifa(struct net_device *dev, struct in_ifaddr *ifa)
{
	struct in_device *in_dev = __in_dev_get_rtnl(dev);

	ASSERT_RTNL();

	if (!in_dev) {
		inet_free_ifa(ifa);
		return -ENOBUFS;
	}
	ipv4_devconf_setall(in_dev);
	neigh_parms_data_state_setall(in_dev->arp_parms);
	if (ifa->ifa_dev != in_dev) {
		WARN_ON(ifa->ifa_dev);
		in_dev_hold(in_dev);
		ifa->ifa_dev = in_dev;
	}
	if (ipv4_is_loopback(ifa->ifa_local))
		ifa->ifa_scope = RT_SCOPE_HOST;
	return inet_insert_ifa(ifa);
}

/* Caller must hold RCU or RTNL :
 * We dont take a reference on found in_device
 */
 /*
  * inetdev_by_index()根据网络设备索引号获取
  * 对应网络设备的IP配置块
  */
struct in_device *inetdev_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;
	struct in_device *in_dev = NULL;

	rcu_read_lock();
	 /*
	  * 根据索引获取对应的网络设备
	  */
	dev = dev_get_by_index_rcu(net, ifindex);
	 /*
	  * 如果获得的网络设备有效，则返回其
	  * IP配置块，否则返回NULL。
	  */
	if (dev)
		in_dev = rcu_dereference_rtnl(dev->ip_ptr);
	rcu_read_unlock();
	return in_dev;
}
EXPORT_SYMBOL(inetdev_by_index);

/* Called only from RTNL semaphored context. No locks. */
 /*
  * inet_ifa_byprefix()在正在配置的输入设备的主IP
  * 地址中查找与前缀和掩码匹配的IP地址
  */
struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, __be32 prefix,
				    __be32 mask)
{
	ASSERT_RTNL();

	for_primary_ifa(in_dev) {
		if (ifa->ifa_mask == mask && inet_ifa_match(prefix, ifa))
			return ifa;
	} endfor_ifa(in_dev);
	return NULL;
}

 /*
  * 当通过netlink，操作类型为RTM_DELADDR删除IP地址时，
  * 才调用此函数
  */
static int inet_rtm_deladdr(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tb[IFA_MAX+1];
	struct in_device *in_dev;
	struct ifaddrmsg *ifm;
	struct in_ifaddr *ifa, **ifap;
	int err = -EINVAL;

	ASSERT_RTNL();

	 /*
	  * 解析netlink报文，获取配置参数。
	  */
	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFA_MAX, ifa_ipv4_policy);
	if (err < 0)
		goto errout;

	ifm = nlmsg_data(nlh);
	in_dev = inetdev_by_index(net, ifm->ifa_index);
	if (in_dev == NULL) {
		err = -ENODEV;
		goto errout;
	}

	 /*
	  * 根据本地地址、标签以及掩码查找待删除的
	  * IP地址块，如果查找命中，则将其删除并释放。
	  */
	for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
	     ifap = &ifa->ifa_next) {
		if (tb[IFA_LOCAL] &&
		    ifa->ifa_local != nla_get_be32(tb[IFA_LOCAL]))
			continue;

		if (tb[IFA_LABEL] && nla_strcmp(tb[IFA_LABEL], ifa->ifa_label))
			continue;

		if (tb[IFA_ADDRESS] &&
		    (ifm->ifa_prefixlen != ifa->ifa_prefixlen ||
		    !inet_ifa_match(nla_get_be32(tb[IFA_ADDRESS]), ifa)))
			continue;

		__inet_del_ifa(in_dev, ifap, 1, nlh, NETLINK_CB(skb).portid);
		return 0;
	}

	err = -EADDRNOTAVAIL;
errout:
	return err;
}

#define INFINITY_LIFE_TIME	0xFFFFFFFF

static void check_lifetime(struct work_struct *work)
{
	unsigned long now, next, next_sec, next_sched;
	struct in_ifaddr *ifa;
	struct hlist_node *n;
	int i;

	now = jiffies;
	next = round_jiffies_up(now + ADDR_CHECK_FREQUENCY);

	for (i = 0; i < IN4_ADDR_HSIZE; i++) {
		bool change_needed = false;

		rcu_read_lock();
		hlist_for_each_entry_rcu(ifa, &inet_addr_lst[i], hash) {
			unsigned long age;

			if (ifa->ifa_flags & IFA_F_PERMANENT)
				continue;

			/* We try to batch several events at once. */
			age = (now - ifa->ifa_tstamp +
			       ADDRCONF_TIMER_FUZZ_MINUS) / HZ;

			if (ifa->ifa_valid_lft != INFINITY_LIFE_TIME &&
			    age >= ifa->ifa_valid_lft) {
				change_needed = true;
			} else if (ifa->ifa_preferred_lft ==
				   INFINITY_LIFE_TIME) {
				continue;
			} else if (age >= ifa->ifa_preferred_lft) {
				if (time_before(ifa->ifa_tstamp +
						ifa->ifa_valid_lft * HZ, next))
					next = ifa->ifa_tstamp +
					       ifa->ifa_valid_lft * HZ;

				if (!(ifa->ifa_flags & IFA_F_DEPRECATED))
					change_needed = true;
			} else if (time_before(ifa->ifa_tstamp +
					       ifa->ifa_preferred_lft * HZ,
					       next)) {
				next = ifa->ifa_tstamp +
				       ifa->ifa_preferred_lft * HZ;
			}
		}
		rcu_read_unlock();
		if (!change_needed)
			continue;
		rtnl_lock();
		hlist_for_each_entry_safe(ifa, n, &inet_addr_lst[i], hash) {
			unsigned long age;

			if (ifa->ifa_flags & IFA_F_PERMANENT)
				continue;

			/* We try to batch several events at once. */
			age = (now - ifa->ifa_tstamp +
			       ADDRCONF_TIMER_FUZZ_MINUS) / HZ;

			if (ifa->ifa_valid_lft != INFINITY_LIFE_TIME &&
			    age >= ifa->ifa_valid_lft) {
				struct in_ifaddr **ifap;

				for (ifap = &ifa->ifa_dev->ifa_list;
				     *ifap != NULL; ifap = &(*ifap)->ifa_next) {
					if (*ifap == ifa) {
						inet_del_ifa(ifa->ifa_dev,
							     ifap, 1);
						break;
					}
				}
			} else if (ifa->ifa_preferred_lft !=
				   INFINITY_LIFE_TIME &&
				   age >= ifa->ifa_preferred_lft &&
				   !(ifa->ifa_flags & IFA_F_DEPRECATED)) {
				ifa->ifa_flags |= IFA_F_DEPRECATED;
				rtmsg_ifa(RTM_NEWADDR, ifa, NULL, 0);
			}
		}
		rtnl_unlock();
	}

	next_sec = round_jiffies_up(next);
	next_sched = next;

	/* If rounded timeout is accurate enough, accept it. */
	if (time_before(next_sec, next + ADDRCONF_TIMER_FUZZ))
		next_sched = next_sec;

	now = jiffies;
	/* And minimum interval is ADDRCONF_TIMER_FUZZ_MAX. */
	if (time_before(next_sched, now + ADDRCONF_TIMER_FUZZ_MAX))
		next_sched = now + ADDRCONF_TIMER_FUZZ_MAX;

	queue_delayed_work(system_power_efficient_wq, &check_lifetime_work,
			next_sched - now);
}

static void set_ifa_lifetime(struct in_ifaddr *ifa, __u32 valid_lft,
			     __u32 prefered_lft)
{
	unsigned long timeout;

	ifa->ifa_flags &= ~(IFA_F_PERMANENT | IFA_F_DEPRECATED);

	timeout = addrconf_timeout_fixup(valid_lft, HZ);
	if (addrconf_finite_timeout(timeout))
		ifa->ifa_valid_lft = timeout;
	else
		ifa->ifa_flags |= IFA_F_PERMANENT;

	timeout = addrconf_timeout_fixup(prefered_lft, HZ);
	if (addrconf_finite_timeout(timeout)) {
		if (timeout == 0)
			ifa->ifa_flags |= IFA_F_DEPRECATED;
		ifa->ifa_preferred_lft = timeout;
	}
	ifa->ifa_tstamp = jiffies;
	if (!ifa->ifa_cstamp)
		ifa->ifa_cstamp = ifa->ifa_tstamp;
}

static struct in_ifaddr *rtm_to_ifaddr(struct net *net, struct nlmsghdr *nlh,
				       __u32 *pvalid_lft, __u32 *pprefered_lft)
{
	struct nlattr *tb[IFA_MAX+1];
	struct in_ifaddr *ifa;
	struct ifaddrmsg *ifm;
	struct net_device *dev;
	struct in_device *in_dev;
	int err;

	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFA_MAX, ifa_ipv4_policy);
	if (err < 0)
		goto errout;

	ifm = nlmsg_data(nlh);
	err = -EINVAL;
	if (ifm->ifa_prefixlen > 32 || tb[IFA_LOCAL] == NULL)
		goto errout;

	dev = __dev_get_by_index(net, ifm->ifa_index);
	err = -ENODEV;
	if (dev == NULL)
		goto errout;

	in_dev = __in_dev_get_rtnl(dev);
	err = -ENOBUFS;
	if (in_dev == NULL)
		goto errout;

	ifa = inet_alloc_ifa();
	if (ifa == NULL)
		/*
		 * A potential indev allocation can be left alive, it stays
		 * assigned to its device and is destroy with it.
		 */
		goto errout;

	ipv4_devconf_setall(in_dev);
	neigh_parms_data_state_setall(in_dev->arp_parms);
	in_dev_hold(in_dev);

	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	INIT_HLIST_NODE(&ifa->hash);
	ifa->ifa_prefixlen = ifm->ifa_prefixlen;
	ifa->ifa_mask = inet_make_mask(ifm->ifa_prefixlen);
	ifa->ifa_flags = tb[IFA_FLAGS] ? nla_get_u32(tb[IFA_FLAGS]) :
					 ifm->ifa_flags;
	ifa->ifa_scope = ifm->ifa_scope;
	ifa->ifa_dev = in_dev;

	ifa->ifa_local = nla_get_be32(tb[IFA_LOCAL]);
	ifa->ifa_address = nla_get_be32(tb[IFA_ADDRESS]);

	if (tb[IFA_BROADCAST])
		ifa->ifa_broadcast = nla_get_be32(tb[IFA_BROADCAST]);

	if (tb[IFA_LABEL])
		nla_strlcpy(ifa->ifa_label, tb[IFA_LABEL], IFNAMSIZ);
	else
		memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);

	if (tb[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ci;

		ci = nla_data(tb[IFA_CACHEINFO]);
		if (!ci->ifa_valid || ci->ifa_prefered > ci->ifa_valid) {
			err = -EINVAL;
			goto errout_free;
		}
		*pvalid_lft = ci->ifa_valid;
		*pprefered_lft = ci->ifa_prefered;
	}

	return ifa;

errout_free:
	inet_free_ifa(ifa);
errout:
	return ERR_PTR(err);
}

static struct in_ifaddr *find_matching_ifa(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct in_ifaddr *ifa1, **ifap;

	if (!ifa->ifa_local)
		return NULL;

	for (ifap = &in_dev->ifa_list; (ifa1 = *ifap) != NULL;
	     ifap = &ifa1->ifa_next) {
		if (ifa1->ifa_mask == ifa->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, ifa) &&
		    ifa1->ifa_local == ifa->ifa_local)
			return ifa1;
	}
	return NULL;
}

static int inet_rtm_newaddr(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct in_ifaddr *ifa;
	struct in_ifaddr *ifa_existing;
	__u32 valid_lft = INFINITY_LIFE_TIME;
	__u32 prefered_lft = INFINITY_LIFE_TIME;

	ASSERT_RTNL();

	ifa = rtm_to_ifaddr(net, nlh, &valid_lft, &prefered_lft);
	if (IS_ERR(ifa))
		return PTR_ERR(ifa);

	ifa_existing = find_matching_ifa(ifa);
	if (!ifa_existing) {
		/* It would be best to check for !NLM_F_CREATE here but
		 * userspace already relies on not having to provide this.
		 */
		set_ifa_lifetime(ifa, valid_lft, prefered_lft);
		return __inet_insert_ifa(ifa, nlh, NETLINK_CB(skb).portid);
	} else {
		inet_free_ifa(ifa);

		if (nlh->nlmsg_flags & NLM_F_EXCL ||
		    !(nlh->nlmsg_flags & NLM_F_REPLACE))
			return -EEXIST;
		ifa = ifa_existing;
		set_ifa_lifetime(ifa, valid_lft, prefered_lft);
		cancel_delayed_work(&check_lifetime_work);
		queue_delayed_work(system_power_efficient_wq,
				&check_lifetime_work, 0);
		rtmsg_ifa(RTM_NEWADDR, ifa, nlh, NETLINK_CB(skb).portid);
		blocking_notifier_call_chain(&inetaddr_chain, NETDEV_UP, ifa);
	}
	return 0;
}

/*
 *	Determine a default network mask, based on the IP address.
 */
/*
  * inet_abc_len()根据指定的IP地址获取默认掩码
  * 长度。默认掩码长度表:
  * ------------------------------------------
  * 地址			默认掩码长度
  * ------------------------------------------
  * 0地址				0
  * A类地址				8
  * B类地址				16
  * C类地址				24
  */
static int inet_abc_len(__be32 addr)
{
	int rc = -1;	/* Something else, probably a multicast. */

	if (ipv4_is_zeronet(addr))
		rc = 0;
	else {
		__u32 haddr = ntohl(addr);

		if (IN_CLASSA(haddr))
			rc = 8;
		else if (IN_CLASSB(haddr))
			rc = 16;
		else if (IN_CLASSC(haddr))
			rc = 24;
	}

	return rc;
}

 /*
  * 应用程序对套接字有关接口层地址的ioctl操作，
  * 最终由devinet_ioctl()来处理
  */
int devinet_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	struct ifreq ifr;
	struct sockaddr_in sin_orig;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	struct in_device *in_dev;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	struct net_device *dev;
	char *colon;
	int ret = -EFAULT;
	int tryaddrmatch = 0;

	/*
	 *	Fetch the caller's info block into kernel space
	 */

	 /*
	  * 从用户空间复制配置参数
	  */
	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		goto out;
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	/* save original address for comparison */
	 /*
	  * 将原始的配置参数保存起来，用于
	  * 后续的比较操作。
	  */
	memcpy(&sin_orig, sin, sizeof(*sin));

	 /*
	  * 配置的设备名中如果存在":"，则表示
	  * 配置了别名。由于需要根据名称操作，
	  * 因此先将该设备名截断，后续再恢复
	  */
	colon = strchr(ifr.ifr_name, ':');
	if (colon)
		*colon = 0;

	 /*
	  * 根据网络设备名，记载相应的设备驱动
	  * 模块
	  */
	dev_load(net, ifr.ifr_name);

	 /*
	  * 进行相关校验。对于获取操作，则检测
	  * 地址族是否为AF_INET；对于设置操作，
	  * 则必须要有相应的特权；而对于SIOCSIFADDR、
	  * SIOCSIFBRDADDR、SIOCSIFDSTADDR和SIOCSIFNETMASK操作，
	  * 地址族也必须是AF_INET。
	  */
	switch (cmd) {
	case SIOCGIFADDR:	/* Get interface address */
	case SIOCGIFBRDADDR:	/* Get the broadcast address */
	case SIOCGIFDSTADDR:	/* Get the destination address */
	case SIOCGIFNETMASK:	/* Get the netmask for the interface */
		/* Note that these ioctls will not sleep,
		   so that we do not impose a lock.
		   One day we will be forced to put shlock here (I mean SMP)
		 */
		tryaddrmatch = (sin_orig.sin_family == AF_INET);
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		break;

	case SIOCSIFFLAGS:
		ret = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			goto out;
		break;
	case SIOCSIFADDR:	/* Set interface address (and family) */
	case SIOCSIFBRDADDR:	/* Set the broadcast address */
	case SIOCSIFDSTADDR:	/* Set the destination address */
	case SIOCSIFNETMASK: 	/* Set the netmask for the interface */
		ret = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			goto out;
		ret = -EINVAL;
		if (sin->sin_family != AF_INET)
			goto out;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	rtnl_lock();

	ret = -ENODEV;
	 /*
	  * 根据网络设备名获取网络设备
	  */
	dev = __dev_get_by_name(net, ifr.ifr_name);
	if (!dev)
		goto done;

	 /*
	  * 恢复配置参数中的标签别名
	  */
	if (colon)
		*colon = ':';

	 /*
	  * 取IP配置块，及用户地址标签对应的设备地址
	  * 结构
	  */
	in_dev = __in_dev_get_rtnl(dev);
	if (in_dev) {
		if (tryaddrmatch) {
			/* Matthias Andree */
			/* compare label and address (4.4BSD style) */
			/* note: we only do this for a limited set of ioctls
			   and only if the original address family was AF_INET.
			   This is checked above. */
			for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
			     ifap = &ifa->ifa_next) {
				if (!strcmp(ifr.ifr_name, ifa->ifa_label) &&
				    sin_orig.sin_addr.s_addr ==
							ifa->ifa_local) {
					break; /* found */
				}
			}
		}
		/* we didn't get a match, maybe the application is
		   4.3BSD-style and passed in junk so we fall back to
		   comparing just the label */
		if (!ifa) {
			for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
			     ifap = &ifa->ifa_next)
				if (!strcmp(ifr.ifr_name, ifa->ifa_label))
					break;
		}
	}

	 /*
	  * 设置地址和标志。SIOCSIFFLAGS是设置网络设备
	  * 的标志，SIOCSIFADDR是添加IP地址，这两个操作
	  * 不针对现有的IP地址块。而其他操作
	  * ，如SIOCGIFBRDADDR，都是针对现有的IP地址块，如果
	  * 不存在与配置参数中的标签或地址匹配的IP
	  * 地址块，则不能继续操作。
	  */
	ret = -EADDRNOTAVAIL;
	if (!ifa && cmd != SIOCSIFADDR && cmd != SIOCSIFFLAGS)
		goto done;

	 /*
	  * 针对具体的命令进行操作。
	  */
	switch (cmd) {
	 /*
	  * 获取指定网络设备的本地IP地址
	  */
	case SIOCGIFADDR:	/* Get interface address */
		sin->sin_addr.s_addr = ifa->ifa_local;
		goto rarok;

	 /*
	  * 获取指定网络设备的组播地址
	  */
	case SIOCGIFBRDADDR:	/* Get the broadcast address */
		sin->sin_addr.s_addr = ifa->ifa_broadcast;
		goto rarok;

	 /*
	  * 在点对点连接的情况下，获取指定
	  * 网络设备点对点对端的IP地址
	  */
	case SIOCGIFDSTADDR:	/* Get the destination address */
		sin->sin_addr.s_addr = ifa->ifa_address;
		goto rarok;

	 /*
	  * 获取指定网络设备的地址掩码
	  */
	case SIOCGIFNETMASK:	/* Get the netmask for the interface */
		sin->sin_addr.s_addr = ifa->ifa_mask;
		goto rarok;

	 /*
	  * 获取网络设备的标志
	  */
	case SIOCSIFFLAGS:
		 /*
		  * 对于关闭网络设备，如果指定了网络
		  * 设备别名，并且存在与之对应的
		  * IP地址块，则需要删除释放该IP地址块
		  */
		if (colon) {
			ret = -EADDRNOTAVAIL;
			if (!ifa)
				break;
			ret = 0;
			if (!(ifr.ifr_flags & IFF_UP))
				inet_del_ifa(in_dev, ifap, 1);
			break;
		}
		 /*
		  * 将地址设置到网络设备中。
		  */
		ret = dev_change_flags(dev, ifr.ifr_flags);
		break;

	 /*
	  * 设置指定网络设备的本地地址
	  */
	case SIOCSIFADDR:	/* Set interface address (and family) */
		ret = -EINVAL;
		 /*
		  * 根据本地地址默认的掩码长度，校验
		  * 本地地址的有效性
		  */
		if (inet_abc_len(sin->sin_addr.s_addr) < 0)
			break;

		 /*
		  * 如果尚未分配IP地址块，则进行分配，
		  * 并将网络设备别名或网络设备名
		  * 设置到地址标签中
		  */
		if (!ifa) {
			ret = -ENOBUFS;
			ifa = inet_alloc_ifa();
			if (!ifa)
				break;
			INIT_HLIST_NODE(&ifa->hash);
			if (colon)
				memcpy(ifa->ifa_label, ifr.ifr_name, IFNAMSIZ);
			else
				memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
		} else {
			ret = 0;
			if (ifa->ifa_local == sin->sin_addr.s_addr)
				break;
			 /*
			  * 首先将对应的IP地址块从地址列表
			  * 中删除
			  */
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_broadcast = 0;
			ifa->ifa_scope = 0;
		}

		 /*
		  * 然后设置本地IP地址
		  */
		ifa->ifa_address = ifa->ifa_local = sin->sin_addr.s_addr;

		 /*
		  * 接着根据接口是否为点对点设备，来设置
		  * 子网掩码长度和子网掩码。如果是非点对点
		  * 设备，则根据地址的掩码长度和网络掩码
		  * 设置标准广播地址；否则网络掩码长度为32.
		  * 
		  */
		if (!(dev->flags & IFF_POINTOPOINT)) {
			ifa->ifa_prefixlen = inet_abc_len(ifa->ifa_address);
			ifa->ifa_mask = inet_make_mask(ifa->ifa_prefixlen);
			if ((dev->flags & IFF_BROADCAST) &&
			    ifa->ifa_prefixlen < 31)
				ifa->ifa_broadcast = ifa->ifa_address |
						     ~ifa->ifa_mask;
		} else {
			ifa->ifa_prefixlen = 32;
			ifa->ifa_mask = inet_make_mask(32);
		}
		set_ifa_lifetime(ifa, INFINITY_LIFE_TIME, INFINITY_LIFE_TIME);
		 /*
		  * 最后将配置信息再添加到IP地址块列表中
		  */
		ret = inet_set_ifa(dev, ifa);
		break;

	 /*
	  * 设置指定网络设备的组播地址
	  */
	case SIOCSIFBRDADDR:	/* Set the broadcast address */
		ret = 0;
		 /*
		  * 如果原有的组播地址与待设置的
		  * 组播地址不等，则先得将对应
		  * IP地址块从地址列表中删除，
		  * 然后再将配置信息添加到
		  * IP地址块列表中
		  */
		if (ifa->ifa_broadcast != sin->sin_addr.s_addr) {
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_broadcast = sin->sin_addr.s_addr;
			inet_insert_ifa(ifa);
		}
		break;

	 /*
	  * 在点对点连接的情况下，设置指定
	  * 网络设备点对点对端的IP地址
	  */
	case SIOCSIFDSTADDR:	/* Set the destination address */
		ret = 0;
		 /*
		  * 只有当原有的网络设备点对点
		  * 对端IP地址与待设置的地址不等时，
		  * 才有必要进行设置。
		  */
		if (ifa->ifa_address == sin->sin_addr.s_addr)
			break;
		ret = -EINVAL;
		 /*
		  * 校验待设置的IP地址是否有效
		  */
		if (inet_abc_len(sin->sin_addr.s_addr) < 0)
			break;
		ret = 0;
		 /*
		  * 先将对应IP地址块从地址列表删除，
		  * 然后再将待设置的IP地址设置到
		  * IP地址块中并添加到IP地址块列表
		  */
		inet_del_ifa(in_dev, ifap, 0);
		ifa->ifa_address = sin->sin_addr.s_addr;
		inet_insert_ifa(ifa);
		break;

	 /*
	  * 设置指定网络设备的地址掩码
	  */
	case SIOCSIFNETMASK: 	/* Set the netmask for the interface */

		/*
		 *	The mask we set must be legal.
		 */
		ret = -EINVAL;
		 /*
		  * 检测待设置的掩码是否有效。
		  */
		if (bad_mask(sin->sin_addr.s_addr, 0))
			break;
		ret = 0;
		 /*
		  * 原有的掩码与待设置的掩码不等时，
		  * 才有必要进行设置。
		  */
		if (ifa->ifa_mask != sin->sin_addr.s_addr) {
			__be32 old_mask = ifa->ifa_mask;
			 /*
			  * 先将对应IP地址块从地址列表中
			  * 删除，接着如果目前的广播地址
			  * 与当前的网络掩码匹配时，则
			  * 重新计算广播地址，最后将其
			  * 设置到IP地址块中，并添加到
			  * IP地址块列表中。
			  */
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_mask = sin->sin_addr.s_addr;
			ifa->ifa_prefixlen = inet_mask_len(ifa->ifa_mask);

			/* See if current broadcast address matches
			 * with current netmask, then recalculate
			 * the broadcast address. Otherwise it's a
			 * funny address, so don't touch it since
			 * the user seems to know what (s)he's doing...
			 */
			if ((dev->flags & IFF_BROADCAST) &&
			    (ifa->ifa_prefixlen < 31) &&
			    (ifa->ifa_broadcast ==
			     (ifa->ifa_local|~old_mask))) {
				ifa->ifa_broadcast = (ifa->ifa_local |
						      ~sin->sin_addr.s_addr);
			}
			inet_insert_ifa(ifa);
		}
		break;
	}
done:
	rtnl_unlock();
out:
	return ret;
rarok:
	rtnl_unlock();
	ret = copy_to_user(arg, &ifr, sizeof(struct ifreq)) ? -EFAULT : 0;
	goto out;
}

static int inet_gifconf(struct net_device *dev, char __user *buf, int len)
{
	struct in_device *in_dev = __in_dev_get_rtnl(dev);
	struct in_ifaddr *ifa;
	struct ifreq ifr;
	int done = 0;

	if (!in_dev)
		goto out;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		if (!buf) {
			done += sizeof(ifr);
			continue;
		}
		if (len < (int) sizeof(ifr))
			break;
		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifa->ifa_label);

		(*(struct sockaddr_in *)&ifr.ifr_addr).sin_family = AF_INET;
		(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr =
								ifa->ifa_local;

		if (copy_to_user(buf, &ifr, sizeof(struct ifreq))) {
			done = -EFAULT;
			break;
		}
		buf  += sizeof(struct ifreq);
		len  -= sizeof(struct ifreq);
		done += sizeof(struct ifreq);
	}
out:
	return done;
}

/*
  * 在通过输出网络设备向目的地址发送报文时，如果
  * 没有指定源地址，会调用inet_select_addr()来根据给定设备、
  * 目的地址和作用范围，获取给定作用范围内的主IP
  * 地址作为源地址
  * @dev:获取源地址的网络设备
  * @dst:发送报文的目的地址。不为0，返回与目的地址
  *          在同一子网的IP地址(输出网络设备上配置的不同
  *           地址属于不同子网)。等于0，返回本地地址。
  * @scope:地址作用的范围。为RT_SCOPE_HOST时，表示当报文被
  *             送往本地；为RT_SCOPE_LINK，表示报文被送给只在
  *             本地链路上有意义的地址，诸如广播、受限
  *             广播和本地组播；为RT_SCOPE_UNIVERSE，表示当
  *             报文发送到通往远程非直连目的地
  */
__be32 inet_select_addr(const struct net_device *dev, __be32 dst, int scope)
{
	__be32 addr = 0;
	struct in_device *in_dev;
	struct net *net = dev_net(dev);

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		goto no_in_dev;

	/*
	  * 先检测该网络设备上IPv4配置块是否有效，
	  * 通过检测后遍历IPv4配置块的本地IP地址列表，
	  * 获取第一个满足条件(如scope和dst)的本地地址。
	  */
	for_primary_ifa(in_dev) {
		if (ifa->ifa_scope > scope)
			continue;
		if (!dst || inet_ifa_match(dst, ifa)) {
			addr = ifa->ifa_local;
			break;
		}
		if (!addr)
			addr = ifa->ifa_local;
	} endfor_ifa(in_dev);

	/*
	  * 如果获得满足条件的地址，则将其返回
	  */
	if (addr)
		goto out_unlock;
no_in_dev:

	/* Not loopback addresses on loopback should be preferred
	   in this case. It is importnat that lo is the first interface
	   in dev_base list.
	 */
	/*
	  * 如果给定配置的地址都不满足由scope和dst限定
	  * 的条件，则尝试其他设备是否满足所要求的
	  * scope的一个IP地址。
	  */
	for_each_netdev_rcu(net, dev) {
		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

		for_primary_ifa(in_dev) {
			if (ifa->ifa_scope != RT_SCOPE_LINK &&
			    ifa->ifa_scope <= scope) {
				addr = ifa->ifa_local;
				goto out_unlock;
			}
		} endfor_ifa(in_dev);
	}
out_unlock:
	rcu_read_unlock();
	return addr;
}
EXPORT_SYMBOL(inet_select_addr);

static __be32 confirm_addr_indev(struct in_device *in_dev, __be32 dst,
			      __be32 local, int scope)
{
	int same = 0;
	__be32 addr = 0;

	for_ifa(in_dev) {
		if (!addr &&
		    (local == ifa->ifa_local || !local) &&
		    ifa->ifa_scope <= scope) {
			addr = ifa->ifa_local;
			if (same)
				break;
		}
		if (!same) {
			same = (!local || inet_ifa_match(local, ifa)) &&
				(!dst || inet_ifa_match(dst, ifa));
			if (same && addr) {
				if (local || !dst)
					break;
				/* Is the selected addr into dst subnet? */
				if (inet_ifa_match(addr, ifa))
					break;
				/* No, then can we use new local src? */
				if (ifa->ifa_scope <= scope) {
					addr = ifa->ifa_local;
					break;
				}
				/* search for large dst subnet for addr */
				same = 0;
			}
		}
	} endfor_ifa(in_dev);

	return same ? addr : 0;
}

/*
 * Confirm that local IP address exists using wildcards:
 * - net: netns to check, cannot be NULL
 * - in_dev: only on this interface, NULL=any interface
 * - dst: only in the same subnet as dst, 0=any dst
 * - local: address, 0=autoselect the local address
 * - scope: maximum allowed scope value for the local address
 */
/*
  * 用来确认参数中指定的本地地址是否
  * 存在。
  * @in_dev:用来确定是否在指定本地地址的
  *          IP配置块，如果为NULL，则表示
  *          在所有的网络设备上确认本地地址
  * @dst:目的IP地址，当其不为0时，则待确定
  *          的本地地址必须与该地址在同一子网
  *          内。
  * @local:待确认的本地地址，当其为0时，则自动
  *           选择一个本地地址
  * @scope:确认本地地址时允许的最大范围。
  */
__be32 inet_confirm_addr(struct net *net, struct in_device *in_dev,
			 __be32 dst, __be32 local, int scope)
{
	__be32 addr = 0;
	struct net_device *dev;

	if (in_dev != NULL)
	/*
	  * 如果指定IP配置块，则在该IP配置块
	  * 所属的网络设备上
	  * 确认本地IP地址。确认过程如下:
	  * 调用confirm_addr_indev()在指定的IP配置块上
	  * 查找与参数local给出的IP地址相同，
	  * 与参数dst给出的IP地址在相同子网内，
	  * 且范围小于scope的本地地址。
	  */
		return confirm_addr_indev(in_dev, dst, local, scope);

	rcu_read_lock();
	/*
	  * 当没有指定IP配置块时，则在所有的网络
	  * 设备上确认本地IP地址。
	  */
	for_each_netdev_rcu(net, dev) {
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev) {
			addr = confirm_addr_indev(in_dev, dst, local, scope);
			if (addr)
				break;
		}
	}
	rcu_read_unlock();

	return addr;
}
EXPORT_SYMBOL(inet_confirm_addr);

/*
 *	Device notifier
 */

int register_inetaddr_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&inetaddr_chain, nb);
}
EXPORT_SYMBOL(register_inetaddr_notifier);

int unregister_inetaddr_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&inetaddr_chain, nb);
}
EXPORT_SYMBOL(unregister_inetaddr_notifier);

/* Rename ifa_labels for a device name change. Make some effort to preserve
 * existing alias numbering and to create unique labels if possible.
*/
static void inetdev_changename(struct net_device *dev, struct in_device *in_dev)
{
	struct in_ifaddr *ifa;
	int named = 0;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		char old[IFNAMSIZ], *dot;

		memcpy(old, ifa->ifa_label, IFNAMSIZ);
		memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
		if (named++ == 0)
			goto skip;
		dot = strchr(old, ':');
		if (dot == NULL) {
			sprintf(old, ":%d", named);
			dot = old;
		}
		if (strlen(dot) + strlen(dev->name) < IFNAMSIZ)
			strcat(ifa->ifa_label, dot);
		else
			strcpy(ifa->ifa_label + (IFNAMSIZ - strlen(dot) - 1), dot);
skip:
		rtmsg_ifa(RTM_NEWADDR, ifa, NULL, 0);
	}
}

static bool inetdev_valid_mtu(unsigned int mtu)
{
	return mtu >= IPV4_MIN_MTU;
}

static void inetdev_send_gratuitous_arp(struct net_device *dev,
					struct in_device *in_dev)

{
	struct in_ifaddr *ifa;

	for (ifa = in_dev->ifa_list; ifa;
	     ifa = ifa->ifa_next) {
		arp_send(ARPOP_REQUEST, ETH_P_ARP,
			 ifa->ifa_local, dev,
			 ifa->ifa_local, NULL,
			 dev->dev_addr, NULL);
	}
}

/* Called only under RTNL semaphore */

static int inetdev_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev = __in_dev_get_rtnl(dev);

	ASSERT_RTNL();

	if (!in_dev) {
		if (event == NETDEV_REGISTER) {
			in_dev = inetdev_init(dev);
			if (IS_ERR(in_dev))
				return notifier_from_errno(PTR_ERR(in_dev));
			if (dev->flags & IFF_LOOPBACK) {
				IN_DEV_CONF_SET(in_dev, NOXFRM, 1);
				IN_DEV_CONF_SET(in_dev, NOPOLICY, 1);
			}
		} else if (event == NETDEV_CHANGEMTU) {
			/* Re-enabling IP */
			if (inetdev_valid_mtu(dev->mtu))
				in_dev = inetdev_init(dev);
		}
		goto out;
	}

	switch (event) {
	case NETDEV_REGISTER:
		pr_debug("%s: bug\n", __func__);
		RCU_INIT_POINTER(dev->ip_ptr, NULL);
		break;
	case NETDEV_UP:
		if (!inetdev_valid_mtu(dev->mtu))
			break;
		if (dev->flags & IFF_LOOPBACK) {
			struct in_ifaddr *ifa = inet_alloc_ifa();

			if (ifa) {
				INIT_HLIST_NODE(&ifa->hash);
				ifa->ifa_local =
				  ifa->ifa_address = htonl(INADDR_LOOPBACK);
				ifa->ifa_prefixlen = 8;
				ifa->ifa_mask = inet_make_mask(8);
				in_dev_hold(in_dev);
				ifa->ifa_dev = in_dev;
				ifa->ifa_scope = RT_SCOPE_HOST;
				memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
				set_ifa_lifetime(ifa, INFINITY_LIFE_TIME,
						 INFINITY_LIFE_TIME);
				ipv4_devconf_setall(in_dev);
				neigh_parms_data_state_setall(in_dev->arp_parms);
				inet_insert_ifa(ifa);
			}
		}
		ip_mc_up(in_dev);
		/* fall through */
	case NETDEV_CHANGEADDR:
		if (!IN_DEV_ARP_NOTIFY(in_dev))
			break;
		/* fall through */
	case NETDEV_NOTIFY_PEERS:
		/* Send gratuitous ARP to notify of link change */
		inetdev_send_gratuitous_arp(dev, in_dev);
		break;
	case NETDEV_DOWN:
		ip_mc_down(in_dev);
		break;
	case NETDEV_PRE_TYPE_CHANGE:
		ip_mc_unmap(in_dev);
		break;
	case NETDEV_POST_TYPE_CHANGE:
		ip_mc_remap(in_dev);
		break;
	case NETDEV_CHANGEMTU:
		if (inetdev_valid_mtu(dev->mtu))
			break;
		/* disable IP when MTU is not enough */
	case NETDEV_UNREGISTER:
		inetdev_destroy(in_dev);
		break;
	case NETDEV_CHANGENAME:
		/* Do not notify about label change, this event is
		 * not interesting to applications using netlink.
		 */
		inetdev_changename(dev, in_dev);

		devinet_sysctl_unregister(in_dev);
		devinet_sysctl_register(in_dev);
		break;
	}
out:
	return NOTIFY_DONE;
}

static struct notifier_block ip_netdev_notifier = {
	.notifier_call = inetdev_event,
};

static size_t inet_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ifaddrmsg))
	       + nla_total_size(4) /* IFA_ADDRESS */
	       + nla_total_size(4) /* IFA_LOCAL */
	       + nla_total_size(4) /* IFA_BROADCAST */
	       + nla_total_size(IFNAMSIZ) /* IFA_LABEL */
	       + nla_total_size(4)  /* IFA_FLAGS */
	       + nla_total_size(sizeof(struct ifa_cacheinfo)); /* IFA_CACHEINFO */
}

static inline u32 cstamp_delta(unsigned long cstamp)
{
	return (cstamp - INITIAL_JIFFIES) * 100UL / HZ;
}

static int put_cacheinfo(struct sk_buff *skb, unsigned long cstamp,
			 unsigned long tstamp, u32 preferred, u32 valid)
{
	struct ifa_cacheinfo ci;

	ci.cstamp = cstamp_delta(cstamp);
	ci.tstamp = cstamp_delta(tstamp);
	ci.ifa_prefered = preferred;
	ci.ifa_valid = valid;

	return nla_put(skb, IFA_CACHEINFO, sizeof(ci), &ci);
}

static int inet_fill_ifaddr(struct sk_buff *skb, struct in_ifaddr *ifa,
			    u32 portid, u32 seq, int event, unsigned int flags)
{
	struct ifaddrmsg *ifm;
	struct nlmsghdr  *nlh;
	u32 preferred, valid;

	nlh = nlmsg_put(skb, portid, seq, event, sizeof(*ifm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ifm = nlmsg_data(nlh);
	ifm->ifa_family = AF_INET;
	ifm->ifa_prefixlen = ifa->ifa_prefixlen;
	ifm->ifa_flags = ifa->ifa_flags;
	ifm->ifa_scope = ifa->ifa_scope;
	ifm->ifa_index = ifa->ifa_dev->dev->ifindex;

	if (!(ifm->ifa_flags & IFA_F_PERMANENT)) {
		preferred = ifa->ifa_preferred_lft;
		valid = ifa->ifa_valid_lft;
		if (preferred != INFINITY_LIFE_TIME) {
			long tval = (jiffies - ifa->ifa_tstamp) / HZ;

			if (preferred > tval)
				preferred -= tval;
			else
				preferred = 0;
			if (valid != INFINITY_LIFE_TIME) {
				if (valid > tval)
					valid -= tval;
				else
					valid = 0;
			}
		}
	} else {
		preferred = INFINITY_LIFE_TIME;
		valid = INFINITY_LIFE_TIME;
	}
	if ((ifa->ifa_address &&
	     nla_put_be32(skb, IFA_ADDRESS, ifa->ifa_address)) ||
	    (ifa->ifa_local &&
	     nla_put_be32(skb, IFA_LOCAL, ifa->ifa_local)) ||
	    (ifa->ifa_broadcast &&
	     nla_put_be32(skb, IFA_BROADCAST, ifa->ifa_broadcast)) ||
	    (ifa->ifa_label[0] &&
	     nla_put_string(skb, IFA_LABEL, ifa->ifa_label)) ||
	    nla_put_u32(skb, IFA_FLAGS, ifa->ifa_flags) ||
	    put_cacheinfo(skb, ifa->ifa_cstamp, ifa->ifa_tstamp,
			  preferred, valid))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int inet_dump_ifaddr(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int h, s_h;
	int idx, s_idx;
	int ip_idx, s_ip_idx;
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct hlist_head *head;

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];
	s_ip_idx = ip_idx = cb->args[2];

	for (h = s_h; h < NETDEV_HASHENTRIES; h++, s_idx = 0) {
		idx = 0;
		head = &net->dev_index_head[h];
		rcu_read_lock();
		cb->seq = atomic_read(&net->ipv4.dev_addr_genid) ^
			  net->dev_base_seq;
		hlist_for_each_entry_rcu(dev, head, index_hlist) {
			if (idx < s_idx)
				goto cont;
			if (h > s_h || idx > s_idx)
				s_ip_idx = 0;
			in_dev = __in_dev_get_rcu(dev);
			if (!in_dev)
				goto cont;

			for (ifa = in_dev->ifa_list, ip_idx = 0; ifa;
			     ifa = ifa->ifa_next, ip_idx++) {
				if (ip_idx < s_ip_idx)
					continue;
				if (inet_fill_ifaddr(skb, ifa,
					     NETLINK_CB(cb->skb).portid,
					     cb->nlh->nlmsg_seq,
					     RTM_NEWADDR, NLM_F_MULTI) <= 0) {
					rcu_read_unlock();
					goto done;
				}
				nl_dump_check_consistent(cb, nlmsg_hdr(skb));
			}
cont:
			idx++;
		}
		rcu_read_unlock();
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	cb->args[2] = ip_idx;

	return skb->len;
}

static void rtmsg_ifa(int event, struct in_ifaddr *ifa, struct nlmsghdr *nlh,
		      u32 portid)
{
	struct sk_buff *skb;
	u32 seq = nlh ? nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;
	struct net *net;

	net = dev_net(ifa->ifa_dev->dev);
	skb = nlmsg_new(inet_nlmsg_size(), GFP_KERNEL);
	if (skb == NULL)
		goto errout;

	err = inet_fill_ifaddr(skb, ifa, portid, seq, event, 0);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in inet_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, portid, RTNLGRP_IPV4_IFADDR, nlh, GFP_KERNEL);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_IPV4_IFADDR, err);
}

static size_t inet_get_link_af_size(const struct net_device *dev)
{
	struct in_device *in_dev = rcu_dereference_rtnl(dev->ip_ptr);

	if (!in_dev)
		return 0;

	return nla_total_size(IPV4_DEVCONF_MAX * 4); /* IFLA_INET_CONF */
}

static int inet_fill_link_af(struct sk_buff *skb, const struct net_device *dev)
{
	struct in_device *in_dev = rcu_dereference_rtnl(dev->ip_ptr);
	struct nlattr *nla;
	int i;

	if (!in_dev)
		return -ENODATA;

	nla = nla_reserve(skb, IFLA_INET_CONF, IPV4_DEVCONF_MAX * 4);
	if (nla == NULL)
		return -EMSGSIZE;

	for (i = 0; i < IPV4_DEVCONF_MAX; i++)
		((u32 *) nla_data(nla))[i] = in_dev->cnf.data[i];

	return 0;
}

static const struct nla_policy inet_af_policy[IFLA_INET_MAX+1] = {
	[IFLA_INET_CONF]	= { .type = NLA_NESTED },
};

static int inet_validate_link_af(const struct net_device *dev,
				 const struct nlattr *nla)
{
	struct nlattr *a, *tb[IFLA_INET_MAX+1];
	int err, rem;

	if (dev && !__in_dev_get_rtnl(dev))
		return -EAFNOSUPPORT;

	err = nla_parse_nested(tb, IFLA_INET_MAX, nla, inet_af_policy);
	if (err < 0)
		return err;

	if (tb[IFLA_INET_CONF]) {
		nla_for_each_nested(a, tb[IFLA_INET_CONF], rem) {
			int cfgid = nla_type(a);

			if (nla_len(a) < 4)
				return -EINVAL;

			if (cfgid <= 0 || cfgid > IPV4_DEVCONF_MAX)
				return -EINVAL;
		}
	}

	return 0;
}

static int inet_set_link_af(struct net_device *dev, const struct nlattr *nla)
{
	struct in_device *in_dev = __in_dev_get_rtnl(dev);
	struct nlattr *a, *tb[IFLA_INET_MAX+1];
	int rem;

	if (!in_dev)
		return -EAFNOSUPPORT;

	if (nla_parse_nested(tb, IFLA_INET_MAX, nla, NULL) < 0)
		BUG();

	if (tb[IFLA_INET_CONF]) {
		nla_for_each_nested(a, tb[IFLA_INET_CONF], rem)
			ipv4_devconf_set(in_dev, nla_type(a), nla_get_u32(a));
	}

	return 0;
}

static int inet_netconf_msgsize_devconf(int type)
{
	int size = NLMSG_ALIGN(sizeof(struct netconfmsg))
		   + nla_total_size(4);	/* NETCONFA_IFINDEX */

	/* type -1 is used for ALL */
	if (type == -1 || type == NETCONFA_FORWARDING)
		size += nla_total_size(4);
	if (type == -1 || type == NETCONFA_RP_FILTER)
		size += nla_total_size(4);
	if (type == -1 || type == NETCONFA_MC_FORWARDING)
		size += nla_total_size(4);
	if (type == -1 || type == NETCONFA_PROXY_NEIGH)
		size += nla_total_size(4);

	return size;
}

static int inet_netconf_fill_devconf(struct sk_buff *skb, int ifindex,
				     struct ipv4_devconf *devconf, u32 portid,
				     u32 seq, int event, unsigned int flags,
				     int type)
{
	struct nlmsghdr  *nlh;
	struct netconfmsg *ncm;

	nlh = nlmsg_put(skb, portid, seq, event, sizeof(struct netconfmsg),
			flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ncm = nlmsg_data(nlh);
	ncm->ncm_family = AF_INET;

	if (nla_put_s32(skb, NETCONFA_IFINDEX, ifindex) < 0)
		goto nla_put_failure;

	/* type -1 is used for ALL */
	if ((type == -1 || type == NETCONFA_FORWARDING) &&
	    nla_put_s32(skb, NETCONFA_FORWARDING,
			IPV4_DEVCONF(*devconf, FORWARDING)) < 0)
		goto nla_put_failure;
	if ((type == -1 || type == NETCONFA_RP_FILTER) &&
	    nla_put_s32(skb, NETCONFA_RP_FILTER,
			IPV4_DEVCONF(*devconf, RP_FILTER)) < 0)
		goto nla_put_failure;
	if ((type == -1 || type == NETCONFA_MC_FORWARDING) &&
	    nla_put_s32(skb, NETCONFA_MC_FORWARDING,
			IPV4_DEVCONF(*devconf, MC_FORWARDING)) < 0)
		goto nla_put_failure;
	if ((type == -1 || type == NETCONFA_PROXY_NEIGH) &&
	    nla_put_s32(skb, NETCONFA_PROXY_NEIGH,
			IPV4_DEVCONF(*devconf, PROXY_ARP)) < 0)
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

void inet_netconf_notify_devconf(struct net *net, int type, int ifindex,
				 struct ipv4_devconf *devconf)
{
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(inet_netconf_msgsize_devconf(type), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = inet_netconf_fill_devconf(skb, ifindex, devconf, 0, 0,
					RTM_NEWNETCONF, 0, type);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in inet_netconf_msgsize_devconf() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_IPV4_NETCONF, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_IPV4_NETCONF, err);
}

static const struct nla_policy devconf_ipv4_policy[NETCONFA_MAX+1] = {
	[NETCONFA_IFINDEX]	= { .len = sizeof(int) },
	[NETCONFA_FORWARDING]	= { .len = sizeof(int) },
	[NETCONFA_RP_FILTER]	= { .len = sizeof(int) },
	[NETCONFA_PROXY_NEIGH]	= { .len = sizeof(int) },
};

static int inet_netconf_get_devconf(struct sk_buff *in_skb,
				    struct nlmsghdr *nlh)
{
	struct net *net = sock_net(in_skb->sk);
	struct nlattr *tb[NETCONFA_MAX+1];
	struct netconfmsg *ncm;
	struct sk_buff *skb;
	struct ipv4_devconf *devconf;
	struct in_device *in_dev;
	struct net_device *dev;
	int ifindex;
	int err;

	err = nlmsg_parse(nlh, sizeof(*ncm), tb, NETCONFA_MAX,
			  devconf_ipv4_policy);
	if (err < 0)
		goto errout;

	err = EINVAL;
	if (!tb[NETCONFA_IFINDEX])
		goto errout;

	ifindex = nla_get_s32(tb[NETCONFA_IFINDEX]);
	switch (ifindex) {
	case NETCONFA_IFINDEX_ALL:
		devconf = net->ipv4.devconf_all;
		break;
	case NETCONFA_IFINDEX_DEFAULT:
		devconf = net->ipv4.devconf_dflt;
		break;
	default:
		dev = __dev_get_by_index(net, ifindex);
		if (dev == NULL)
			goto errout;
		in_dev = __in_dev_get_rtnl(dev);
		if (in_dev == NULL)
			goto errout;
		devconf = &in_dev->cnf;
		break;
	}

	err = -ENOBUFS;
	skb = nlmsg_new(inet_netconf_msgsize_devconf(-1), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = inet_netconf_fill_devconf(skb, ifindex, devconf,
					NETLINK_CB(in_skb).portid,
					nlh->nlmsg_seq, RTM_NEWNETCONF, 0,
					-1);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in inet_netconf_msgsize_devconf() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	err = rtnl_unicast(skb, net, NETLINK_CB(in_skb).portid);
errout:
	return err;
}

static int inet_netconf_dump_devconf(struct sk_buff *skb,
				     struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int h, s_h;
	int idx, s_idx;
	struct net_device *dev;
	struct in_device *in_dev;
	struct hlist_head *head;

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];

	for (h = s_h; h < NETDEV_HASHENTRIES; h++, s_idx = 0) {
		idx = 0;
		head = &net->dev_index_head[h];
		rcu_read_lock();
		cb->seq = atomic_read(&net->ipv4.dev_addr_genid) ^
			  net->dev_base_seq;
		hlist_for_each_entry_rcu(dev, head, index_hlist) {
			if (idx < s_idx)
				goto cont;
			in_dev = __in_dev_get_rcu(dev);
			if (!in_dev)
				goto cont;

			if (inet_netconf_fill_devconf(skb, dev->ifindex,
						      &in_dev->cnf,
						      NETLINK_CB(cb->skb).portid,
						      cb->nlh->nlmsg_seq,
						      RTM_NEWNETCONF,
						      NLM_F_MULTI,
						      -1) <= 0) {
				rcu_read_unlock();
				goto done;
			}
			nl_dump_check_consistent(cb, nlmsg_hdr(skb));
cont:
			idx++;
		}
		rcu_read_unlock();
	}
	if (h == NETDEV_HASHENTRIES) {
		if (inet_netconf_fill_devconf(skb, NETCONFA_IFINDEX_ALL,
					      net->ipv4.devconf_all,
					      NETLINK_CB(cb->skb).portid,
					      cb->nlh->nlmsg_seq,
					      RTM_NEWNETCONF, NLM_F_MULTI,
					      -1) <= 0)
			goto done;
		else
			h++;
	}
	if (h == NETDEV_HASHENTRIES + 1) {
		if (inet_netconf_fill_devconf(skb, NETCONFA_IFINDEX_DEFAULT,
					      net->ipv4.devconf_dflt,
					      NETLINK_CB(cb->skb).portid,
					      cb->nlh->nlmsg_seq,
					      RTM_NEWNETCONF, NLM_F_MULTI,
					      -1) <= 0)
			goto done;
		else
			h++;
	}
done:
	cb->args[0] = h;
	cb->args[1] = idx;

	return skb->len;
}

#ifdef CONFIG_SYSCTL

static void devinet_copy_dflt_conf(struct net *net, int i)
{
	struct net_device *dev;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		struct in_device *in_dev;

		in_dev = __in_dev_get_rcu(dev);
		if (in_dev && !test_bit(i, in_dev->cnf.state))
			in_dev->cnf.data[i] = net->ipv4.devconf_dflt->data[i];
	}
	rcu_read_unlock();
}

/* called with RTNL locked */
static void inet_forward_change(struct net *net)
{
	struct net_device *dev;
	int on = IPV4_DEVCONF_ALL(net, FORWARDING);

	IPV4_DEVCONF_ALL(net, ACCEPT_REDIRECTS) = !on;
	IPV4_DEVCONF_DFLT(net, FORWARDING) = on;
	inet_netconf_notify_devconf(net, NETCONFA_FORWARDING,
				    NETCONFA_IFINDEX_ALL,
				    net->ipv4.devconf_all);
	inet_netconf_notify_devconf(net, NETCONFA_FORWARDING,
				    NETCONFA_IFINDEX_DEFAULT,
				    net->ipv4.devconf_dflt);

	for_each_netdev(net, dev) {
		struct in_device *in_dev;
		if (on)
			dev_disable_lro(dev);
		rcu_read_lock();
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev) {
			IN_DEV_CONF_SET(in_dev, FORWARDING, on);
			inet_netconf_notify_devconf(net, NETCONFA_FORWARDING,
						    dev->ifindex, &in_dev->cnf);
		}
		rcu_read_unlock();
	}
}

static int devinet_conf_ifindex(struct net *net, struct ipv4_devconf *cnf)
{
	if (cnf == net->ipv4.devconf_dflt)
		return NETCONFA_IFINDEX_DEFAULT;
	else if (cnf == net->ipv4.devconf_all)
		return NETCONFA_IFINDEX_ALL;
	else {
		struct in_device *idev
			= container_of(cnf, struct in_device, cnf);
		return idev->dev->ifindex;
	}
}

static int devinet_conf_proc(struct ctl_table *ctl, int write,
			     void __user *buffer,
			     size_t *lenp, loff_t *ppos)
{
	int old_value = *(int *)ctl->data;
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	int new_value = *(int *)ctl->data;

	if (write) {
		struct ipv4_devconf *cnf = ctl->extra1;
		struct net *net = ctl->extra2;
		int i = (int *)ctl->data - cnf->data;
		int ifindex;

		set_bit(i, cnf->state);

		if (cnf == net->ipv4.devconf_dflt)
			devinet_copy_dflt_conf(net, i);
		if (i == IPV4_DEVCONF_ACCEPT_LOCAL - 1 ||
		    i == IPV4_DEVCONF_ROUTE_LOCALNET - 1)
			if ((new_value == 0) && (old_value != 0))
				rt_cache_flush(net);

		if (i == IPV4_DEVCONF_RP_FILTER - 1 &&
		    new_value != old_value) {
			ifindex = devinet_conf_ifindex(net, cnf);
			inet_netconf_notify_devconf(net, NETCONFA_RP_FILTER,
						    ifindex, cnf);
		}
		if (i == IPV4_DEVCONF_PROXY_ARP - 1 &&
		    new_value != old_value) {
			ifindex = devinet_conf_ifindex(net, cnf);
			inet_netconf_notify_devconf(net, NETCONFA_PROXY_NEIGH,
						    ifindex, cnf);
		}
	}

	return ret;
}

static int devinet_sysctl_forward(struct ctl_table *ctl, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos)
{
	int *valp = ctl->data;
	int val = *valp;
	loff_t pos = *ppos;
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	if (write && *valp != val) {
		struct net *net = ctl->extra2;

		if (valp != &IPV4_DEVCONF_DFLT(net, FORWARDING)) {
			if (!rtnl_trylock()) {
				/* Restore the original values before restarting */
				*valp = val;
				*ppos = pos;
				return restart_syscall();
			}
			if (valp == &IPV4_DEVCONF_ALL(net, FORWARDING)) {
				inet_forward_change(net);
			} else {
				struct ipv4_devconf *cnf = ctl->extra1;
				struct in_device *idev =
					container_of(cnf, struct in_device, cnf);
				if (*valp)
					dev_disable_lro(idev->dev);
				inet_netconf_notify_devconf(net,
							    NETCONFA_FORWARDING,
							    idev->dev->ifindex,
							    cnf);
			}
			rtnl_unlock();
			rt_cache_flush(net);
		} else
			inet_netconf_notify_devconf(net, NETCONFA_FORWARDING,
						    NETCONFA_IFINDEX_DEFAULT,
						    net->ipv4.devconf_dflt);
	}

	return ret;
}

static int ipv4_doint_and_flush(struct ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int *valp = ctl->data;
	int val = *valp;
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	struct net *net = ctl->extra2;

	if (write && *valp != val)
		rt_cache_flush(net);

	return ret;
}

#define DEVINET_SYSCTL_ENTRY(attr, name, mval, proc) \
	{ \
		.procname	= name, \
		.data		= ipv4_devconf.data + \
				  IPV4_DEVCONF_ ## attr - 1, \
		.maxlen		= sizeof(int), \
		.mode		= mval, \
		.proc_handler	= proc, \
		.extra1		= &ipv4_devconf, \
	}

#define DEVINET_SYSCTL_RW_ENTRY(attr, name) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0644, devinet_conf_proc)

#define DEVINET_SYSCTL_RO_ENTRY(attr, name) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0444, devinet_conf_proc)

#define DEVINET_SYSCTL_COMPLEX_ENTRY(attr, name, proc) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0644, proc)

#define DEVINET_SYSCTL_FLUSHING_ENTRY(attr, name) \
	DEVINET_SYSCTL_COMPLEX_ENTRY(attr, name, ipv4_doint_and_flush)

static struct devinet_sysctl_table {
	struct ctl_table_header *sysctl_header;
	struct ctl_table devinet_vars[__IPV4_DEVCONF_MAX];
} devinet_sysctl = {
	.devinet_vars = {
		DEVINET_SYSCTL_COMPLEX_ENTRY(FORWARDING, "forwarding",
					     devinet_sysctl_forward),
		DEVINET_SYSCTL_RO_ENTRY(MC_FORWARDING, "mc_forwarding"),

		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_REDIRECTS, "accept_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(SECURE_REDIRECTS, "secure_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(SHARED_MEDIA, "shared_media"),
		DEVINET_SYSCTL_RW_ENTRY(RP_FILTER, "rp_filter"),
		DEVINET_SYSCTL_RW_ENTRY(SEND_REDIRECTS, "send_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_SOURCE_ROUTE,
					"accept_source_route"),
		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_LOCAL, "accept_local"),
		DEVINET_SYSCTL_RW_ENTRY(SRC_VMARK, "src_valid_mark"),
		DEVINET_SYSCTL_RW_ENTRY(PROXY_ARP, "proxy_arp"),
		DEVINET_SYSCTL_RW_ENTRY(MEDIUM_ID, "medium_id"),
		DEVINET_SYSCTL_RW_ENTRY(BOOTP_RELAY, "bootp_relay"),
		DEVINET_SYSCTL_RW_ENTRY(LOG_MARTIANS, "log_martians"),
		DEVINET_SYSCTL_RW_ENTRY(TAG, "tag"),
		DEVINET_SYSCTL_RW_ENTRY(ARPFILTER, "arp_filter"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_ANNOUNCE, "arp_announce"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_IGNORE, "arp_ignore"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_ACCEPT, "arp_accept"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_NOTIFY, "arp_notify"),
		DEVINET_SYSCTL_RW_ENTRY(PROXY_ARP_PVLAN, "proxy_arp_pvlan"),
		DEVINET_SYSCTL_RW_ENTRY(FORCE_IGMP_VERSION,
					"force_igmp_version"),
		DEVINET_SYSCTL_RW_ENTRY(IGMPV2_UNSOLICITED_REPORT_INTERVAL,
					"igmpv2_unsolicited_report_interval"),
		DEVINET_SYSCTL_RW_ENTRY(IGMPV3_UNSOLICITED_REPORT_INTERVAL,
					"igmpv3_unsolicited_report_interval"),

		DEVINET_SYSCTL_FLUSHING_ENTRY(NOXFRM, "disable_xfrm"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(NOPOLICY, "disable_policy"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(PROMOTE_SECONDARIES,
					      "promote_secondaries"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(ROUTE_LOCALNET,
					      "route_localnet"),
	},
};

static int __devinet_sysctl_register(struct net *net, char *dev_name,
					struct ipv4_devconf *p)
{
	int i;
	struct devinet_sysctl_table *t;
	char path[sizeof("net/ipv4/conf/") + IFNAMSIZ];

	t = kmemdup(&devinet_sysctl, sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	for (i = 0; i < ARRAY_SIZE(t->devinet_vars) - 1; i++) {
		t->devinet_vars[i].data += (char *)p - (char *)&ipv4_devconf;
		t->devinet_vars[i].extra1 = p;
		t->devinet_vars[i].extra2 = net;
	}

	snprintf(path, sizeof(path), "net/ipv4/conf/%s", dev_name);

	t->sysctl_header = register_net_sysctl(net, path, t->devinet_vars);
	if (!t->sysctl_header)
		goto free;

	p->sysctl = t;
	return 0;

free:
	kfree(t);
out:
	return -ENOBUFS;
}

static void __devinet_sysctl_unregister(struct ipv4_devconf *cnf)
{
	struct devinet_sysctl_table *t = cnf->sysctl;

	if (t == NULL)
		return;

	cnf->sysctl = NULL;
	unregister_net_sysctl_table(t->sysctl_header);
	kfree(t);
}

static int devinet_sysctl_register(struct in_device *idev)
{
	int err;

	if (!sysctl_dev_name_is_allowed(idev->dev->name))
		return -EINVAL;

	err = neigh_sysctl_register(idev->dev, idev->arp_parms, NULL);
	if (err)
		return err;
	err = __devinet_sysctl_register(dev_net(idev->dev), idev->dev->name,
					&idev->cnf);
	if (err)
		neigh_sysctl_unregister(idev->arp_parms);
	return err;
}

static void devinet_sysctl_unregister(struct in_device *idev)
{
	__devinet_sysctl_unregister(&idev->cnf);
	neigh_sysctl_unregister(idev->arp_parms);
}

static struct ctl_table ctl_forward_entry[] = {
	{
		.procname	= "ip_forward",
		.data		= &ipv4_devconf.data[
					IPV4_DEVCONF_FORWARDING - 1],
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= devinet_sysctl_forward,
		.extra1		= &ipv4_devconf,
		.extra2		= &init_net,
	},
	{ },
};
#endif

static __net_init int devinet_init_net(struct net *net)
{
	int err;
	struct ipv4_devconf *all, *dflt;
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl = ctl_forward_entry;
	struct ctl_table_header *forw_hdr;
#endif

	err = -ENOMEM;
	all = &ipv4_devconf;
	dflt = &ipv4_devconf_dflt;

	if (!net_eq(net, &init_net)) {
		all = kmemdup(all, sizeof(ipv4_devconf), GFP_KERNEL);
		if (all == NULL)
			goto err_alloc_all;

		dflt = kmemdup(dflt, sizeof(ipv4_devconf_dflt), GFP_KERNEL);
		if (dflt == NULL)
			goto err_alloc_dflt;

#ifdef CONFIG_SYSCTL
		tbl = kmemdup(tbl, sizeof(ctl_forward_entry), GFP_KERNEL);
		if (tbl == NULL)
			goto err_alloc_ctl;

		tbl[0].data = &all->data[IPV4_DEVCONF_FORWARDING - 1];
		tbl[0].extra1 = all;
		tbl[0].extra2 = net;
#endif
	}

#ifdef CONFIG_SYSCTL
	err = __devinet_sysctl_register(net, "all", all);
	if (err < 0)
		goto err_reg_all;

	err = __devinet_sysctl_register(net, "default", dflt);
	if (err < 0)
		goto err_reg_dflt;

	err = -ENOMEM;
	forw_hdr = register_net_sysctl(net, "net/ipv4", tbl);
	if (forw_hdr == NULL)
		goto err_reg_ctl;
	net->ipv4.forw_hdr = forw_hdr;
#endif

	net->ipv4.devconf_all = all;
	net->ipv4.devconf_dflt = dflt;
	return 0;

#ifdef CONFIG_SYSCTL
err_reg_ctl:
	__devinet_sysctl_unregister(dflt);
err_reg_dflt:
	__devinet_sysctl_unregister(all);
err_reg_all:
	if (tbl != ctl_forward_entry)
		kfree(tbl);
err_alloc_ctl:
#endif
	if (dflt != &ipv4_devconf_dflt)
		kfree(dflt);
err_alloc_dflt:
	if (all != &ipv4_devconf)
		kfree(all);
err_alloc_all:
	return err;
}

static __net_exit void devinet_exit_net(struct net *net)
{
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl;

	tbl = net->ipv4.forw_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv4.forw_hdr);
	__devinet_sysctl_unregister(net->ipv4.devconf_dflt);
	__devinet_sysctl_unregister(net->ipv4.devconf_all);
	kfree(tbl);
#endif
	kfree(net->ipv4.devconf_dflt);
	kfree(net->ipv4.devconf_all);
}

static __net_initdata struct pernet_operations devinet_ops = {
	.init = devinet_init_net,
	.exit = devinet_exit_net,
};

static struct rtnl_af_ops inet_af_ops = {
	.family		  = AF_INET,
	.fill_link_af	  = inet_fill_link_af,
	.get_link_af_size = inet_get_link_af_size,
	.validate_link_af = inet_validate_link_af,
	.set_link_af	  = inet_set_link_af,
};

void __init devinet_init(void)
{
	int i;

	for (i = 0; i < IN4_ADDR_HSIZE; i++)
		INIT_HLIST_HEAD(&inet_addr_lst[i]);

	register_pernet_subsys(&devinet_ops);

	register_gifconf(PF_INET, inet_gifconf);
	register_netdevice_notifier(&ip_netdev_notifier);

	queue_delayed_work(system_power_efficient_wq, &check_lifetime_work, 0);

	rtnl_af_register(&inet_af_ops);

	rtnl_register(PF_INET, RTM_NEWADDR, inet_rtm_newaddr, NULL, NULL);
	rtnl_register(PF_INET, RTM_DELADDR, inet_rtm_deladdr, NULL, NULL);
	rtnl_register(PF_INET, RTM_GETADDR, NULL, inet_dump_ifaddr, NULL);
	rtnl_register(PF_INET, RTM_GETNETCONF, inet_netconf_get_devconf,
		      inet_netconf_dump_devconf, NULL);
}

