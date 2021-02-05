/*
 * xfrm_state.c
 *
 * Changes:
 *	Mitsuru KANDA @USAGI
 * 	Kazunori MIYAZAWA @USAGI
 * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
 * 		IPv6 support
 * 	YOSHIFUJI Hideaki @USAGI
 * 		Split up af-specific functions
 *	Derek Atkins <derek@ihtfp.com>
 *		Add UDP Encapsulation
 *
 */

#include <linux/workqueue.h>
#include <net/xfrm.h>
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/audit.h>
#include <asm/uaccess.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>

#include "xfrm_hash.h"

/* Each xfrm_state may be linked to two tables:

   1. Hash table by (spi,daddr,ah/esp) to find SA by SPI. (input,ctl)
   2. Hash table by (daddr,family,reqid) to find what SAs exist for given
      destination/tunnel endpoint. (output)
 */

static unsigned int xfrm_state_hashmax __read_mostly = 1 * 1024 * 1024;

static inline unsigned int xfrm_dst_hash(struct net *net,
					 const xfrm_address_t *daddr,
					 const xfrm_address_t *saddr,
					 u32 reqid,
					 unsigned short family)
{
	return __xfrm_dst_hash(daddr, saddr, reqid, family, net->xfrm.state_hmask);
}

static inline unsigned int xfrm_src_hash(struct net *net,
					 const xfrm_address_t *daddr,
					 const xfrm_address_t *saddr,
					 unsigned short family)
{
	return __xfrm_src_hash(daddr, saddr, family, net->xfrm.state_hmask);
}

static inline unsigned int
xfrm_spi_hash(struct net *net, const xfrm_address_t *daddr,
	      __be32 spi, u8 proto, unsigned short family)
{
	return __xfrm_spi_hash(daddr, spi, proto, family, net->xfrm.state_hmask);
}

static void xfrm_hash_transfer(struct hlist_head *list,
			       struct hlist_head *ndsttable,
			       struct hlist_head *nsrctable,
			       struct hlist_head *nspitable,
			       unsigned int nhashmask)
{
	struct hlist_node *tmp;
	struct xfrm_state *x;

	// 循环状态链表
	hlist_for_each_entry_safe(x, tmp, list, bydst) {
		unsigned int h;

		h = __xfrm_dst_hash(&x->id.daddr, &x->props.saddr,
				    x->props.reqid, x->props.family,
				    nhashmask);
		// 将状态插入目的HASH链表, hlist_add_head函数在节点插入前会将其从原链表中断开
		hlist_add_head(&x->bydst, ndsttable+h);

		h = __xfrm_src_hash(&x->id.daddr, &x->props.saddr,
				    x->props.family,
				    nhashmask);
		// 将状态插入源HASH链表, hlist_add_head函数在节点插入前会将其从原链表中断开
		hlist_add_head(&x->bysrc, nsrctable+h);

		if (x->id.spi) {
			h = __xfrm_spi_hash(&x->id.daddr, x->id.spi,
					    x->id.proto, x->props.family,
					    nhashmask);
			// 将状态插入SPI的HASH链表, hlist_add_head函数在节点插入前会将其从原链表中断开
			hlist_add_head(&x->byspi, nspitable+h);
		}
	}
}

static unsigned long xfrm_hash_new_size(unsigned int state_hmask)
{
	return ((state_hmask + 1) << 1) * sizeof(struct hlist_head);
}

static void xfrm_hash_resize(struct work_struct *work)
{
	struct net *net = container_of(work, struct net, xfrm.state_hash_work);
	struct hlist_head *ndst, *nsrc, *nspi, *odst, *osrc, *ospi;
	unsigned long nsize, osize;
	unsigned int nhashmask, ohashmask;
	int i;

	nsize = xfrm_hash_new_size(net->xfrm.state_hmask);
	ndst = xfrm_hash_alloc(nsize);
	if (!ndst)
		return;
	nsrc = xfrm_hash_alloc(nsize);
	if (!nsrc) {
		xfrm_hash_free(ndst, nsize);
		return;
	}
	nspi = xfrm_hash_alloc(nsize);
	if (!nspi) {
		xfrm_hash_free(ndst, nsize);
		xfrm_hash_free(nsrc, nsize);
		return;
	}

	spin_lock_bh(&net->xfrm.xfrm_state_lock);

	nhashmask = (nsize / sizeof(struct hlist_head)) - 1U;
	for (i = net->xfrm.state_hmask; i >= 0; i--)
		xfrm_hash_transfer(net->xfrm.state_bydst+i, ndst, nsrc, nspi,
				   nhashmask);

	odst = net->xfrm.state_bydst;
	osrc = net->xfrm.state_bysrc;
	ospi = net->xfrm.state_byspi;
	ohashmask = net->xfrm.state_hmask;

	net->xfrm.state_bydst = ndst;
	net->xfrm.state_bysrc = nsrc;
	net->xfrm.state_byspi = nspi;
	net->xfrm.state_hmask = nhashmask;

	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	osize = (ohashmask + 1) * sizeof(struct hlist_head);
	xfrm_hash_free(odst, osize);
	xfrm_hash_free(osrc, osize);
	xfrm_hash_free(ospi, osize);
}

static DEFINE_SPINLOCK(xfrm_state_afinfo_lock);
static struct xfrm_state_afinfo __rcu *xfrm_state_afinfo[NPROTO];

static DEFINE_SPINLOCK(xfrm_state_gc_lock);

int __xfrm_state_delete(struct xfrm_state *x);

int km_query(struct xfrm_state *x, struct xfrm_tmpl *t, struct xfrm_policy *pol);
bool km_is_alive(const struct km_event *c);
void km_state_expired(struct xfrm_state *x, int hard, u32 portid);

static DEFINE_SPINLOCK(xfrm_type_lock);
int xfrm_register_type(const struct xfrm_type *type, unsigned short family)
{
	// 找到协议族相关的策略信息结构
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	typemap = afinfo->type_map;
	// 策略信息结构中的类型数组
	spin_lock_bh(&xfrm_type_lock);

	// 如果数组中相应协议对应元素非空, 则赋值, 否则发生错误
	if (likely(typemap[type->proto] == NULL))
		typemap[type->proto] = type;
	else
		err = -EEXIST;
	spin_unlock_bh(&xfrm_type_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_register_type);

// 拆除协议处理类型, 返回0成功, 非0失败
int xfrm_unregister_type(const struct xfrm_type *type, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	// 找到协议族相关的策略信息结构
	typemap = afinfo->type_map;
	spin_lock_bh(&xfrm_type_lock);

	// 如果数组中相应协议对应元素等于要删除的结构, 元素清空, 否则发生错误
	if (unlikely(typemap[type->proto] != type))
		err = -ENOENT;
	else
		typemap[type->proto] = NULL;
	spin_unlock_bh(&xfrm_type_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_unregister_type);

// 根据协议号和协议族查找类型
static const struct xfrm_type *xfrm_get_type(u8 proto, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo;
	const struct xfrm_type **typemap;
	const struct xfrm_type *type;
	int modload_attempted = 0;

retry:
	// 找到协议族相关的策略信息结构
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return NULL;
	// 策略信息结构中的类型数组
	typemap = afinfo->type_map;

	// 数组中对应指定协议的元素
	type = typemap[proto];
	// 增加type模块的使用计数
	if (unlikely(type && !try_module_get(type->owner)))
		type = NULL;
	// 如果当前type为空, 则加载type的内核模块, 重新查找
	if (!type && !modload_attempted) {
		xfrm_state_put_afinfo(afinfo);
		request_module("xfrm-type-%d-%d", family, proto);
		modload_attempted = 1;
		goto retry;
	}

	xfrm_state_put_afinfo(afinfo);
	return type;
}

// 释放类型模块使用计数
static void xfrm_put_type(const struct xfrm_type *type)
{
	module_put(type->owner);
}

static DEFINE_SPINLOCK(xfrm_mode_lock);
// 登记模式, 返回0成功, 非0失败  模式目前包括通道和传输两种.
int xfrm_register_mode(struct xfrm_mode *mode, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode **modemap;
	int err;

	if (unlikely(mode->encap >= XFRM_MODE_MAX))
		return -EINVAL;

	// 找到协议族相关的策略信息结构
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;

	err = -EEXIST;
	// 策略信息结构中的模式数组
	modemap = afinfo->mode_map;
	spin_lock_bh(&xfrm_mode_lock);
	if (modemap[mode->encap])
		goto out;

	err = -ENOENT;
	if (!try_module_get(afinfo->owner))
		goto out;

	// 数组元素非空的话赋值, 返回成功
	mode->afinfo = afinfo;
	modemap[mode->encap] = mode;
	err = 0;

out:
	spin_unlock_bh(&xfrm_mode_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_register_mode);

// 拆除模式, 返回0成功, 非0失败
int xfrm_unregister_mode(struct xfrm_mode *mode, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode **modemap;
	int err;

	if (unlikely(mode->encap >= XFRM_MODE_MAX))
		return -EINVAL;
	
	// 找到协议族相关的策略信息结构
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;

	err = -ENOENT;
	// 策略信息结构中的模式数组
	modemap = afinfo->mode_map;
	spin_lock_bh(&xfrm_mode_lock);
	// 数组元素等于要拆除的模式, 清空, 返回成功
	if (likely(modemap[mode->encap] == mode)) {
		modemap[mode->encap] = NULL;
		module_put(mode->afinfo->owner);
		err = 0;
	}

	spin_unlock_bh(&xfrm_mode_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_unregister_mode);

// 查找模式
static struct xfrm_mode *xfrm_get_mode(unsigned int encap, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode *mode;
	int modload_attempted = 0;

	if (unlikely(encap >= XFRM_MODE_MAX))
		return NULL;

retry:
	// 找到协议族相关的策略信息结构
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return NULL;

	// 策略信息结构中的模式数组
	mode = afinfo->mode_map[encap];
	// 增加模式模块的使用计数
	if (unlikely(mode && !try_module_get(mode->owner)))
		mode = NULL;
	// 如果当前模式为空, 则加载模式对应的内核模块, 重新查找
	if (!mode && !modload_attempted) {
		xfrm_state_put_afinfo(afinfo);
		request_module("xfrm-mode-%d-%d", family, encap);
		modload_attempted = 1;
		goto retry;
	}

	xfrm_state_put_afinfo(afinfo);
	return mode;
}

// 释放模式模块使用计数
static void xfrm_put_mode(struct xfrm_mode *mode)
{
	module_put(mode->owner);
}

static void xfrm_state_gc_destroy(struct xfrm_state *x)
{
	// 删除定时器
	tasklet_hrtimer_cancel(&x->mtimer);
	del_timer_sync(&x->rtimer);
	// 释放结构
	kfree(x->aalg);
	kfree(x->ealg);
	kfree(x->calg);
	kfree(x->encap);
	kfree(x->coaddr);
	kfree(x->replay_esn);
	kfree(x->preplay_esn);
	if (x->inner_mode)
		xfrm_put_mode(x->inner_mode);
	if (x->inner_mode_iaf)
		xfrm_put_mode(x->inner_mode_iaf);
	if (x->outer_mode)
		xfrm_put_mode(x->outer_mode);
	if (x->type) {
		x->type->destructor(x);
		xfrm_put_type(x->type);
	}
	security_xfrm_state_free(x);
	// 释放状态
	kfree(x);
}

static void xfrm_state_gc_task(struct work_struct *work)
{
	struct net *net = container_of(work, struct net, xfrm.state_gc_work);
	struct xfrm_state *x;
	struct hlist_node *tmp;
	struct hlist_head gc_list;

	spin_lock_bh(&xfrm_state_gc_lock);
	
	hlist_move_list(&net->xfrm.state_gc_list, &gc_list);
	// 重新初始化状态垃圾链表
	spin_unlock_bh(&xfrm_state_gc_lock);

	// 释放当前的垃圾链表中的各个状态
	hlist_for_each_entry_safe(x, tmp, &gc_list, gclist)
		xfrm_state_gc_destroy(x);
}

static inline unsigned long make_jiffies(long secs)
{
	if (secs >= (MAX_SCHEDULE_TIMEOUT-1)/HZ)
		return MAX_SCHEDULE_TIMEOUT-1;
	else
		return secs*HZ;
}

static enum hrtimer_restart xfrm_timer_handler(struct hrtimer *me)
{
	struct tasklet_hrtimer *thr = container_of(me, struct tasklet_hrtimer, timer);
	struct xfrm_state *x = container_of(thr, struct xfrm_state, mtimer);
	unsigned long now = get_seconds();
	long next = LONG_MAX;
	int warn = 0;
	int err = 0;

	spin_lock(&x->lock);
	// 如果该xfrm状态已经处于死亡状态, 可以返回了
	if (x->km.state == XFRM_STATE_DEAD)
		goto out;
	// 如果处于生命期到期状态, 转到期处理
	if (x->km.state == XFRM_STATE_EXPIRED)
		goto expired;
	// 如果到期了还要强制要增加一些时间
	if (x->lft.hard_add_expires_seconds) {
		// 计算强制增加的超时时间
		long tmo = x->lft.hard_add_expires_seconds +
			x->curlft.add_time - now;
		// 没法增加超时了, 到期
		if (tmo <= 0) {
			if (x->xflags & XFRM_SOFT_EXPIRE) {
				/* enter hard expire without soft expire first?!
				 * setting a new date could trigger this.
				 * workarbound: fix x->curflt.add_time by below:
				 */
				x->curlft.add_time = now - x->saved_tmo - 1;
				tmo = x->lft.hard_add_expires_seconds - x->saved_tmo;
			} else
				goto expired;
		}
		if (tmo < next)
			next = tmo;
	}
	// 如果到期了还要强制要增加的使用时间
	if (x->lft.hard_use_expires_seconds) {
		// 计算强制增加的使用时间
		long tmo = x->lft.hard_use_expires_seconds +
			(x->curlft.use_time ? : now) - now;
		// 没法增加超时了, 到期
		if (tmo <= 0)
			goto expired;
		if (tmo < next)
			next = tmo;
	}
	// dying表示软性增加超时已经不可用
	if (x->km.dying)
		goto resched;
	// 如果到期了还要软性要增加一些时间
	if (x->lft.soft_add_expires_seconds) {
		// 计算软性增加的时间
		long tmo = x->lft.soft_add_expires_seconds +
			x->curlft.add_time - now;
		// 软性增加超时不可用了
		if (tmo <= 0) {
			warn = 1;
			x->xflags &= ~XFRM_SOFT_EXPIRE;
		} else if (tmo < next) {
			next = tmo;
			x->xflags |= XFRM_SOFT_EXPIRE;
			x->saved_tmo = tmo;
		}
	}
	// 如果到期了还要软性要增加的使用时间
	if (x->lft.soft_use_expires_seconds) {
		// 计算软性增加的使用时间
		long tmo = x->lft.soft_use_expires_seconds +
			(x->curlft.use_time ? : now) - now;
		// 软性增加超时不可用了
		if (tmo <= 0)
			warn = 1;
		else if (tmo < next)
			next = tmo;
	}
	
	// dying即为软性增加超时是否可用标志
	x->km.dying = warn;
	// 软性增加超时已比不可用, 进行状态的超时到期通知
	if (warn)
		km_state_expired(x, 0, 0);
resched:
	// 如果增加的超时有效, 修改定时器超时时间
	if (next != LONG_MAX) {
		tasklet_hrtimer_start(&x->mtimer, ktime_set(next, 0), HRTIMER_MODE_REL);
	}

	goto out;

expired:// 状态到期
	if (x->km.state == XFRM_STATE_ACQ && x->id.spi == 0)
		// 如果这个状态是ACQ类型状态(不是用户空间主动建立的状态,而是内核根据策略主动要求
	    // 用户空间进行IKE协商建立的状态)
		// 状态设置为到期
		x->km.state = XFRM_STATE_EXPIRED;

	// 删除状态, 进行状态的到期通知
	err = __xfrm_state_delete(x);
	if (!err)
		// 1表示是硬性到期了
		km_state_expired(x, 1, 0);

	xfrm_audit_state_delete(x, err ? 0 : 1, true);

out:
	spin_unlock(&x->lock);
	return HRTIMER_NORESTART;
}

static void xfrm_replay_timer_handler(unsigned long data);

struct xfrm_state *xfrm_state_alloc(struct net *net)
{
	struct xfrm_state *x;

	// 分配空间
	x = kzalloc(sizeof(struct xfrm_state), GFP_ATOMIC);

	if (x) {
		write_pnet(&x->xs_net, net);
		// 使用数初始化为1
		atomic_set(&x->refcnt, 1);
		// 被0个ipsec通道使用
		atomic_set(&x->tunnel_users, 0);
		//初始化链表头
		INIT_LIST_HEAD(&x->km.all);
		// 初始化链表节点, 状态可按目的地址, 源地址和SPI挂接到不同链表
		INIT_HLIST_NODE(&x->bydst);
		INIT_HLIST_NODE(&x->bysrc);
		INIT_HLIST_NODE(&x->byspi);
		// 初始化精度定时器
		tasklet_hrtimer_init(&x->mtimer, xfrm_timer_handler,
					CLOCK_BOOTTIME, HRTIMER_MODE_ABS);
		// 状态定时器
		setup_timer(&x->rtimer, xfrm_replay_timer_handler,
				(unsigned long)x);
		x->curlft.add_time = get_seconds();
		// SA生命期参数
		x->lft.soft_byte_limit = XFRM_INF;
		x->lft.soft_packet_limit = XFRM_INF;
		x->lft.hard_byte_limit = XFRM_INF;
		x->lft.hard_packet_limit = XFRM_INF;
		// 回放处理参数
		x->replay_maxage = 0;
		x->replay_maxdiff = 0;
		
		x->inner_mode = NULL;
		x->inner_mode_iaf = NULL;
		// 初始化状态锁
		spin_lock_init(&x->lock);
	}
	return x;
}
EXPORT_SYMBOL(xfrm_state_alloc);

void __xfrm_state_destroy(struct xfrm_state *x)
{
	struct net *net = xs_net(x);

	WARN_ON(x->km.state != XFRM_STATE_DEAD);

	spin_lock_bh(&xfrm_state_gc_lock);
	hlist_add_head(&x->gclist, &net->xfrm.state_gc_list);
	spin_unlock_bh(&xfrm_state_gc_lock);
	schedule_work(&net->xfrm.state_gc_work);
}
EXPORT_SYMBOL(__xfrm_state_destroy);


// 实际的相同删除操作函数, 必须保证在x->lock加锁状态下执行
int __xfrm_state_delete(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	int err = -ESRCH;

	// 如果状态已经是DEAD就不操作了
	if (x->km.state != XFRM_STATE_DEAD) {
		// 设置状态为DEAD
		x->km.state = XFRM_STATE_DEAD;
		// xfrm_state_lock是全局的状态链表操作锁
		spin_lock(&net->xfrm.xfrm_state_lock);
		list_del(&x->km.all);
		// 从目的地址索引的链表中断开
		hlist_del(&x->bydst);
		// 从源地址索引的链表中断开
		hlist_del(&x->bysrc);
		// 从SPI索引的链表中断开
		if (x->id.spi)
			hlist_del(&x->byspi);
		// xfrm状态总数减一
		net->xfrm.state_num--;
		spin_unlock(&net->xfrm.xfrm_state_lock);

		/* All xfrm_state objects are created by xfrm_state_alloc.
		 * The xfrm_state_alloc call gives a reference, and that
		 * is what we are dropping here.
		 */
		 // 减少该状态引用计数
		xfrm_state_put(x);
		err = 0;
	}

	return err;
}
EXPORT_SYMBOL(__xfrm_state_delete);

//状态删除函数为xfrm_state_delete(), 该函数被pfkey_delete函数调用.
// 这个函数只是__xfrm_state_delete()加锁的包裹函数
int xfrm_state_delete(struct xfrm_state *x)
{
	int err;

	spin_lock_bh(&x->lock);
	err = __xfrm_state_delete(x);
	spin_unlock_bh(&x->lock);

	return err;
}
EXPORT_SYMBOL(xfrm_state_delete);

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static inline int
xfrm_state_flush_secctx_check(struct net *net, u8 proto, bool task_valid)
{
	int i, err = 0;

	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;

		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			if (xfrm_id_proto_match(x->id.proto, proto) &&
			   (err = security_xfrm_state_delete(x)) != 0) {
				xfrm_audit_state_delete(x, 0, task_valid);
				return err;
			}
		}
	}

	return err;
}
#else
static inline int
xfrm_state_flush_secctx_check(struct net *net, u8 proto, bool task_valid)
{
	return 0;
}
#endif

// 删除某种协议proto的所有状态
int xfrm_state_flush(struct net *net, u8 proto, bool task_valid)
{
	int i, err = 0, cnt = 0;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	err = xfrm_state_flush_secctx_check(net, proto, task_valid);
	if (err)
		goto out;

	err = -ESRCH;
	// 循环所有HASH链表
	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;
restart:
		// 在按目的地址进行索引的链表中循环
		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			// 要满足两个条件:
			// 非正在被ipsec通道使用的状态; 协议类型匹配
			if (!xfrm_state_kern(x) &&
				// 先hold住状态,防止在解开xfrm_state_lock锁, 又没被进入xfrm_state_delete()前
				// 被意外删除了, 此处考虑得比较仔细
			    xfrm_id_proto_match(x->id.proto, proto)) {
				xfrm_state_hold(x);
				// 先解开xfrm_state_lock, 在xfrm_state_delete()中要重新上锁
				spin_unlock_bh(&net->xfrm.xfrm_state_lock);

				// 删除状态
				err = xfrm_state_delete(x);
				xfrm_audit_state_delete(x, err ? 0 : 1,
							task_valid);
				// 减少刚才的引用计数
				xfrm_state_put(x);
				if (!err)
					cnt++;

				// 重新加锁, 循环
				spin_lock_bh(&net->xfrm.xfrm_state_lock);
				goto restart;
			}
		}
	}
	if (cnt)
		err = 0;

out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_state_flush);

void xfrm_sad_getinfo(struct net *net, struct xfrmk_sadinfo *si)
{
	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	si->sadcnt = net->xfrm.state_num;
	si->sadhcnt = net->xfrm.state_hmask;
	si->sadhmcnt = xfrm_state_hashmax;
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_sad_getinfo);

static int
xfrm_init_tempstate(struct xfrm_state *x, const struct flowi *fl,
		    const struct xfrm_tmpl *tmpl,
		    const xfrm_address_t *daddr, const xfrm_address_t *saddr,
		    unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		return -1;
	afinfo->init_tempsel(&x->sel, fl);

	if (family != tmpl->encap_family) {
		xfrm_state_put_afinfo(afinfo);
		afinfo = xfrm_state_get_afinfo(tmpl->encap_family);
		if (!afinfo)
			return -1;
	}
	afinfo->init_temprop(x, tmpl, daddr, saddr);
	xfrm_state_put_afinfo(afinfo);
	return 0;
}

static struct xfrm_state *__xfrm_state_lookup(struct net *net, u32 mark,
					      const xfrm_address_t *daddr,
					      __be32 spi, u8 proto,
					      unsigned short family)
{
	// 根据SPI进行HASH
	unsigned int h = xfrm_spi_hash(net, daddr, spi, proto, family);
	struct xfrm_state *x;

	// 循环相应的SPI链表
	hlist_for_each_entry(x, net->xfrm.state_byspi+h, byspi) {
		// 比较协议族, SPI, 和协议是否相同
		if (x->props.family != family ||
		    x->id.spi       != spi ||
		    x->id.proto     != proto ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family))
			continue;

		// 比较源地址和目的地址是否相同
		if ((mark & x->mark.m) != x->mark.v)
			continue;
		// 找到, 增加状态引用计数, 返回
		xfrm_state_hold(x);
		return x;
	}

	return NULL;
}

static struct xfrm_state *__xfrm_state_lookup_byaddr(struct net *net, u32 mark,
						     const xfrm_address_t *daddr,
						     const xfrm_address_t *saddr,
						     u8 proto, unsigned short family)
{
	// 根据目的地址计算HASH值
	unsigned int h = xfrm_src_hash(net, daddr, saddr, family);
	struct xfrm_state *x;

	// 循环相应的源地址链表
	hlist_for_each_entry(x, net->xfrm.state_bysrc+h, bysrc) {
		// 比较协议族和协议是否相同
		if (x->props.family != family ||
		    x->id.proto     != proto ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family) ||
		    !xfrm_addr_equal(&x->props.saddr, saddr, family))
			continue;

		// 比较源地址和目的地址是否相同
		if ((mark & x->mark.m) != x->mark.v)
			continue;
		xfrm_state_hold(x);
		return x;
	}

	return NULL;
}


//这个函数只是__xfrm_state_lookup和__xfrm_state_lookup_byaddr的组合函数
static inline struct xfrm_state *
__xfrm_state_locate(struct xfrm_state *x, int use_spi, int family)
{
	struct net *net = xs_net(x);
	u32 mark = x->mark.v & x->mark.m;

	if (use_spi)
		return __xfrm_state_lookup(net, mark, &x->id.daddr,
					   x->id.spi, x->id.proto, family);
	else
		return __xfrm_state_lookup_byaddr(net, mark,
						  &x->id.daddr,
						  &x->props.saddr,
						  x->id.proto, family);
}

static void xfrm_hash_grow_check(struct net *net, int have_hash_collision)
{
	// 发生碰撞
	if (have_hash_collision &&
		// HASH掩码不论如何不能超过极限, xfrm_state_hashmax为2^20
	    (net->xfrm.state_hmask + 1) < xfrm_state_hashmax &&
	    // 当前状态总数已经大于HASH掩码
	    net->xfrm.state_num > net->xfrm.state_hmask)
	    // 调度一个work结构
		schedule_work(&net->xfrm.state_hash_work);
}

static void xfrm_state_look_at(struct xfrm_policy *pol, struct xfrm_state *x,
			       const struct flowi *fl, unsigned short family,
			       struct xfrm_state **best, int *acq_in_progress,
			       int *error)
{
	/* Resolution logic:
	 * 1. There is a valid state with matching selector. Done.
	 * 2. Valid state with inappropriate selector. Skip.
	 *
	 * Entering area of "sysdeps".
	 *
	 * 3. If state is not valid, selector is temporary, it selects
	 *    only session which triggered previous resolution. Key
	 *    manager will do something to install a state with proper
	 *    selector.
	 */
	 // 如果是合法状态
	if (x->km.state == XFRM_STATE_VALID) {
		// 如果选择子不匹配, 跳过
		if ((x->sel.family &&
		     !xfrm_selector_match(&x->sel, fl, x->sel.family)) ||
		    !security_xfrm_state_pol_flow_match(x, pol, fl))
			return;
		
		// 如果还没找到或原来找到的状态的可用时间比新的小, 将找到的状态置为best
		if (!*best ||
		    (*best)->km.dying > x->km.dying ||
		    ((*best)->km.dying == x->km.dying &&
		     (*best)->curlft.add_time < x->curlft.add_time))
			*best = x;
	}
	// 如果是ACQUIRE的状态
	else if (x->km.state == XFRM_STATE_ACQ) {
		// 设置个ACQ标志
		*acq_in_progress = 1;
	} 
	// 如果是错误或到期的状态
	else if (x->km.state == XFRM_STATE_ERROR ||
		   x->km.state == XFRM_STATE_EXPIRED) {
		// 如果选择子反而匹配了, 设置错误号
		if (xfrm_selector_match(&x->sel, fl, x->sel.family) &&
		    security_xfrm_state_pol_flow_match(x, pol, fl))
			*error = -ESRCH;
	}
}


//xfrm_state_find()函数根据地址, 路由流参数, xfrm模板,
//xfrm策略等参数来查询状态，在现有的状态中找不到时会新分配一个。
//该函数被xfrm_tmpl_resolve_one()函数调用,
//调用该函数的情景是内核发现一个包符合安全策略需要进行加密处理时会查找是否有相应的SA,
//如果有则返回; 如果没找到, 则会通知用户空间的IKE进行进行协商, 生成新的SA,
// 而xfrm_state_find()函数生成的SA就是ACQUIRE类型的SA,不是真实可用的。
struct xfrm_state *
xfrm_state_find(const xfrm_address_t *daddr, const xfrm_address_t *saddr,
		const struct flowi *fl, struct xfrm_tmpl *tmpl,
		struct xfrm_policy *pol, int *err,
		unsigned short family)
{
	static xfrm_address_t saddr_wildcard = { };
	struct net *net = xp_net(pol);
	unsigned int h, h_wildcard;
	struct xfrm_state *x, *x0, *to_put;
	int acquire_in_progress = 0;
	int error = 0;
	struct xfrm_state *best = NULL;
	u32 mark = pol->mark.v & pol->mark.m;
	unsigned short encap_family = tmpl->encap_family;
	struct km_event c;

	to_put = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	// 根据地址进行HASH
	h = xfrm_dst_hash(net, daddr, saddr, tmpl->reqid, encap_family);
	// 循环链表, 找一个最匹配的状态
	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
			// 协议族匹配
		if (x->props.family == encap_family &&
			// 请求ID匹配
		    x->props.reqid == tmpl->reqid &&
		    // 
		    (mark & x->mark.m) == x->mark.v &&
		    // 无WILDRECV标志
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    // 源目的地址匹配
		    xfrm_state_addr_check(x, daddr, saddr, encap_family) &&
		    // 模式匹配
		    tmpl->mode == x->props.mode &&
		    // 协议匹配
		    tmpl->id.proto == x->id.proto &&
		    // SPI匹配
		    (tmpl->id.spi == x->id.spi || !tmpl->id.spi))
			xfrm_state_look_at(pol, x, fl, encap_family,
					   &best, &acquire_in_progress, &error);
	}
	if (best || acquire_in_progress)
		goto found;

	h_wildcard = xfrm_dst_hash(net, daddr, &saddr_wildcard, tmpl->reqid, encap_family);
	hlist_for_each_entry(x, net->xfrm.state_bydst+h_wildcard, bydst) {
		if (x->props.family == encap_family &&
		    x->props.reqid == tmpl->reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_addr_equal(&x->id.daddr, daddr, encap_family) &&
		    tmpl->mode == x->props.mode &&
		    tmpl->id.proto == x->id.proto &&
		    (tmpl->id.spi == x->id.spi || !tmpl->id.spi))
			xfrm_state_look_at(pol, x, fl, encap_family,
					   &best, &acquire_in_progress, &error);
	}

found:
	x = best;
	// 没找到, 没错误, 没ACQ的情况
	if (!x && !error && !acquire_in_progress) {
		// 根据模块的SPI, 地址, 协议进行查找, 不过应该是找不到才对, 因为SPI是唯一的
		if (tmpl->id.spi &&
		    (x0 = __xfrm_state_lookup(net, mark, daddr, tmpl->id.spi,
					      tmpl->id.proto, encap_family)) != NULL) {
			// 本应找不到, 如果找到了说明该SPI值已经被使用, 再使用此SPI是错误的
			to_put = x0;
			error = -EEXIST;
			goto out;
		}

		c.net = net;
		/* If the KMs have no listeners (yet...), avoid allocating an SA
		 * for each and every packet - garbage collection might not
		 * handle the flood.
		 */
		if (!km_is_alive(&c)) {
			error = -ESRCH;
			goto out;
		}
		
		// 分配新状态
		x = xfrm_state_alloc(net);
		if (x == NULL) {
			error = -ENOMEM;
			goto out;
		}
		/* Initialize temporary state matching only
		 * to current session. */
		// 用模板参数初始化状态
		xfrm_init_tempstate(x, fl, tmpl, daddr, saddr, family);
		memcpy(&x->mark, &pol->mark, sizeof(x->mark));

		error = security_xfrm_state_alloc_acquire(x, pol->security, fl->flowi_secid);
		if (error) {
			x->km.state = XFRM_STATE_DEAD;
			to_put = x;
			x = NULL;
			goto out;
		}

		// 将新状态发送给用户空间程序, 在其中调用了pfkey_acquire函数让用户空间进程进行
		// IKE协商生成新SA
		if (km_query(x, tmpl, pol) == 0) {
			// 状态类型设置为ACQ
			x->km.state = XFRM_STATE_ACQ;
			// 添加参数到HASH的链表
			list_add(&x->km.all, &net->xfrm.state_all);
			hlist_add_head(&x->bydst, net->xfrm.state_bydst+h);
			h = xfrm_src_hash(net, daddr, saddr, encap_family);
			hlist_add_head(&x->bysrc, net->xfrm.state_bysrc+h);
			if (x->id.spi) {
				h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto, encap_family);
				hlist_add_head(&x->byspi, net->xfrm.state_byspi+h);
			}
			// 设置定时器
			x->lft.hard_add_expires_seconds = net->xfrm.sysctl_acq_expires;
			tasklet_hrtimer_start(&x->mtimer, ktime_set(net->xfrm.sysctl_acq_expires, 0), HRTIMER_MODE_REL);
			// 状态总数增加
			net->xfrm.state_num++;
			// 检查是否需要扩大HASH表数量
			xfrm_hash_grow_check(net, x->bydst.next != NULL);
		} else {
			// 发送失败, 状态类型置为DEAD, 放弃
			x->km.state = XFRM_STATE_DEAD;
			to_put = x;
			x = NULL;
			error = -ESRCH;
		}
	}
out:
	if (x)
		xfrm_state_hold(x);
	else
		*err = acquire_in_progress ? -EAGAIN : error;
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	if (to_put)
		xfrm_state_put(to_put);
	return x;
}

struct xfrm_state *
xfrm_stateonly_find(struct net *net, u32 mark,
		    xfrm_address_t *daddr, xfrm_address_t *saddr,
		    unsigned short family, u8 mode, u8 proto, u32 reqid)
{
	unsigned int h;
	struct xfrm_state *rx = NULL, *x = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	h = xfrm_dst_hash(net, daddr, saddr, reqid, family);
	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		if (x->props.family == family &&
		    x->props.reqid == reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_state_addr_check(x, daddr, saddr, family) &&
		    mode == x->props.mode &&
		    proto == x->id.proto &&
		    x->km.state == XFRM_STATE_VALID) {
			rx = x;
			break;
		}
	}

	if (rx)
		xfrm_state_hold(rx);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);


	return rx;
}
EXPORT_SYMBOL(xfrm_stateonly_find);

struct xfrm_state *xfrm_state_lookup_byspi(struct net *net, __be32 spi,
					      unsigned short family)
{
	struct xfrm_state *x;
	struct xfrm_state_walk *w;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	list_for_each_entry(w, &net->xfrm.state_all, all) {
		x = container_of(w, struct xfrm_state, km);
		if (x->props.family != family ||
			x->id.spi != spi)
			continue;

		spin_unlock_bh(&net->xfrm.xfrm_state_lock);
		xfrm_state_hold(x);
		return x;
	}
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return NULL;
}
EXPORT_SYMBOL(xfrm_state_lookup_byspi);

static void __xfrm_state_insert(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	unsigned int h;

	list_add(&x->km.all, &net->xfrm.state_all);

	// 添加到按目的地址HASH的链表
	h = xfrm_dst_hash(net, &x->id.daddr, &x->props.saddr,
			  x->props.reqid, x->props.family);
	hlist_add_head(&x->bydst, net->xfrm.state_bydst+h);

	// 添加到按源地址HASH的链表
	h = xfrm_src_hash(net, &x->id.daddr, &x->props.saddr, x->props.family);
	hlist_add_head(&x->bysrc, net->xfrm.state_bysrc+h);

	if (x->id.spi) {
		// 添加到按SPI进行HASH的链表
		h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto,
				  x->props.family);

		hlist_add_head(&x->byspi, net->xfrm.state_byspi+h);
	}

	// 修改定时器, 超时仅1秒
	tasklet_hrtimer_start(&x->mtimer, ktime_set(1, 0), HRTIMER_MODE_REL);
	if (x->replay_maxage)
		// 如果设置了回放最大时间间隔, 超时改为该值
		mod_timer(&x->rtimer, jiffies + x->replay_maxage);

	net->xfrm.state_num++;

	// HASH扩大检查, 检查是否需要扩展HASH表数量
	xfrm_hash_grow_check(net, x->bydst.next != NULL);
}

/* net->xfrm.xfrm_state_lock is held */
/* xfrm_state_lock is held */
// 碰撞检查, 看是否有多个连接状态, 要进行区别
static void __xfrm_state_bump_genids(struct xfrm_state *xnew)
{
	struct net *net = xs_net(xnew);
	unsigned short family = xnew->props.family;
	u32 reqid = xnew->props.reqid;
	struct xfrm_state *x;
	unsigned int h;
	u32 mark = xnew->mark.v & xnew->mark.m;

	// 计算状态HASH值来找相关链表
	h = xfrm_dst_hash(net, &xnew->id.daddr, &xnew->props.saddr, reqid, family);
	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		// 如果已经在链表中的状态的协议族, 请求ID, 源地址, 目的地址都和新状态匹配
		if (x->props.family	== family &&
		    x->props.reqid	== reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    xfrm_addr_equal(&x->id.daddr, &xnew->id.daddr, family) &&
		    xfrm_addr_equal(&x->props.saddr, &xnew->props.saddr, family))
			x->genid++;
	}
}


// xfrm_state_insert只是个包裹函数, 加xfrm_state_lock锁后调用__xfrm_state_bump_genids和
// __xfrm_state_insert
void xfrm_state_insert(struct xfrm_state *x)
{
	struct net *net = xs_net(x);

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	__xfrm_state_bump_genids(x);
	__xfrm_state_insert(x);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_state_insert);

/* net->xfrm.xfrm_state_lock is held */
static struct xfrm_state *__find_acq_core(struct net *net,
					  const struct xfrm_mark *m,
					  unsigned short family, u8 mode,
					  u32 reqid, u8 proto,
					  const xfrm_address_t *daddr,
					  const xfrm_address_t *saddr,
					  int create)
{
	// 根据源地址，目的地址,请求ID进行目的地址类型HASH
	unsigned int h = xfrm_dst_hash(net, daddr, saddr, reqid, family);
	struct xfrm_state *x;
	u32 mark = m->v & m->m;

	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		// 比较请求ID，数据模式，协议族
		// 要求状态的类型为XFRM_STATE_ACQ，SPI值为0
		if (x->props.reqid  != reqid ||
		    x->props.mode   != mode ||
		    x->props.family != family ||
		    x->km.state     != XFRM_STATE_ACQ ||
		    x->id.spi       != 0 ||
		    x->id.proto	    != proto ||
		    // 再比较源地址和目的地址是否相同
		    (mark & x->mark.m) != x->mark.v ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family) ||
		    !xfrm_addr_equal(&x->props.saddr, saddr, family))
			continue;
		
		// 找到, 增加状态引用计数, 返回
		xfrm_state_hold(x);
		return x;
	}
	// 没找到
	// 如果不需要创建, 返回NULL
	if (!create)
		return NULL;

	// 创建ACQ类型的xfrm_state
	// 分配空间
	x = xfrm_state_alloc(net);
	if (likely(x)) {
		// 填写网络地址基本参数
		switch (family) {
		case AF_INET:
			x->sel.daddr.a4 = daddr->a4;
			x->sel.saddr.a4 = saddr->a4;
			x->sel.prefixlen_d = 32;
			x->sel.prefixlen_s = 32;
			x->props.saddr.a4 = saddr->a4;
			x->id.daddr.a4 = daddr->a4;
			break;

		case AF_INET6:
			*(struct in6_addr *)x->sel.daddr.a6 = *(struct in6_addr *)daddr;
			*(struct in6_addr *)x->sel.saddr.a6 = *(struct in6_addr *)saddr;
			x->sel.prefixlen_d = 128;
			x->sel.prefixlen_s = 128;
			*(struct in6_addr *)x->props.saddr.a6 = *(struct in6_addr *)saddr;
			*(struct in6_addr *)x->id.daddr.a6 = *(struct in6_addr *)daddr;
			break;
		}

		// 状态类型设置为XFRM_STATE_ACQ
		x->km.state = XFRM_STATE_ACQ;
		// 状态其他参数赋值
		x->id.proto = proto;
		x->props.family = family;
		x->props.mode = mode;
		x->props.reqid = reqid;
		x->mark.v = m->v;
		x->mark.m = m->m;
		// 硬性可增加的超时
		x->lft.hard_add_expires_seconds = net->xfrm.sysctl_acq_expires;
		xfrm_state_hold(x);
		// 超时XFRM_ACQ_EXPIRES秒
		tasklet_hrtimer_start(&x->mtimer, ktime_set(net->xfrm.sysctl_acq_expires, 0), HRTIMER_MODE_REL);
		list_add(&x->km.all, &net->xfrm.state_all);
		// 添加到目的HASH链表
		hlist_add_head(&x->bydst, net->xfrm.state_bydst+h);
		// 添加到源地址HASH链表
		h = xfrm_src_hash(net, daddr, saddr, family);
		hlist_add_head(&x->bysrc, net->xfrm.state_bysrc+h);

		// 增加状态总数
		net->xfrm.state_num++;

		// 检查是否需要扩大HASH表数量
		xfrm_hash_grow_check(net, x->bydst.next != NULL);
	}

	return x;
}

static struct xfrm_state *__xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq);


//状态增加函数为xfrm_state_add(), 状态更新函数为xfrm_state_update(),这两个函数都被pfkey_add函数调用.
// 添加xfrm状态
int xfrm_state_add(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	struct xfrm_state *x1, *to_put;
	int family;
	int err;
	u32 mark = x->mark.v & x->mark.m;
	// 当协议为为ESP, AH, COMP以及ANY时为真, 其他为假
	int use_spi = xfrm_id_proto_match(x->id.proto, IPSEC_PROTO_ANY);

	family = x->props.family;

	to_put = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	
	// 根据xfrm的地址, SPI, 协议, 协议族等信息查找内核中是否已经存在相同的xfrm
	x1 = __xfrm_state_locate(x, use_spi, family);
	if (x1) {
		// 确实已经存在, 返回错误
		to_put = x1;
		x1 = NULL;
		err = -EEXIST;
		goto out;
	}

	if (use_spi && x->km.seq) {
		// 如果序列号有效, 根据序列号查找内核中是否已经存在相同的xfrm
		x1 = __xfrm_find_acq_byseq(net, mark, x->km.seq);
		// 找到, 但如果目的地址不符合的话, 仍试为没找到
		if (x1 && ((x1->id.proto != x->id.proto) ||
		    !xfrm_addr_equal(&x1->id.daddr, &x->id.daddr, family))) {
			to_put = x1;
			x1 = NULL;
		}
	}
	
	// 如果没找到x1, 根据各种信息再查找xfrm
	if (use_spi && !x1)
		x1 = __find_acq_core(net, &x->mark, family, x->props.mode,
				     x->props.reqid, x->id.proto,
				     &x->id.daddr, &x->props.saddr, 0);
	// 如果x和现在内核中的xfrm匹配的话为x生成genid参数
	// 会用到一个静态单文件全局变量: xfrm_state_genid

	__xfrm_state_bump_genids(x);
	// 将新xfrm插入内核的各xfrm表, 这些表是以HASH表形式实现的, 分别根据
  	// 源地址, 目的地址形成两个HASH表
	__xfrm_state_insert(x);
	err = 0;

out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	// 如果按后来的条件找到x1, 删除之, 该状态不需要了
	if (x1) {
		// 将找到的x1从链表中删除,
		xfrm_state_delete(x1);
		// 释放x1
		xfrm_state_put(x1);
	}

	if (to_put)
		xfrm_state_put(to_put);

	return err;
}
EXPORT_SYMBOL(xfrm_state_add);

#ifdef CONFIG_XFRM_MIGRATE
static struct xfrm_state *xfrm_state_clone(struct xfrm_state *orig)
{
	struct net *net = xs_net(orig);
	struct xfrm_state *x = xfrm_state_alloc(net);
	if (!x)
		goto out;

	memcpy(&x->id, &orig->id, sizeof(x->id));
	memcpy(&x->sel, &orig->sel, sizeof(x->sel));
	memcpy(&x->lft, &orig->lft, sizeof(x->lft));
	x->props.mode = orig->props.mode;
	x->props.replay_window = orig->props.replay_window;
	x->props.reqid = orig->props.reqid;
	x->props.family = orig->props.family;
	x->props.saddr = orig->props.saddr;

	if (orig->aalg) {
		x->aalg = xfrm_algo_auth_clone(orig->aalg);
		if (!x->aalg)
			goto error;
	}
	x->props.aalgo = orig->props.aalgo;

	if (orig->aead) {
		x->aead = xfrm_algo_aead_clone(orig->aead);
		if (!x->aead)
			goto error;
	}
	if (orig->ealg) {
		x->ealg = xfrm_algo_clone(orig->ealg);
		if (!x->ealg)
			goto error;
	}
	x->props.ealgo = orig->props.ealgo;

	if (orig->calg) {
		x->calg = xfrm_algo_clone(orig->calg);
		if (!x->calg)
			goto error;
	}
	x->props.calgo = orig->props.calgo;

	if (orig->encap) {
		x->encap = kmemdup(orig->encap, sizeof(*x->encap), GFP_KERNEL);
		if (!x->encap)
			goto error;
	}

	if (orig->coaddr) {
		x->coaddr = kmemdup(orig->coaddr, sizeof(*x->coaddr),
				    GFP_KERNEL);
		if (!x->coaddr)
			goto error;
	}

	if (orig->replay_esn) {
		if (xfrm_replay_clone(x, orig))
			goto error;
	}

	memcpy(&x->mark, &orig->mark, sizeof(x->mark));

	if (xfrm_init_state(x) < 0)
		goto error;

	x->props.flags = orig->props.flags;
	x->props.extra_flags = orig->props.extra_flags;

	x->tfcpad = orig->tfcpad;
	x->replay_maxdiff = orig->replay_maxdiff;
	x->replay_maxage = orig->replay_maxage;
	x->curlft.add_time = orig->curlft.add_time;
	x->km.state = orig->km.state;
	x->km.seq = orig->km.seq;
	x->replay = orig->replay;
	x->preplay = orig->preplay;

	return x;

 error:
	xfrm_state_put(x);
out:
	return NULL;
}

struct xfrm_state *xfrm_migrate_state_find(struct xfrm_migrate *m, struct net *net)
{
	unsigned int h;
	struct xfrm_state *x = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);

	if (m->reqid) {
		h = xfrm_dst_hash(net, &m->old_daddr, &m->old_saddr,
				  m->reqid, m->old_family);
		hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
			if (x->props.mode != m->mode ||
			    x->id.proto != m->proto)
				continue;
			if (m->reqid && x->props.reqid != m->reqid)
				continue;
			if (!xfrm_addr_equal(&x->id.daddr, &m->old_daddr,
					     m->old_family) ||
			    !xfrm_addr_equal(&x->props.saddr, &m->old_saddr,
					     m->old_family))
				continue;
			xfrm_state_hold(x);
			break;
		}
	} else {
		h = xfrm_src_hash(net, &m->old_daddr, &m->old_saddr,
				  m->old_family);
		hlist_for_each_entry(x, net->xfrm.state_bysrc+h, bysrc) {
			if (x->props.mode != m->mode ||
			    x->id.proto != m->proto)
				continue;
			if (!xfrm_addr_equal(&x->id.daddr, &m->old_daddr,
					     m->old_family) ||
			    !xfrm_addr_equal(&x->props.saddr, &m->old_saddr,
					     m->old_family))
				continue;
			xfrm_state_hold(x);
			break;
		}
	}

	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	return x;
}
EXPORT_SYMBOL(xfrm_migrate_state_find);

struct xfrm_state *xfrm_state_migrate(struct xfrm_state *x,
				      struct xfrm_migrate *m)
{
	struct xfrm_state *xc;

	xc = xfrm_state_clone(x);
	if (!xc)
		return NULL;

	memcpy(&xc->id.daddr, &m->new_daddr, sizeof(xc->id.daddr));
	memcpy(&xc->props.saddr, &m->new_saddr, sizeof(xc->props.saddr));

	/* add state */
	if (xfrm_addr_equal(&x->id.daddr, &m->new_daddr, m->new_family)) {
		/* a care is needed when the destination address of the
		   state is to be updated as it is a part of triplet */
		xfrm_state_insert(xc);
	} else {
		if (xfrm_state_add(xc) < 0)
			goto error;
	}

	return xc;
error:
	xfrm_state_put(xc);
	return NULL;
}
EXPORT_SYMBOL(xfrm_state_migrate);
#endif

int xfrm_state_update(struct xfrm_state *x)
{
	struct xfrm_state *x1, *to_put;
	int err;
	int use_spi = xfrm_id_proto_match(x->id.proto, IPSEC_PROTO_ANY);
	struct net *net = xs_net(x);

	to_put = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	// 查找内核中相应的xfrm, 找不到的话出错
	x1 = __xfrm_state_locate(x, use_spi, x->props.family);

	err = -ESRCH;
	if (!x1)
		goto out;
	
	// 如果该xfrm正在被IPSEC通道使用, 返回错误
	if (xfrm_state_kern(x1)) {
		to_put = x1;
		err = -EEXIST;
		goto out;
	}

	// 找到的x1本来就是在acquire状态, 直接将x插入系统xfrm表就行了
	if (x1->km.state == XFRM_STATE_ACQ) {
		__xfrm_state_insert(x);
		x = NULL;
	}
	err = 0;

out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	if (to_put)
		xfrm_state_put(to_put);

	if (err)
		return err;

	if (!x) {
		// 将找到的acquire状态的xfrm删除, 正确返回
		xfrm_state_delete(x1);
		xfrm_state_put(x1);
		return 0;
	}
	
	// 找到了x1, 状态也不是acquire, 即进行正常的更新x1中的数据为x的数据
	err = -EINVAL;
	spin_lock_bh(&x1->lock);
	if (likely(x1->km.state == XFRM_STATE_VALID)) {
		// 拷贝封装处理
		if (x->encap && x1->encap)
			memcpy(x1->encap, x->encap, sizeof(*x1->encap));
		// 拷贝care of的地址
		if (x->coaddr && x1->coaddr) {
			memcpy(x1->coaddr, x->coaddr, sizeof(*x1->coaddr));
		}
		// 没有SPI时拷贝选择子
		if (!use_spi && memcmp(&x1->sel, &x->sel, sizeof(x1->sel)))
			memcpy(&x1->sel, &x->sel, sizeof(x1->sel));
		// 拷贝生命期
		memcpy(&x1->lft, &x->lft, sizeof(x1->lft));
		x1->km.dying = 0;

		// 1秒钟的超时
		tasklet_hrtimer_start(&x1->mtimer, ktime_set(1, 0), HRTIMER_MODE_REL);
		if (x1->curlft.use_time)
			xfrm_state_check_expire(x1);

		err = 0;
		x->km.state = XFRM_STATE_DEAD;
		__xfrm_state_put(x);
	}
	spin_unlock_bh(&x1->lock);

	xfrm_state_put(x1);

	return err;
}
EXPORT_SYMBOL(xfrm_state_update);

int xfrm_state_check_expire(struct xfrm_state *x)
{
	// 当前生命期初始时间
	if (!x->curlft.use_time)
		x->curlft.use_time = get_seconds();

	// 检查使用该状态的包数字节数是否已经超过硬限制值
	if (x->curlft.bytes >= x->lft.hard_byte_limit ||
	    x->curlft.packets >= x->lft.hard_packet_limit) {
	    // 设置为状态到期
		x->km.state = XFRM_STATE_EXPIRED;
		// 立即调用定时器超时函数
		tasklet_hrtimer_start(&x->mtimer, ktime_set(0, 0), HRTIMER_MODE_REL);
		return -EINVAL;
	}

	// 检查使用该状态的包数字节数是否已经超过软限制值
	if (!x->km.dying &&
	    (x->curlft.bytes >= x->lft.soft_byte_limit ||
	     x->curlft.packets >= x->lft.soft_packet_limit)) {
	    // 已经超过软限制标志
		x->km.dying = 1;
		// 状态到期通知
		km_state_expired(x, 0, 0);
	}
	return 0;
}
EXPORT_SYMBOL(xfrm_state_check_expire);

// 只是__xfrm_state_lookup的包裹函数， 是根据SPI进行HASH后查找
struct xfrm_state *
xfrm_state_lookup(struct net *net, u32 mark, const xfrm_address_t *daddr, __be32 spi,
		  u8 proto, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __xfrm_state_lookup(net, mark, daddr, spi, proto, family);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return x;
}
EXPORT_SYMBOL(xfrm_state_lookup);

// 只是__xfrm_state_lookup_byaddr的包裹函数，是根据目的地址进行HASH后查找
struct xfrm_state *
xfrm_state_lookup_byaddr(struct net *net, u32 mark,
			 const xfrm_address_t *daddr, const xfrm_address_t *saddr,
			 u8 proto, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __xfrm_state_lookup_byaddr(net, mark, daddr, saddr, proto, family);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return x;
}
EXPORT_SYMBOL(xfrm_state_lookup_byaddr);


//ACQUIRE类型的SA的产生是内核发现数据需要进行保护, 但却没有找到相关的SA, 
//就向用户空间的IKE协商程序发送ACQUIRE请求, 并生成一个ACQUIRE类型的SA,
//如果用户空间协议协商成功会生成合适的SA传内核, 内核就会替换此ACQUIRE的SA,
//因此ACQUIRE不是真正可用的SA, 只是表示有此SA的需求, 等待用户空间程序协商结果。

// 只是__find_acq_core的包裹函数

struct xfrm_state *
xfrm_find_acq(struct net *net, const struct xfrm_mark *mark, u8 mode, u32 reqid,
	      u8 proto, const xfrm_address_t *daddr,
	      const xfrm_address_t *saddr, int create, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __find_acq_core(net, mark, family, mode, reqid, proto, daddr, saddr, create);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	return x;
}
EXPORT_SYMBOL(xfrm_find_acq);

#ifdef CONFIG_XFRM_SUB_POLICY
int
xfrm_tmpl_sort(struct xfrm_tmpl **dst, struct xfrm_tmpl **src, int n,
	       unsigned short family, struct net *net)
{
	int err = 0;
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		return -EAFNOSUPPORT;

	spin_lock_bh(&net->xfrm.xfrm_state_lock); /*FIXME*/
	if (afinfo->tmpl_sort)
		err = afinfo->tmpl_sort(dst, src, n);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_tmpl_sort);

int
xfrm_state_sort(struct xfrm_state **dst, struct xfrm_state **src, int n,
		unsigned short family)
{
	int err = 0;
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	struct net *net = xs_net(*src);

	if (!afinfo)
		return -EAFNOSUPPORT;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	if (afinfo->state_sort)
		err = afinfo->state_sort(dst, src, n);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	xfrm_state_put_afinfo(afinfo);
	return err;
}
EXPORT_SYMBOL(xfrm_state_sort);
#endif

/* Silly enough, but I'm lazy to build resolution list */

static struct xfrm_state *__xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq)
{
	int i;

	// 循环所有HASH链表
	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;

		// 循环链表
		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			// 序号比较, 状态类型也必须是XFRM_STATE_ACQ
			if (x->km.seq == seq &&
			    (mark & x->mark.m) == x->mark.v &&
			    x->km.state == XFRM_STATE_ACQ) {
				xfrm_state_hold(x);
				return x;
			}
		}
	}
	return NULL;
}

// 只是__xfrm_find_acq_byseq()的包裹函数
struct xfrm_state *xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __xfrm_find_acq_byseq(net, mark, seq);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return x;
}
EXPORT_SYMBOL(xfrm_find_acq_byseq);

u32 xfrm_get_acqseq(void)
{
	u32 res;
	static atomic_t acqseq;

	do {
		res = atomic_inc_return(&acqseq);
	} while (!res);

	return res;
}
EXPORT_SYMBOL(xfrm_get_acqseq);

int verify_spi_info(u8 proto, u32 min, u32 max)
{
	switch (proto) {
	case IPPROTO_AH:
	case IPPROTO_ESP:
		break;

	case IPPROTO_COMP:
		/* IPCOMP spi is 16-bits. */
		if (max >= 0x10000)
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	if (min > max)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(verify_spi_info);

int xfrm_alloc_spi(struct xfrm_state *x, u32 low, u32 high)
{
	struct net *net = xs_net(x);
	unsigned int h;
	struct xfrm_state *x0;
	int err = -ENOENT;
	__be32 minspi = htonl(low);
	__be32 maxspi = htonl(high);
	u32 mark = x->mark.v & x->mark.m;

	spin_lock_bh(&x->lock);
	if (x->km.state == XFRM_STATE_DEAD)
		goto unlock;

	err = 0;
	if (x->id.spi)
		goto unlock;

	err = -ENOENT;

	if (minspi == maxspi) {
		x0 = xfrm_state_lookup(net, mark, &x->id.daddr, minspi, x->id.proto, x->props.family);
		if (x0) {
			xfrm_state_put(x0);
			goto unlock;
		}
		x->id.spi = minspi;
	} else {
		u32 spi = 0;
		for (h = 0; h < high-low+1; h++) {
			spi = low + prandom_u32()%(high-low+1);
			x0 = xfrm_state_lookup(net, mark, &x->id.daddr, htonl(spi), x->id.proto, x->props.family);
			if (x0 == NULL) {
				x->id.spi = htonl(spi);
				break;
			}
			xfrm_state_put(x0);
		}
	}
	if (x->id.spi) {
		spin_lock_bh(&net->xfrm.xfrm_state_lock);
		h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto, x->props.family);
		hlist_add_head(&x->byspi, net->xfrm.state_byspi+h);
		spin_unlock_bh(&net->xfrm.xfrm_state_lock);

		err = 0;
	}

unlock:
	spin_unlock_bh(&x->lock);

	return err;
}
EXPORT_SYMBOL(xfrm_alloc_spi);

static bool __xfrm_state_filter_match(struct xfrm_state *x,
				      struct xfrm_address_filter *filter)
{
	if (filter) {
		if ((filter->family == AF_INET ||
		     filter->family == AF_INET6) &&
		    x->props.family != filter->family)
			return false;

		return addr_match(&x->props.saddr, &filter->saddr,
				  filter->splen) &&
		       addr_match(&x->id.daddr, &filter->daddr,
				  filter->dplen);
	}
	return true;
}

int xfrm_state_walk(struct net *net, struct xfrm_state_walk *walk,
		    int (*func)(struct xfrm_state *, int, void*),
		    void *data)
{
	struct xfrm_state *state;
	struct xfrm_state_walk *x;
	int err = 0;

	if (walk->seq != 0 && list_empty(&walk->all))
		return 0;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	//获取对象指针
	if (list_empty(&walk->all))
		x = list_first_entry(&net->xfrm.state_all, struct xfrm_state_walk, all);
	else
		x = list_entry(&walk->all, struct xfrm_state_walk, all);
	//对列表进行遍历
	list_for_each_entry_from(x, &net->xfrm.state_all, all) {
		if (x->state == XFRM_STATE_DEAD)
			continue;
		state = container_of(x, struct xfrm_state, km);
		if (!xfrm_id_proto_match(state->id.proto, walk->proto))
			continue;
		if (!__xfrm_state_filter_match(state, walk->filter))
			continue;
		err = func(state, walk->seq, data);
		if (err) {
			list_move_tail(&walk->all, &x->all);
			goto out;
		}
		//统计符合协议的SA
		walk->seq++;
	}
	if (walk->seq == 0) {
		err = -ENOENT;
		goto out;
	}
	list_del_init(&walk->all);
out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_state_walk);

void xfrm_state_walk_init(struct xfrm_state_walk *walk, u8 proto,
			  struct xfrm_address_filter *filter)
{
	INIT_LIST_HEAD(&walk->all);
	walk->proto = proto;
	walk->state = XFRM_STATE_DEAD;
	walk->seq = 0;
	walk->filter = filter;
}
EXPORT_SYMBOL(xfrm_state_walk_init);

void xfrm_state_walk_done(struct xfrm_state_walk *walk, struct net *net)
{
	kfree(walk->filter);

	if (list_empty(&walk->all))
		return;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	list_del(&walk->all);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_state_walk_done);

// 回放定时器超时回调函数
static void xfrm_replay_timer_handler(unsigned long data)
{
	struct xfrm_state *x = (struct xfrm_state *)data;

	spin_lock(&x->lock);

	// 只是状态为有效时才检查
	if (x->km.state == XFRM_STATE_VALID) {
		// 是否有NETLINK的监听者
		if (xfrm_aevent_is_on(xs_net(x)))
			// 通知回放超时事件
			x->repl->notify(x, XFRM_REPLAY_TIMEOUT);
		else
			// 设置通知推迟标志
			x->xflags |= XFRM_TIME_DEFER;
	}

	spin_unlock(&x->lock);
}

static LIST_HEAD(xfrm_km_list);

void km_policy_notify(struct xfrm_policy *xp, int dir, const struct km_event *c)
{
	struct xfrm_mgr *km;

	rcu_read_lock();
	// 状态的通知回调函数为notify_policy
	list_for_each_entry_rcu(km, &xfrm_km_list, list)
		if (km->notify_policy)
			km->notify_policy(xp, dir, c);
	rcu_read_unlock();
}

// SA状态通知回调
void km_state_notify(struct xfrm_state *x, const struct km_event *c)
{
	struct xfrm_mgr *km;
	rcu_read_lock();
	// 状态的通知回调函数为notify
	list_for_each_entry_rcu(km, &xfrm_km_list, list)
		if (km->notify)
			km->notify(x, c);
	rcu_read_unlock();
}

EXPORT_SYMBOL(km_policy_notify);
EXPORT_SYMBOL(km_state_notify);

void km_state_expired(struct xfrm_state *x, int hard, u32 portid)
{
	struct km_event c;

	c.data.hard = hard;
	c.portid = portid;
	c.event = XFRM_MSG_EXPIRE;
	km_state_notify(x, &c);
}

EXPORT_SYMBOL(km_state_expired);
/*
 * We send to all registered managers regardless of failure
 * We are happy with one success
*/
int km_query(struct xfrm_state *x, struct xfrm_tmpl *t, struct xfrm_policy *pol)
{
	int err = -EINVAL, acqret;
	struct xfrm_mgr *km;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		acqret = km->acquire(x, t, pol);
		if (!acqret)
			err = acqret;
	}
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_query);

int km_new_mapping(struct xfrm_state *x, xfrm_address_t *ipaddr, __be16 sport)
{
	int err = -EINVAL;
	struct xfrm_mgr *km;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->new_mapping)
			err = km->new_mapping(x, ipaddr, sport);
		if (!err)
			break;
	}
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_new_mapping);

void km_policy_expired(struct xfrm_policy *pol, int dir, int hard, u32 portid)
{
	struct km_event c;

	c.data.hard = hard;
	c.portid = portid;
	c.event = XFRM_MSG_POLEXPIRE;
	// 实际是调用策略通知回调
	km_policy_notify(pol, dir, &c);
}
EXPORT_SYMBOL(km_policy_expired);

#ifdef CONFIG_XFRM_MIGRATE
int km_migrate(const struct xfrm_selector *sel, u8 dir, u8 type,
	       const struct xfrm_migrate *m, int num_migrate,
	       const struct xfrm_kmaddress *k)
{
	int err = -EINVAL;
	int ret;
	struct xfrm_mgr *km;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->migrate) {
			ret = km->migrate(sel, dir, type, m, num_migrate, k);
			if (!ret)
				err = ret;
		}
	}
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_migrate);
#endif

int km_report(struct net *net, u8 proto, struct xfrm_selector *sel, xfrm_address_t *addr)
{
	int err = -EINVAL;
	int ret;
	struct xfrm_mgr *km;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->report) {
			ret = km->report(net, proto, sel, addr);
			if (!ret)
				err = ret;
		}
	}
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_report);

bool km_is_alive(const struct km_event *c)
{
	struct xfrm_mgr *km;
	bool is_alive = false;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->is_alive && km->is_alive(c)) {
			is_alive = true;
			break;
		}
	}
	rcu_read_unlock();

	return is_alive;
}
EXPORT_SYMBOL(km_is_alive);

int xfrm_user_policy(struct sock *sk, int optname, u8 __user *optval, int optlen)
{
	int err;
	u8 *data;
	struct xfrm_mgr *km;
	struct xfrm_policy *pol = NULL;

#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return -EOPNOTSUPP;
#endif

	if (!optval && !optlen) {
		xfrm_sk_policy_insert(sk, XFRM_POLICY_IN, NULL);
		xfrm_sk_policy_insert(sk, XFRM_POLICY_OUT, NULL);
		__sk_dst_reset(sk);
		return 0;
	}

	if (optlen <= 0 || optlen > PAGE_SIZE)
		return -EMSGSIZE;

	data = kmalloc(optlen, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	err = -EFAULT;
	if (copy_from_user(data, optval, optlen))
		goto out;

	err = -EINVAL;
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		pol = km->compile_policy(sk, optname, data,
					 optlen, &err);
		if (err >= 0)
			break;
	}
	rcu_read_unlock();

	if (err >= 0) {
		xfrm_sk_policy_insert(sk, err, pol);
		xfrm_pol_put(pol);
		err = 0;
	}

out:
	kfree(data);
	return err;
}
EXPORT_SYMBOL(xfrm_user_policy);

static DEFINE_SPINLOCK(xfrm_km_lock);

// 登记xfrm_mgr结构, 就是将结构挂到xfrm_km_list链表
int xfrm_register_km(struct xfrm_mgr *km)
{
	spin_lock_bh(&xfrm_km_lock);
	// 将结构挂接到xfrm_km_list链表
	list_add_tail_rcu(&km->list, &xfrm_km_list);
	spin_unlock_bh(&xfrm_km_lock);
	return 0;
}
EXPORT_SYMBOL(xfrm_register_km);

// 拆除xfrm_mgr结构, 就是将结构从xfrm_km_list链表拆除
int xfrm_unregister_km(struct xfrm_mgr *km)
{
	spin_lock_bh(&xfrm_km_lock);
	list_del_rcu(&km->list);
	spin_unlock_bh(&xfrm_km_lock);
	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(xfrm_unregister_km);

int xfrm_state_register_afinfo(struct xfrm_state_afinfo *afinfo)
{
	int err = 0;
	if (unlikely(afinfo == NULL))
		return -EINVAL;
	if (unlikely(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	spin_lock_bh(&xfrm_state_afinfo_lock);
	if (unlikely(xfrm_state_afinfo[afinfo->family] != NULL))
		err = -ENOBUFS;
	else
		rcu_assign_pointer(xfrm_state_afinfo[afinfo->family], afinfo);
	spin_unlock_bh(&xfrm_state_afinfo_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_state_register_afinfo);

int xfrm_state_unregister_afinfo(struct xfrm_state_afinfo *afinfo)
{
	int err = 0;
	if (unlikely(afinfo == NULL))
		return -EINVAL;
	if (unlikely(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	spin_lock_bh(&xfrm_state_afinfo_lock);
	if (likely(xfrm_state_afinfo[afinfo->family] != NULL)) {
		if (unlikely(xfrm_state_afinfo[afinfo->family] != afinfo))
			err = -EINVAL;
		else
			RCU_INIT_POINTER(xfrm_state_afinfo[afinfo->family], NULL);
	}
	spin_unlock_bh(&xfrm_state_afinfo_lock);
	synchronize_rcu();
	return err;
}
EXPORT_SYMBOL(xfrm_state_unregister_afinfo);

// 协议信息结构加写锁, 返回指定的协议信息结构, 错误时返回NULL
struct xfrm_state_afinfo *xfrm_state_get_afinfo(unsigned int family)
{
	struct xfrm_state_afinfo *afinfo;
	if (unlikely(family >= NPROTO))
		return NULL;
	rcu_read_lock();
	// 获取指定协议位置处的协议信息结构
	afinfo = rcu_dereference(xfrm_state_afinfo[family]);
	// 如果该协议信息结构不存在, 解锁
	if (unlikely(!afinfo))
		rcu_read_unlock();
	return afinfo;
}

// 协议信息结构解写锁
void xfrm_state_put_afinfo(struct xfrm_state_afinfo *afinfo)
{
	rcu_read_unlock();
}

/* Temporarily located here until net/xfrm/xfrm_tunnel.c is created */
void xfrm_state_delete_tunnel(struct xfrm_state *x)
{
	if (x->tunnel) {
		struct xfrm_state *t = x->tunnel;

		if (atomic_read(&t->tunnel_users) == 2)
			xfrm_state_delete(t);
		atomic_dec(&t->tunnel_users);
		xfrm_state_put(t);
		x->tunnel = NULL;
	}
}
EXPORT_SYMBOL(xfrm_state_delete_tunnel);

int xfrm_state_mtu(struct xfrm_state *x, int mtu)
{
	int res;

	spin_lock_bh(&x->lock);
	if (x->km.state == XFRM_STATE_VALID &&
	    x->type && x->type->get_mtu)
		res = x->type->get_mtu(x, mtu);
	else
		res = mtu - x->props.header_len;
	spin_unlock_bh(&x->lock);
	return res;
}

int __xfrm_init_state(struct xfrm_state *x, bool init_replay)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode *inner_mode;
	int family = x->props.family;
	int err;

	err = -EAFNOSUPPORT;
	// 获取协议族信息结构
	afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		goto error;

	err = 0;
	// 协议族信息初始化
	if (afinfo->init_flags)
		err = afinfo->init_flags(x);

	xfrm_state_put_afinfo(afinfo);

	if (err)
		goto error;

	err = -EPROTONOSUPPORT;

	if (x->sel.family != AF_UNSPEC) {
		inner_mode = xfrm_get_mode(x->props.mode, x->sel.family);
		if (inner_mode == NULL)
			goto error;

		if (!(inner_mode->flags & XFRM_MODE_FLAG_TUNNEL) &&
		    family != x->sel.family) {
			xfrm_put_mode(inner_mode);
			goto error;
		}

		x->inner_mode = inner_mode;
	} else {
		struct xfrm_mode *inner_mode_iaf;
		int iafamily = AF_INET;

		inner_mode = xfrm_get_mode(x->props.mode, x->props.family);
		if (inner_mode == NULL)
			goto error;

		if (!(inner_mode->flags & XFRM_MODE_FLAG_TUNNEL)) {
			xfrm_put_mode(inner_mode);
			goto error;
		}
		x->inner_mode = inner_mode;

		if (x->props.family == AF_INET)
			iafamily = AF_INET6;

		inner_mode_iaf = xfrm_get_mode(x->props.mode, iafamily);
		if (inner_mode_iaf) {
			if (inner_mode_iaf->flags & XFRM_MODE_FLAG_TUNNEL)
				x->inner_mode_iaf = inner_mode_iaf;
			else
				xfrm_put_mode(inner_mode_iaf);
		}
	}

	x->type = xfrm_get_type(x->id.proto, family);
	if (x->type == NULL)
		goto error;

	// 获取可用协议(ah, esp, ipcomp, ip)
	err = x->type->init_state(x);
	if (err)
		goto error;

	// 获取可用模式(transport, tunnel)
	x->outer_mode = xfrm_get_mode(x->props.mode, family);
	if (x->outer_mode == NULL) {
		err = -EPROTONOSUPPORT;
		goto error;
	}

	if (init_replay) {
		err = xfrm_init_replay(x);
		if (err)
			goto error;
	}

	x->km.state = XFRM_STATE_VALID;

error:
	return err;
}

EXPORT_SYMBOL(__xfrm_init_state);

int xfrm_init_state(struct xfrm_state *x)
{
	return __xfrm_init_state(x, true);
}

EXPORT_SYMBOL(xfrm_init_state);

int __net_init xfrm_state_init(struct net *net)
{
	unsigned int sz;

	INIT_LIST_HEAD(&net->xfrm.state_all);
	
	//初始HASH表不大, 每个HASH中初始化为8个链表,
	//但随着状态数量的增加会动态增加HASH表数量
	sz = sizeof(struct hlist_head) * 8;

	//建立3组HASH, 分别按SA的源地址, 目的地址和SPI值
	net->xfrm.state_bydst = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bydst)
		goto out_bydst;
	net->xfrm.state_bysrc = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bysrc)
		goto out_bysrc;
	net->xfrm.state_byspi = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_byspi)
		goto out_byspi;

	// xfrm_state_hmask初始值为=7, 计算出的HASH值与该值与来得到链表号
	net->xfrm.state_hmask = ((sz / sizeof(struct hlist_head)) - 1);

	net->xfrm.state_num = 0;
	INIT_WORK(&net->xfrm.state_hash_work, xfrm_hash_resize);
	INIT_HLIST_HEAD(&net->xfrm.state_gc_list);
	// 初始化工作队列work_queue, 完成对状态垃圾的搜集和释放
	INIT_WORK(&net->xfrm.state_gc_work, xfrm_state_gc_task);
	spin_lock_init(&net->xfrm.xfrm_state_lock);
	return 0;

out_byspi:
	xfrm_hash_free(net->xfrm.state_bysrc, sz);
out_bysrc:
	xfrm_hash_free(net->xfrm.state_bydst, sz);
out_bydst:
	return -ENOMEM;
}

void xfrm_state_fini(struct net *net)
{
	unsigned int sz;

	flush_work(&net->xfrm.state_hash_work);
	xfrm_state_flush(net, IPSEC_PROTO_ANY, false);
	flush_work(&net->xfrm.state_gc_work);

	WARN_ON(!list_empty(&net->xfrm.state_all));

	sz = (net->xfrm.state_hmask + 1) * sizeof(struct hlist_head);
	WARN_ON(!hlist_empty(net->xfrm.state_byspi));
	xfrm_hash_free(net->xfrm.state_byspi, sz);
	WARN_ON(!hlist_empty(net->xfrm.state_bysrc));
	xfrm_hash_free(net->xfrm.state_bysrc, sz);
	WARN_ON(!hlist_empty(net->xfrm.state_bydst));
	xfrm_hash_free(net->xfrm.state_bydst, sz);
}

#ifdef CONFIG_AUDITSYSCALL
static void xfrm_audit_helper_sainfo(struct xfrm_state *x,
				     struct audit_buffer *audit_buf)
{
	struct xfrm_sec_ctx *ctx = x->security;
	u32 spi = ntohl(x->id.spi);

	if (ctx)
		audit_log_format(audit_buf, " sec_alg=%u sec_doi=%u sec_obj=%s",
				 ctx->ctx_alg, ctx->ctx_doi, ctx->ctx_str);

	switch (x->props.family) {
	case AF_INET:
		audit_log_format(audit_buf, " src=%pI4 dst=%pI4",
				 &x->props.saddr.a4, &x->id.daddr.a4);
		break;
	case AF_INET6:
		audit_log_format(audit_buf, " src=%pI6 dst=%pI6",
				 x->props.saddr.a6, x->id.daddr.a6);
		break;
	}

	audit_log_format(audit_buf, " spi=%u(0x%x)", spi, spi);
}

static void xfrm_audit_helper_pktinfo(struct sk_buff *skb, u16 family,
				      struct audit_buffer *audit_buf)
{
	const struct iphdr *iph4;
	const struct ipv6hdr *iph6;

	switch (family) {
	case AF_INET:
		iph4 = ip_hdr(skb);
		audit_log_format(audit_buf, " src=%pI4 dst=%pI4",
				 &iph4->saddr, &iph4->daddr);
		break;
	case AF_INET6:
		iph6 = ipv6_hdr(skb);
		audit_log_format(audit_buf,
				 " src=%pI6 dst=%pI6 flowlbl=0x%x%02x%02x",
				 &iph6->saddr, &iph6->daddr,
				 iph6->flow_lbl[0] & 0x0f,
				 iph6->flow_lbl[1],
				 iph6->flow_lbl[2]);
		break;
	}
}

void xfrm_audit_state_add(struct xfrm_state *x, int result, bool task_valid)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SAD-add");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_usrinfo(task_valid, audit_buf);
	xfrm_audit_helper_sainfo(x, audit_buf);
	audit_log_format(audit_buf, " res=%u", result);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_add);

void xfrm_audit_state_delete(struct xfrm_state *x, int result, bool task_valid)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SAD-delete");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_usrinfo(task_valid, audit_buf);
	xfrm_audit_helper_sainfo(x, audit_buf);
	audit_log_format(audit_buf, " res=%u", result);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_delete);

void xfrm_audit_state_replay_overflow(struct xfrm_state *x,
				      struct sk_buff *skb)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-replay-overflow");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	/* don't record the sequence number because it's inherent in this kind
	 * of audit message */
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x)", spi, spi);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_replay_overflow);

void xfrm_audit_state_replay(struct xfrm_state *x,
			     struct sk_buff *skb, __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-replayed-pkt");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_replay);

void xfrm_audit_state_notfound_simple(struct sk_buff *skb, u16 family)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SA-notfound");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, family, audit_buf);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_notfound_simple);

void xfrm_audit_state_notfound(struct sk_buff *skb, u16 family,
			       __be32 net_spi, __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-notfound");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, family, audit_buf);
	spi = ntohl(net_spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_notfound);

void xfrm_audit_state_icvfail(struct xfrm_state *x,
			      struct sk_buff *skb, u8 proto)
{
	struct audit_buffer *audit_buf;
	__be32 net_spi;
	__be32 net_seq;

	audit_buf = xfrm_audit_start("SA-icv-failure");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	if (xfrm_parse_spi(skb, proto, &net_spi, &net_seq) == 0) {
		u32 spi = ntohl(net_spi);
		audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
				 spi, spi, ntohl(net_seq));
	}
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_icvfail);
#endif /* CONFIG_AUDITSYSCALL */
