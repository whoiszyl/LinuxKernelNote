/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic INET transport hashtables
 *
 * Authors:	Lotsa people, from code originally in tcp
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/secure_seq.h>
#include <net/ip.h>

static unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
				 const __u16 lport, const __be32 faddr,
				 const __be16 fport)
{
	static u32 inet_ehash_secret __read_mostly;

	net_get_random_once(&inet_ehash_secret, sizeof(inet_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      inet_ehash_secret + net_hash_mix(net));
}


static unsigned int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->inet_rcv_saddr;
	const __u16 lport = inet->inet_num;
	const __be32 faddr = inet->inet_daddr;
	const __be16 fport = inet->inet_dport;
	struct net *net = sock_net(sk);

	return inet_ehashfn(net, laddr, lport, faddr, fport);
}

/*
 * Allocate and initialize a new local port bind bucket.
 * The bindhash mutex for snum's hash chain must be held here.
 */
 /*
 * 用来在bind_bucket_cachep高速缓存中分配bind端口实例，
 * 设置后将其添加到inet_bind_hashbucket散列表中
 */ //cachep见tcp_hashinfo
struct inet_bind_bucket *inet_bind_bucket_create(struct kmem_cache *cachep,
						 struct net *net,
						 struct inet_bind_hashbucket *head,
						 const unsigned short snum)
{
	struct inet_bind_bucket *tb = kmem_cache_alloc(cachep, GFP_ATOMIC);

	if (tb != NULL) {
		/* 指定网络命名空间 */
		write_pnet(&tb->ib_net, hold_net(net));
		/* 指定绑定端口 */
		tb->port      = snum;
		tb->fastreuse = 0;
		tb->fastreuseport = 0;
		/* 初始化owners哈希链表 */
		tb->num_owners = 0;
		INIT_HLIST_HEAD(&tb->owners);
		/* 把此inet_bind_bucket实例添加到哈希桶中 */
		hlist_add_head(&tb->node, &head->chain);
	}
	return tb;
}

/*
 * Caller must hold hashbucket lock for this tb with local BH disabled
 *//*
 * 将指定的bind端口实例从inet_bind_hashbucket散列表中删除并释放
 */
void inet_bind_bucket_destroy(struct kmem_cache *cachep, struct inet_bind_bucket *tb)
{
	if (hlist_empty(&tb->owners)) {
		__hlist_del(&tb->node);
		release_net(ib_net(tb));
		kmem_cache_free(cachep, tb);
	}
}

//将传输控制块与绑定端口信息关联，完成绑定。把tb与sk关联起来
void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
		    const unsigned short snum)
{
	/* 指向tcp_hashinfo */
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;

	/* 增加总的绑定次数 */
	atomic_inc(&hashinfo->bsockets);

	/* 保存绑定的端口 */
	inet_sk(sk)->inet_num = snum;
	/* 把此sock链入tb->owners哈希链表中 */
	sk_add_bind_node(sk, &tb->owners);
	/* 增加端口绑定次数 */
	tb->num_owners++;
	/* 把此tb作为icsk成员icsk_bind_hash */
	inet_csk(sk)->icsk_bind_hash = tb;
}

/*
 * Get rid of any references to a local port held by the given sock.
 */
static void __inet_put_port(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	const int bhash = inet_bhashfn(sock_net(sk), inet_sk(sk)->inet_num,
			hashinfo->bhash_size);
	struct inet_bind_hashbucket *head = &hashinfo->bhash[bhash];
	struct inet_bind_bucket *tb;

	atomic_dec(&hashinfo->bsockets);

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	__sk_del_bind_node(sk);
	tb->num_owners--;
	inet_csk(sk)->icsk_bind_hash = NULL;
	inet_sk(sk)->inet_num = 0;
	inet_bind_bucket_destroy(hashinfo->bind_bucket_cachep, tb);
	spin_unlock(&head->lock);
}

void inet_put_port(struct sock *sk)
{
	local_bh_disable();
	__inet_put_port(sk);
	local_bh_enable();
}
EXPORT_SYMBOL(inet_put_port);

int __inet_inherit_port(struct sock *sk, struct sock *child)
{
	struct inet_hashinfo *table = sk->sk_prot->h.hashinfo;
	unsigned short port = inet_sk(child)->inet_num;
	const int bhash = inet_bhashfn(sock_net(sk), port,
			table->bhash_size);
	struct inet_bind_hashbucket *head = &table->bhash[bhash];
	struct inet_bind_bucket *tb;

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	if (tb->port != port) {
		/* NOTE: using tproxy and redirecting skbs to a proxy
		 * on a different listener port breaks the assumption
		 * that the listener socket's icsk_bind_hash is the same
		 * as that of the child socket. We have to look up or
		 * create a new bind bucket for the child here. */
		inet_bind_bucket_for_each(tb, &head->chain) {
			if (net_eq(ib_net(tb), sock_net(sk)) &&
			    tb->port == port)
				break;
		}
		if (!tb) {
			tb = inet_bind_bucket_create(table->bind_bucket_cachep,
						     sock_net(sk), head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				return -ENOMEM;
			}
		}
	}
	inet_bind_hash(child, tb, port);
	spin_unlock(&head->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(__inet_inherit_port);

static inline int compute_score(struct sock *sk, struct net *net,
				const unsigned short hnum, const __be32 daddr,
				const int dif)
{
	int score = -1;
	struct inet_sock *inet = inet_sk(sk);

	if (net_eq(sock_net(sk), net) && inet->inet_num == hnum &&
			!ipv6_only_sock(sk)) {
		__be32 rcv_saddr = inet->inet_rcv_saddr;
		score = sk->sk_family == PF_INET ? 2 : 1;
		if (rcv_saddr) {
			if (rcv_saddr != daddr)
				return -1;
			score += 4;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score += 4;
		}
	}
	return score;
}

/*
 * Don't inline this cruft. Here are some nice properties to exploit here. The
 * BSD API does not allow a listening sock to specify the remote port nor the
 * remote address for the connection. So always assume those are both
 * wildcarded during the search since they can never be otherwise.
 */


struct sock *__inet_lookup_listener(struct net *net,
				    struct inet_hashinfo *hashinfo,
				    const __be32 saddr, __be16 sport,
				    const __be32 daddr, const unsigned short hnum,
				    const int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned int hash = inet_lhashfn(net, hnum);
	struct inet_listen_hashbucket *ilb = &hashinfo->listening_hash[hash];
	int score, hiscore, matches = 0, reuseport = 0;
	u32 phash = 0;

	rcu_read_lock();
begin:
	result = NULL;
	hiscore = 0;
	sk_nulls_for_each_rcu(sk, node, &ilb->head) {
		score = compute_score(sk, net, hnum, daddr, dif);
		if (score > hiscore) {
			result = sk;
			hiscore = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				phash = inet_ehashfn(net, daddr, hnum,
						     saddr, sport);
				matches = 1;
			}
		} else if (score == hiscore && reuseport) {
			matches++;
			if (reciprocal_scale(phash, matches) == 0)
				result = sk;
			phash = next_pseudo_random32(phash);
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
			result = NULL;
		else if (unlikely(compute_score(result, net, hnum, daddr,
				  dif) < hiscore)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(__inet_lookup_listener);

/* All sockets share common refcount, but have different destructors */
void sock_gen_put(struct sock *sk)
{
	if (!atomic_dec_and_test(&sk->sk_refcnt))
		return;

	if (sk->sk_state == TCP_TIME_WAIT)
		inet_twsk_free(inet_twsk(sk));
	else
		sk_free(sk);
}
EXPORT_SYMBOL_GPL(sock_gen_put);

struct sock *__inet_lookup_established(struct net *net,
				  struct inet_hashinfo *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 hnum,
				  const int dif)
{
	INET_ADDR_COOKIE(acookie, saddr, daddr);
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	const struct hlist_nulls_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
	unsigned int slot = hash & hashinfo->ehash_mask;
	struct inet_ehash_bucket *head = &hashinfo->ehash[slot];

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(sk, node, &head->chain) {
		if (sk->sk_hash != hash)
			continue;
		if (likely(INET_MATCH(sk, net, acookie,
				      saddr, daddr, ports, dif))) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt)))
				goto out;
			if (unlikely(!INET_MATCH(sk, net, acookie,
						 saddr, daddr, ports, dif))) {
				sock_gen_put(sk);
				goto begin;
			}
			goto found;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;
out:
	sk = NULL;
found:
	rcu_read_unlock();
	return sk;
}
EXPORT_SYMBOL_GPL(__inet_lookup_established);

/* called with local bh disabled 
 * 通过__inet_check_established()来检测该端口能否被复用，
 * 动态绑定的端口只能复用在TIME_WAIT状态下绑定的端口，
 * 当然还需要启用tcp_tw_reuse
 */
static int __inet_check_established(struct inet_timewait_death_row *death_row,
				    struct sock *sk, __u16 lport,
				    struct inet_timewait_sock **twp)
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	struct inet_sock *inet = inet_sk(sk);
	__be32 daddr = inet->inet_rcv_saddr;
	__be32 saddr = inet->inet_daddr;
	int dif = sk->sk_bound_dev_if;
	INET_ADDR_COOKIE(acookie, saddr, daddr);
	const __portpair ports = INET_COMBINED_PORTS(inet->inet_dport, lport);
	struct net *net = sock_net(sk);
	unsigned int hash = inet_ehashfn(net, daddr, lport,
					 saddr, inet->inet_dport);
	struct inet_ehash_bucket *head = inet_ehash_bucket(hinfo, hash);
	spinlock_t *lock = inet_ehash_lockp(hinfo, hash);
	struct sock *sk2;
	const struct hlist_nulls_node *node;
	struct inet_timewait_sock *tw = NULL;
	int twrefcnt = 0;

	spin_lock(lock);

	sk_nulls_for_each(sk2, node, &head->chain) {
		if (sk2->sk_hash != hash)
			continue;

		if (likely(INET_MATCH(sk2, net, acookie,
					 saddr, daddr, ports, dif))) {
			if (sk2->sk_state == TCP_TIME_WAIT) {
				tw = inet_twsk(sk2);
				if (twsk_unique(sk, sk2, twp))
					break;
			}
			goto not_unique;
		}
	}

	/* Must record num and sport now. Otherwise we will see
	 * in hash table socket with a funny identity.
	 */
	inet->inet_num = lport;
	inet->inet_sport = htons(lport);
	sk->sk_hash = hash;
	WARN_ON(!sk_unhashed(sk));
	__sk_nulls_add_node_rcu(sk, &head->chain);
	if (tw) {
		twrefcnt = inet_twsk_unhash(tw);
		NET_INC_STATS_BH(net, LINUX_MIB_TIMEWAITRECYCLED);
	}
	spin_unlock(lock);
	if (twrefcnt)
		inet_twsk_put(tw);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

	if (twp) {
		*twp = tw;
	} else if (tw) {
		/* Silly. Should hash-dance instead... */
		inet_twsk_deschedule(tw, death_row);

		inet_twsk_put(tw);
	}
	return 0;

not_unique:
	spin_unlock(lock);
	return -EADDRNOTAVAIL;
}

static inline u32 inet_sk_port_offset(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	return secure_ipv4_port_ephemeral(inet->inet_rcv_saddr,
					  inet->inet_daddr,
					  inet->inet_dport);
}


//把sk添加到tcp_hashinfo的ehash中
int __inet_hash_nolisten(struct sock *sk, struct inet_timewait_sock *tw)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct hlist_nulls_head *list;
	spinlock_t *lock;
	struct inet_ehash_bucket *head;
	int twrefcnt = 0;

	WARN_ON(!sk_unhashed(sk));

	sk->sk_hash = inet_sk_ehashfn(sk);
	head = inet_ehash_bucket(hashinfo, sk->sk_hash);
	list = &head->chain;
	lock = inet_ehash_lockp(hashinfo, sk->sk_hash);

	spin_lock(lock);
	__sk_nulls_add_node_rcu(sk, list);
	if (tw) {
		WARN_ON(sk->sk_hash != tw->tw_hash);
		twrefcnt = inet_twsk_unhash(tw);
	}
	spin_unlock(lock);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	return twrefcnt;
}
EXPORT_SYMBOL_GPL(__inet_hash_nolisten);

/* 把sock链接入tcp_hashinfo->listening_hash哈希表 */
static void __inet_hash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_listen_hashbucket *ilb;

	/* sock不处于listen状态时 */
	if (sk->sk_state != TCP_LISTEN) {  //把sk添加到tcp_hashinfo的ehash中
		/* 这里对应的是已建立的连接 */
		__inet_hash_nolisten(sk, NULL);
		return;
	}

    //把sk添加到tcp_hashinfo的listening_hash中
	WARN_ON(!sk_unhashed(sk));
	/* 根据端口号，找到对应的监听哈希桶 */
	ilb = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)];

	spin_lock(&ilb->lock);
	/* 把sock放入监听哈希桶的头，链接节点为sk->sk_nulls_node */
	__sk_nulls_add_node_rcu(sk, &ilb->head);
	/* 此CPU上该协议的使用数加一 */
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	spin_unlock(&ilb->lock);
}

////将该传输控制块socket添加到tcp_hashinfo的对应hash中
void inet_hash(struct sock *sk)
{
	if (sk->sk_state != TCP_CLOSE) {
		local_bh_disable();
		__inet_hash(sk);
		local_bh_enable();
	}
}
EXPORT_SYMBOL_GPL(inet_hash);

void inet_unhash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	spinlock_t *lock;
	int done;

	if (sk_unhashed(sk))
		return;

	if (sk->sk_state == TCP_LISTEN)
		lock = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)].lock;
	else
		lock = inet_ehash_lockp(hashinfo, sk->sk_hash);

	spin_lock_bh(lock);
	done = __sk_nulls_del_node_init_rcu(sk);
	if (done)
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	spin_unlock_bh(lock);
}
EXPORT_SYMBOL_GPL(inet_unhash);

/*从这个函数的实现可以看出，主要是由于可用的端口被占满了，所以找不到一个可用的端口，导致连接失败。
运行netstat可以发现确实存在很多TIME_WAIT状态的socket，这些socket将可用端口占满了。
[root@test miuistorage-dev]# netstat -n | awk '/^tcp/ {++state[$NF]} END {for(key in state) 
print key,"\t",state[key]}'
TIME_WAIT        26837
ESTABLISHED      30 
*/
//参考:http://www.yunstorage.org/%E7%BD%91%E7%BB%9C%E7%BC%96%E7%A8%8B/socket-connect-error-99cannot-assign-requested-address/
//如果快速回收TIME_WAIT状态的端口
int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		int (*hash)(struct sock *sk, struct inet_timewait_sock *twp))
{
    /* 通过tcp_death_row中的成员hashinfo，获取指向TCP中散列表管理器hashinfo。 */
	struct inet_hashinfo *hinfo = death_row->hashinfo;//也就是tcp_hashinfo
	const unsigned short snum = inet_sk(sk)->inet_num;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sock_net(sk);
	int twrefcnt = 1;

	if (!snum) {//如果是应用程序bind的时候指定了端口，则无需端口复用检查。
		int i, remaining, low, high, port;
		static u32 hint;
		u32 offset = hint + port_offset;
		struct inet_timewait_sock *tw = NULL;

		inet_get_local_port_range(net, &low, &high);
		remaining = (high - low) + 1;

		local_bh_disable();
		for (i = 1; i <= remaining; i++) {
		    /*
			 * 在动态端口范围内，把通过源地址、目的地址和
			 * 目的端口计算得到的值作为端口号初始值。offset从这里inet_sk_port_offset来
			 */
			port = low + (i + offset) % remaining;
			if (inet_is_local_reserved_port(net, port))
				continue;
			head = &hinfo->bhash[inet_bhashfn(net, port,
					hinfo->bhash_size)]; //bhash计算出的是key键值， head为找到的hash桶中的关键字表头
			spin_lock(&head->lock);

			/* Does not bother with rcv_saddr checks,
			 * because the established check is already
			 * unique enough.
			 */
			 /*
			 * 在inet_bind_hashbucket散列表中查找该端口是否已被使用。
			 * 如果已被使用，则需要检测能否被复用。
			 * 在动态选择端口不允许复用通过bind系统调用绑定的
			 * 端口，无论该端口能否被复用，都不能被复用，需
			 * 重新选择。见应用层listen的时候，在内核中分配检查端口函数inet_csk_get_port
			 * 通过__inet_check_established()来检测该端口能否被复用，
			 * 动态绑定的端口只能复用在TIME_WAIT状态下绑定的端口，
			 * 当然还需要启用tcp_tw_reuse。若通过检测，则跳转到
			 * ok处进行绑定，否则递增端口号，继续下一轮确认。
			 */
			inet_bind_bucket_for_each(tb, &head->chain) {
				if (net_eq(ib_net(tb), net) &&
				    tb->port == port) {
					if (tb->fastreuse >= 0 ||
					    tb->fastreuseport >= 0)
						goto next_port;
					WARN_ON(hlist_empty(&tb->owners));
					if (!check_established(death_row, sk,
								port, &tw)) //这里调用的是__inet_check_established()函数
						goto ok;
					goto next_port;
				}
			}
            /*
			 * 如果该端口号未使用，则可使用该端口，为该端口创建信息块并将其添加到bhash散列表中。创建信息块失败，返回EADDRNOTAVAIL错误号。
			 */
			tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					net, head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				break;
			}
			tb->fastreuse = -1;
			tb->fastreuseport = -1;
			goto ok;

		next_port:
			spin_unlock(&head->lock);
		}
		local_bh_enable();

		return -EADDRNOTAVAIL;

ok:
		hint += i;

		/* Head lock still held and bh's disabled */
		/*
		 * 将传输控制块与绑定端口信息关联，完成绑定。
		 */
		inet_bind_hash(sk, tb, port);
		/*
		 * 如果该传输控制块未添加到或已脱离
		 * ehash散列表，则需添加到该散列表中。
		 */
		if (sk_unhashed(sk)) {
			inet_sk(sk)->inet_sport = htons(port);
			twrefcnt += hash(sk, tw);//这里调用的是__inet_hash_nolisten()函数
		}
		if (tw)
			twrefcnt += inet_twsk_bind_unhash(tw, hinfo);
		spin_unlock(&head->lock);

        /*
		 * 如果与一个TIME_WAIT状态的套接字复用该端口，
		 * 则需删除释放该TIMEWAIT状态的套接字。绑定
		 * 完成后返回。
		 */
		if (tw) {
			inet_twsk_deschedule(tw, death_row);
			while (twrefcnt) {
				twrefcnt--;
				inet_twsk_put(tw);
			}
		}

		ret = 0;
		goto out;
	}

    /*
	 * 对于已绑定端口的传输控制块和绑定信息块需要
	 * 相应确认。确认绑定端口信息块与之相绑定的传
	 * 输控制块是不是该传输控制块，该传输控制块指
	 * 向绑定信息块的指针是否有效。不然需要重新通
	 * 过__inet_check_established()来检测该端口能否被使用。
	 */
	head = &hinfo->bhash[inet_bhashfn(net, snum, hinfo->bhash_size)];
	tb  = inet_csk(sk)->icsk_bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		hash(sk, NULL);//这里调用的是__inet_hash_nolisten()函数
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = check_established(death_row, sk, snum, NULL);//这里调用的是__inet_check_established()函数
out:
		local_bh_enable();
		return ret;
	}
}

/*
 * Bind a port for a connect operation and hash it.
 */
 /*
 * inet_hash_connect()主要用于在主动连接时动态绑定一个端口。
 * 1)在动态端口范围内，从通过源地址、目的地址和目的端口
 *    计算得到的偏移开始，确认一个可用的端口号
 * 2)如果该端口已使用，则进而确定该端口是否能使用，不能
 *    则递增端口号继续确认；能使用则可用端口已找到。
 * 3)如果该端口未使用，则可使用该端口
 * 4)最后完成绑定过程。
 */ 
 /* 动态绑定一个本地端口，并将传输控制块添加到ehash散列表中。由于在动态分配端口时，如果找到的是已使用的端口，则
	 * 需在TIME_WAIT状态中进行相应的确认，因此调用inet_hash_connect()时需用timewait传输控制块和参数管理器tcp_death_row作为参数。*/
 //这里面会把sk添加到ehash中，虽然连接还没建立起来。该函数外的tcp_connect才是真正发送SYN报文的地方
int inet_hash_connect(struct inet_timewait_death_row *death_row,
		      struct sock *sk)
{
	return __inet_hash_connect(death_row, sk, inet_sk_port_offset(sk),
			__inet_check_established, __inet_hash_nolisten);
}
EXPORT_SYMBOL_GPL(inet_hash_connect);

void inet_hashinfo_init(struct inet_hashinfo *h)
{
	int i;

	atomic_set(&h->bsockets, 0);
	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		spin_lock_init(&h->listening_hash[i].lock);
		INIT_HLIST_NULLS_HEAD(&h->listening_hash[i].head,
				      i + LISTENING_NULLS_BASE);
		}
}
EXPORT_SYMBOL_GPL(inet_hashinfo_init);
