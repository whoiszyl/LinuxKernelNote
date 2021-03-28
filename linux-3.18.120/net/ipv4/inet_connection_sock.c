/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>

#ifdef INET_CSK_DEBUG
const char inet_csk_timer_bug_msg[] = "inet_csk BUG: unknown timer value\n";
EXPORT_SYMBOL(inet_csk_timer_bug_msg);
#endif

/*
 * 获取自动分配端口的区间
 */
void inet_get_local_port_range(struct net *net, int *low, int *high)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&net->ipv4.ip_local_ports.lock);

		*low = net->ipv4.ip_local_ports.range[0];
		*high = net->ipv4.ip_local_ports.range[1];
	} while (read_seqretry(&net->ipv4.ip_local_ports.lock, seq));
}
EXPORT_SYMBOL(inet_get_local_port_range);

/* 用于判断绑定端口是否冲突 */
int inet_csk_bind_conflict(const struct sock *sk,
			   const struct inet_bind_bucket *tb, bool relax)
{
	struct sock *sk2;
	/* SO_REUSEADDR，表示处于TIME_WAIT状态的端口允许重用 */
	int reuse = sk->sk_reuse;
	int reuseport = sk->sk_reuseport;
	kuid_t uid = sock_i_uid((struct sock *)sk);

	/*
	 * Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners list belong to the same net - the
	 * one this bucket belongs to.
	 */

	/* 遍历此端口上的sock */
	sk_for_each_bound(sk2, &tb->owners) {
		/* 冲突的条件1：不是同一socket、绑定在相同的设备上 */
		if (sk != sk2 &&
		    !inet_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
		    /* 冲突的条件2：绑定在相同的IP上
             * 冲突的条件3（符合一个即满足）：
             * 3.1 本socket不允许重用
             * 3.2 链表中的socket不允许重用
             * 3.3 链表中的socket处于监听状态
             */
			if ((!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) &&
			    (!reuseport || !sk2->sk_reuseport ||
			    (sk2->sk_state != TCP_TIME_WAIT &&
			     !uid_eq(uid, sock_i_uid(sk2))))) {

				if (!sk2->sk_rcv_saddr || !sk->sk_rcv_saddr ||
				    sk2->sk_rcv_saddr == sk->sk_rcv_saddr)
					break;
			}
			if (!relax && reuse && sk2->sk_reuse &&
			    sk2->sk_state != TCP_LISTEN) {

				if (!sk2->sk_rcv_saddr || !sk->sk_rcv_saddr ||
				    sk2->sk_rcv_saddr == sk->sk_rcv_saddr)
					break;
			}
		}
	}
	return sk2 != NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_bind_conflict);

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */

 /*
 * @sk: 当前进行绑定操作的传输控制块
 * @snum: 进行绑定的端口号
 */
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{
	/* 指向tcp_hashinfo */	
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret, attempts = 5;
	struct net *net = sock_net(sk);
	int smallest_size = -1, smallest_rover;
	kuid_t uid = sock_i_uid(sk);
	/*
	 * 禁止下半部，进程与下半部之间进行同步，因为在后面的操作中
	 * 有些有被进程和下半部同时访问的可能，因此先禁止下半部，再
	 * 进行后面的操作
	 */
	local_bh_disable();
	/*
	 * 如果待绑定的本地端口号为0，则自动为套接字分配
	 * 一个可用的端口
	 */
	if (!snum) {
		int remaining, rover, low, high;

again:
		/*
		 * 获取自动分配端口的区间
		 */
		inet_get_local_port_range(net, &low, &high);
		/*
		 * 获取重试分配次数
		 */
		remaining = (high - low) + 1;
		/*
		 * 随机生成一个在分配区间内的起始端口rover
		 */
		smallest_rover = rover = prandom_u32() % remaining + low;

		smallest_size = -1;
		/*
		 * 开始尝试获取空闲的端口号，首先从bhash散列表中
		 * 根据由端口号和bhash_size计算得到的键值获取一链表
		 * 然后加锁后遍历该链表，判断是否有相同的端口号
		 * 在此链表上。如果在选择的链表中没有找到相同的端口
		 * 号，则跳出循环进行下面的处理(这个循环有可能再次执行)
		 * 找到相同的端口号时，如果允许端口复用并且套接字不是
		 * 监听状态，tb结构的拥有者小于smallest_size或者smallest_size等于-1，
		 * 则重新初始化smallest_size和smallest_rover，如果同时hashinfo中的
		 * 绑定套接字数量大于区间的总数，则找到一个可以分配
		 * 的端口号(不一定就可用，后面还要处理)；否则修改rover，
		 * 重新开始循环
		 */
		do {
			 /* 查看端口是否属于保留的 */
			if (inet_is_local_reserved_port(net, rover))
				/* rover加1，继续 */
				goto next_nolock;
			/* 根据端口号，确定所在的哈希桶 */
			head = &hashinfo->bhash[inet_bhashfn(net, rover,
					hashinfo->bhash_size)];
			/* 锁住哈希桶 */
			spin_lock(&head->lock);
			/* 从头遍历哈希桶 */
			inet_bind_bucket_for_each(tb, &head->chain)
				/* 如果端口被使用了 */
				if (net_eq(ib_net(tb), net) && tb->port == rover) {
					if (((tb->fastreuse > 0 &&
					      sk->sk_reuse &&
					      sk->sk_state != TCP_LISTEN) ||
					     (tb->fastreuseport > 0 &&
					      sk->sk_reuseport &&
					      uid_eq(tb->fastuid, uid))) &&
					    (tb->num_owners < smallest_size || smallest_size == -1)) {
					    /* 记下这个端口使用者的个数 */
						smallest_size = tb->num_owners;
						 /* 记下这个端口 */
						smallest_rover = rover;
						/*
						 * 如果已绑定的端口号数量已经大于区间
						 * 的总数，并且允许复用(前面的判断成立
						 * 才会执行到此处)，就没必要再去寻找了
						 * 直接将当前的端口号作为找到的"空闲"
						 * 端口号
						 */
						if (atomic_read(&hashinfo->bsockets) > (high - low) + 1 &&
						    !inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false)) {
							/* 没有冲突，使用此端口 */
							snum = smallest_rover;
							goto tb_found;
						}
					}
					/* 检查是否有端口绑定冲突，该端口是否能重用 */
					if (!inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false)) {
						snum = rover;
						goto tb_found;
					}
					/* 此端口不可重用，看下一个 */
					goto next;
				}
			/* 找到了没被用的端口，退出 */
			break;
		next:
			spin_unlock(&head->lock);
		next_nolock:
			if (++rover > high)
				rover = low;
		} while (--remaining > 0);

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
		/* 完全遍历 */
		if (remaining <= 0) {
			if (smallest_size != -1) {
				snum = smallest_rover;
				goto have_snum;
			}
			goto fail;
		}
		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		/* 自动选择的可用端口 */
		snum = rover;
	} else {
		/* 如果有指定要绑定的端口 */
have_snum:
        /*
             * 如果是指定端口号，则需要在已绑定的信息
             * 中查找，根据不同的查找结果进行不同的处理
             * 根据由端口号和bhash_size计算出的键值从bhash
             * 散列表上获取一链表，然后加锁后遍历该
             * 链表，判断是否有相同的端口号在此链表
             * 上，如果有则跳转到tb_found处作处理，否则
             * 跳转到tb_not_found处作处理
             */
		head = &hashinfo->bhash[inet_bhashfn(net, snum,
				hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain)
			if (net_eq(ib_net(tb), net) && tb->port == snum)
				/* 发现端口在用 */
				goto tb_found;
	}
	tb = NULL;
	goto tb_not_found;
tb_found:
	/* 端口上有绑定sock时 */
	if (!hlist_empty(&tb->owners)) {
		/* 这是强制的绑定啊，不管端口是否会绑定冲突！*/
		if (sk->sk_reuse == SK_FORCE_REUSE)
			goto success;

		if (((tb->fastreuse > 0 &&
		      sk->sk_reuse && sk->sk_state != TCP_LISTEN) ||
		     (tb->fastreuseport > 0 &&
		      sk->sk_reuseport && uid_eq(tb->fastuid, uid))) &&
		    smallest_size == -1) {
		    /* 指定端口的情况 */
			goto success;
		} else {
			ret = 1;
			if (inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, true)) {
                /* 自动分配的端口绑定冲突了，再次尝试，最多重试5次。 
                 * 我觉得以下if不必要，因为自动选择时goto tb_found之前都有检测过了。
                 */
				if (((sk->sk_reuse && sk->sk_state != TCP_LISTEN) ||
				     (tb->fastreuseport > 0 &&
				      sk->sk_reuseport && uid_eq(tb->fastuid, uid))) &&
				    smallest_size != -1 && --attempts >= 0) {
					spin_unlock(&head->lock);
					goto again;
				}
				/* 失败 */
				goto fail_unlock;
			}
		}
	}
tb_not_found:
	ret = 1;
	 /* 申请和初始化一个inet_bind_bucket结构 */
	if (!tb && (tb = inet_bind_bucket_create(hashinfo->bind_bucket_cachep,
					net, head, snum)) == NULL)
		goto fail_unlock;
	if (hlist_empty(&tb->owners)) {
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1;
		else
			tb->fastreuse = 0;
		if (sk->sk_reuseport) {
			tb->fastreuseport = 1;
			tb->fastuid = uid;
		} else
			tb->fastreuseport = 0;
	} else {
		if (tb->fastreuse &&
		    (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
			tb->fastreuse = 0;
		if (tb->fastreuseport &&
		    (!sk->sk_reuseport || !uid_eq(tb->fastuid, uid)))
			tb->fastreuseport = 0;
	}
success:
	/* 赋值icsk中的inet_bind_bucket */
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}
EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
 /* 用于监听的传输控制块在指定的时间内等待新的连接，直至建立新的连接，
  * 或等到超时，或者收到某个信号等其他情况发生
  */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	/* 初始化等待任务 */
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		/* 把等待任务加入到socket的等待队列中，把进程状态设置为TASK_INTERRUPTIBLE */
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		/* 等下可能要睡觉了，先释放 */
		release_sock(sk);
		/* 如果全连接队列为空 */
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			/* 进入睡眠，直到超时或收到信号 */
			timeo = schedule_timeout(timeo);
		/* 醒来后重新上锁 */
		lock_sock(sk);
		err = 0;
		/* 全连接队列不为空时，退出 */
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		/* 如果sock不处于监听状态了，退出 */
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		
        /* 
         * 如果进程有待处理的信号，退出。
         * 因为timeo默认为MAX_SCHEDULE_TIMEOUT，所以err默认为-ERESTARTSYS。
         * 接下来会重新调用此函数，所以accept()依然阻塞。
         */
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		/* 如果等待超时，即超过用户设置的sk->sk_rcvtimeo，退出 */
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
/*
 * inet_csk_accept()函数是accept系统调用传输层接口的实现。
 * 如果有完成连接的传输控制块，则将其从连接请求容器中取出；如果
 * 没有，则根据是否阻塞来决定返回或等待新连接
 * @sk: 进行accept调用的传输控制块
 * @flags: 操作文件的标志，如O_NONBLOCK是最常用的
 * @err: 输出参数，用于返回错误码
 */ 
 //从inet_connection_sock的icsk_accept_queue队列上取出一个struct sock结构
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct sock *newsk;
	struct request_sock *req;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
    /*
     * accept调用只针对处于监听状态的套接字，如果该套接字的状态
     * 不是LISTEN，则不能进行accept操作
     */
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
    /*
     * 如果该监听套接字的已完成建立连接队列为空，则说明还
     * 没有收到新连接
     */
	if (reqsk_queue_empty(queue)) {
        /*
         * 如果该套接字是非阻塞的，则直接返回而无需睡眠等待；
         * 否则在该套接字的超时时间内等待新连接，如果超时
         * 时间到达还没有等到新连接，则返回EAGAIN错误码
         */
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		/* 如果是非阻塞的，则直接退出 */
		if (!timeo)
			goto out_err;

		/* 阻塞等待，直到有全连接。如果用户有设置等待超时时间，超时后会退出 */
		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}
	/*
     * 执行到此处，则肯定已接受了新的连接，因此需从连接队列上
     * 将新的子传输控制块取出
     */
	req = reqsk_queue_remove(queue);
	/* 获取新连接的sock，释放连接控制块 */
	newsk = req->sk;

	/* 当前backlog队列的全连接数减一 */
	sk_acceptq_removed(sk);
	if (sk->sk_protocol == IPPROTO_TCP && queue->fastopenq != NULL) {
		spin_lock_bh(&queue->fastopenq->lock);
		if (tcp_rsk(req)->listener) {
			/* We are still waiting for the final ACK from 3WHS
			 * so can't free req now. Instead, we set req->sk to
			 * NULL to signify that the child socket is taken
			 * so reqsk_fastopen_remove() will free the req
			 * when 3WHS finishes (or is aborted).
			 */
			req->sk = NULL;
			req = NULL;
		}
		spin_unlock_bh(&queue->fastopenq->lock);
	}
out:
	release_sock(sk);
	if (req)
		__reqsk_free(req);
	return newsk;
out_err:
	newsk = NULL;
	req = NULL;
	*err = error;
	goto out;
}
EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

    //定时器使用过程:  init_timer   setup_timer   mod_timer
	setup_timer(&icsk->icsk_retransmit_timer, retransmit_handler,
			(unsigned long)sk);
	setup_timer(&icsk->icsk_delack_timer, delack_handler,
			(unsigned long)sk);
	setup_timer(&sk->sk_timer, keepalive_handler, (unsigned long)sk);
	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}
EXPORT_SYMBOL(inet_csk_init_xmit_timers);

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}
EXPORT_SYMBOL(inet_csk_clear_xmit_timers);

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}
EXPORT_SYMBOL(inet_csk_delete_keepalive_timer);

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}
EXPORT_SYMBOL(inet_csk_reset_keepalive_timer);

struct dst_entry *inet_csk_route_req(struct sock *sk,
				     struct flowi4 *fl4,
				     const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options_rcu *opt = inet_rsk(req)->opt;
	struct net *net = sock_net(sk);
	int flags = inet_sk_flowi_flags(sk);

	flowi4_init_output(fl4, sk->sk_bound_dev_if, ireq->ir_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol,
			   flags,
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port, inet_sk(sk)->inet_sport);
	security_req_classify_flow(req, flowi4_to_flowi(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_route_req);

struct dst_entry *inet_csk_route_child_sock(struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct inet_sock *newinet = inet_sk(newsk);
	struct ip_options_rcu *opt;
	struct net *net = sock_net(sk);
	struct flowi4 *fl4;
	struct rtable *rt;

	fl4 = &newinet->cork.fl.u.ip4;

	rcu_read_lock();
	opt = rcu_dereference(newinet->inet_opt);
	flowi4_init_output(fl4, sk->sk_bound_dev_if, inet_rsk(req)->ir_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port, inet_sk(sk)->inet_sport);
	security_req_classify_flow(req, flowi4_to_flowi(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	rcu_read_unlock();
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	rcu_read_unlock();
	IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_route_child_sock);

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

#if IS_ENABLED(CONFIG_IPV6)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

//这里面搜索的是inet_connection_sock->icsk_accept_queue中的半连接syn_table hash表
struct request_sock *inet_csk_search_req(const struct sock *sk,
					 struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	for (prev = &lopt->syn_table[inet_synq_hash(raddr, rport, lopt->hash_rnd,
						    lopt->nr_table_entries)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->ir_rmt_port == rport &&
		    ireq->ir_rmt_addr == raddr &&
		    ireq->ir_loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			WARN_ON(req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}
EXPORT_SYMBOL_GPL(inet_csk_search_req);

/*
 * 用来将连接请求块保存到"父"传输控制块的散列表中
 */
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
    /*
	 * 计算散列表键值
	 */
	const u32 h = inet_synq_hash(inet_rsk(req)->ir_rmt_addr,
				     inet_rsk(req)->ir_rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

    /*
	 * 将连接请求块保存到"父"传输控制块的散列表中，并设置连接
	 * 建立定时器超时时间
	 */
	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);

    /*
	 * 最后更新已存在连接请求块数，并启动连接建立定时器
	 */
	inet_csk_reqsk_queue_added(sk, timeout);
}
EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_hash_add);

/* Only thing we need from tcp.h */
extern int sysctl_tcp_synack_retries;


/* Decide when to expire the request and when to resend SYN-ACK */
static inline void syn_ack_recalc(struct request_sock *req, const int thresh,
				  const int max_retries,
				  const u8 rskq_defer_accept,
				  int *expire, int *resend)
{
	/* 没有开启defer_accept， 也就是说不需要等数据包 */
	if (!rskq_defer_accept) {
		/* 使用synack的重传次数来判断，是否超时 */
		*expire = req->num_timeout >= thresh;
		/* 需要重传 */
		*resend = 1;
		return;
	}
	/* 对与defer_accept如果收到ack了，但未达到最大重传次数，则*expire=0，不重传synack */
	*expire = req->num_timeout >= thresh &&
			/* 未收到ack过，超过最大重传次数 */
		  (!inet_rsk(req)->acked || req->num_timeout >= max_retries);
	/*
	 * Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
	*resend = !inet_rsk(req)->acked ||
		 /* 被ack了,但是一直没收到数据，在defer_accept的最后一次重传中重传synack */
		  req->num_timeout >= rskq_defer_accept - 1;
}

int inet_rtx_syn_ack(struct sock *parent, struct request_sock *req)
{
	int err = req->rsk_ops->rtx_syn_ack(parent, req);

	if (!err)
		req->num_retrans++;
	return err;
}
EXPORT_SYMBOL(inet_rtx_syn_ack);

/*
 * inet_csk_reqsk_queue_prune()用于扫描半连接散列表，当
 * 半连接队列的连接请求块个数超过最大个数的
 * 一半时，需要为接受没有重传过的连接保留一半
 * 的空间。半连接队列里面要尽量保持没有重传
 * 过的连接，并删除一些长时间空闲或者没有接受
 * 的连接。参数说明如下:
 * @parent: 进行侦听的传输控制块。
 * @interval:建立连接定时器的超时时间
 * @timeout:往返超时的初始值。每超时一次，加倍上次的超时时间。
 * @max_rto:往返时间的最大值。
 */
void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	/*
	 * 获取建立TCP连接时最多允许重传SYN+ACK段的次数。
	 */
	int max_retries = icsk->icsk_syn_retries ? : sysctl_tcp_synack_retries;

	/*
	 * 局部变量thresh用于控制重传次数。在计算thresh时，年轻
	 * 连接越多则可容忍的重传次数也越多。
	 */
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

    /*
	 * 如果该套接字中保存连接请求快的散列表
	 * 还没有建立，或者还没有处于连接过程中
	 * 的连接请求块，则直接返回。
	 */
	if (lopt == NULL || lopt->qlen == 0) //说明还没收到客户端过来的三次握手中的syn，直接退出
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 1 second, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

    /*
	 * 获取在启用加速连接(启用TCP_DEFER_ACCEPT选项)情况下最多允许重传SYN段的
	 * 次数。
	 * 
	 * 注意:在启用TCP_DEFER_ACCEPT选项后，将使用rskq_defer_accept作为
	 * 最大的允许重传的次数。
	 */
	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;


    /*
	 * 计算需要检测的半连接队列的个数，得到预计值。
	 * 由于半连接队列是一个链表，并且数量可能比较大，
	 * 因此为了提高效率，每次只是遍历几个链表。
	 * 
	 * timeout是超时时间，interval是连接建立定时器的间隔，
	 * 相处后就是一个连接请求块从建立到超时，需要经历
	 * 的连接建立定时器处理的次数。
	 * budget是本次处理时，要处理的链表个数。
	 */
	budget = 2 * (lopt->nr_table_entries / (timeout / interval)); //保证所有的request都会被重传检查，所有的半连接散列表都会被遍历到
    /*
	 * clock_hand的初值为0，每次遍历完半连接队列，会把最后
	 * 的i保存到clock_hand中，从而下一次遍历会从上次的
	 * clock_hand开始。
	 */
	i = lopt->clock_hand;

	do {
	    /*
		 * 获取当前处理入口的链表头，循环遍历该链表，
		 * 处理其上的连接请求块。
		 */
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
		    /*
			 * 如果当前连接请求块的连接已经超时，则
			 * 将根据已重传的次数来决定是再次重传还
			 * 是放弃该连接建立。
			 * 
			 * 
			 * 这里的超时是在发送
			 * SYN+ACK段后，过了一段时间仍然没有接收
			 * 到确认。
			 */
			if (time_after_eq(now, req->expires)) {
				int expire = 0, resend = 0;

				/*
				 * 在以下两种情况下需要累计重传SYN+ACK段的
				 * 次数，并因重传而递减qlen_young。然后重新
				 * 计算下次的超时时间(加倍上次的超时时间)，
				 * 设置到该连接请求块上，最后获取下一个
				 * 连接请求块进行处理。
				 * 1)SYN+ACK段重传次数未到上限
				 * 2)已经接收到第三次握手的ACK段后，由于繁忙或
				 *    其他原因导致未能建立起连接。
				 */
				syn_ack_recalc(req, thresh, max_retries,
					       queue->rskq_defer_accept,
					       &expire, &resend);
				/* tcp_syn_ack_timeout */
				req->rsk_ops->syn_ack_timeout(parent, req);
				/* 
				 * 没有超过最大重传次数； 对于defer_accept来说，如果收到ack了，
				 * 但是一直没有收到数据 , 不需要重传
				 */
				if (!expire &&
				    (!resend ||
				     !inet_rtx_syn_ack(parent, req) ||
				     inet_rsk(req)->acked)) {
					unsigned long timeo;

                    /*
					 * if (req->retrans++ == 0)这个判断相当于是
					 * 先判断req->retrans是否等于0，然后再加1.
					 * 只有在req->retrans为0时，才需要对lopt->qlen_young减1.
					 */
					if (req->num_timeout++ == 0)
						lopt->qlen_young--;

					/*
					 * 更新超时时间
					 */
					timeo = min(timeout << req->num_timeout,
						    max_rto);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

                /*
				 * 如果SYN+ACK段重传次数超过指定值，则
				 * 需要取消该连接请求，并将当前连接
				 * 请求块从连接请求散列表中删除并释放。
				 */
				/* Drop this request */
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);
				continue;
			}
			/*
			 * 取链表中下一个连接请求块进行处理。
			 */
			reqp = &req->dl_next;
		}

        /*
		 * 当前入口链表上的连接请求块处理完后，
		 * 处理下一入口链表上的连接请求块。
		 */
		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	lopt->clock_hand = i;

    /*
	 * 如果连接请求散列表中还有未完成连接的
	 * 连接请求块，则再次启动定时器。
	 */
	if (lopt->qlen)
		inet_csk_reset_keepalive_timer(parent, interval);
}
EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_prune);

/**
 *	inet_csk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
//还有个开辟sock空间的地方是inet_csk_clone，sk_alloc也开辟sock空间
//tcp_create_openreq_child在三次握手成功后的第三步会创建一个sk  ????????? 应该是第一步收到SYN的时候就开辟空间了，所以要限制半连接数，防止空间用完
////注意，这个应该是在服务器端收到第一个SYN的时候，就开辟了struct sock ，这里进入了TCP_SYN_RECV状态

struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;//说明这个应该是在服务器端收到第一个SYN的时候，就开辟了struct sock
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->ir_rmt_port;
		inet_sk(newsk)->inet_num = inet_rsk(req)->ir_num;
		inet_sk(newsk)->inet_sport = htons(inet_rsk(req)->ir_num);
		newsk->sk_write_space = sk_stream_write_space;

		inet_sk(newsk)->mc_list = NULL;

		newsk->sk_mark = inet_rsk(req)->ir_mark;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}
EXPORT_SYMBOL_GPL(inet_csk_clone_lock);

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	WARN_ON(sk->sk_state != TCP_CLOSE);
	WARN_ON(!sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	WARN_ON(!sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
	WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	percpu_counter_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}
EXPORT_SYMBOL(inet_csk_destroy_sock);

/* This function allows to force a closure of a socket after the call to
 * tcp/dccp_create_openreq_child().
 */
void inet_csk_prepare_forced_close(struct sock *sk)
	__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	percpu_counter_inc(sk->sk_prot->orphan_count);
	inet_sk(sk)->inet_num = 0;
}
EXPORT_SYMBOL(inet_csk_prepare_forced_close);

/*
 * 使TCP传输控制块进入监听状态，实现监听状态:为管理连接
 * 请求块的散列表分配存储空间，接着使TCP传输控制块的状态
 * 迁移到LISTEN状态，然后将传输控制块添加到监听散列表中。
 * @nr_table_entries:允许连接的队列长度上限，通过此值
 *                   合理计算出存储连接请求块的散列表大小
 */ //nr_table_entries为应用层listen的第二个参数
int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	/*
	 * 为管理连接请求块的散列表分配存储空间，如果分配失败则返回
	 * 相应错误码
	 */
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

	if (rc != 0)
		return rc;

	/*
	 * 初始化连接队列长度上限，清除当前已建立连接数
	 */
	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	/*
	 * 初始化传输控制块中与延时发送ACK段有关的控制数据结构icsk_ack
	 */
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	/*
	 * 设置传输控制块状态为监听状态
	 */
	sk->sk_state = TCP_LISTEN;
	/*
	 * 调用的是inet_csk_get_port()，如果没有绑定端口，则进行绑定
	 * 端口操作；如果已经绑定了端口，则对绑定的端口进行校验。绑定
	 * 或校验端口成功后，根据端口号在传输控制块中设置网络字节序的
	 * 端口号成员，然后再清除缓存在传输控制块中的目的路由缓存，最后
	 * 调用hash接口inet_hash()将该传输控制块添加到监听散列表listening_hash
	 * 中，完成监听
	 */
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		/*
		 * 如果是TCP协议，这里调用的是inet_hash函数。
		 */
		sk->sk_prot->hash(sk);

		return 0;
	}

	/*
	 * 如果绑定或校验端口失败，则说明监听失败，设置传输控制块状态
	 * 为TCP_CLOSE状态
	 */
	sk->sk_state = TCP_CLOSE;
	/*
	 * 释放之前分配的inet_bind_bucket实例
	 */
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}
EXPORT_SYMBOL_GPL(inet_csk_listen_start);

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		percpu_counter_inc(sk->sk_prot->orphan_count);

		if (sk->sk_protocol == IPPROTO_TCP && tcp_rsk(req)->listener) {
			BUG_ON(tcp_sk(child)->fastopen_rsk != req);
			BUG_ON(sk != tcp_rsk(req)->listener);

			/* Paranoid, to prevent race condition if
			 * an inbound pkt destined for child is
			 * blocked by sock lock in tcp_v4_rcv().
			 * Also to satisfy an assertion in
			 * tcp_v4_destroy_sock().
			 */
			tcp_sk(child)->fastopen_rsk = NULL;
			sock_put(sk);
		}
		inet_csk_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	if (queue->fastopenq != NULL) {
		/* Free all the reqs queued in rskq_rst_head. */
		spin_lock_bh(&queue->fastopenq->lock);
		acc_req = queue->fastopenq->rskq_rst_head;
		queue->fastopenq->rskq_rst_head = NULL;
		spin_unlock_bh(&queue->fastopenq->lock);
		while ((req = acc_req) != NULL) {
			acc_req = req->dl_next;
			__reqsk_free(req);
		}
	}
	WARN_ON(sk->sk_ack_backlog);
}
EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->inet_daddr;
	sin->sin_port		= inet->inet_dport;
}
EXPORT_SYMBOL_GPL(inet_csk_addr2sockaddr);

#ifdef CONFIG_COMPAT
int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_getsockopt != NULL)
		return icsk->icsk_af_ops->compat_getsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->getsockopt(sk, level, optname,
					     optval, optlen);
}
EXPORT_SYMBOL_GPL(inet_csk_compat_getsockopt);

int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, unsigned int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_setsockopt != NULL)
		return icsk->icsk_af_ops->compat_setsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->setsockopt(sk, level, optname,
					     optval, optlen);
}
EXPORT_SYMBOL_GPL(inet_csk_compat_setsockopt);
#endif

static struct dst_entry *inet_csk_rebuild_route(struct sock *sk, struct flowi *fl)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct ip_options_rcu *inet_opt;
	__be32 daddr = inet->inet_daddr;
	struct flowi4 *fl4;
	struct rtable *rt;

	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;
	fl4 = &fl->u.ip4;
	rt = ip_route_output_ports(sock_net(sk), fl4, sk, daddr,
				   inet->inet_saddr, inet->inet_dport,
				   inet->inet_sport, sk->sk_protocol,
				   RT_CONN_FLAGS(sk), sk->sk_bound_dev_if);
	if (IS_ERR(rt))
		rt = NULL;
	if (rt)
		sk_setup_caps(sk, &rt->dst);
	rcu_read_unlock();

	return &rt->dst;
}

struct dst_entry *inet_csk_update_pmtu(struct sock *sk, u32 mtu)
{
	struct dst_entry *dst = __sk_dst_check(sk, 0);
	struct inet_sock *inet = inet_sk(sk);

	if (!dst) {
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
		if (!dst)
			goto out;
	}
	dst->ops->update_pmtu(dst, sk, NULL, mtu);

	dst = __sk_dst_check(sk, 0);
	if (!dst)
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
out:
	return dst;
}
EXPORT_SYMBOL_GPL(inet_csk_update_pmtu);
