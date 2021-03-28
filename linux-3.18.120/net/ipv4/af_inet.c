/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET protocol family socket handler.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Changes (see also sock.c)
 *
 *		piggy,
 *		Karl Knutson	:	Socket protocol table
 *		A.N.Kuznetsov	:	Socket death error in accept().
 *		John Richardson :	Fix non blocking error in connect()
 *					so sockets that fail to connect
 *					don't return -EINPROGRESS.
 *		Alan Cox	:	Asynchronous I/O support
 *		Alan Cox	:	Keep correct socket pointer on sock
 *					structures
 *					when accept() ed
 *		Alan Cox	:	Semantics of SO_LINGER aren't state
 *					moved to close when you look carefully.
 *					With this fixed and the accept bug fixed
 *					some RPC stuff seems happier.
 *		Niibe Yutaka	:	4.4BSD style write async I/O
 *		Alan Cox,
 *		Tony Gale 	:	Fixed reuse semantics.
 *		Alan Cox	:	bind() shouldn't abort existing but dead
 *					sockets. Stops FTP netin:.. I hope.
 *		Alan Cox	:	bind() works correctly for RAW sockets.
 *					Note that FreeBSD at least was broken
 *					in this respect so be careful with
 *					compatibility tests...
 *		Alan Cox	:	routing cache support
 *		Alan Cox	:	memzero the socket structure for
 *					compactness.
 *		Matt Day	:	nonblock connect error handler
 *		Alan Cox	:	Allow large numbers of pending sockets
 *					(eg for big web sites), but only if
 *					specifically application requested.
 *		Alan Cox	:	New buffering throughout IP. Used
 *					dumbly.
 *		Alan Cox	:	New buffering now used smartly.
 *		Alan Cox	:	BSD rather than common sense
 *					interpretation of listen.
 *		Germano Caronni	:	Assorted small races.
 *		Alan Cox	:	sendmsg/recvmsg basic support.
 *		Alan Cox	:	Only sendmsg/recvmsg now supported.
 *		Alan Cox	:	Locked down bind (see security list).
 *		Alan Cox	:	Loosened bind a little.
 *		Mike McLagan	:	ADD/DEL DLCI Ioctls
 *	Willy Konynenberg	:	Transparent proxying support.
 *		David S. Miller	:	New socket lookup architecture.
 *					Some other random speedups.
 *		Cyrus Durgin	:	Cleaned up file for kmod hacks.
 *		Andi Kleen	:	Fix inet_stream_connect TCP race.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
//PF_INET协议族相关参考http://jianshu.io/p/5d82a685b5b6可以知道应用层创建PF_INET socket过程中内核函数调用情况
#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/ping.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/inet_common.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/secure_seq.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif


/* The inetsw table contains everything that inet_create needs to
 * build a new socket.
 */
//当应用程序通过socket函数创建套接字的时候，通过协议类型protocol和套接字type在inet_create里面的inetsw中查找到对应的tcp_proto udp_proto raw_proto等
static struct list_head inetsw[SOCK_MAX];//见inet_init  inet_register_protosw(q); inetsw_array中的信息存放在该链表中的protocol，然后让struct socket的ops等指向对应的协议
static DEFINE_SPINLOCK(inetsw_lock);

/* New destruction routine */

void inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	kfree(rcu_dereference_protected(inet->inet_opt, 1));
	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	dst_release(sk->sk_rx_dst);
	sk_refcnt_debug_dec(sk);
}
EXPORT_SYMBOL(inet_sock_destruct);

/*
 *	The routines beyond this point handle the behaviour of an AF_INET
 *	socket object. Mostly it punts to the subprotocols of IP to do
 *	the work.
 */

/*
 *	Automatically bind an unbound socket.
 */

static int inet_autobind(struct sock *sk)
{
	struct inet_sock *inet;
	/* We may need to bind the socket. */
	lock_sock(sk);
	inet = inet_sk(sk);
	if (!inet->inet_num) {
		if (sk->sk_prot->get_port(sk, 0)) {
			release_sock(sk);
			return -EAGAIN;
		}
		inet->inet_sport = htons(inet->inet_num);
	}
	release_sock(sk);
	return 0;
}

/*
 *	Move a socket into listening state.
 */
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	/*
	 * 检测调用listen的套接字的当前状态和类型。如果套接字状态
	 * 不是SS_UNCONNECTED，或套接字类型不是SOCK_STREAM，则不
	 * 允许进行监听操作，返回相应错误码
	 */
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	/* 当前连接状态 */
	old_state = sk->sk_state;
	/* 当前的连接需为CLOSED或LISTEN状态 */
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		/* Check special setups for testing purpose to enable TFO w/o
		 * requiring TCP_FASTOPEN sockopt.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopenq may already been allocated because this
		 * socket was in TCP_LISTEN state previously but was
		 * shutdown() (rather than close()).
		 */
		if ((sysctl_tcp_fastopen & TFO_SERVER_ENABLE) != 0 &&
		    inet_csk(sk)->icsk_accept_queue.fastopenq == NULL) {
			if ((sysctl_tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) != 0)
				err = fastopen_init_queue(sk, backlog);
			else if ((sysctl_tcp_fastopen &
				  TFO_SERVER_WO_SOCKOPT2) != 0)
				err = fastopen_init_queue(sk,
				    ((uint)sysctl_tcp_fastopen) >> 16);
			else
				err = 0;
			if (err)
				goto out;

			tcp_fastopen_init_key_once(true);
		}
		/* 启动监听 */
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	/* 最大全连接队列长度 */
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_listen);

/*
 *	Create an inet socket.
 */
//pf_inet的net_families[]为inet_family_ops，对应的套接口层ops参考inetsw_array中的inet_stream_ops inet_dgram_ops inet_sockraw_ops，传输层操作集分别为tcp_prot udp_prot raw_prot
//netlink的net_families[]netlink_family_ops，对应的套接口层ops为netlink_ops
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	sock->state = SS_UNCONNECTED;//设置socket的状态为SS_UNCONNECTED；

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (unlikely(err)) {
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern &&
	    !ns_capable(net->user_ns, CAP_NET_RAW))
	/*
	 * 检查网络命名空间，检查指定的协议类型
	 * 是否已经添加，参见init_inet()，tcp协议对应
	 * 的net_protocol实例是tcp_protocol。
	 */
		goto out_rcu_unlock;

	/*  sock->ops指向inet_stream_ops，然后创建sk */
	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(answer_prot->slab == NULL);

	err = -ENOBUFS;
	/*
	 * 分配sock实例并初始化，如果是TCP协议，
	 * 则实际分配的大小为sizeof(tcp_sock)。
	 */
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot);
	if (sk == NULL)
		goto out;

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	/* 设置inet的一些参数，这里直接将sk类型转换为inet */
	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	inet->nodefrag = 0;

	if (SOCK_RAW == sock->type) {
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->inet_id = 0;

	/* 将sock与sk关联起来 */
	sock_init_data(sock, sk);

	sk->sk_destruct	   = inet_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;

	sk_refcnt_debug_inc(sk);

	if (inet->inet_num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->inet_sport = htons(inet->inet_num);
		/* Add to protocol hash chains. */
		sk->sk_prot->hash(sk);
	}

	/* 调用init函数 */
	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			sk_common_release(sk);
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 *	从sock_release走到这里，见sock_release
 */
int inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		sock_rps_reset_flow(sk);

		/* Applications forget to leave groups before exiting */
		ip_mc_drop_socket(sk);

		/* If linger is set, we don't return until the close
		 * is complete.  Otherwise we return immediately. The
		 * actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		timeout = 0;
		/*
		 * 如果设置了SO_LINGER选项，则关闭连接的时候会等待
		 * 关闭完成，否则会立即返回。但是如果是进程退出，
		 * 则会忽略SO_LINGER选项
		 */
		if (sock_flag(sk, SOCK_LINGER) &&
		    !(current->flags & PF_EXITING))
			timeout = sk->sk_lingertime;
		sock->sk = NULL;
		sk->sk_prot->close(sk, timeout);
	}
	return 0;
}
EXPORT_SYMBOL(inet_release);

int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	/* 传输层实例 */
	struct sock *sk = sock->sk;
	/* INET实例 */
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	/* 要绑定的端口 */
	unsigned short snum;
	/* IP地址类型 */
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	/*
	 * 如果是TCP套接字，sk->sk_prot指向的是tcp_prot，在
	 * inet_create()中调用的sk_alloc()函数中初始化。由于
	 * tcp_prot中没有设置bind接口，因此判断条件不成立。 现在只有RAW才有
	 */
	if (sk->sk_prot->bind) {
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	err = -EINVAL;
	/* socket地址长度错误 */
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	/* 非INET协议族 */
	if (addr->sin_family != AF_INET) {
		/* Compatibility games : accept AF_UNSPEC (mapped to AF_INET)
		 * only if s_addr is INADDR_ANY.
		 */
		err = -EAFNOSUPPORT;
		if (addr->sin_family != AF_UNSPEC ||
		    addr->sin_addr.s_addr != htonl(INADDR_ANY))
			goto out;
	}

	/* 在路由中检查IP地址类型，单播、多播还是广播 */
	chk_addr_ret = inet_addr_type(net, addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	 
    /* sysctl_ip_nonlocal_bind表示是否允许绑定非本地的IP地址。
     * inet->freebind表示是否允许绑定非主机地址。
     * 这里需要允许绑定非本地地址，除非是发送给自己、多播或广播。
     */
	err = -EADDRNOTAVAIL;
	if (!net->ipv4.sysctl_ip_nonlocal_bind &&
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	/* 要绑定的端口 */
	snum = ntohs(addr->sin_port);
	err = -EACCES;
	
    /*
     * snum为0表示让系统随机选择一个未使用的端口，因此是合法的。
     * 如要需要绑定的端口为1 ~ 1023，则需要对应的特权。
     */
	if (snum && snum < PROT_SOCK &&
	    !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	/*
	 * 如果套接字状态不是TCP_CLOSE(套接字的初始状态，参见
	 * sock_init_data()函数)，或者已经绑定过，则返回EINVAL错误。
	 */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	/* 绑定地址 */
	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	/*
     * 如果使用的是TCP，则sk_prot为tcp_prot，get_port为inet_csk_get_port()
     * 端口可用的话返回0
     */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	/* inet_rcv_saddr表示绑定的地址，接收数据时用于查找socket */
	if (inet->inet_rcv_saddr)
		/* 表示绑定了本地地址 */
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		/* 表示绑定了本地端口 */
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	/* 绑定端口 */
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}
EXPORT_SYMBOL(inet_bind);

int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (!inet_sk(sk)->inet_num && inet_autobind(sk))
		return -EAGAIN;
	return sk->sk_prot->connect(sk, uaddr, addr_len);
}
EXPORT_SYMBOL(inet_dgram_connect);

static long inet_wait_for_connect(struct sock *sk, long timeo, int writebias)
{
	/* 初始化等待任务 */
	DEFINE_WAIT(wait);

	/* 把等待任务加入到socket的等待队列头部，把进程的状态设为TASK_INTERRUPTIBLE */
	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	sk->sk_write_pending += writebias;

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	/* 完成三次握手后，状态就会变为TCP_ESTABLISHED，从而退出循环 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		/* 进入睡眠前先将锁释放 */
		release_sock(sk);		
        /* 进入睡眠，直到超时或收到信号，或者被I/O事件处理函数唤醒。
         * 1. 如果是收到信号退出的，timeo为剩余的jiffies。
         * 2. 如果使用了SO_SNDTIMEO选项，超时退出后，timeo为0。
         * 3. 如果没有使用SO_SNDTIMEO选项，timeo为无穷大，即MAX_SCHEDULE_TIMEOUT，
         *    那么返回值也是这个，而超时时间不定。为了无限阻塞，需要上面的while循环。
         */
		timeo = schedule_timeout(timeo);
		/* 被唤醒后重新上锁 */
		lock_sock(sk);
		/* 如果进程有待处理的信号，或者睡眠超时了，退出循环，之后会返回错误码 */
		if (signal_pending(current) || !timeo)
			break;
		/* 继续睡眠吧 */
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	}
	/* 等待结束时，把等待进程从等待队列中删除，把当前进程的状态设为TASK_RUNNING */
	finish_wait(sk_sleep(sk), &wait);
	sk->sk_write_pending -= writebias;
	return timeo;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			  int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	/* 检查socket地址长度 */
	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;

	/* socket的协议族错误 */
	if (uaddr->sa_family == AF_UNSPEC) {
		/* 如果使用的是TCP，则sk_prot为tcp_prot，disconnect为tcp_disconnect() */
		err = sk->sk_prot->disconnect(sk, flags);
		/* 根据是否成功断开连接，来设置socket状态 */
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	/* 此套接口已经和对端的套接口相连接了，即连接已经建立 */
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	/* 此套接口正在尝试连接对端的套接口，即连接正在建立中 */
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	/* 此套接口尚未连接对端的套接口，即连接尚未建立 */
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;

		/* 如果使用的是TCP，则sk_prot为tcp_prot，connect为tcp_v4_connect() */
		err = sk->sk_prot->connect(sk, uaddr, addr_len);/* 发送SYN包 */
		if (err < 0)
			goto out;

		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	/* sock的发送超时时间，非阻塞则为0 */
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	/* 发出SYN包后，等待后续握手的完成 */
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int writebias = (sk->sk_protocol == IPPROTO_TCP) &&
				tcp_sk(sk)->fastopen_req &&
				tcp_sk(sk)->fastopen_req->data ? 1 : 0;

		/* Error code is set above */
		
        /* 如果是非阻塞的，那么就直接返回错误码-EINPROGRESS。
         * socket为阻塞时，使用inet_wait_for_connect()来等待协议栈的处理：
         * 1. 使用SO_SNDTIMEO，睡眠时间超过timeo就返回0，之后返回错误码-EINPROGRESS。
         * 2. 收到信号，就返回剩余的等待时间。之后会返回错误码-ERESTARTSYS或-EINTR。
         * 3. 三次握手成功，被sock I/O事件处理函数唤醒，之后会返回0。
         */
		if (!timeo || !inet_wait_for_connect(sk, timeo, writebias))
			goto out;

		err = sock_intr_errno(timeo);
		/* 进程收到信号，如果err为-ERESTARTSYS，接下来库函数会重新调用connect() */
		if (signal_pending(current))
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	/* 更新socket状态为连接已建立 */
	sock->state = SS_CONNECTED;
	/* 清除错误码 */
	err = 0;
out:
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	 /* 如果使用的是TCP，则sk_prot为tcp_prot，disconnect为tcp_disconnect() */
	if (sk->sk_prot->disconnect(sk, flags))
		/* 如果失败 */
		sock->state = SS_DISCONNECTING;
	goto out;
}
EXPORT_SYMBOL(__inet_stream_connect);

int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	int err;

	lock_sock(sock->sk);
	err = __inet_stream_connect(sock, uaddr, addr_len, flags);
	release_sock(sock->sk);
	return err;
}
EXPORT_SYMBOL(inet_stream_connect);

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */

int inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk1 = sock->sk;
	int err = -EINVAL;

	/*
	 * 调用accept的传输层接口实现inet_csk_accept()获取已完成
	 * 连接(被接受)的传输控制块,这是在三次握手的时候，会创建一个传输控制块
	 */
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err);//这个是inet_csk_accept的时候从reqsk_queue_get_child队列中取出来的，是三次握手第三步的时候开辟的sk空间

	if (!sk2)
		goto do_err;

	/* RPS补丁 */
	lock_sock(sk2);

	sock_rps_record_flow(sk2);
	WARN_ON(!((1 << sk2->sk_state) &
		  (TCPF_ESTABLISHED | TCPF_SYN_RECV |
		  TCPF_CLOSE_WAIT | TCPF_CLOSE)));
    /*
	 * 如果accept成功，则需调用sock_graft()把子套接字和传输控制块关联
	 * 起来以便这两者之间相互索引
	 */
	sock_graft(sk2, newsock);

	/* 把新socket的状态设为已连接 */
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk2);
do_err:
	return err;
}
EXPORT_SYMBOL(inet_accept);


/*
 *	This does both peername and sockname.
 */ //获取本端或者对端的地址和端口   peer=1获取对端的，peer=0获取本端的
int inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, uaddr);

	sin->sin_family = AF_INET;
	/* 如果是getpeername，要求连接已经建立 */
	if (peer) {
		if (!inet->inet_dport ||
		    (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		     peer == 1))
			return -ENOTCONN;
		/* 获取对端端口、IP */
		sin->sin_port = inet->inet_dport;
		sin->sin_addr.s_addr = inet->inet_daddr;
	} else {
		__be32 addr = inet->inet_rcv_saddr;
		if (!addr)
			addr = inet->inet_saddr;
		/* 获取本端端口、IP */
		sin->sin_port = inet->inet_sport;
		sin->sin_addr.s_addr = addr;
	}
	memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	*uaddr_len = sizeof(*sin);
	return 0;
}
EXPORT_SYMBOL(inet_getname);

int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
		/* 如果没调用bind(), 则自动绑定一个可用端口 */
	    inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}
EXPORT_SYMBOL(inet_sendmsg);

ssize_t inet_sendpage(struct socket *sock, struct page *page, int offset,
		      size_t size, int flags)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}
EXPORT_SYMBOL(inet_sendpage);

int inet_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int err;

	sock_rps_record_flow(sk);

	err = sk->sk_prot->recvmsg(iocb, sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;
	return err;
}
EXPORT_SYMBOL(inet_recvmsg);

int inet_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	/* This should really check to make sure
	 * the socket is a TCP socket. (WHY AC...)
	 */
	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

	lock_sock(sk);
	if (sock->state == SS_CONNECTING) {
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
			sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case TCP_CLOSE:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case TCP_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case TCP_SYN_SENT:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_shutdown);

/*
 *	ioctl() calls you can issue on an INET socket. Most of these are
 *	device configuration and stuff and very rarely used. Some ioctls
 *	pass on to the socket itself.
 *
 *	NOTE: I like the idea of a module for the config stuff. ie ifconfig
 *	loads the devconfigure module does its configuring and unloads it.
 *	There's a good 20K of config code hanging around the kernel.
 */

int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = 0;
	struct net *net = sock_net(sk);

	switch (cmd) {
	case SIOCGSTAMP:
		err = sock_get_timestamp(sk, (struct timeval __user *)arg);
		break;
	case SIOCGSTAMPNS:
		err = sock_get_timestampns(sk, (struct timespec __user *)arg);
		break;
		/* 添加 删除 路由操作 */
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCRTMSG:
		err = ip_rt_ioctl(net, cmd, (void __user *)arg);
		break;

		//ARP添加 删除 设置
	case SIOCDARP:
	case SIOCGARP:
	case SIOCSARP:
		err = arp_ioctl(net, cmd, (void __user *)arg);
		break;

		/* DEV设备接口操作 */
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFPFLAGS:
	case SIOCGIFPFLAGS:
	case SIOCSIFFLAGS:
		err = devinet_ioctl(net, cmd, (void __user *)arg);
		break;
		
	default://对具体的某个协议的套接口ioctl操作
		if (sk->sk_prot->ioctl)
			err = sk->sk_prot->ioctl(sk, cmd, arg);
		else
			err = -ENOIOCTLCMD;
		break;
	}
	return err;
}
EXPORT_SYMBOL(inet_ioctl);

#ifdef CONFIG_COMPAT
static int inet_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = -ENOIOCTLCMD;

	if (sk->sk_prot->compat_ioctl)
		err = sk->sk_prot->compat_ioctl(sk, cmd, arg);

	return err;
}
#endif

//TCP协议z在INET层操作集inet_stream_ops
const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = tcp_poll,
	.ioctl		   = inet_ioctl, //通过sock_do_ioctl走到这里
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt, //解析应用程序的setsockopt，并内核生效
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
	.splice_read	   = tcp_splice_read,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};
EXPORT_SYMBOL(inet_stream_ops);

//UDP协议在INET层操作集inet_dgram_ops
const struct proto_ops inet_dgram_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};
EXPORT_SYMBOL(inet_dgram_ops);

/*
 * For SOCK_RAW sockets; should be the same as inet_dgram_ops but without
 * udp_poll
 */
static const struct proto_ops inet_sockraw_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};

////ops->create在应用程序创建套接字的时候，引起系统调用，从而在函数__sock_create中执行ops->create  netlink为netlink_family_ops
//应用层创建套接字的时候，内核系统调用sock_create，然后执行该函数
////pf_inet的net_families[]为inet_family_ops，对应的套接口层ops参考inetsw_array中的inet_stream_ops inet_dgram_ops inet_sockraw_ops，传输层操作集分别为tcp_prot udp_prot raw_prot
//netlink的net_families[]netlink_family_ops，对应的套接口层ops为netlink_ops
//family协议族通过sock_register注册  传输层接口tcp_prot udp_prot netlink_prot等通过proto_register注册   IP层接口通过inet_add_protocol(&icmp_protocol等注册 ，这些组成过程参考inet_init函数
static const struct net_proto_family inet_family_ops = {//操作集参考inetsw_array  
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};

/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 在初始化的时候我们会将上面数组中的的元素按套接字类型插入static struct list_head inetsw[SOCK_MAX];链表数组中
 */  //参见樊东东P211 
 /* 
  * inetsw_array数组包含三个inet_protosw结构的实例，分别对应
  * TCP、UDP和原始套接字。在Internet协议族初始化函数inet_init()中
  * 调用inet_register_protosw()将inetsw_array数组中
  * 的inet_protosw结构实例，以其type值为key组织到散列表inetsw中，
  * 也就是说各协议族中type值相同而protocol值不同的inet_protosw结构
  * 实例，在inetsw散列表中以type为关键字连接成链表，通过inetsw
  * 散列表可以找到所有协议族的inet_protosw结构实例。
  */ ////ipv4_specific是TCP传输层到网络层数据发送以及TCP建立过程的真正OPS，在tcp_prot->init中被赋值给inet_connection_sock->icsk_af_ops
static struct inet_protosw inetsw_array[] =   //这个和应用层创建套接字相关，个人我理解是属于套接口层,为了把套接口层和传输层衔接起来(tcp_protocol udp_protol icmp_protocol)
{
	{  
		.type =       SOCK_STREAM, //在inet_create的时候，用它做为关键字，把下面这几个成员联系在一起
		.protocol =   IPPROTO_TCP,

    //tcp_prot udp proto raw_proto头添加到的proto_list中，通过遍历该链表就可以知道有哪些传输层协议添加到该链表中
//协议最终都是通过inet_init中的proto_register添加到proto_list链表中的。family协议族通过sock_register注册  传输层接口tcp_prot udp_prot netlink_prot等通过proto_register注册   IP层接口通过inet_add_protocol(&icmp_protocol等注册 ，这些组成过程参考inet_init函数
		.prot =       &tcp_prot,//传输层操作集  在inet_create中的sk_alloc中赋值  先执行ops中的函数，然后执行prot中对应的函数 proto结构为网络接口层，结构中的操作实现传输层的操作和从传输层到网络层调用的跳转，在proto结构中的某些成员跟proto_ops结构中的成员对应，比如connect()等
		.ops =        &inet_stream_ops,//套接口层操作集,也就是协议族操作集 用来区分协议族(netlink family(ops为netlink_ops)或者 inet family)  ops在创建套接字的时候被赋值，例如netlink赋值的地方在__netlink_create  pf_net赋值的地方在inet_create中
		.flags =      INET_PROTOSW_PERMANENT |
			      INET_PROTOSW_ICSK,
	},

	{
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_UDP,
		.prot =       &udp_prot,//传输层操作集  在inet_create中的sk_alloc中赋值  先执行ops中的函数，然后执行prot中对应的函数
		.ops =        &inet_dgram_ops,//套接口层操作集 用来区分协议族(netlink family(ops为netlink_ops)或者 inet family)  ops在创建套接字的时候被赋值，例如netlink赋值的地方在__netlink_create  pf_net赋值的地方在inet_create中
		.flags =      INET_PROTOSW_PERMANENT,
       },

       {
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_ICMP,
		.prot =       &ping_prot,
		.ops =        &inet_sockraw_ops,
		.flags =      INET_PROTOSW_REUSE,
       },

       {
	       .type =       SOCK_RAW,  //原始套接口
	       .protocol =   IPPROTO_IP,	/* wild card */
	       .prot =       &raw_prot,//传输层操作集  在inet_create中的sk_alloc中赋值  先执行ops中的函数，然后执行prot中对应的函数
	       .ops =        &inet_sockraw_ops,//套接口层操作集  用来区分协议族(netlink family(ops为netlink_ops)或者 inet family)  ops在创建套接字的时候被赋值，例如netlink赋值的地方在__netlink_create  pf_net赋值的地方在inet_create中
	       .flags =      INET_PROTOSW_REUSE,
       }
};

#define INETSW_ARRAY_LEN ARRAY_SIZE(inetsw_array)
/*
inet_register_protosw把数组inetsw_array中定义的套接字类型全部注册到inetsw数组中；其中相同套接字类型，不同协议类型的套接字
通过链表存放在到inetsw数组中，以套接字类型为索引，在系统实际使用的时候，只使用inetsw，而不使用 inetsw_array；
*/
void inet_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	int protocol = p->protocol;
	struct list_head *last_perm;

	spin_lock_bh(&inetsw_lock);

	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	last_perm = &inetsw[p->type];
	list_for_each(lh, &inetsw[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	/* Add the new entry after the last permanent entry if any, so that
	 * the new entry does not override a permanent entry when matched with
	 * a wild-card protocol. But it is allowed to override any existing
	 * non-permanent entry.  This means that when we remove this entry, the
	 * system automatically returns to the old behavior.
	 */
	list_add_rcu(&p->list, last_perm);
out:
	spin_unlock_bh(&inetsw_lock);

	return;

out_permanent:
	pr_err("Attempt to override permanent protocol %d\n", protocol);
	goto out;

out_illegal:
	pr_err("Ignoring attempt to register invalid socket type %d\n",
	       p->type);
	goto out;
}
EXPORT_SYMBOL(inet_register_protosw);

void inet_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		pr_err("Attempt to unregister permanent protocol %d\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetsw_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetsw_lock);

		synchronize_net();
	}
}
EXPORT_SYMBOL(inet_unregister_protosw);

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

int sysctl_ip_dynaddr __read_mostly;

static int inet_sk_reselect_saddr(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	__be32 old_saddr = inet->inet_saddr;
	__be32 daddr = inet->inet_daddr;
	struct flowi4 *fl4;
	struct rtable *rt;
	__be32 new_saddr;
	struct ip_options_rcu *inet_opt;

	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     sock_owned_by_user(sk));
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;

	/* Query new route. */
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, daddr, 0, RT_CONN_FLAGS(sk),
			      sk->sk_bound_dev_if, sk->sk_protocol,
			      inet->inet_sport, inet->inet_dport, sk);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	sk_setup_caps(sk, &rt->dst);

	new_saddr = fl4->saddr;

	if (new_saddr == old_saddr)
		return 0;

	if (sysctl_ip_dynaddr > 1) {
		pr_info("%s(): shifting inet->saddr from %pI4 to %pI4\n",
			__func__, &old_saddr, &new_saddr);
	}

	inet->inet_saddr = inet->inet_rcv_saddr = new_saddr;

	/*
	 * XXX The only one ugly spot where we need to
	 * XXX really change the sockets identity after
	 * XXX it has entered the hashes. -DaveM
	 *
	 * Besides that, it does not check for connection
	 * uniqueness. Wait for troubles.
	 */
	__sk_prot_rehash(sk);
	return 0;
}

int inet_sk_rebuild_header(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
	__be32 daddr;
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	int err;

	/* Route is OK, nothing to do. */
	if (rt)
		return 0;

	/* Reroute. */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	daddr = inet->inet_daddr;
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;
	rcu_read_unlock();
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_output_ports(sock_net(sk), fl4, sk, daddr, inet->inet_saddr,
				   inet->inet_dport, inet->inet_sport,
				   sk->sk_protocol, RT_CONN_FLAGS(sk),
				   sk->sk_bound_dev_if);
	if (!IS_ERR(rt)) {
		err = 0;
		sk_setup_caps(sk, &rt->dst);
	} else {
		err = PTR_ERR(rt);

		/* Routing failed... */
		sk->sk_route_caps = 0;
		/*
		 * Other protocols have to map its equivalent state to TCP_SYN_SENT.
		 * DCCP maps its DCCP_REQUESTING state to TCP_SYN_SENT. -acme
		 */
		if (!sysctl_ip_dynaddr ||
		    sk->sk_state != TCP_SYN_SENT ||
		    (sk->sk_userlocks & SOCK_BINDADDR_LOCK) ||
		    (err = inet_sk_reselect_saddr(sk)) != 0)
			sk->sk_err_soft = -err;
	}

	return err;
}
EXPORT_SYMBOL(inet_sk_rebuild_header);

/*
 * inet_gso_segment()是IP层gso_segment接口的实现函数，根据
 * 分段数据包获取对应的传输层接口，并完成GSO
 * 分段后，对分段后的IP数据包重新计算校验和。
 */

static struct sk_buff *inet_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	const struct net_offload *ops;
	unsigned int offset = 0;
	bool udpfrag, encap;
	struct iphdr *iph;
	int proto;
	int nhoff;
	int ihl;
	int id;

	/*
	 * 检验待软GSO分段的SKB，其gsotype是否
	 * 存在其他非法的值。
	 */
	if (unlikely(skb_shinfo(skb)->gso_type &
		     ~(SKB_GSO_TCPV4 |
		       SKB_GSO_UDP |
		       SKB_GSO_DODGY |
		       SKB_GSO_TCP_ECN |
		       SKB_GSO_GRE |
		       SKB_GSO_GRE_CSUM |
		       SKB_GSO_IPIP |
		       SKB_GSO_SIT |
		       SKB_GSO_TCPV6 |
		       SKB_GSO_UDP_TUNNEL |
		       SKB_GSO_UDP_TUNNEL_CSUM |
		       SKB_GSO_MPLS |
		       0)))
		goto out;

	skb_reset_network_header(skb);
	nhoff = skb_network_header(skb) - skb_mac_header(skb);
	/*
	 * 待分段数据包长度至少大于IP首部长度，
	 * 否则必定是无效IP数据包。
	 */
	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	/*
	 * 检测IP首部中长度字段是否有效。
	 */
	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	id = ntohs(iph->id);
	proto = iph->protocol;

	/* Warning: after this point, iph might be no longer valid */
	/*
	 * 再次通过IP首部中长度字段检测
	 * IP数据包长度是否有效。
	 */
	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	/*
	 * 取出IP首部中ID字段值，用于分片数据包
	 * 的IP首部中ID的基础值。取出IP首部中的
	 * 协议字段值，用于定位与之对应的传输
	 * 层协议接口。
	 */
	__skb_pull(skb, ihl);

	encap = SKB_GSO_CB(skb)->encap_level > 0;
	if (encap)
		features &= skb->dev->hw_enc_features;
	SKB_GSO_CB(skb)->encap_level += ihl;

	skb_reset_transport_header(skb);

	segs = ERR_PTR(-EPROTONOSUPPORT);

	if (skb->encapsulation &&
	    skb_shinfo(skb)->gso_type & (SKB_GSO_SIT|SKB_GSO_IPIP))
		udpfrag = proto == IPPROTO_UDP && encap;
	else
		udpfrag = proto == IPPROTO_UDP && !skb->encapsulation;

	/*
	 * 根据IP首部中协议字段值，获取对应的
	 * 传输层协议接口，然后通过gso_segment接口
	 * (参见tcp_tso_segment())，对TCP段进行软GSO分段，
	 * 分段得到的新段通过next链表在原先的段
	 * 之后。
	 */
	 
	ops = rcu_dereference(inet_offloads[proto]);
	if (likely(ops && ops->callbacks.gso_segment))//icmp_protocol、udp_protocol、tcp_protocol和igmp_protocol
		segs = ops->callbacks.gso_segment(skb, features);//分段得到的新段通过next链表在原先的段之后

	if (IS_ERR_OR_NULL(segs))
		goto out;

	skb = segs;
	do {
		iph = (struct iphdr *)(skb_mac_header(skb) + nhoff);
		if (udpfrag) {
			iph->id = htons(id);
			iph->frag_off = htons(offset >> 3);
			if (skb->next != NULL)
				iph->frag_off |= htons(IP_MF);
			offset += skb->len - nhoff - ihl;
		} else {
			iph->id = htons(id++);
		}
		iph->tot_len = htons(skb->len - nhoff);
		ip_send_check(iph);
		if (encap)
			skb_reset_inner_headers(skb);
		skb->network_header = (u8 *)iph - skb->head;
	} while ((skb = skb->next));

out:
	/*
	 * 最后，如果分段成功，则返回分段后SKB链表
	 * 中的第一个SKB，否则返回相应的错误码。
	 */
	return segs;
}

static struct sk_buff **inet_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	const struct net_offload *ops;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	const struct iphdr *iph;
	unsigned int hlen;
	unsigned int off;
	unsigned int id;
	int flush = 1;
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		iph = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!iph))
			goto out;
	}

	proto = iph->protocol;

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);
	if (!ops || !ops->callbacks.gro_receive)
		goto out_unlock;

	if (*(u8 *)iph != 0x45)
		goto out_unlock;

	if (unlikely(ip_fast_csum((u8 *)iph, 5)))
		goto out_unlock;

	id = ntohl(*(__be32 *)&iph->id);
	flush = (u16)((ntohl(*(__be32 *)iph) ^ skb_gro_len(skb)) | (id & ~IP_DF));
	id >>= 16;

	for (p = *head; p; p = p->next) {
		struct iphdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		iph2 = (struct iphdr *)(p->data + off);
		/* The above works because, with the exception of the top
		 * (inner most) layer, we only aggregate pkts with the same
		 * hdr length so all the hdrs we'll need to verify will start
		 * at the same offset.
		 */
		if ((iph->protocol ^ iph2->protocol) |
		    ((__force u32)iph->saddr ^ (__force u32)iph2->saddr) |
		    ((__force u32)iph->daddr ^ (__force u32)iph2->daddr)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			(iph->ttl ^ iph2->ttl) |
			(iph->tos ^ iph2->tos) |
			((iph->frag_off ^ iph2->frag_off) & htons(IP_DF));

		/* Save the IP ID check to be included later when we get to
		 * the transport layer so only the inner most IP ID is checked.
		 * This is because some GSO/TSO implementations do not
		 * correctly increment the IP ID for the outer hdrs.
		 */
		NAPI_GRO_CB(p)->flush_id =
			    ((u16)(ntohs(iph2->id) + NAPI_GRO_CB(p)->count) ^ id);
		NAPI_GRO_CB(p)->flush |= flush;
	}

	NAPI_GRO_CB(skb)->flush |= flush;
	skb_set_network_header(skb, off);
	/* The above will be needed by the transport layer if there is one
	 * immediately following this IP hdr.
	 */

	/* Note : No need to call skb_gro_postpull_rcsum() here,
	 * as we already checked checksum over ipv4 header was 0
	 */
	skb_gro_pull(skb, sizeof(*iph));
	skb_set_transport_header(skb, skb_gro_offset(skb));

	pp = ops->callbacks.gro_receive(head, skb);

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

static struct sk_buff **ipip_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	if (NAPI_GRO_CB(skb)->encap_mark) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	NAPI_GRO_CB(skb)->encap_mark = 1;

	return inet_gro_receive(head, skb);
}

#define SECONDS_PER_DAY	86400

/* inet_current_timestamp - Return IP network timestamp
 *
 * Return milliseconds since midnight in network byte order.
 */
__be32 inet_current_timestamp(void)
{
	u32 secs;
	u32 msecs;
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);

	/* Get secs since midnight. */
	(void)div_u64_rem(ts.tv_sec, SECONDS_PER_DAY, &secs);
	/* Convert to msecs. */
	msecs = secs * MSEC_PER_SEC;
	/* Convert nsec to msec. */
	msecs += (u32)ts.tv_nsec / NSEC_PER_MSEC;

	/* Convert to network byte order. */
	return htons(msecs);
}
EXPORT_SYMBOL(inet_current_timestamp);

int inet_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len)
{
	if (sk->sk_family == AF_INET)
		return ip_recv_error(sk, msg, len, addr_len);
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return pingv6_ops.ipv6_recv_error(sk, msg, len, addr_len);
#endif
	return -EINVAL;
}

static int inet_gro_complete(struct sk_buff *skb, int nhoff)
{
	__be16 newlen = htons(skb->len - nhoff);
	struct iphdr *iph = (struct iphdr *)(skb->data + nhoff);
	const struct net_offload *ops;
	int proto = iph->protocol;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_network_header(skb, nhoff);

	csum_replace2(&iph->check, iph->tot_len, newlen);
	iph->tot_len = newlen;

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out_unlock;

	/* Only need to add sizeof(*iph) to get to the next hdr below
	 * because any hdr with option will have been flushed in
	 * inet_gro_receive().
	 */
	err = ops->callbacks.gro_complete(skb, nhoff + sizeof(*iph));

out_unlock:
	rcu_read_unlock();

	return err;
}

static int ipip_gro_complete(struct sk_buff *skb, int nhoff)
{
	skb->encapsulation = 1;
	skb_shinfo(skb)->gso_type |= SKB_GSO_IPIP;
	return inet_gro_complete(skb, nhoff);
}

int inet_ctl_sock_create(struct sock **sk, unsigned short family,
			 unsigned short type, unsigned char protocol,
			 struct net *net)
{
	struct socket *sock;
	int rc = sock_create_kern(family, type, protocol, &sock);

	if (rc == 0) {
		*sk = sock->sk;
		(*sk)->sk_allocation = GFP_ATOMIC;
		/*
		 * Unhash it so that IP input processing does not even see it,
		 * we do not wish this socket to see incoming packets.
		 */
		(*sk)->sk_prot->unhash(*sk);

		sk_change_net(*sk, net);
	}
	return rc;
}
EXPORT_SYMBOL_GPL(inet_ctl_sock_create);

unsigned long snmp_fold_field(void __percpu *mib, int offt)
{
	unsigned long res = 0;
	int i;

	for_each_possible_cpu(i)
		res += *(((unsigned long *) per_cpu_ptr(mib, i)) + offt);
	return res;
}
EXPORT_SYMBOL_GPL(snmp_fold_field);

#if BITS_PER_LONG==32

u64 snmp_fold_field64(void __percpu *mib, int offt, size_t syncp_offset)
{
	u64 res = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		void *bhptr;
		struct u64_stats_sync *syncp;
		u64 v;
		unsigned int start;

		bhptr = per_cpu_ptr(mib, cpu);
		syncp = (struct u64_stats_sync *)(bhptr + syncp_offset);
		do {
			start = u64_stats_fetch_begin_irq(syncp);
			v = *(((u64 *) bhptr) + offt);
		} while (u64_stats_fetch_retry_irq(syncp, start));

		res += v;
	}
	return res;
}
EXPORT_SYMBOL_GPL(snmp_fold_field64);
#endif

#ifdef CONFIG_IP_MULTICAST
static const struct net_protocol igmp_protocol = {
	.handler =	igmp_rcv,
	.netns_ok =	1,
};
#endif

////ipv4_specific是TCP传输层到网络层数据发送以及TCP建立过程的真正OPS，在tcp_prot->init中被赋值给inet_connection_sock->icsk_af_ops
////这里面有每种协议传输层的接收函数，后面的inetsw_array那几行是套接口层的相关函数  在函数中执行handler,见函数ip_local_deliver_finish
//family协议族通过sock_register注册  传输层接口tcp_prot udp_prot netlink_prot等通过proto_register注册   IP层接口通过inet_add_protocol(&icmp_protocol等注册 ，这些组成过程参考inet_init函数

//IP层处理完后(包括ip_local_deliver_finish和icmp_unreach)，走到这里，这是IP层和传输层的邻借口，然后在由这里走到tcp_prot udp_prot raw_prot
static const struct net_protocol tcp_protocol = { //这些是传输层的接收处理过程，传输层和套接口层的处理过程需要使用udp_prot tcp_prot raw_prot过渡到socket层，处理过程参考inetsw_array
	.early_demux	=	tcp_v4_early_demux,
	.handler =	tcp_v4_rcv,  //当接收到报文后，ip层处理完后在ip_local_deliver_finish 函数中ret = ipprot->handler(skb);走到这里          //从这里面跳转到tcp_prot
	.err_handler =	tcp_v4_err, //icmp_unreach当收到ICMP差错报文后，如果引起差错的是TCP包就走到该函数
	.no_policy	=	1,
	.netns_ok	=	1,
	.icmp_strict_tag_validation = 1,
};
//这几个是接收的过程处理
static const struct net_protocol udp_protocol = { //在函数中执行handler,见函数ip_local_deliver_finish
	.early_demux =	udp_v4_early_demux,
	.handler =	udp_rcv,
	.err_handler =	udp_err,
	.no_policy =	1,
	.netns_ok =	1,
};

static const struct net_protocol icmp_protocol = {//在函数中执行handler,见函数ip_local_deliver_finish
	.handler =	icmp_rcv,
	.err_handler =	icmp_err,
	.no_policy =	1,
	.netns_ok =	1,
};

/*
上面几个结构体中的err_handler的解释如下:
 * 目的不可达、源端被关闭、超时、参数错误这四种类型
 * 的差错ICMP报文，都是由同一个函数icmp_unreach()来处理的，
 * 对其中目的不可达、源端被关闭这两种类型ICMP报文
 * 因要提取某些信息而需作一些特殊的处理，而另外
 * 一些则不需要，根据差错报文中的信息直接调用
 * 传输层的错误处理例程。参见<Linux内核源码剖析348页>
 */

static __net_init int ipv4_mib_init_net(struct net *net)
{
	int i;

	net->mib.tcp_statistics = alloc_percpu(struct tcp_mib);
	if (!net->mib.tcp_statistics)
		goto err_tcp_mib;
	net->mib.ip_statistics = alloc_percpu(struct ipstats_mib);
	if (!net->mib.ip_statistics)
		goto err_ip_mib;

	for_each_possible_cpu(i) {
		struct ipstats_mib *af_inet_stats;
		af_inet_stats = per_cpu_ptr(net->mib.ip_statistics, i);
		u64_stats_init(&af_inet_stats->syncp);
	}

	net->mib.net_statistics = alloc_percpu(struct linux_mib);
	if (!net->mib.net_statistics)
		goto err_net_mib;
	net->mib.udp_statistics = alloc_percpu(struct udp_mib);
	if (!net->mib.udp_statistics)
		goto err_udp_mib;
	net->mib.udplite_statistics = alloc_percpu(struct udp_mib);
	if (!net->mib.udplite_statistics)
		goto err_udplite_mib;
	net->mib.icmp_statistics = alloc_percpu(struct icmp_mib);
	if (!net->mib.icmp_statistics)
		goto err_icmp_mib;
	net->mib.icmpmsg_statistics = kzalloc(sizeof(struct icmpmsg_mib),
					      GFP_KERNEL);
	if (!net->mib.icmpmsg_statistics)
		goto err_icmpmsg_mib;

	tcp_mib_init(net);
	return 0;

err_icmpmsg_mib:
	free_percpu(net->mib.icmp_statistics);
err_icmp_mib:
	free_percpu(net->mib.udplite_statistics);
err_udplite_mib:
	free_percpu(net->mib.udp_statistics);
err_udp_mib:
	free_percpu(net->mib.net_statistics);
err_net_mib:
	free_percpu(net->mib.ip_statistics);
err_ip_mib:
	free_percpu(net->mib.tcp_statistics);
err_tcp_mib:
	return -ENOMEM;
}

static __net_exit void ipv4_mib_exit_net(struct net *net)
{
	kfree(net->mib.icmpmsg_statistics);
	free_percpu(net->mib.icmp_statistics);
	free_percpu(net->mib.udplite_statistics);
	free_percpu(net->mib.udp_statistics);
	free_percpu(net->mib.net_statistics);
	free_percpu(net->mib.ip_statistics);
	free_percpu(net->mib.tcp_statistics);
}

static __net_initdata struct pernet_operations ipv4_mib_ops = {
	.init = ipv4_mib_init_net,
	.exit = ipv4_mib_exit_net,
};

static int __init init_ipv4_mibs(void)
{
	return register_pernet_subsys(&ipv4_mib_ops);
}

static __net_init int inet_init_net(struct net *net)
{
	/*
	 * Set defaults for local port range
	 */
	seqlock_init(&net->ipv4.ip_local_ports.lock);
	net->ipv4.ip_local_ports.range[0] =  32768;
	net->ipv4.ip_local_ports.range[1] =  61000;

	seqlock_init(&net->ipv4.ping_group_range.lock);
	/*
	 * Sane defaults - nobody may create ping sockets.
	 * Boot scripts should set this to distro-specific group.
	 */
	net->ipv4.ping_group_range.range[0] = make_kgid(&init_user_ns, 1);
	net->ipv4.ping_group_range.range[1] = make_kgid(&init_user_ns, 0);
	return 0;
}

static __net_exit void inet_exit_net(struct net *net)
{
}

static __net_initdata struct pernet_operations af_inet_ops = {
	.init = inet_init_net,
	.exit = inet_exit_net,
};

static int __init init_inet_pernet_ops(void)
{
	return register_pernet_subsys(&af_inet_ops);
}

static int ipv4_proc_init(void);

/*
 *	IP protocol layer initialiser
 */

static struct packet_offload ip_packet_offload __read_mostly = {
    /* 
        * 由于类型不是ETH_P_ALL，所以ip_packet_type
        * 会被添加到ptype_base链表中，参见dev_add_pack
        */
	.type = cpu_to_be16(ETH_P_IP),
	.callbacks = {
		.gso_segment = inet_gso_segment,//使用的地方在skb_gso_segment
		.gro_receive = inet_gro_receive,
		.gro_complete = inet_gro_complete,
	},
};

static const struct net_offload ipip_offload = {
	.callbacks = {
		.gso_segment	= inet_gso_segment,
		.gro_receive	= ipip_gro_receive,
		.gro_complete	= ipip_gro_complete,
	},
};

static int __init ipv4_offload_init(void)
{
	/*
	 * Add offloads
	 */
	if (udpv4_offload_init() < 0)
		pr_crit("%s: Cannot add UDP protocol offload\n", __func__);
	if (tcpv4_offload_init() < 0)
		pr_crit("%s: Cannot add TCP protocol offload\n", __func__);

	dev_add_offload(&ip_packet_offload);
	inet_add_offload(&ipip_offload, IPPROTO_IPIP);
	return 0;
}

fs_initcall(ipv4_offload_init);

static struct packet_type ip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,
};

//设备物理层的初始化net_dev_init
 //TCP/IP协议栈初始化inet_init 其实传输层的协议初始化也在这里面
 //传输层初始化proto_init  只是为了显示各种协议用的
 //套接口层初始化sock_init  netfilter_init在套接口层初始化的时候也初始化了
 static int __init inet_init(void)
{
	struct inet_protosw *q;
	struct list_head *r;
	int rc = -EINVAL;

	BUILD_BUG_ON(sizeof(struct inet_skb_parm) > FIELD_SIZEOF(struct sk_buff, cb));

	rc = proto_register(&tcp_prot, 1);
	if (rc)
		goto out;

	rc = proto_register(&udp_prot, 1);
	if (rc)
		goto out_unregister_tcp_proto;

	rc = proto_register(&raw_prot, 1);
	if (rc)
		goto out_unregister_udp_proto;

	rc = proto_register(&ping_prot, 1);
	if (rc)
		goto out_unregister_raw_proto;

	/*
	 *	Tell SOCKET that we are alive...注册socket，告诉socket inet类型的地址族已经准备好了
	 */
	/* 注册Internet协议簇的相关信息 */
	(void)sock_register(&inet_family_ops);

#ifdef CONFIG_SYSCTL
	ip_static_sysctl_init();
#endif

	/*
	 *	Add all the base protocols.包括arp,ip、ICMP、UPD、tcp_v4、tcp、igmp的初始化，
	 *	主要初始化各种协议对应的inode和socket变量。
	 *	其中arp_init完成系统中路由部分neighbour表的初始化ip_init完成ip协议的初始化。
	 *	在这两个函数中，都通过定义一个packet_type结构的变量将这种数据包对应的协议发送数据、
	 *	允许发送设备都做初始化。
	 */

	if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
		pr_crit("%s: Cannot add ICMP protocol\n", __func__);
	if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
		pr_crit("%s: Cannot add UDP protocol\n", __func__);
	if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
		pr_crit("%s: Cannot add TCP protocol\n", __func__);
#ifdef CONFIG_IP_MULTICAST
	if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
		pr_crit("%s: Cannot add IGMP protocol\n", __func__);
#endif

	/* Register the socket-side information for inet_create. */
	/* 将inetsw_array中元素加入到inetsw链表中 */
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		inet_register_protosw(q); //把inetsw_array结构中的节点添加到inetsw表中，以type为索引

	/*
	 *	Set the ARP module up
	 */
	/* ARP协议初始化 */
	arp_init();

	/*
	 *	Set the IP module up
	 */

	/* IP协议初始化 */
	ip_init();

	tcp_v4_init();

	/* Setup TCP slab cache for open requests. */
	tcp_init();

	/* Setup UDP memory threshold */
	udp_init();

	/* Add UDP-Lite (RFC 3828) */
	udplite4_register();

	ping_init();

	/*
	 *	Set the ICMP layer up
	 */
        /*由于协议栈本身有发送ICMP数据报的需求，所以，需要在协议栈中创建内核态的原始套接字，用于发送ICMP数据报，这个事情在协议栈初始化时，
        由 icmp_init函数完成。它为每个CPU都创建一个icmp_socket，创建工作由sock_create_kern函数完成，创建流程跟应用层 创建socket完全一致。*/
    if (icmp_init() < 0)
		panic("Failed to create the ICMP control socket.\n");

	/*
	 *	Initialise the multicast router
	 */
#if defined(CONFIG_IP_MROUTE)
	if (ip_mr_init())
		pr_crit("%s: Cannot init ipv4 mroute\n", __func__);
#endif

	if (init_inet_pernet_ops())
		pr_crit("%s: Cannot init ipv4 inet pernet ops\n", __func__);
	/*
	 *	Initialise per-cpu ipv4 mibs
	 */

	if (init_ipv4_mibs())
		pr_crit("%s: Cannot init ipv4 mibs\n", __func__);

	ipv4_proc_init();

	ipfrag_init();

	dev_add_pack(&ip_packet_type);

	rc = 0;
out:
	return rc;
out_unregister_raw_proto:
	proto_unregister(&raw_prot);
out_unregister_udp_proto:
	proto_unregister(&udp_prot);
out_unregister_tcp_proto:
	proto_unregister(&tcp_prot);
	goto out;
}

fs_initcall(inet_init);//internet协议族的初始化

/* ------------------------------------------------------------------------ */

#ifdef CONFIG_PROC_FS
static int __init ipv4_proc_init(void)
{
	int rc = 0;

	if (raw_proc_init())
		goto out_raw;
	if (tcp4_proc_init())
		goto out_tcp;
	if (udp4_proc_init())
		goto out_udp;
	if (ping_proc_init())
		goto out_ping;
	if (ip_misc_proc_init())
		goto out_misc;
out:
	return rc;
out_misc:
	ping_proc_exit();
out_ping:
	udp4_proc_exit();
out_udp:
	tcp4_proc_exit();
out_tcp:
	raw_proc_exit();
out_raw:
	rc = -ENOMEM;
	goto out;
}

#else /* CONFIG_PROC_FS */
static int __init ipv4_proc_init(void)
{
	return 0;
}
#endif /* CONFIG_PROC_FS */

MODULE_ALIAS_NETPROTO(PF_INET);

