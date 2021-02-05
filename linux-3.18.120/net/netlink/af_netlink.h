#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <net/sock.h>

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

struct netlink_ring {
	void			**pg_vec;
	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	atomic_t		pending;
};

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			portid;  //表示本套接字自己绑定的id号，对于内核来说它就是0
	u32			dst_portid;//表示为目的ID号
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;//表示协议支持多播组数量
	unsigned long		*groups;//保存组位掩码
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			cb_running;
	int			dump_done_errno;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);//保存接收到用户态数据后的处理函数
	//协议子协议自身特有的绑定和解绑定处理函数
	int			(*netlink_bind)(int group);
	void			(*netlink_unbind)(int group);
	struct module		*module;

	struct rhash_head	node;
};

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

struct netlink_table {
	struct rhashtable	hash;   //用来索引同种协议类型的不同netlink套接字实例
	struct hlist_head	mc_list;//多播使用的sock散列表
	struct listeners __rcu	*listeners;//监听者掩码
	unsigned int		flags;
	unsigned int		groups;		//协议支持的最大多播组数量
	struct mutex		*cb_mutex;
	struct module		*module;
	//函数指针会在内核首次创建netlink的时候被赋值，后续应用层创建和绑定套接字使用
	int			(*bind)(int group);
	void			(*unbind)(int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;
extern struct mutex nl_sk_hash_lock;

#endif
