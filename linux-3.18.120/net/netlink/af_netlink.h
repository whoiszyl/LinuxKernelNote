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
	u32			portid;  //��ʾ���׽����Լ��󶨵�id�ţ������ں���˵������0
	u32			dst_portid;//��ʾΪĿ��ID��
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;//��ʾЭ��֧�ֶಥ������
	unsigned long		*groups;//������λ����
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			cb_running;
	int			dump_done_errno;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);//������յ��û�̬���ݺ�Ĵ�����
	//Э����Э���������еİ󶨺ͽ�󶨴�����
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
	struct rhashtable	hash;   //��������ͬ��Э�����͵Ĳ�ͬnetlink�׽���ʵ��
	struct hlist_head	mc_list;//�ಥʹ�õ�sockɢ�б�
	struct listeners __rcu	*listeners;//����������
	unsigned int		flags;
	unsigned int		groups;		//Э��֧�ֵ����ಥ������
	struct mutex		*cb_mutex;
	struct module		*module;
	//����ָ������ں��״δ���netlink��ʱ�򱻸�ֵ������Ӧ�ò㴴���Ͱ��׽���ʹ��
	int			(*bind)(int group);
	void			(*unbind)(int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;
extern struct mutex nl_sk_hash_lock;

#endif
