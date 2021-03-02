#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/percpu.h>
#include <linux/dynamic_queue_limits.h>
#include <net/gen_stats.h>
#include <net/rtnetlink.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;

// �������ʿ��Ʊ�ṹ ��һ��������Դ�����㷨
struct qdisc_rate_table { //���еĶ���ӵ�qdisc_rtab_list
	struct tc_ratespec rate;
	u32		data[256];//�ο�Ӧ�ò�tc_calc_rtable   //����õ��ľ���2047���ֽ������ĵĿ�����Դ��
	struct qdisc_rate_table *next;
	int		refcnt;
};

//qdisc->state
enum qdisc_state_t {
	__QDISC_STATE_SCHED,
	__QDISC_STATE_DEACTIVATED,
	__QDISC_STATE_THROTTLED,
};

/*
 * following bits are only changed while qdisc lock is held
 */
enum qdisc___state_t {
	__QDISC___STATE_RUNNING = 1,
};

struct qdisc_size_table {
	struct rcu_head		rcu;
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};
/*
 * tc����ʹ�����������QDisc����͹��������в�����
 * add����һ���ڵ������һ��QDisc������߹����������ʱ����Ҫ����һ��������Ϊ���������ݲ���ʱ�ȿ���ʹ��IDҲ����ֱ�Ӵ����豸�ĸ������Ҫ����һ��QDisc���߹�����������ʹ�þ��(handle)�����������Ҫ����һ���࣬����ʹ����ʶ���(classid)��������
 * remove��ɾ����ĳ�����(handle)ָ����QDisc����QDisc(root)Ҳ����ɾ������ɾ��QDisc�ϵ����������Լ������ڸ�����Ĺ��������ᱻ�Զ�ɾ����
 * change��������ķ�ʽ�޸�ĳЩ��Ŀ�����˾��(handle)�����Ȳ����޸����⣬change������﷨��add������ͬ�����仰˵��change�����һ���ڵ��λ�á�
 * replace����һ�����нڵ���н���ԭ�Ӳ�����ɾ������ӡ�����ڵ㲻���ڣ��������ͻὨ���ڵ㡣
 * link��ֻ������DQisc�����һ�����еĽڵ㡣
 * tc qdisc [ add | change | replace | link ] dev DEV [ parent qdisc-id | root ] [ handle qdisc-id ] qdisc [ qdisc specific parameters ]
 * tc class [ add | change | replace ] dev DEV parent qdisc-id [ classid class-id ] qdisc [ qdisc specific parameters ]
 * tc filter [ add | change | replace ] dev DEV [ parent qdisc-id | root ] protocol protocol prio priority filtertype [ filtertype specific parameters ] flowid flow-id
 * tc [-s | -d ] qdisc show [ dev DEV ]
 * tc [-s | -d ] class show dev DEV tc filter show dev DEV

 * tc qdisc show dev eth0
 * tc class show dev eth0
 */
//tc qdisc add dev eth0 parent 22:4 handle 33�е�22:4�е�4ʵ���϶�Ӧ����Qdisc˽�����ݲ��ַ�����Ϣ�е�3,parent 22:x�е�x�Ǵ�1��ʼ�ţ����Ƕ�Ӧ�����������о�������ʱ���Ǵ�0��ʼ�ţ�����Ҫ��1������prio�ο�prio_get
//ǰ��linux�ں����ṩ���������Ƶ���ش����ܣ���ش�����net/schedĿ¼�£���Ӧ�ò��ϵĿ�����ͨ��iproute2������е�tc��ʵ�֣�tc��sched�Ĺ�ϵ�ͺ���iptables��netfilter�Ĺ�ϵһ����һ�����û���ӿڣ�һ���Ǿ���ʵ�֣�����tc��ʹ�÷������꽫Linux Advanced Routing HOWTO��������Ҫ�����ں��еľ���ʵ�֡�
//�ýṹ���ĳƺ�Ϊ:���ض���(���й涨)
//Qdisc���ٿռ�qdisc_alloc���������priv_size���ݣ���pfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(������ض��� ) ���е�priv_size�� ͼ�λ��ο�TC��������ʵ�ַ����������� 
/*
 * ���й�̷�Ϊ������й�̺�������˹�̣�����Ķ��й�̿��Դ�������Ӷ��й��(�����Ƿ����Ҳ����������Ķ��й��)�����ֻ����һ��������й�̾��൱��һ��Ҷ�ӹ��
 * ��SKBֱ����ӵ��ö��й�̵�skb�����С�����Ǵ���һ������Ķ��й�̣����һ�������Ķ��й�̾��Ǹ���������԰�������Ӷ��й�̣������Է�����й�̱����ж�Ӧ
 * ��Ҷ��������й�̣���Ϊ������й��������û��skb���еġ�
 * ��һ��SKB��������й�̵ĸ���ʱ�򣬸�ѡ���������Ӷ��й�������? ����ǹ����������ã�����������ͨ��IP MASK����Ϣ��ȷ�����Ǹ��Ӷ��й�̷�֧�����û������
 * ����������һ�����skb->priority��ȷ�����Ǹ���֧��
 * tc qdisc add dev eth0 root handle 1: htb ���������й�� (�ڴ����������̵�ʱ��һ��Ĭ���ǻ����Զ��й�̵ģ�����pfifo������)
 * tc class add dev eth0 parent 1: classid 1:2 htb xxxx  ��1:���й������ĵ�1:2��֧�ϣ���htb����һ����������й��htb��������xxx��ָ��htb�Ĳ�����Ϣ
 * tc class add dev eth0 parent 1: classid 1:1 htb xxxx  ��1:���й������ĵ�1:1��֧�ϣ���htb����һ����������й��htb��������xxx��ָ��htb�Ĳ�����Ϣ
 * tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 4.3.2.1/32 flowid 1:2 ����յ�����ip��ַΪ4.3.2.1��SKB���������Ӷ��й��1:2��ӣ���������1:1�������
 */ 
//��õ�Դ�����ο�<<linux�ں�����������>>
struct Qdisc { /* �ο� TC��������ʵ�ַ�����������*/ //prio_sched_data�е�queuesָ���Qdisc              #ע�������е�ID(parent 1:2 xxx flowid 3:3)�����������Ϊ16���Ƶ���
	//qdisc_alloc��������struct Qdisc�ṹ�����˽������Ϊpfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops�е�priv_size����
    //enqueue��dequeue�ĸ�ֵ��qdisc_alloc
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev);// ��Ӳ���
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);// ���Ӳ���
	unsigned int		flags; //�Ŷӹ����־��ȡֵΪ�����⼸�ֺ궨��  TCQ_F_THROTTLED
#define TCQ_F_BUILTIN		1//��ʾ�Ŷӹ����ǿյ��Ŷӹ�����ɾ���ͷ�ʱ����Ҫ���������Դ�ͷ�
#define TCQ_F_INGRESS		2//��ʾ�Ŷӹ���Ϊ�����Ŷӹ���
#define TCQ_F_CAN_BYPASS	4
#define TCQ_F_MQROOT		8
#define TCQ_F_ONETXQUEUE	0x10 /* dequeue_skb() can assume all skbs are for
				      * q->dev_queue : It can test
				      * netif_xmit_frozen_or_stopped() before
				      * dequeueing next packet.
				      * Its true for MQ/MQPRIO slaves, or non
				      * multiqueue device.
				      */
#define TCQ_F_WARN_NONWC	(1 << 16)// ��Ϊ�Ѿ���ӡ�˾�����Ϣ�ı�־
#define TCQ_F_CPUSTATS		0x20 /* run using percpu statistics */
	u32			limit;
	// Qdisc�Ļ��������ṹ
	/*pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops�⼸����Ϊ���ڣ�ingress_qdisc_opsΪ��� */
	const struct Qdisc_ops	*ops;//prio���й���opsΪpfifo_qdisc_ops����������prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(������ض��� ) ��
	struct qdisc_size_table	__rcu *stab;
	struct list_head	list;//���ӵ������õ������豸��

	/*�Ŷӹ���ʵ���ı�ʶ��Ϊ����Ų��ֺ͸���Ų��֣���������Ų������û����䣬��Χ��
	0X0001��0X7FFFF������û�ָ�������Ϊ0����ô�ں˽���0X8000��0XFFFF֮�����һ�������
	��ʶ�ڵ��������豸��Ψһ�ģ����ڶ�������豸֮��������ظ�*/
	u32			handle; //��Qdisc�ľ����tc qdisc add dev eth0 root handle 22�е�22
	u32			parent;//�����й���ľ��ֵ  tc qdisc add dev eth0 parent 22:4 handle 33 ��handleΪ33 parentΪ22
    /* ����ʵ�ָ����ӵ��������ƻ��ƣ������Ŷӹ����ʵ�ִ˽ӿڡ���һ���ⲿ�������ڲ�����
     * ���ݱ���ʱ�����ܳ��ֱ��ı��뱻������������統û�п��û�����ʱ������Ŷӹ���ʵ���˸ûص�
     * ��������ô��ʱ�Ϳ��Ա��ڲ��Ŷӹ������
	 */
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);

	void			*u32_node;//ָ��tc_u_common����u32_init  ָ�����ָ�����й�̵ĵ�һ��u32������

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;
	struct netdev_queue	*dev_queue;

	struct gnet_stats_rate_est64	rate_est;
	struct gnet_stats_basic_cpu __percpu *cpu_bstats;
	struct gnet_stats_queue	__percpu *cpu_qstats;

	struct Qdisc		*next_sched;
	struct sk_buff		*gso_skb;
	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	unsigned long		state;
	struct sk_buff_head	q; //SKB������ӵ��ö����е�  pfifo����ӵ�ʱ��ֱ�Ӽ����skb���������ǵ��͵��Ƚ��ȳ�
	struct gnet_stats_basic_packed bstats;//��¼��ӱ������ֽ�������ӱ�������
	unsigned int		__state;
	struct gnet_stats_queue	qstats;//��¼�������ͳ������
	struct rcu_head     rcu_head;//ͨ�����ֽ���û�ж�����ʹ�ø��Ŷӹ���ʱ�ͷŸ��Ŷӹ���
	int			padded;
	atomic_t		refcnt;

	spinlock_t		busylock ____cacheline_aligned_in_smp;
};

static inline bool qdisc_is_running(const struct Qdisc *qdisc)
{
	return (qdisc->__state & __QDISC___STATE_RUNNING) ? true : false;
}

static inline bool qdisc_run_begin(struct Qdisc *qdisc)
{
	if (qdisc_is_running(qdisc))
		return false;
	qdisc->__state |= __QDISC___STATE_RUNNING;
	return true;
}

static inline void qdisc_run_end(struct Qdisc *qdisc)
{
	qdisc->__state &= ~__QDISC___STATE_RUNNING;
}

static inline bool qdisc_may_bulk(const struct Qdisc *qdisc)
{
	return qdisc->flags & TCQ_F_ONETXQUEUE;
}

static inline int qdisc_avail_bulklimit(const struct netdev_queue *txq)
{
#ifdef CONFIG_BQL
	/* Non-BQL migrated drivers will return 0, too. */
	return dql_avail(&txq->dql);
#else
	return 0;
#endif
}

static inline bool qdisc_is_throttled(const struct Qdisc *qdisc)
{
	return test_bit(__QDISC_STATE_THROTTLED, &qdisc->state) ? true : false;
}

static inline void qdisc_throttled(struct Qdisc *qdisc)
{
	set_bit(__QDISC_STATE_THROTTLED, &qdisc->state);
}

static inline void qdisc_unthrottled(struct Qdisc *qdisc)
{
	clear_bit(__QDISC_STATE_THROTTLED, &qdisc->state);
}
/*
 * ����Ķ��й涨������prio cbq htb����Щ���й���Qdisc�����Ӧһ����ӿڣ����������Ķ��й涨����û�и�������ӿ�
 * prio��Ӧprio_class_ops htb��Ӧhtb_class_ops cbq��Ӧcbq_class_ops�ȵ�

 * ������й��Qdisc ops�е�Qdisc_class_ops��Ҫ���ڴ�����Qdisc��ʱ�򣬰���parent 22:4�е�22:4�Ը�Qdisc���з��࣬�Ӷ�ͨ��22:4��Ϊ������
 * ѡ������QdiscӦ�üӵ��Ǹ�����Qdisc���档���Բο�prio_qdisc_ops�е�prio_get��prio_graft���ͺܺ�������
 */ 
//�����Ӷ��й������class��ʱ�򣬸ýṹ�����þ���ͨ��parent 22:8�е�8��prio_get(��prio������й��Ϊ��)ѡ����prize_size˽�����ݲ��������е���һ��������Ϣ��
//���ض����������ṹ
struct Qdisc_class_ops { //��Ҫ��qdisc_graftִ���������غ���       ���Բο�prio_qdisc_ops����prioΪ��        tc_ctl_tclass
	/* Child qdisc manipulation */
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);
	// ���ӽڵ�
	//����qdisc_graft�е���
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);//���ڽ�һ�����й���Qdisc�󶨵�һ���࣬��������ǰ�󶨵������Ķ��й���
	// �����ӽڵ�
	//��ȡ��ǰ�󶨵�������Ķ��й���
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);

	//������Ӧ���г��ȱ仯
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
    //���ݸ���������������Ŷӹ����в��Ҷ�Ӧ���࣬�����ø��࣬��������ü�������
    //��ʾʹ�ö��й������ĵڼ���������Ϣ��һ��������й�����涼���кü���������Ϣ��ͨ��classid������ѡһ��������prio������ͨ��prio_get��ȡ����Ƶ���еĵڼ���Ƶ��
    //���ݸú�����ȷ��ʹ�ø�Qdisc���Ǹ��࣬�ж�����Ϊtc qdisc add dev eth0 parent 22:4 handle 33�е�22:4,��prio������й��Ϊ������prio_get
	unsigned long		(*get)(struct Qdisc *, u32 classid);// ��ȡ, ����ʹ�ü�����ͨ��qdisc_graft����
    //�ݼ�ָ��������ü�����������ü���Ϊ0����ɾ���ͷŴ��ࡣ
	void			(*put)(struct Qdisc *, unsigned long);// �ͷ�, ����ʹ�ü���������qdisc_graft�е���
    //���ڱ��ָ����Ĳ�����������಻�������½�֮��
	int			(*change)(struct Qdisc *, u32, u32,
					struct nlattr **, unsigned long *);// �ı�
    //����ɾ�����ͷ�ָ�����ࡣ���Ȼ�ݼ���������ü�����������ü����ݼ���Ϊ0��ɾ���ͷ�֮��
	int			(*delete)(struct Qdisc *, unsigned long);// ɾ��
    //����һ���Ŷӹ���������࣬ȡ��ʵ���˻ص���������������ݼ�ͳ����Ϣ
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);// ����

	/* Filter manipulation */
	//��ȡ�󶨵�����Ĺ���������������׽ڵ�
	struct tcf_proto __rcu ** (*tcf_chain)(struct Qdisc *, unsigned long);
    //��һ����������׼���󶨵�ָ������֮ǰ�����ã�ͨ�����ʶ����ȡ�࣬���ȵ������ü�����Ȼ����һЩ�����ļ��
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);// tc���󣬼�tcf_bind_filter
    //�ڹ�������ɰ󶨵�ָ������󱻵��ã��ݼ������ü���
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);// tc���

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);// ���
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

//���е�Qdisc_ops�ṹͨ��register_qdisc��ӵ�qdisc_base������
//Qdisc�е�opsָ������              
/*pfifo_fast_ops pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops prio_class_ops�⼸����Ϊ���ڣ�ingress_qdisc_opsΪ��� */
struct Qdisc_ops { //prio���й���opsΪpfifo_qdisc_ops����������tbf_qdisc_ops sfq_qdisc_ops�ȣ� 
	struct Qdisc_ops	*next;// �����е���һ��
    //���й����ṩ��������ӿڡ�
	const struct Qdisc_class_ops	*cl_ops; //����Ķ���pfifo bfifo����û��class����ops��
	char			id[IFNAMSIZ];// Qdisc������, �������С��Ӧ�þ�����������
	//�������Ŷӹ����ϵ�˽����Ϣ���С������Ϣ��ͨ�����Ŷӹ���һ������ڴ棬�������Ŷ�
	//������棬����qdisc_priv��ȡ�� 
	int			priv_size; //�������˽�����ݴ�С Qdisc_alloc����Qdisc�ռ��ʱ���࿪��priv_size�ռ�

	//enqueue����ֵNET_XMIT_SUCCESS��
	int 			(*enqueue)(struct sk_buff *, struct Qdisc *);// ���
	//����ǰ���ӵı����������뵽�����еĺ�������ͬ��enqueue���ǣ�������ӵı�����Ҫ����������
	//����ǰ���Ŷӹ��������������λ���ϡ��ýӿ�ͨ�����ڱ���Ҫ���ͳ�ȥ����dequeue���Ӻ���ĳ������Ԥ����ԭ������δ�ܷ��͵������
	struct sk_buff *	(*dequeue)(struct Qdisc *);// ����
	struct sk_buff *	(*peek)(struct Qdisc *);// �����ݰ������Ŷ�
	//�Ӷ����Ƴ�������һ�����ĵĺ���
	unsigned int		(*drop)(struct Qdisc *);// ����

	int			(*init)(struct Qdisc *, struct nlattr *arg);// ��ʼ��
	void			(*reset)(struct Qdisc *);// ��λΪ��ʼ״̬,�ͷŻ���,ɾ����ʱ��,��ռ�����
	void			(*destroy)(struct Qdisc *);// �ͷ�
	int			(*change)(struct Qdisc *, struct nlattr *arg);//����Qdisc����
	void			(*attach)(struct Qdisc *);

	int			(*dump)(struct Qdisc *, struct sk_buff *);// ���
    //��������Ŷӹ�������ò�����ͳ�����ݵĺ�����
	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};

//ͨ������SKB�е�������ƥ�������tc filter��ƥ�����浽�ýṹ�С�Ҳ����ֱ�ӻ�ȡ�ù���������class��(tc add class��ʱ�򴴽���class���ڵ�)htb_class
struct tcf_result {
	unsigned long	class; //���ʵ������һ��ָ���ַ��ָ�����tc filter add xxxx flowid 22:4��Ӧ��htb_class�ṹ����tcf_bind_filter
	u32		classid;//��u32_set_parms����ֵΪ//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4�е�flowid����ʾ�ù����������Ǹ����й�����ڵ�
};

//tcf_proto�е�ops�����е�tcf_proto_opsͨ��tcf_proto_base������һ�𣬼�register_tcf_proto_ops
//��Ҫ��cls_u32_ops cls_basic_ops  cls_cgroup_ops  cls_flow_ops cls_route4_ops RSVP_OPS
struct tcf_proto_ops {
	struct list_head	head;//��������ע����������ӵ�tcf_proto_base�����ϵ�ָ��
	char			kind[IFNAMSIZ];//���������� 

	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);//���ຯ�������������tcf_result�У�����ֵ��TC_POLICE_OK��
	int			(*init)(struct tcf_proto*);//tc_ctl_tclass�е���
    //�ͷŲ�ɾ������������
	void			(*destroy)(struct tcf_proto*);

    //��һ��������Ԫ�صľ��ӳ�䵽һ���ڲ���������ʶ����ʵ�����ǹ�����ʵ��ָ�룬�����䷵��
	unsigned long		(*get)(struct tcf_proto*, u32 handle); //��ȡ��Ӧ�Ĺ�����
    //�ͷŶ�get�õ��Ĺ�����������
	void			(*put)(struct tcf_proto*, unsigned long);
	//��������һ���¹��������Ǳ��һ���Ѵ��ڵĹ��������á�
	int			(*change)(struct net *net, struct sk_buff *,
					struct tcf_proto*, unsigned long,
					u32 handle, struct nlattr **,
					unsigned long *, bool);
	int			(*delete)(struct tcf_proto*, unsigned long);
    //�������е�Ԫ�ز��ҵ��ûص�����ȡ���������ݺ�ͳ������
	void			(*walk)(struct tcf_proto*, struct tcf_walker *arg);

	/* rtnetlink specific */  
	//����������е�Ԫ�ز��ҵ��ûص�����ȡ���������ݺ�ͳ������
	int			(*dump)(struct net*, struct tcf_proto*, unsigned long,
					struct sk_buff *skb, struct tcmsg*);

	struct module		*owner;
};
/* ���ȼ����й涨��bandΪ16��,�ο�TC��������ʵ�ַ���(����)-ͼ3  ������prio�����͵ĸ����ض���_2 */   //��ϸ���Ҳ���Բο�<<LINUX�߼�·�ɺ���������>>
//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4
/*�������ݰ�������������£�
1.      ������Ĺ��������ǿգ�����������Ĺ���������������һ��ƥ��Ĺ������ͷ��أ������ݷ��صĽ��ѡ�����ࡣ
2.      ÿ����������������Ӧ�ķ��ຯ���������ݹ�������˽��������ƥ�����ݰ���
*/
//tc filter u32�������Ľṹ    ������������tc_ctl_tfilter�У����ڸú����г�ʼ��
struct tcf_proto { //�ýṹ�Ǽ��뵽prio_sched_data�е�filter_list������  ÿ����һ��tc filter add�ͻᴴ��һ��tcf_proto�ṹ�����ö��tc filter add��ʱ��ʹ������tcf_proto�ṹ��ͨ��next����
	/* Fast access part */ 
	//tcfһ���ʾtcf_proto�������ļ�д
	struct tcf_proto __rcu	*next;
	void __rcu		*root;//���Ϊu32���ͣ�ָ���������tc_u_hnode�� ��u32_init���ù��������������tc_u_common�ڵ㶼��ӵ���tc_u_hnode����
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					struct tcf_result *); //���ຯ�������������tcf_result�С�ͨ��SKB�е����ݣ���ƥ�������������������ظ�tcf_result����tc_classify_compat
	__be16			protocol; //Э��ţ�//tc filter add dev eth0 protocol ip��protocol ip��Ӧ��������ETH_P_IP

	/* All the rest */
	u32			prio; //����������ȼ����뵽prio_sched_data�е�filter_list�����С�tc filter add dev eth0 protocol ip parent 22: prio 2Ϊ2
	u32			classid; //ָ����Qdisc�е�����λ��=22:4
	struct Qdisc		*q; //��Qdisc,���Ǹù����������Ķ��й���ڵ���ϼ���Qdisc
	void			*data; //�����󴴽���u32���͹������ڵ�tc_u_common����u32_init
	//cls_u32_ops 
	//��Ҫ��cls_u32_ops cls_basic_ops  cls_cgroup_ops  cls_flow_ops cls_route4_ops RSVP_OPS
	const struct tcf_proto_ops	*ops;
	struct rcu_head		rcu;
};

struct qdisc_skb_cb {
	unsigned int		pkt_len;//��qdisc_enqueue_root������ӵ�ʱ�򣬸�ֵΪSKB->len
	u16			slave_dev_queue_mapping;
	u16			_pad;
#define QDISC_CB_PRIV_LEN 20
	unsigned char		data[QDISC_CB_PRIV_LEN];
};

static inline void qdisc_cb_private_validate(const struct sk_buff *skb, int sz)
{
	struct qdisc_skb_cb *qcb;

	BUILD_BUG_ON(sizeof(skb->cb) < offsetof(struct qdisc_skb_cb, data) + sz);
	BUILD_BUG_ON(sizeof(qcb->data) < sz);
}

static inline int qdisc_qlen(const struct Qdisc *q)
{
	return q->q.qlen;
}

static inline struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static inline spinlock_t *qdisc_lock(struct Qdisc *qdisc)
{
	return &qdisc->q.lock;
}

static inline struct Qdisc *qdisc_root(const struct Qdisc *qdisc)
{
	struct Qdisc *q = rcu_dereference_rtnl(qdisc->dev_queue->qdisc);

	return q;
}

static inline struct Qdisc *qdisc_root_sleeping(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->qdisc_sleeping;
}

/* The qdisc root lock is a mechanism by which to top level
 * of a qdisc tree can be locked from any qdisc node in the
 * forest.  This allows changing the configuration of some
 * aspect of the qdisc tree while blocking out asynchronous
 * qdisc access in the packet processing paths.
 *
 * It is only legal to do this when the root will not change
 * on us.  Otherwise we'll potentially lock the wrong qdisc
 * root.  This is enforced by holding the RTNL semaphore, which
 * all users of this lock accessor must do.
 */
static inline spinlock_t *qdisc_root_lock(const struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline spinlock_t *qdisc_root_sleeping_lock(const struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root_sleeping(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline struct net_device *qdisc_dev(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->dev;
}

static inline void sch_tree_lock(const struct Qdisc *q)
{
	spin_lock_bh(qdisc_root_sleeping_lock(q));
}

static inline void sch_tree_unlock(const struct Qdisc *q)
{
	spin_unlock_bh(qdisc_root_sleeping_lock(q));
}

#define tcf_tree_lock(tp)	sch_tree_lock((tp)->q)
#define tcf_tree_unlock(tp)	sch_tree_unlock((tp)->q)

extern struct Qdisc noop_qdisc;
extern struct Qdisc_ops noop_qdisc_ops;
extern struct Qdisc_ops pfifo_fast_ops;
extern struct Qdisc_ops mq_qdisc_ops;
extern const struct Qdisc_ops *default_qdisc_ops;
//�ýṹΪhtb_class -> common
struct Qdisc_class_common {//�����Qdisc_class_hash��, ����class��qdisc_class_find
	u32			classid;// ���IDֵ, ��16λ�������ֲ�ͬ��HTB����, ��16λΪ����ͬһHTB�����еĲ�ͬ���
	struct hlist_node	hnode; //ͨ�����hnode���հ�htb_class���뵽htb_sched->clhash�У���htb_change_class -> qdisc_class_hash_insert
};

//�ýṹΪhtb˽������htb_sched�е�clhash�������洢����tc class add������htb_class
struct Qdisc_class_hash { //hash���̼�qdisc_class_hash_grow
	struct hlist_head	*hash;//�������д�ŵ���Qdisc_class_common,��hash��ռ���qdisc_class_hash_init����     qdisc_class_find
	unsigned int		hashsize; //Ĭ�ϳ�ʼֵ��qdisc_class_hash_init�����hash�ڵ���hashelems�������õ�hashsize��0.75�������hash��hashsize����֮ǰhashsize��������qdisc_class_hash_grow
	unsigned int		hashmask;  //qdisc_class_hash_init
	unsigned int		hashelems; //ʵ�ʵ�hash class�ڵ��� //hashelems��hashsize��ϵ��qdisc_class_hash_grow
};

static inline unsigned int qdisc_class_hash(u32 id, u32 mask)
{
	id ^= id >> 8;
	id ^= id >> 4;
	return id & mask;
}

//����
static inline struct Qdisc_class_common *
qdisc_class_find(const struct Qdisc_class_hash *hash, u32 id)
{
	struct Qdisc_class_common *cl;
	unsigned int h;

	h = qdisc_class_hash(id, hash->hashmask);
	hlist_for_each_entry(cl, &hash->hash[h], hnode) {// ���ݾ�������ϣֵ, Ȼ������ù�ϣ����
		if (cl->classid == id)
			return cl;
	}
	return NULL;
}

int qdisc_class_hash_init(struct Qdisc_class_hash *);
void qdisc_class_hash_insert(struct Qdisc_class_hash *,
			     struct Qdisc_class_common *);
void qdisc_class_hash_remove(struct Qdisc_class_hash *,
			     struct Qdisc_class_common *);
void qdisc_class_hash_grow(struct Qdisc *, struct Qdisc_class_hash *);
void qdisc_class_hash_destroy(struct Qdisc_class_hash *);

void dev_init_scheduler(struct net_device *dev);
void dev_shutdown(struct net_device *dev);
void dev_activate(struct net_device *dev);
void dev_deactivate(struct net_device *dev);
void dev_deactivate_many(struct list_head *head);
struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
			      struct Qdisc *qdisc);
void qdisc_reset(struct Qdisc *qdisc);
void qdisc_destroy(struct Qdisc *qdisc);
void qdisc_tree_reduce_backlog(struct Qdisc *qdisc, unsigned int n,
			       unsigned int len);
struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
			  const struct Qdisc_ops *ops);
struct Qdisc *qdisc_create_dflt(struct netdev_queue *dev_queue,
				const struct Qdisc_ops *ops, u32 parentid);
void __qdisc_calculate_pkt_len(struct sk_buff *skb,
			       const struct qdisc_size_table *stab);
void tcf_destroy(struct tcf_proto *tp);
void tcf_destroy_chain(struct tcf_proto __rcu **fl);

/* Reset all TX qdiscs greater then index of a device.  */
static inline void qdisc_reset_all_tx_gt(struct net_device *dev, unsigned int i)
{
	struct Qdisc *qdisc;

	for (; i < dev->num_tx_queues; i++) {
		qdisc = rtnl_dereference(netdev_get_tx_queue(dev, i)->qdisc);
		if (qdisc) {
			spin_lock_bh(qdisc_lock(qdisc));
			qdisc_reset(qdisc);
			spin_unlock_bh(qdisc_lock(qdisc));
		}
	}
}

static inline void qdisc_reset_all_tx(struct net_device *dev)
{
	qdisc_reset_all_tx_gt(dev, 0);
}

/* Are all TX queues of the device empty?  */
static inline bool qdisc_all_tx_empty(const struct net_device *dev)
{
	unsigned int i;

	rcu_read_lock();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		const struct Qdisc *q = rcu_dereference(txq->qdisc);

		if (q->q.qlen) {
			rcu_read_unlock();
			return false;
		}
	}
	rcu_read_unlock();
	return true;
}

/* Are any of the TX qdiscs changing?  */
static inline bool qdisc_tx_changing(const struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (rcu_access_pointer(txq->qdisc) != txq->qdisc_sleeping)
			return true;
	}
	return false;
}

/* Is the device using the noop qdisc on all queues?  */
static inline bool qdisc_tx_is_noop(const struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (rcu_access_pointer(txq->qdisc) != &noop_qdisc)
			return false;
	}
	return true;
}

static inline unsigned int qdisc_pkt_len(const struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

/* additional qdisc xmit flags (NET_XMIT_MASK in linux/netdevice.h) */
enum net_xmit_qdisc_t {
	__NET_XMIT_STOLEN = 0x00010000,
	__NET_XMIT_BYPASS = 0x00020000,
};

#ifdef CONFIG_NET_CLS_ACT
#define net_xmit_drop_count(e)	((e) & __NET_XMIT_STOLEN ? 0 : 1)
#else
#define net_xmit_drop_count(e)	(1)
#endif

static inline void qdisc_calculate_pkt_len(struct sk_buff *skb,
					   const struct Qdisc *sch)
{
#ifdef CONFIG_NET_SCHED
	struct qdisc_size_table *stab = rcu_dereference_bh(sch->stab);

	if (stab)
		__qdisc_calculate_pkt_len(skb, stab);
#endif
}

static inline int qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	qdisc_calculate_pkt_len(skb, sch);
	return sch->enqueue(skb, sch);
}

//ingressͨ��ing_filter���
static inline int qdisc_enqueue_root(struct sk_buff *skb, struct Qdisc *sch) //sch dev�豸��qdisc
{
	qdisc_skb_cb(skb)->pkt_len = skb->len;
	return qdisc_enqueue(skb, sch) & NET_XMIT_MASK;
}

static inline bool qdisc_is_percpu_stats(const struct Qdisc *q)
{
	return q->flags & TCQ_F_CPUSTATS;
}

static inline void bstats_update(struct gnet_stats_basic_packed *bstats,
				 const struct sk_buff *skb)
{
	bstats->bytes += qdisc_pkt_len(skb);
	bstats->packets += skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
}

static inline void qdisc_bstats_update_cpu(struct Qdisc *sch,
					   const struct sk_buff *skb)
{
	struct gnet_stats_basic_cpu *bstats =
				this_cpu_ptr(sch->cpu_bstats);

	u64_stats_update_begin(&bstats->syncp);
	bstats_update(&bstats->bstats, skb);
	u64_stats_update_end(&bstats->syncp);
}

static inline void qdisc_bstats_update(struct Qdisc *sch,
				       const struct sk_buff *skb)
{
	bstats_update(&sch->bstats, skb);
}

static inline void qdisc_qstats_backlog_dec(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog -= qdisc_pkt_len(skb);
}

static inline void qdisc_qstats_backlog_inc(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog += qdisc_pkt_len(skb);
}

static inline void __qdisc_qstats_drop(struct Qdisc *sch, int count)
{
	sch->qstats.drops += count;
}

static inline void qdisc_qstats_drop(struct Qdisc *sch)
{
	sch->qstats.drops++;
}

static inline void qdisc_qstats_drop_cpu(struct Qdisc *sch)
{
	struct gnet_stats_queue *qstats = this_cpu_ptr(sch->cpu_qstats);

	qstats->drops++;
}

static inline void qdisc_qstats_overlimit(struct Qdisc *sch)
{
	sch->qstats.overlimits++;
}

static inline int __qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	__skb_queue_tail(list, skb);
	qdisc_qstats_backlog_inc(sch, skb);

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_enqueue_tail(skb, sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_head(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue(list);

	if (likely(skb != NULL)) {
		qdisc_qstats_backlog_dec(sch, skb);
		qdisc_bstats_update(sch, skb);
	}

	return skb;
}

//__qdisc_run -> qdisc_restart -> dequeue_skb -> prio_dequeue(�������и��ݹ���ù���) -> qdisc_dequeue_head
static inline struct sk_buff *qdisc_dequeue_head(struct Qdisc *sch)
{
	return __qdisc_dequeue_head(sch, &sch->q);
}

static inline unsigned int __qdisc_queue_drop_head(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue(list);

	if (likely(skb != NULL)) {
		unsigned int len = qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		kfree_skb(skb);
		return len;
	}

	return 0;
}

static inline unsigned int qdisc_queue_drop_head(struct Qdisc *sch)
{
	return __qdisc_queue_drop_head(sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_tail(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue_tail(list);

	if (likely(skb != NULL))
		qdisc_qstats_backlog_dec(sch, skb);

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_tail(struct Qdisc *sch)
{
	return __qdisc_dequeue_tail(sch, &sch->q);
}

static inline struct sk_buff *qdisc_peek_head(struct Qdisc *sch)
{
	return skb_peek(&sch->q);
}

/* generic pseudo peek method for non-work-conserving qdisc */
static inline struct sk_buff *qdisc_peek_dequeued(struct Qdisc *sch)
{
	/* we can reuse ->gso_skb because peek isn't called for root qdiscs */
	if (!sch->gso_skb) {
		sch->gso_skb = sch->dequeue(sch);
		if (sch->gso_skb)
			/* it's still part of the queue */
			sch->q.qlen++;
	}

	return sch->gso_skb;
}

/* use instead of qdisc->dequeue() for all qdiscs queried with ->peek() */
static inline struct sk_buff *qdisc_dequeue_peeked(struct Qdisc *sch)
{
	struct sk_buff *skb = sch->gso_skb;

	if (skb) {
		sch->gso_skb = NULL;
		sch->q.qlen--;
	} else {
		skb = sch->dequeue(sch);
	}

	return skb;
}

static inline void __qdisc_reset_queue(struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	/*
	 * We do not know the backlog in bytes of this list, it
	 * is up to the caller to correct it
	 */
	__skb_queue_purge(list);
}

static inline void qdisc_reset_queue(struct Qdisc *sch)
{
	__qdisc_reset_queue(sch, &sch->q);
	sch->qstats.backlog = 0;
}

static inline struct Qdisc *qdisc_replace(struct Qdisc *sch, struct Qdisc *new,
					  struct Qdisc **pold)
{
	struct Qdisc *old;

	sch_tree_lock(sch);
	old = *pold;
	*pold = new;
	if (old != NULL) {
		unsigned int qlen = old->q.qlen;
		unsigned int backlog = old->qstats.backlog;

		qdisc_reset(old);
		qdisc_tree_reduce_backlog(old, qlen, backlog);
	}
	sch_tree_unlock(sch);

	return old;
}

static inline unsigned int __qdisc_queue_drop(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __qdisc_dequeue_tail(sch, list);

	if (likely(skb != NULL)) {
		unsigned int len = qdisc_pkt_len(skb);
		kfree_skb(skb);
		return len;
	}

	return 0;
}

//����qdisc�Ŷӹ��skb�����ϵ�����
static inline unsigned int qdisc_queue_drop(struct Qdisc *sch)
{
	return __qdisc_queue_drop(sch, &sch->q);
}

static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch)
{
	kfree_skb(skb);
	qdisc_qstats_drop(sch);

	return NET_XMIT_DROP;
}

static inline int qdisc_reshape_fail(struct sk_buff *skb, struct Qdisc *sch)
{
	qdisc_qstats_drop(sch);

#ifdef CONFIG_NET_CLS_ACT
	if (sch->reshape_fail == NULL || sch->reshape_fail(skb, sch))
		goto drop;

	return NET_XMIT_SUCCESS;

drop:
#endif
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

/*
qdisc_rate_table{
  struct tc_ratespec rate;
  u32 data[256];
  struct qdisc_rate_table *next;
  int refcnt;
}

����ṹ��Ҫ���������ں˼�������ʱ�õġ�
������⣬�������е�˵�����ס�
�ں˵���С���ȵ�λ��һ��tick�������ں�Ҫ������ʱ��ת��Ϊ�ں˵�tickʱ�䡣
���ںú����һ�£����൱����һ�����ʣ�����ʱ���100ms��ת�����ں�tickʱ����Ҫ��һ��ϵ���ġ�

��һ��������Դ�����㷨
�㷨��������λʱ���ڲ����Ŀ�����Դһ����ÿ����һ���ֽڶ�Ҫ������Ӧ��С�Ŀ�����Դ����������Դ����ʱֹͣ�������ݰ����趨������Խ��
����һ���ֽ������ĵĿ�����Դ��ԽС��ͨ�����÷���һ���ֽ������ĵĿ�����Դ���������ٿ��ơ�

��������:
1. ������Դ������һ�����ݰ����������Ŀ�����Դ�����ĳ������Ŀ�����ԴΪ0�����޷��������ݰ���ֻҪ������Դ�㹻��Ϳ��Է������ݰ���
(TC�û��ռ����ÿ������Ŀ�����Դ��TIME_UNITS_PER_SEC       1000000����TC�ں˸��ݿ���ʱ�������������Դ��)
2.����ʱ�䣺����������һ�η������ݰ���ʱ����T1��ϵͳ��ǰ��ʱ����T2�������ʱ��tk = T1 �C T2��
3. ����rate��ÿ�������͵ĵ��ֽڸ�����
4. ������Դ���������Կ���ʱ��Ϊ��������һ�����㷨�õ���ֵ��������Խ�����ʱ�����һ��������������Ҫ��֤����ʱ��Խ�󣬶�Ӧ�Ŀ�����Դ�Ļ������ض�ҪԽ��
5. ������Դʣ���������һ�η������ݰ��Ժ󣬿�����Դ��ʣ������
6. ��ǰ���ÿ�����Դ���Կ�����Դ��ʣ�����Ϳ�����Դ�Ļ�����Ϊ��������һ�����㷨�õ���ֵ��������� = 1/6������Դ��ʣ���� + (1 �C 1/6)������Դ�Ļ��ۣ���
   ����Ҫ��֤��ǰ���ÿ�����Դ���ǿ�����Դʣ�����Ϳ�����Դ�������ĵ���������
   Ϊ�˸��õ���������Դ�����㷨����Ҫ�������ٸ���ĵڶ���������Ҳ���ǣ�ʹ�ÿ�����Դ���������ٵĸ��
7.����kc(�ÿ�����Դ����)������ÿ������Ŀ�����Դ��TIME_UNITS_PER_SEC������rate(ÿ�������͵���������rate���ֽ�)������һ���ֽڵ�������Ҫ���ĵ�
  ������Դ��kc = TIME_UNITS_PER_SEC/rate
  �����kc�����������������������������rateԽ��kc��ԽС��

  ���Ҫ����size�ֽڵ����ݰ���Ҫ����size*(TIME_UNITS_PER_SEC/rate)�Ŀ�����Դ��
  ֻҪ������Դ�㹻�࣬�Ϳ��Է������ݰ���ÿ����һ�����ݰ���������Դ��ȥ��Ӧ����������
  ֻҪ����ʱ��һֱ�ۻ���������Դ�����úܴ���ʱ��ʧȥ�˵������ٵ����壬����������������Դ����ʹ������Դ����̫��
�������ٵĹ��̣�
����ֻҪ������Դ���㣬����ͼ����һ��������L�����ݰ���������kc��
1.      ��ʼʱ�̿�����Դ�Ϳ���ʱ�䶼Ϊ0����Ȼ�����������ݰ���
2.      ����һ��ʱ�䣬����ʱ�����0�����������Դ�ۻ����������㵱ǰ���ÿ�����Դtu��
3.      ����L���ȵ����ݰ���Ҫ����kc*L�Ŀ�����Դ�����tu > a*L���������ݰ�������������һ��ʱ�䡣
4.      �������ݰ�����ٿ�����Դ��tu = tu �C a*L�����tu > 0���ظ�3�Ĺ��̣�ֱ���ٴ����ߡ�
5.      �������״̬�ǣ����ǳ���ts = a*L��

������ʱ���Դﵽ���ص�Ŀ�ģ����ǽ���ǲ�׼ȷ�ģ���ͬ���㷨����ͬ�Ĳ������ڲ�ͬ�����绷������Ҫ��Ӳ�������ò�ͬ�������صĽ���϶���ͬ��
���ǿ��Ը��ݾ�������绷������ѡ���ʵ��Ĳ���������㷨��׼ȷ�ȡ�
���Ե����Ĳ��������ࣺ1. �㷨������2. ���ò�����
�ɵ����㷨�����У�1. ����ʱ��Ϳ�����Դ�Ļ������ 2. ÿ��ɲ����Ŀ�����ԴTIME_UNITS_PER_SEC��

*/
/* Length to Time (L2T) lookup in a qdisc_rate_table, to determine how
   long it will take to send a packet given its size.
 
 */ 
// ������ת��Ϊ������ �ο�<��һ��������Դ�����㷨>  �ο�Ӧ�ò�tc_calc_rtable   
static inline u32 qdisc_l2t(struct qdisc_rate_table* rtab, unsigned int pktlen) //��ʾ����ptklen������Ҫ���Ķ��ٿ�����Դʱ��
{
	int slot = pktlen + rtab->rate.cell_align + rtab->rate.overhead;
	if (slot < 0)
		slot = 0;
	slot >>= rtab->rate.cell_log;
	if (slot > 255)// ���������255, ����Ϊ255
		return rtab->data[255]*(slot >> 8) + rtab->data[slot & 0xFF];
	return rtab->data[slot];//Ĭ�������//����õ��ľ���2047���ֽ������ĵĿ�����Դ��
}

#ifdef CONFIG_NET_CLS_ACT
static inline struct sk_buff *skb_act_clone(struct sk_buff *skb, gfp_t gfp_mask,
					    int action)
{
	struct sk_buff *n;

	n = skb_clone(skb, gfp_mask);

	if (n) {
		n->tc_verd = SET_TC_VERD(n->tc_verd, 0);
		n->tc_verd = CLR_TC_OK2MUNGE(n->tc_verd);
		n->tc_verd = CLR_TC_MUNGED(n->tc_verd);
	}
	return n;
}
#endif

struct psched_ratecfg {
	u64	rate_bytes_ps; /* bytes per second */
	u32	mult;
	u16	overhead;
	u8	linklayer;
	u8	shift;
};

static inline u64 psched_l2t_ns(const struct psched_ratecfg *r,
				unsigned int len)
{
	len += r->overhead;

	if (unlikely(r->linklayer == TC_LINKLAYER_ATM))
		return ((u64)(DIV_ROUND_UP(len,48)*53) * r->mult) >> r->shift;

	return ((u64)len * r->mult) >> r->shift;
}

void psched_ratecfg_precompute(struct psched_ratecfg *r,
			       const struct tc_ratespec *conf,
			       u64 rate64);

static inline void psched_ratecfg_getrate(struct tc_ratespec *res,
					  const struct psched_ratecfg *r)
{
	memset(res, 0, sizeof(*res));

	/* legacy struct tc_ratespec has a 32bit @rate field
	 * Qdisc using 64bit rate should add new attributes
	 * in order to maintain compatibility.
	 */
	res->rate = min_t(u64, r->rate_bytes_ps, ~0U);

	res->overhead = r->overhead;
	res->linklayer = (r->linklayer & TC_LINKLAYER_MASK);
}

#endif
