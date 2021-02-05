#ifndef _X_TABLES_H
#define _X_TABLES_H


#include <linux/netdevice.h>
#include <uapi/linux/netfilter/x_tables.h>

/**
 * struct xt_action_param - parameters for matches/targets
 *
 * @match:	the match extension
 * @target:	the target extension
 * @matchinfo:	per-match data
 * @targetinfo:	per-target data
 * @in:		input netdevice
 * @out:	output netdevice
 * @fragoff:	packet is a fragment, this is the data offset
 * @thoff:	position of transport header relative to skb->data
 * @hook:	hook number given packet came from
 * @family:	Actual NFPROTO_* through which the function is invoked
 * 		(helpful when match->family == NFPROTO_UNSPEC)
 *
 * Fields written to by extensions:
 *
 * @hotdrop:	drop packet if we had inspection problems
 * Network namespace obtainable using dev_net(in/out)
 */
struct xt_action_param {
	union {
		const struct xt_match *match;
		const struct xt_target *target;
	};
	union {
		const void *matchinfo, *targinfo;
	};
	const struct net_device *in, *out;
	int fragoff;
	unsigned int thoff;
	unsigned int hooknum;
	u_int8_t family;
	bool hotdrop;
};

/**
 * struct xt_mtchk_param - parameters for match extensions'
 * checkentry functions
 *
 * @net:	network namespace through which the check was invoked
 * @table:	table the rule is tried to be inserted into
 * @entryinfo:	the family-specific rule data
 * 		(struct ipt_ip, ip6t_ip, arpt_arp or (note) ebt_entry)
 * @match:	struct xt_match through which this function was invoked
 * @matchinfo:	per-match data
 * @hook_mask:	via which hooks the new rule is reachable
 * Other fields as above.
 */
struct xt_mtchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
};

/**
 * struct xt_mdtor_param - match destructor parameters
 * Fields as above.
 */
struct xt_mtdtor_param {
	struct net *net;
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

/**
 * struct xt_tgchk_param - parameters for target extensions'
 * checkentry functions
 *
 * @entryinfo:	the family-specific rule data
 * 		(struct ipt_entry, ip6t_entry, arpt_entry, ebt_entry)
 *
 * Other fields see above.
 */
struct xt_tgchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_target *target;
	void *targinfo;
	unsigned int hook_mask;
	u_int8_t family;
};

/* Target destructor parameters */
struct xt_tgdtor_param {
	struct net *net;
	const struct xt_target *target;
	void *targinfo;
	u_int8_t family;
};

/*���е�ƥ�䴦��ע�ᵽһ��match���������У�����������;�������Ľṹ���͡���
����ƥ��ʱ���ǵ�������ע��Ĵ�������ÿ�����ʵ�����������������ɣ�һ��ƥ�䴦
������һ���Ϸ��Լ�麯����һ���������������һ���Ƿ���ָ�룬ָ���������ע��
��ʾ�� */
struct xt_match {
	struct list_head list;//�����ҽӵ�ƥ�����������ʼ��Ϊ{NULL, NULL}��

	const char name[XT_EXTENSION_MAXNAMELEN];//ÿ��match������
	u_int8_t revision;//�޶��İ汾��

	/* Return true or false: return FALSE and set *hotdrop = 1 to
           force immediate packet drop. */
	/* Arguments changed since 2.6.9, as this must now handle
	   non-linear skb, using skb_header_pointer and
	   skb_ip_make_writable. */
	 //�ú���������Ҫ��������ɶ����ݰ���ƥ��������飬����1��ʾƥ��ɹ���0��ʾʧ�ܣ�
	bool (*match)(const struct sk_buff *skb,
		      struct xt_action_param *);

	/* Called when user tries to insert an entry of this type. */
	//���ڶ��û��㴫������ݽ��кϷ��Լ�飬��ƥ�����ݳ����Ƿ���ȷ���Ƿ�������ȷ�ı���ʹ�õ�
	/* ���û����Բ�������͵���Ŀʱ���� */
	int (*checkentry)(const struct xt_mtchk_param *);

	/* Called when entry of this type deleted. */
	/*�����ͷŸ�ƥ���ж�̬�������Դ���ڹ���ɾ�������͵���Ŀʱ����*/
	void (*destroy)(const struct xt_mtdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	/*���û��ռ�������ں˿ռ����ʱ����*/

	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	/*�������һ��ģ�飬����ΪTHIS_MODULE������ΪNULL */
	struct module *me;

	const char *table;//���match�����ı������
	unsigned int matchsize;//match��С
#ifdef CONFIG_COMPAT
	unsigned int compatsize;//�Ƚϴ�С
#endif
	unsigned int hooks;//match���ĸ�hookע��
	unsigned short proto;//Э���

	unsigned short family;//��ַ��
};

/* Registration hooks for targets. */
/*��matchһ�������е�target��ע�ᵽ����ṹ���͵�ȫ�������У�ÿ��target�Ĵ�����
��������ע��ĺ�����������Ľ���һ��������Ҳ��Ҫ������������ָ�롣*/
struct xt_target {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
	u_int8_t revision;

	/* Returns verdict. Argument order changed since 2.6.9, as this
	   must now handle non-linear skbs, using skb_copy_bits and
	   skb_ip_make_writable. */
	unsigned int (*target)(struct sk_buff *skb,
			       const struct xt_action_param *);

	/* Called when user tries to insert an entry of this type:
           hook_mask is a bitmask of hooks from which it can be
           called. */
    /* ���û����Բ�������͵���Ŀʱ���ã�hook_mask��һ�����ӵ�λ���룬���Դ��е�������*/
	/* Should return 0 on success or an error code otherwise (-Exxxx). */
	/* �ɹ�ʱӦ����0�����򷵻ش�����루-Exxxx����*/
	int (*checkentry)(const struct xt_tgchk_param *);

	/* Called when entry of this type deleted. */
	/* ɾ�������͵���Ŀʱ���á�*/
	void (*destroy)(const struct xt_tgdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	/*���û��ռ�������ں˿ռ����ʱ����*/

	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	/*�������һ��ģ�飬����ΪTHIS_MODULE������ΪNULL */

	struct module *me;

	const char *table;//���target�����ı������
	unsigned int targetsize;//target��С
#ifdef CONFIG_COMPAT
	unsigned int compatsize;//�Ƚϴ�С
#endif
	unsigned int hooks;//target���ĸ�hookע��
	unsigned short proto;//Э���

	unsigned short family;//��ַ��
};

/* Furniture shopping... */
struct xt_table {

	/* ���ڹ�����ά�������ʽ�ṹ */
	struct list_head list;
	
	/* ����Щhook����ע����hook��������һ��λͼ */
	/* What hooks you will enter on */
	unsigned int valid_hooks;

	/*���ʵ������ */
	/* Man behind the curtain... */
	struct xt_table_info *private;

	/*�Ƿ���ģ���ж��壬���û����ΪNULL*/
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	u_int8_t af;		/* address/protocol family   ����Э���� */
	int priority;		/* hook order */

	/* A unique name... */
	const char name[XT_TABLE_MAXNAMELEN]; 	/*�������硰filter������nat���ȣ����û��ռ�����iptables���򣬻����ں�ƥ��iptables���� */
};

#include <linux/netfilter_ipv4.h>

/* The table itself */
struct xt_table_info {
	/* Size per table */
	/* ��Ĵ�С */
	unsigned int size;
	/* Number of entries������������� */
	unsigned int number;
	/* Initial number of entries��һ��Ϊ��һ���޸Ĺ���ʱ��number������ģ�����*/
	unsigned int initial_entries;

	/* ��ÿ��hook�����õ�entry��ƫ��(ע������������һ������entry��ƫ�ƣ�����һ��hook�ĵ�һ��ipt_entry��hook_entryΪ0) */
	unsigned int hook_entry[NF_INET_NUMHOOKS];
    /* ����������½� */
	unsigned int underflow[NF_INET_NUMHOOKS];
	/* ���޹������ʱ����Ӧ�� hook_entry��underflow��ֵ��Ϊ0*/

	/*
	 * Number of user chains. Since tables cannot have loops, at most
	 * @stacksize jumps (number of user chains) can possibly be made.
	 */
	unsigned int stacksize;//�û��Զ������ĸ���
	unsigned int __percpu *stackptr; //xt_jumpstack_alloc��������
	void ***jumpstack;               //xt_jumpstack_alloc��������
	/* ipt_entry tables: one per CPU */
	/* Note : this field MUST be the last one, see XT_TABLE_INFO_SZ */
	/* �������ڣ��������Ĺ���洢�ṹ. �ڱ���һ�������ʱ���Դ���Ϊ�����ʼ(����һ��ipt_entry)���ɶ����֪����һ�����飬ÿ��Ԫ�ض�Ӧÿ��CPU�ϵĹ��� ��ڡ� */
	void *entries[1];
};

#define XT_TABLE_INFO_SZ (offsetof(struct xt_table_info, entries) \
			  + nr_cpu_ids * sizeof(char *))
int xt_register_target(struct xt_target *target);
void xt_unregister_target(struct xt_target *target);
int xt_register_targets(struct xt_target *target, unsigned int n);
void xt_unregister_targets(struct xt_target *target, unsigned int n);

int xt_register_match(struct xt_match *target);
void xt_unregister_match(struct xt_match *target);
int xt_register_matches(struct xt_match *match, unsigned int n);
void xt_unregister_matches(struct xt_match *match, unsigned int n);

int xt_check_entry_offsets(const void *base, const char *elems,
			   unsigned int target_offset,
			   unsigned int next_offset);

unsigned int *xt_alloc_entry_offsets(unsigned int size);
bool xt_find_jump_offset(const unsigned int *offsets,
			 unsigned int target, unsigned int size);

int xt_check_proc_name(const char *name, unsigned int size);

int xt_check_match(struct xt_mtchk_param *, unsigned int size, u_int8_t proto,
		   bool inv_proto);
int xt_check_target(struct xt_tgchk_param *, unsigned int size, u_int8_t proto,
		    bool inv_proto);

void *xt_copy_counters_from_user(const void __user *user, unsigned int len,
				 struct xt_counters_info *info, bool compat);

struct xt_table *xt_register_table(struct net *net,
				   const struct xt_table *table,
				   struct xt_table_info *bootstrap,
				   struct xt_table_info *newinfo);
void *xt_unregister_table(struct xt_table *table);

struct xt_table_info *xt_replace_table(struct xt_table *table,
				       unsigned int num_counters,
				       struct xt_table_info *newinfo,
				       int *error);

struct xt_match *xt_find_match(u8 af, const char *name, u8 revision);
struct xt_target *xt_find_target(u8 af, const char *name, u8 revision);
struct xt_match *xt_request_find_match(u8 af, const char *name, u8 revision);
struct xt_target *xt_request_find_target(u8 af, const char *name, u8 revision);
int xt_find_revision(u8 af, const char *name, u8 revision, int target,
		     int *err);

struct xt_table *xt_find_table_lock(struct net *net, u_int8_t af,
				    const char *name);
void xt_table_unlock(struct xt_table *t);

int xt_proto_init(struct net *net, u_int8_t af);
void xt_proto_fini(struct net *net, u_int8_t af);

struct xt_table_info *xt_alloc_table_info(unsigned int size);
void xt_free_table_info(struct xt_table_info *info);

/**
 * xt_recseq - recursive seqcount for netfilter use
 * 
 * Packet processing changes the seqcount only if no recursion happened
 * get_counters() can use read_seqcount_begin()/read_seqcount_retry(),
 * because we use the normal seqcount convention :
 * Low order bit set to 1 if a writer is active.
 */
DECLARE_PER_CPU(seqcount_t, xt_recseq);

/**
 * xt_write_recseq_begin - start of a write section
 *
 * Begin packet processing : all readers must wait the end
 * 1) Must be called with preemption disabled
 * 2) softirqs must be disabled too (or we should use this_cpu_add())
 * Returns :
 *  1 if no recursion on this cpu
 *  0 if recursion detected
 */
static inline unsigned int xt_write_recseq_begin(void)
{
	unsigned int addend;

	/*
	 * Low order bit of sequence is set if we already
	 * called xt_write_recseq_begin().
	 */
	addend = (__this_cpu_read(xt_recseq.sequence) + 1) & 1;

	/*
	 * This is kind of a write_seqcount_begin(), but addend is 0 or 1
	 * We dont check addend value to avoid a test and conditional jump,
	 * since addend is most likely 1
	 */
	__this_cpu_add(xt_recseq.sequence, addend);
	smp_wmb();

	return addend;
}

/**
 * xt_write_recseq_end - end of a write section
 * @addend: return value from previous xt_write_recseq_begin()
 *
 * End packet processing : all readers can proceed
 * 1) Must be called with preemption disabled
 * 2) softirqs must be disabled too (or we should use this_cpu_add())
 */
static inline void xt_write_recseq_end(unsigned int addend)
{
	/* this is kind of a write_seqcount_end(), but addend is 0 or 1 */
	smp_wmb();
	__this_cpu_add(xt_recseq.sequence, addend);
}

/*
 * This helper is performance critical and must be inlined
 */
static inline unsigned long ifname_compare_aligned(const char *_a,
						   const char *_b,
						   const char *_mask)
{
	const unsigned long *a = (const unsigned long *)_a;
	const unsigned long *b = (const unsigned long *)_b;
	const unsigned long *mask = (const unsigned long *)_mask;
	unsigned long ret;

	ret = (a[0] ^ b[0]) & mask[0];
	if (IFNAMSIZ > sizeof(unsigned long))
		ret |= (a[1] ^ b[1]) & mask[1];
	if (IFNAMSIZ > 2 * sizeof(unsigned long))
		ret |= (a[2] ^ b[2]) & mask[2];
	if (IFNAMSIZ > 3 * sizeof(unsigned long))
		ret |= (a[3] ^ b[3]) & mask[3];
	BUILD_BUG_ON(IFNAMSIZ > 4 * sizeof(unsigned long));
	return ret;
}

struct nf_hook_ops *xt_hook_link(const struct xt_table *, nf_hookfn *);
void xt_hook_unlink(const struct xt_table *, struct nf_hook_ops *);

#ifdef CONFIG_COMPAT
#include <net/compat.h>

struct compat_xt_entry_match {
	union {
		struct {
			u_int16_t match_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t match_size;
			compat_uptr_t match;
		} kernel;
		u_int16_t match_size;
	} u;
	unsigned char data[0];
};

struct compat_xt_entry_target {
	union {
		struct {
			u_int16_t target_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;
			compat_uptr_t target;
		} kernel;
		u_int16_t target_size;
	} u;
	unsigned char data[0];
};

/* FIXME: this works only on 32 bit tasks
 * need to change whole approach in order to calculate align as function of
 * current task alignment */

struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
};

struct compat_xt_counters_info {
	char name[XT_TABLE_MAXNAMELEN];
	compat_uint_t num_counters;
	struct compat_xt_counters counters[0];
};

struct _compat_xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	compat_u64 u64;
};

#define COMPAT_XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _compat_xt_align))

void xt_compat_lock(u_int8_t af);
void xt_compat_unlock(u_int8_t af);

int xt_compat_add_offset(u_int8_t af, unsigned int offset, int delta);
void xt_compat_flush_offsets(u_int8_t af);
void xt_compat_init_offsets(u_int8_t af, unsigned int number);
int xt_compat_calc_jump(u_int8_t af, unsigned int offset);

int xt_compat_match_offset(const struct xt_match *match);
void xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			      unsigned int *size);
int xt_compat_match_to_user(const struct xt_entry_match *m,
			    void __user **dstptr, unsigned int *size);

int xt_compat_target_offset(const struct xt_target *target);
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size);
int xt_compat_target_to_user(const struct xt_entry_target *t,
			     void __user **dstptr, unsigned int *size);
int xt_compat_check_entry_offsets(const void *base, const char *elems,
				  unsigned int target_offset,
				  unsigned int next_offset);

#endif /* CONFIG_COMPAT */
#endif /* _X_TABLES_H */
