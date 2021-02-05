#ifndef _UAPI_X_TABLES_H
#define _UAPI_X_TABLES_H
#include <linux/kernel.h>
#include <linux/types.h>

#define XT_FUNCTION_MAXNAMELEN 30
#define XT_EXTENSION_MAXNAMELEN 29
#define XT_TABLE_MAXNAMELEN 32

/*这个结构存储match的信息，这里的匹配主要是指与IP无关的防火墙规则信息。由系统缺
省设置的匹配主要有三个“tcp”、“udp”，“icmp”*/
struct xt_entry_match {
	union {
		struct {
			__u16 match_size;//match尺寸

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];//match名称
			__u8 revision;
		} user;//用户空间使用的match信息
		struct {
			__u16 match_size;//match尺寸

			/* Used inside the kernel */
			struct xt_match *match;//具体的match
		} kernel;//内核空间使用的match信息

		/* Total length */
		__u16 match_size;//match总尺寸
	} u;

	unsigned char data[0];//match信息，可变数据区
};

/* target结构信息，是决定一个分组命运的信息。也可以理解为action信息，其意义是指
当一个分组与rule和match信息匹配后，如何处置该分组。处置方法一般有三种：一，命令
常数，比如DROP ACCEPT等等；二 系统预定义的模块处理函数，比如”SNAT DNAT"等等；
第三种是用户自己写模块函数。 */
struct xt_entry_target {
	union {
		struct {
			__u16 target_size;//target尺寸

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];//target名称
			__u8 revision;
		} user;//用户空间使用的target信息
		struct {
			__u16 target_size;//target尺寸

			/* Used inside the kernel */
			struct xt_target *target;//具体的target
		} kernel;//内核空间使用的targe信息

		/* Total length */
		__u16 target_size;//targe总尺寸
	} u;

	unsigned char data[0];//targe信息，可变数据区
};

#define XT_TARGET_INIT(__name, __size)					       \
{									       \
	.target.u.user = {						       \
		.target_size	= XT_ALIGN(__size),			       \
		.name		= __name,				       \
	},								       \
}
/*这个结构已经很明显给出了target的形式：命令常数或者模块函数。 */
struct xt_standard_target {
	struct xt_entry_target target;
	int verdict;
};

struct xt_error_target {
	struct xt_entry_target target;
	char errorname[XT_FUNCTION_MAXNAMELEN];
};

/* The argument to IPT_SO_GET_REVISION_*.  Returns highest revision
 * kernel supports, if >= revision. */
struct xt_get_revision {
	char name[XT_EXTENSION_MAXNAMELEN];
	__u8 revision;
};

/* CONTINUE verdict for targets */
#define XT_CONTINUE 0xFFFFFFFF

/* For standard target */
#define XT_RETURN (-NF_REPEAT - 1)

/* this is a dummy structure to find out the alignment requirement for a struct
 * containing all the fundamental data types that are used in ipt_entry,
 * ip6t_entry and arpt_entry.  This sucks, and it is a hack.  It will be my
 * personal pleasure to remove it -HW
 */
struct _xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	__u64 u64;
};

#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))

/* Standard return verdict, or do jump. */
#define XT_STANDARD_TARGET ""
/* Error verdict. */
#define XT_ERROR_TARGET "ERROR"

#define SET_COUNTER(c,b,p) do { (c).bcnt = (b); (c).pcnt = (p); } while(0)
#define ADD_COUNTER(c,b,p) do { (c).bcnt += (b); (c).pcnt += (p); } while(0)

/*计数器结构，每一个rule都有一个计数器结构用来统计匹配该条规则的分组数目和字节数
目。为基于统计的安全工具提供分析基础。*/
struct xt_counters {
	__u64 pcnt, bcnt;			/* Packet and byte counters */
};

/* The argument to IPT_SO_ADD_COUNTERS. */
//这个更改计数器时传递的参数类型。 
struct xt_counters_info {
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];

	unsigned int num_counters;

	/* The counters (actually `number' of these). */
	struct xt_counters counters[0];
};

#define XT_INV_PROTO		0x40	/* Invert the sense of PROTO. */

#ifndef __KERNEL__
/* fn returns 0 to continue iteration */
#define XT_MATCH_ITERATE(type, e, fn, args...)			\
({								\
	unsigned int __i;					\
	int __ret = 0;						\
	struct xt_entry_match *__m;				\
								\
/*首先__i取值为ipt_entry结构的大小，实质上就是match匹配
的开始处的偏移地址，将其与e相加就得到了match匹配的地址，然后调用fn处理这个匹配
。如果函数返回值为零，当前匹配的偏移地址加上当前匹配的大小，如果不超过target的
偏移地址，则继续处理下一条匹配。 */
	for (__i = sizeof(type);				\
	     __i < (e)->target_offset;				\
	     __i += __m->u.match_size) {			\//在这里得到的I就是对应的match的偏移
		__m = (void *)e + __i;				\//在这里的match的地址
							\
		//没找到一个match，就交由fn函数处理，在print_firewall中，传递过来的是函数print_match
		__ret = fn(__m , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE_CONTINUE(type, entries, size, n, fn, args...) \
({								\
	unsigned int __i, __n;					\
	int __ret = 0;						\
	type *__entry;						\
								\
	for (__i = 0, __n = 0; __i < (size);			\
	     __i += __entry->next_offset, __n++) { 		\
		__entry = (void *)(entries) + __i;		\
		if (__n < n)					\
			continue;				\
								\
		__ret = fn(__entry , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE(type, entries, size, fn, args...) \
	XT_ENTRY_ITERATE_CONTINUE(type, entries, size, 0, fn, args)

#endif /* !__KERNEL__ */

/* pos is normally a struct ipt_entry/ip6t_entry/etc. */
#define xt_entry_foreach(pos, ehead, esize) \
	for ((pos) = (typeof(pos))(ehead); \
	     (pos) < (typeof(pos))((char *)(ehead) + (esize)); \
	     (pos) = (typeof(pos))((char *)(pos) + (pos)->next_offset))

/* can only be xt_entry_match, so no use of typeof here */
#define xt_ematch_foreach(pos, entry) \
	for ((pos) = (struct xt_entry_match *)entry->elems; \
	     (pos) < (struct xt_entry_match *)((char *)(entry) + \
	             (entry)->target_offset); \
	     (pos) = (struct xt_entry_match *)((char *)(pos) + \
	             (pos)->u.match_size))


#endif /* _UAPI_X_TABLES_H */
