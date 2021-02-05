/*
 * 25-Jul-1998 Major changes to allow for ip chain table
 *
 * 3-Jan-2000 Named tables to allow packet selection for different uses.
 */

/*
 * 	Format of an IP firewall descriptor
 *
 * 	src, dst, src_mask, dst_mask are always stored in network byte order.
 * 	flags are stored in host byte order (of course).
 * 	Port numbers are stored in HOST byte order.
 */

#ifndef _UAPI_IPTABLES_H
#define _UAPI_IPTABLES_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/netfilter_ipv4.h>

#include <linux/netfilter/x_tables.h>

#ifndef __KERNEL__
#define IPT_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IPT_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ipt_match xt_match
#define ipt_target xt_target
#define ipt_table xt_table
#define ipt_get_revision xt_get_revision
#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_standard_target xt_standard_target
#define ipt_error_target xt_error_target
#define ipt_counters xt_counters
#define IPT_CONTINUE XT_CONTINUE
#define IPT_RETURN XT_RETURN

/* This group is older than old (iptables < v1.4.0-rc1~89) */
#include <linux/netfilter/xt_tcpudp.h>
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp
//tcp的取反标志值。 
#define IPT_TCP_INV_SRCPT	XT_TCP_INV_SRCPT
#define IPT_TCP_INV_DSTPT	XT_TCP_INV_DSTPT
#define IPT_TCP_INV_FLAGS	XT_TCP_INV_FLAGS
#define IPT_TCP_INV_OPTION	XT_TCP_INV_OPTION
#define IPT_TCP_INV_MASK	XT_TCP_INV_MASK
#define IPT_UDP_INV_SRCPT	XT_UDP_INV_SRCPT
#define IPT_UDP_INV_DSTPT	XT_UDP_INV_DSTPT
#define IPT_UDP_INV_MASK	XT_UDP_INV_MASK

/* The argument to IPT_SO_ADD_COUNTERS. */
#define ipt_counters_info xt_counters_info
/* Standard return verdict, or do jump. */
#define IPT_STANDARD_TARGET XT_STANDARD_TARGET
/* Error verdict. */
#define IPT_ERROR_TARGET XT_ERROR_TARGET

/*下面的宏遍历处理一条防火墙规则的所有匹配。每一条防火墙规则在iptables
中分为三部分，而且每一部分的大小都是可变的。比如match部分，它本身可以有多个mat
ch项。*/
/* fn returns 0 to continue iteration */
#define IPT_MATCH_ITERATE(e, fn, args...) \
	XT_MATCH_ITERATE(struct ipt_entry, e, fn, ## args)

/* fn returns 0 to continue iteration */
//这个宏处理一个table中的所有防火墙规则
#define IPT_ENTRY_ITERATE(entries, size, fn, args...) \
	XT_ENTRY_ITERATE(struct ipt_entry, entries, size, fn, ## args)
#endif

/* Yes, Virginia, you have to zero the padding.
 * 这里的注释说“这个结构无须填充零字节”，
 * 就是说这个结构的大小正好是4的倍数。这里由于IFNAMSIZ等于16，所以整个结构大小
 * 确实是4的倍数。 */
struct ipt_ip {
	/* Source and destination IP addr */
	/* 源/目的地址 */
	struct in_addr src, dst;
	/* Mask for src and dest IP addr */
	/* 源/目的地址的掩码 */
	struct in_addr smsk, dmsk;
	/*输入/输出网络接口*/
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* Protocol, 0 = ANY */
	/* 协议, 0 = ANY */
	__u16 proto;

	/* Flags word */
	/* 标志字段 */
	__u8 flags;
	/* Inverse flags */
	/* 取反标志 */
	__u8 invflags;
};

/* Values for "flag" field in struct ipt_ip (general ip structure). */
#define IPT_F_FRAG		0x01	/* Set if rule is a fragment rule */
#define IPT_F_GOTO		0x02	/* Set if jump is a goto */
#define IPT_F_MASK		0x03	/* All possible flag bits mask. */

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_VIA_IN		0x01	/* Invert the sense of IN IFACE. */
#define IPT_INV_VIA_OUT		0x02	/* Invert the sense of OUT IFACE */
#define IPT_INV_TOS		0x04	/* Invert the sense of TOS. */
#define IPT_INV_SRCIP		0x08	/* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP		0x10	/* Invert the sense of DST OP. */
#define IPT_INV_FRAG		0x20	/* Invert the sense of FRAG. */
#define IPT_INV_PROTO		XT_INV_PROTO
#define IPT_INV_MASK		0x7F	/* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */
/*iptables的构成是ip匹配信息＋match＋target。同时iptables构成的每一个部分都是可
变大小的，由于经常出现”char XXX[0]“就可以看出。但是我个人认为规则的组织有点不好理解，
它经常是先分配一段空间，然后将规则一条一条放入。如同文件系统存放变长记录的文件时，
总要在记录中放入记录长度，以便以后取出记录，这里iptables正是使用这种方法，在每个规则中都
放入长度字段，这样方便提取各个组成部分和计算下一条规则的位置。
  math 分为两部分，一部分为基本元素，如源/目的IP，协议，进/出网口对应ipt_ip，这一部分被称为标准math
  	   			   另一部分则是已插件的形式存在，被称为扩展math，如字符串的匹配。
  同样target也支持扩展。
  一条规则所占用的空间=ipt_ip+n*math+n*target
  */
struct ipt_entry {
	/* 所要匹配的报文的IP头信息 */
	/*这是基本math，正如前面所讲的，math包括基本math和扩展math*/
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	/* 经过这个规则后数据报的状态:未改变，已改变，不确定。是一个标志位 */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	//下面两个字段用来计算target的位置和下一条规则的位置
	/* target区的偏移，通常target区位于match区之后，而match区则在ipt_entry的末尾；
	初始化为sizeof(struct ipt_entry)，即假定没有match */
	__u16 target_offset;
	/* Size of ipt_entry + matches + target */
	/* 下一条规则相对于本规则的偏移，也即本规则所用空间的总和，
	初始化为sizeof(struct ipt_entry)+sizeof(struct ipt_target)，即没有match */
	__u16 next_offset;

	/* Back pointer */
	//这个字段的存在，为发现规则中存在”环路“提供手段。
	/* 位向量，标记调用本规则的HOOK号，可用于检查规则的有效性 */
	unsigned int comefrom;

	/* Packet and byte counters. */
	/* 记录该规则处理过的报文数和报文总字节数 */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	/*target或者是match的起始位置 */
	unsigned char elems[0];
};

/*
 * New IP firewall options for [gs]etsockopt at the RAW IP level.
 * Unlike BSD Linux inherits IP options so you don't have to use a raw
 * socket for this. Instead we check rights in the calls.
 *
 * ATTENTION: check linux/in.h before adding new number here.
 */
 //定义提供给set/getsockopt系统调用的命令常数的基常数
#define IPT_BASE_CTL		64

#define IPT_SO_SET_REPLACE	(IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS	(IPT_BASE_CTL + 1)
#define IPT_SO_SET_MAX		IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET

/* ICMP matching stuff */
//ICMP匹配规则信息 
struct ipt_icmp {
	__u8 type;				/* type to match */
	__u8 code[2];				/* range of code */
	__u8 invflags;				/* Inverse flags */
};

/* Values for "inv" field for struct ipt_icmp. */
#define IPT_ICMP_INV	0x01	/* Invert the sense of type/code test */

/* The argument to IPT_SO_GET_INFO */
//这个结构实质上用户通过getsockopt系统调用获取table信息时所传递参数的类型
struct ipt_getinfo {
	/* Which table: caller fills this in.  哪个表：调用者填写此内容。*/
	char name[XT_TABLE_MAXNAMELEN];

	/* Kernel fills these in.  内核填补了这些内容。*/
	/* Which hook entry points are valid: bitmask  哪个钩子入口点有效：位掩码*/
	unsigned int valid_hooks;

	/* Hook entry points: one per netfilter hook.  钩子入口点：每个netfilter钩子一个*/
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Number of entries 条目数量*/
	unsigned int num_entries;

	/* Size of entries. */
	unsigned int size;
};

/* The argument to IPT_SO_SET_REPLACE. */
//这个结构是用户通过系统调用更换table是所传递的参数类型。
struct ipt_replace {
	/* Which table. */
	/* 表名 */
	char name[XT_TABLE_MAXNAMELEN];

	/* Which hook entry points are valid: bitmask.  You can't
           change this. */
    /* hook mask无法修改*/
	unsigned int valid_hooks;

	/* Number of entries */
	/* 新规则的entry数 */
	unsigned int num_entries;

	/* Total size of new entries */
	unsigned int size;

	/* Hook entry points. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Information about old entries: */
	/* Number of counters (must be equal to current number of entries). */
	/* 旧规则的entry数 */
	unsigned int num_counters;
	/* The old entries' counters. */
	struct xt_counters __user *counters;

	/* The entries (hang off end: not really an array). */
	/* 规则本身        实际的规则内容*/
	struct ipt_entry entries[0];
};

/* The argument to IPT_SO_GET_ENTRIES. */
//这个是想获取防火墙规则时，传递给系统调用的参数类型
struct ipt_get_entries {
	/* Which table: user fills this in. */
	char name[XT_TABLE_MAXNAMELEN];

	/* User fills this in: total entry size. */
	unsigned int size;

	/* The entries. */
	struct ipt_entry entrytable[0];
};

/* Helper functions */
//下面定义了一些使用例程 
static __inline__ struct xt_entry_target *
//获取一条防火墙规则的target位置 
ipt_get_target(struct ipt_entry *e)
{
	return (void *)e + e->target_offset;
}

/*
 *	Main firewall chains definitions and global var's definitions.
 */
#endif /* _UAPI_IPTABLES_H */
