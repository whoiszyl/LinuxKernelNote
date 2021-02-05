#define pr_fmt(fmt) "IPsec: " fmt

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/ah.h>
#include <linux/crypto.h>
#include <linux/pfkeyv2.h>
#include <linux/scatterlist.h>
#include <net/icmp.h>
#include <net/protocol.h>

struct ah_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

#define AH_SKB_CB(__skb) ((struct ah_skb_cb *)&((__skb)->cb[0]))

static void *ah_alloc_tmp(struct crypto_ahash *ahash, int nfrags,
			  unsigned int size)
{
	unsigned int len;

	len = size + crypto_ahash_digestsize(ahash) +
	      (crypto_ahash_alignmask(ahash) &
	       ~(crypto_tfm_ctx_alignment() - 1));

	len = ALIGN(len, crypto_tfm_ctx_alignment());

	len += sizeof(struct ahash_request) + crypto_ahash_reqsize(ahash);
	len = ALIGN(len, __alignof__(struct scatterlist));

	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}

static inline u8 *ah_tmp_auth(void *tmp, unsigned int offset)
{
	return tmp + offset;
}

static inline u8 *ah_tmp_icv(struct crypto_ahash *ahash, void *tmp,
			     unsigned int offset)
{
	return PTR_ALIGN((u8 *)tmp + offset, crypto_ahash_alignmask(ahash) + 1);
}

static inline struct ahash_request *ah_tmp_req(struct crypto_ahash *ahash,
					       u8 *icv)
{
	struct ahash_request *req;

	req = (void *)PTR_ALIGN(icv + crypto_ahash_digestsize(ahash),
				crypto_tfm_ctx_alignment());

	ahash_request_set_tfm(req, ahash);

	return req;
}

static inline struct scatterlist *ah_req_sg(struct crypto_ahash *ahash,
					     struct ahash_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_ahash_reqsize(ahash),
			     __alignof__(struct scatterlist));
}

/* Clear mutable options and find final destination to substitute
 * into IP header for icv calculation. Options are already checked
 * for validity, so paranoia is not required. */

static int ip_clear_mutable_options(const struct iphdr *iph, __be32 *daddr)
{
	unsigned char *optptr = (unsigned char *)(iph+1);
	int  l = iph->ihl*4 - sizeof(struct iphdr);
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return 0;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
			return -EINVAL;
		switch (*optptr) {
		case IPOPT_SEC:
		case 0x85:	/* Some "Extended Security" crap. */
		case IPOPT_CIPSO:
		case IPOPT_RA:
		case 0x80|21:	/* RFC1770 */
			break;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if (optlen < 6)
				return -EINVAL;
			memcpy(daddr, optptr+optlen-4, 4);
			/* Fall through */
		default:
			memset(optptr, 0, optlen);
		}
		l -= optlen;
		optptr += optlen;
	}
	return 0;
}

static void ah_output_done(struct crypto_async_request *base, int err)
{
	u8 *icv;
	struct iphdr *iph;
	struct sk_buff *skb = base->data;
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	struct ah_data *ahp = x->data;
	struct iphdr *top_iph = ip_hdr(skb);
	struct ip_auth_hdr *ah = ip_auth_hdr(skb);
	int ihl = ip_hdrlen(skb);

	iph = AH_SKB_CB(skb)->tmp;
	icv = ah_tmp_icv(ahp->ahash, iph, ihl);
	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);

	top_iph->tos = iph->tos;
	top_iph->ttl = iph->ttl;
	top_iph->frag_off = iph->frag_off;
	if (top_iph->ihl != 5) {
		top_iph->daddr = iph->daddr;
		memcpy(top_iph+1, iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
	}

	kfree(AH_SKB_CB(skb)->tmp);
	xfrm_output_resume(skb, err);
}

// 发送数据处理, 在xfrm4_output_one()中调用
// 计算AH认证值, 添加AH头
static int ah_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	int nfrags;
	int ihl;
	u8 *icv;
	struct sk_buff *trailer;
	struct crypto_ahash *ahash;
	struct ahash_request *req;
	struct scatterlist *sg;
	struct iphdr *iph, *top_iph;
	struct ip_auth_hdr *ah;
	struct ah_data *ahp;
	int seqhi_len = 0;
	__be32 *seqhi;
	int sglists = 0;
	struct scatterlist *seqhisg;

	ahp = x->data;
	ahash = ahp->ahash;

	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto out;
	nfrags = err;

	skb_push(skb, -skb_network_offset(skb));
	// AH头定位在外部IP头后面, skb缓冲中已经预留出AH头的数据部分了,
	// 这是通过mode->output函数预留的, 通常调用type->output前要调用mode->oputput
	ah = ip_auth_hdr(skb);
	ihl = ip_hdrlen(skb);

	if (x->props.flags & XFRM_STATE_ESN) {
		sglists = 1;
		seqhi_len = sizeof(*seqhi);
	}
	err = -ENOMEM;
	// 临时IP头,用于临时保存IP头内部分字段数据
	iph = ah_alloc_tmp(ahash, nfrags + sglists, ihl + seqhi_len);
	if (!iph)
		goto out;
	seqhi = (__be32 *)((char *)iph + ihl);
	icv = ah_tmp_icv(ahash, seqhi, seqhi_len);
	req = ah_tmp_req(ahash, icv);
	sg = ah_req_sg(ahash, req);
	seqhisg = sg + nfrags;

	memset(ah->auth_data, 0, ahp->icv_trunc_len);

	// 临时IP头,用于临时保存IP头内部分字段数据
	top_iph = ip_hdr(skb);

	// 将当前IP头中不进行认证的字段数据复制到临时IP头
	iph->tos = top_iph->tos;
	iph->ttl = top_iph->ttl;
	iph->frag_off = top_iph->frag_off;

	// 如果有IP选项, 处理IP选项
	if (top_iph->ihl != 5) {
		iph->daddr = top_iph->daddr;
		memcpy(iph+1, top_iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
		err = ip_clear_mutable_options(top_iph, &top_iph->daddr);
		if (err)
			goto out_free;
	}
	
	// AH中的下一个头用原来的外部IP头中的协议
	ah->nexthdr = *skb_mac_header(skb);
	// IP协议改为AH
	*skb_mac_header(skb) = IPPROTO_AH;

	// 将外部IP头的不进行认证计算的部分字段清零
	top_iph->tos = 0;
	top_iph->tot_len = htons(skb->len);
	top_iph->frag_off = 0;
	top_iph->ttl = 0;
	top_iph->check = 0;

	// AH头长度对齐
	if (x->props.flags & XFRM_STATE_ALIGN4)
		ah->hdrlen  = (XFRM_ALIGN4(sizeof(*ah) + ahp->icv_trunc_len) >> 2) - 2;
	else
		ah->hdrlen  = (XFRM_ALIGN8(sizeof(*ah) + ahp->icv_trunc_len) >> 2) - 2;

	// AH头参数赋值
	ah->reserved = 0;
	// SPI值
	ah->spi = x->id.spi;
	// 序列号
	ah->seq_no = htonl(XFRM_SKB_CB(skb)->seq.output.low);

	sg_init_table(sg, nfrags + sglists);
	err = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(err < 0))
		goto out_free;

	if (x->props.flags & XFRM_STATE_ESN) {
		/* Attach seqhi sg right after packet payload */
		*seqhi = htonl(XFRM_SKB_CB(skb)->seq.output.hi);
		sg_set_buf(seqhisg, seqhi, seqhi_len);
	}
	ahash_request_set_crypt(req, sg, icv, skb->len + seqhi_len);
	ahash_request_set_callback(req, 0, ah_output_done, skb);

	AH_SKB_CB(skb)->tmp = iph;

	err = crypto_ahash_digest(req);
	if (err) {
		if (err == -EINPROGRESS)
			goto out;

		if (err == -EBUSY)
			err = NET_XMIT_DROP;
		goto out_free;
	}

	// 赋值初始化向量值到认证数据部分
	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);

	// 恢复原来IP头的的不认证部分的值
	top_iph->tos = iph->tos;
	top_iph->ttl = iph->ttl;
	top_iph->frag_off = iph->frag_off;
	if (top_iph->ihl != 5) {
		top_iph->daddr = iph->daddr;
		memcpy(top_iph+1, iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
	}

out_free:
	kfree(iph);
out:
	return err;
}

static void ah_input_done(struct crypto_async_request *base, int err)
{
	u8 *auth_data;
	u8 *icv;
	struct iphdr *work_iph;
	struct sk_buff *skb = base->data;
	struct xfrm_state *x = xfrm_input_state(skb);
	struct ah_data *ahp = x->data;
	struct ip_auth_hdr *ah = ip_auth_hdr(skb);
	int ihl = ip_hdrlen(skb);
	int ah_hlen = (ah->hdrlen + 2) << 2;

	if (err)
		goto out;

	work_iph = AH_SKB_CB(skb)->tmp;
	auth_data = ah_tmp_auth(work_iph, ihl);
	icv = ah_tmp_icv(ahp->ahash, auth_data, ahp->icv_trunc_len);

	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG: 0;
	if (err)
		goto out;

	err = ah->nexthdr;

	skb->network_header += ah_hlen;
	memcpy(skb_network_header(skb), work_iph, ihl);
	__skb_pull(skb, ah_hlen + ihl);

	if (x->props.mode == XFRM_MODE_TUNNEL)
		skb_reset_transport_header(skb);
	else
		skb_set_transport_header(skb, -ihl);
out:
	kfree(AH_SKB_CB(skb)->tmp);
	xfrm_input_resume(skb, err);
}

// 接收数据处理, 在xfrm4_rcv_encap()函数中调用
// 进行AH认证, 剥离AH头
static int ah_input(struct xfrm_state *x, struct sk_buff *skb)
{
	int ah_hlen;
	int ihl;
	int nexthdr;
	int nfrags;
	u8 *auth_data;
	u8 *icv;
	struct sk_buff *trailer;
	struct crypto_ahash *ahash;
	struct ahash_request *req;
	struct scatterlist *sg;
	struct iphdr *iph, *work_iph;
	struct ip_auth_hdr *ah;
	struct ah_data *ahp;
	int err = -ENOMEM;
	int seqhi_len = 0;
	__be32 *seqhi;
	int sglists = 0;
	struct scatterlist *seqhisg;

	// skb数据包要准备留出AH头空间
	if (!pskb_may_pull(skb, sizeof(*ah)))
		goto out;

	// IP上层数据为AH数据
	ah = (struct ip_auth_hdr *)skb->data;
	// SA相关的AH处理数据
	ahp = x->data;
	ahash = ahp->ahash;

	nexthdr = ah->nexthdr;
	ah_hlen = (ah->hdrlen + 2) << 2;

	if (x->props.flags & XFRM_STATE_ALIGN4) {
		// AH头部长度合法性检查
		if (ah_hlen != XFRM_ALIGN4(sizeof(*ah) + ahp->icv_full_len) &&
		    ah_hlen != XFRM_ALIGN4(sizeof(*ah) + ahp->icv_trunc_len))
			goto out;
	} else {
		if (ah_hlen != XFRM_ALIGN8(sizeof(*ah) + ahp->icv_full_len) &&
		    ah_hlen != XFRM_ALIGN8(sizeof(*ah) + ahp->icv_trunc_len))
			goto out;
	}

	// skb数据包要准备留出实际AH头空间
	if (!pskb_may_pull(skb, ah_hlen))
		goto out;

	/* We are going to _remove_ AH header to keep sockets happy,
	 * so... Later this can change. */
	if (skb_unclone(skb, GFP_ATOMIC))
		goto out;

	skb->ip_summed = CHECKSUM_NONE;


	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto out;
	nfrags = err;

	// 可能包已经进行了复制, 所以对ah重新赋值
	ah = (struct ip_auth_hdr *)skb->data;
	iph = ip_hdr(skb);
	// IP头长度
	ihl = ip_hdrlen(skb);

	if (x->props.flags & XFRM_STATE_ESN) {
		sglists = 1;
		seqhi_len = sizeof(*seqhi);
	}

	work_iph = ah_alloc_tmp(ahash, nfrags + sglists, ihl +
				ahp->icv_trunc_len + seqhi_len);
	if (!work_iph)
		goto out;

	seqhi = (__be32 *)((char *)work_iph + ihl);
	auth_data = ah_tmp_auth(seqhi, seqhi_len);
	icv = ah_tmp_icv(ahash, auth_data, ahp->icv_trunc_len);
	req = ah_tmp_req(ahash, icv);
	sg = ah_req_sg(ahash, req);
	seqhisg = sg + nfrags;

	// 备份外部IP头数据
	memcpy(work_iph, iph, ihl);
	// 拷贝数据包中的认证数据到缓冲区
	memcpy(auth_data, ah->auth_data, ahp->icv_trunc_len);
	memset(ah->auth_data, 0, ahp->icv_trunc_len);

	// 将IP头中的一些参数清零, 这些参数不进行认证
	iph->ttl = 0;
	iph->tos = 0;
	iph->frag_off = 0;
	iph->check = 0;
	// IP头长度超过20字节时,处理IP选项参数
	if (ihl > sizeof(*iph)) {
		__be32 dummy;
		err = ip_clear_mutable_options(iph, &dummy);
		if (err)
			goto out_free;
	}

	// 包括IP头部分数据
	skb_push(skb, ihl);

	sg_init_table(sg, nfrags + sglists);
	err = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(err < 0))
		goto out_free;

	if (x->props.flags & XFRM_STATE_ESN) {
		/* Attach seqhi sg right after packet payload */
		*seqhi = XFRM_SKB_CB(skb)->seq.input.hi;
		sg_set_buf(seqhisg, seqhi, seqhi_len);
	}
	ahash_request_set_crypt(req, sg, icv, skb->len + seqhi_len);
	ahash_request_set_callback(req, 0, ah_input_done, skb);

	AH_SKB_CB(skb)->tmp = work_iph;

	err = crypto_ahash_digest(req);
	if (err) {
		if (err == -EINPROGRESS)
			goto out;

		goto out_free;
	}

	err = memcmp(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG: 0;
	if (err)
		goto out_free;

	skb->network_header += ah_hlen;
	memcpy(skb_network_header(skb), work_iph, ihl);
	// skb包缩减原来的IP头和AH头, 以新IP头作为数据开始
	__skb_pull(skb, ah_hlen + ihl);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		skb_reset_transport_header(skb);
	else
		skb_set_transport_header(skb, -ihl);

	err = nexthdr;

out_free:
	kfree (work_iph);
out:
	return err;
}

// 错误处理, 收到ICMP错误包时的处理情况, 此时的skb包是ICMP包
static int ah4_err(struct sk_buff *skb, u32 info)
{
	struct net *net = dev_net(skb->dev);
	// 应用层, data指向ICMP错误包里的内部IP头
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	// AH头
	struct ip_auth_hdr *ah = (struct ip_auth_hdr *)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	// ICMP错误类型检查, 本处理函数只处理"目的不可达"和"需要分片"两种错误
	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
		if (icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
			return 0;
	case ICMP_REDIRECT:
		break;
	default:
		return 0;
	}

	// 重新查找SA
	x = xfrm_state_lookup(net, skb->mark, (const xfrm_address_t *)&iph->daddr,
			      ah->spi, IPPROTO_AH, AF_INET);
	if (!x)
		return 0;

	if (icmp_hdr(skb)->type == ICMP_DEST_UNREACH)
		ipv4_update_pmtu(skb, net, info, 0, 0, IPPROTO_AH, 0);
	else
		ipv4_redirect(skb, net, 0, 0, IPPROTO_AH, 0);
	xfrm_state_put(x);

	return 0;
}

// 该函数被xfrm状态(SA)初始化函数xfrm_init_state调用
// 用来生成SA中所用的AH数据处理结构相关信息
static int ah_init_state(struct xfrm_state *x)
{
	struct ah_data *ahp = NULL;
	struct xfrm_algo_desc *aalg_desc;
	struct crypto_ahash *ahash;

	// 对AH协议的SA, 认证算法是必须的, 否则就没法进行AH认证了
	if (!x->aalg)
		goto error;

	// 如果要进行UDP封装(进行NAT穿越), 错误, 因为AH是不支持NAT的
	if (x->encap)
		goto error;

	// 分配ah_data数据结构空间
	ahp = kzalloc(sizeof(*ahp), GFP_KERNEL);
	if (!ahp)
		return -ENOMEM;

	// 分配认证算法HASH结构指针并赋值给AH数据结构
	// 算法是固定相同的, 但在每个应用使用算法时的上下文是不同的, 该结构就是描述具体应用
	// 时的相关处理的上下文数据的
	ahash = crypto_alloc_ahash(x->aalg->alg_name, 0, 0);
	if (IS_ERR(ahash))
		goto error;
	
	// 设置AH数据结构的密钥和长度
	ahp->ahash = ahash;
	if (crypto_ahash_setkey(ahash, x->aalg->alg_key,
				(x->aalg->alg_key_len + 7) / 8))
		goto error;

	/*
	 * Lookup the algorithm description maintained by xfrm_algo,
	 * verify crypto transform properties, and store information
	 * we need for AH processing.  This lookup cannot fail here
	 * after a successful crypto_alloc_ahash().
	 */
	 // 分配算法描述结构
	aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0);
	BUG_ON(!aalg_desc);

	if (aalg_desc->uinfo.auth.icv_fullbits/8 !=
	    crypto_ahash_digestsize(ahash)) {
		pr_info("%s: %s digestsize %u != %hu\n",
			__func__, x->aalg->alg_name,
			crypto_ahash_digestsize(ahash),
			aalg_desc->uinfo.auth.icv_fullbits / 8);
		goto error;
	}
		
	// AH数据结构的初始化向量的总长和截断长度的赋值 
	ahp->icv_full_len = aalg_desc->uinfo.auth.icv_fullbits/8;
	ahp->icv_trunc_len = x->aalg->alg_trunc_len/8;

	if (x->props.flags & XFRM_STATE_ALIGN4)
		x->props.header_len = XFRM_ALIGN4(sizeof(struct ip_auth_hdr) +
						  ahp->icv_trunc_len);
	else
		// AH类型SA中AH头长度: ip_auth_hdr结构和初始化向量长度, 按8字节对齐 
		// 反映在AH封装操作时要将数据包增加的长度
		x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) +
						  ahp->icv_trunc_len);
	// 如果是通道模式, 增加IP头长度
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	// SA数据指向AH数据结构		
	x->data = ahp;

	return 0;

error:
	if (ahp) {
		crypto_free_ahash(ahp->ahash);
		kfree(ahp);
	}
	return -EINVAL;
}

// 该函数被xfrm状态(SA)释放函数xfrm_state_gc_destroy()调用
static void ah_destroy(struct xfrm_state *x)
{
	struct ah_data *ahp = x->data;

	if (!ahp)
		return;
	// 算法描述释放
	crypto_free_ahash(ahp->ahash);
	// AH数据结构释放
	kfree(ahp);
}

static int ah4_rcv_cb(struct sk_buff *skb, int err)
{
	return 0;
}

// AH4的xfrm协议处理结构
static const struct xfrm_type ah_type =
{
	.description	= "AH4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_AH,
	.flags		= XFRM_TYPE_REPLAY_PROT,
	// 状态初始化
	.init_state	= ah_init_state,
	// 协议释放
	.destructor	= ah_destroy,
	// 协议输入
	.input		= ah_input,
	// 协议输出
	.output		= ah_output
};

static struct xfrm4_protocol ah4_protocol = {
	.handler	=	xfrm4_rcv,
	.input_handler	=	xfrm_input,
	.cb_handler	=	ah4_rcv_cb,
	.err_handler	=	ah4_err,
	.priority	=	0,
};

static int __init ah4_init(void)
{
	// 登记AH协议的xfrm协议处理结构
	if (xfrm_register_type(&ah_type, AF_INET) < 0) {
		pr_info("%s: can't add xfrm type\n", __func__);
		return -EAGAIN;
	}
	// 登记AH协议到IP协议
	if (xfrm4_protocol_register(&ah4_protocol, IPPROTO_AH) < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		xfrm_unregister_type(&ah_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit ah4_fini(void)
{
	if (xfrm4_protocol_deregister(&ah4_protocol, IPPROTO_AH) < 0)
		pr_info("%s: can't remove protocol\n", __func__);
	if (xfrm_unregister_type(&ah_type, AF_INET) < 0)
		pr_info("%s: can't remove xfrm type\n", __func__);
}

module_init(ah4_init);
module_exit(ah4_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS_XFRM_TYPE(AF_INET, XFRM_PROTO_AH);
