#include <net/netfilter/nf_tables.h>
#include <linux/tcp.h>
#include "nft_cgroupv2.h"

#if !IS_ENABLED(CONFIG_CGROUPS)
#error Cgroup support is required to build
#endif

// Private data of our match
#define CGROUPV2_CGROUP_SIZE 1024
struct nft_cgroupv2 {
	char cgroup[CGROUPV2_CGROUP_SIZE];
	bool invert;
};

// Called from the `eval` function, the "brain" of our match
static inline bool match_packet(struct nft_cgroupv2 *priv, struct sk_buff *skb)
{
	struct sock_cgroup_data *skcd = &skb->sk->sk_cgrp_data;
	struct sock *sk = skb->sk;
	struct cgroup *cgrp = cgroup_get_from_path(priv->cgroup);
	bool ret;

	if (!sk || !sk_fullsock(sk) || IS_ERR(cgrp))
		return false;

	ret = cgroup_is_descendant(sock_cgroup_ptr(skcd), cgrp);
	if (priv->invert)
		ret = !ret;
	return ret;
}

// Evaluated for each packet that should be checked
static void nft_cgroupv2_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	struct nft_cgroupv2 *priv = nft_expr_priv(expr);
	struct sk_buff *skb = pkt->skb;
	if (match_packet(priv, skb))
		regs->verdict.code = NFT_CONTINUE;
	else
		regs->verdict.code = NFT_BREAK;
}

// Initialize a new match
static int nft_cgroupv2_init(const struct nft_ctx *ctx,
			     const struct nft_expr *expr,
			     const struct nlattr *const tb[])
{
	struct nft_cgroupv2 *priv = nft_expr_priv(expr);
	priv->invert = 0;
	// cgroup
	if (tb[NFTA_CGROUPV2_CGROUP] == NULL)
		return -EINVAL;
	nla_strlcpy(priv->cgroup, tb[NFTA_CGROUPV2_CGROUP],
		    CGROUPV2_CGROUP_SIZE);
	// Invert
	if (tb[NFTA_CGROUPV2_INVERT] != NULL) {
		priv->invert = nla_get_u8(tb[NFTA_CGROUPV2_INVERT]);
		if (priv->invert != 0 && priv->invert != 1)
			return -EINVAL;
	}

	return 0;
}

// Dump the match back to netlink
static int nft_cgroupv2_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_cgroupv2 *priv = nft_expr_priv(expr);

	if (nla_put_string(skb, NFTA_CGROUPV2_CGROUP, priv->cgroup))
		return -1;
	if (nla_put_u8(skb, NFTA_CGROUPV2_INVERT, priv->invert))
		return -1;
	return 0;
}

// Metadata
static const struct nla_policy nft_cgroupv2_policy[NFTA_CGROUPV2_MAX + 1] = {
	[NFTA_CGROUPV2_CGROUP] = { .type = NLA_STRING,
				   .len = CGROUPV2_CGROUP_SIZE },
	[NFTA_CGROUPV2_INVERT] = { .type = NLA_U8 },
};

static struct nft_expr_type nft_cgroupv2_type;
static const struct nft_expr_ops nft_cgroupv2_op = {
	.eval = nft_cgroupv2_eval,
	.size = NFT_EXPR_SIZE(sizeof(struct nft_cgroupv2)),
	.init = nft_cgroupv2_init,
	.dump = nft_cgroupv2_dump,
	.type = &nft_cgroupv2_type,
};

static struct nft_expr_type nft_cgroupv2_type __read_mostly = {
	.ops     = &nft_cgroupv2_op,
	.name    = "cgroupv2",
	.owner   = THIS_MODULE,
	.policy  = nft_cgroupv2_policy,
	.maxattr = NFTA_CGROUPV2_MAX,
};

// Load the expression
static int __init nft_cgroupv2_module_init(void)
{
	return nft_register_expr(&nft_cgroupv2_type);
}

// Unload the expression
static void __exit nft_cgroupv2_module_exit(void)
{
	nft_unregister_expr(&nft_cgroupv2_type);
}

module_init(nft_cgroupv2_module_init);
module_exit(nft_cgroupv2_module_exit);

MODULE_AUTHOR("Janne Heß");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Provides nft matches on cgroupv2 hierachies");
