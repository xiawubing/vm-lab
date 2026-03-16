/*
 * nftables Operation Helpers
 *
 * Simplified nftables netlink communication for exploit development.
 * Extracted and consolidated from 31 kernelCTF nftables exploits.
 *
 * This provides a minimal, self-contained interface without requiring
 * libmnl or libnftnl libraries.
 */

#ifndef NFT_HELPERS_H
#define NFT_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

/* ============================================================
 * Netlink Buffer Management
 * ============================================================ */

#define NL_BUF_SIZE  (32 * 1024)  /* 32KB buffer for batch messages */

struct nl_ctx {
    int fd;
    uint32_t seq;
    uint32_t portid;
    char buf[NL_BUF_SIZE];
    int buf_pos;
};

static inline int nft_init(struct nl_ctx *ctx) {
    ctx->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (ctx->fd < 0) return -1;

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(ctx->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    socklen_t len = sizeof(addr);
    getsockname(ctx->fd, (struct sockaddr *)&addr, &len);
    ctx->portid = addr.nl_pid;
    ctx->seq = 0;
    ctx->buf_pos = 0;
    return 0;
}

/* ============================================================
 * Low-Level Netlink Helpers
 * ============================================================ */

static inline struct nlmsghdr *nl_msg_start(struct nl_ctx *ctx,
                                             uint16_t type, uint16_t flags) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)(ctx->buf + ctx->buf_pos);
    memset(nlh, 0, NLMSG_HDRLEN + sizeof(struct nfgenmsg));

    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_pid = ctx->portid;
    nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(struct nfgenmsg);

    struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->nfgen_family = NFPROTO_IPV4;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    return nlh;
}

static inline void nl_attr_put(struct nlmsghdr *nlh, uint16_t type,
                                const void *data, uint16_t len) {
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nla->nla_type = type;
    nla->nla_len = NLA_HDRLEN + len;
    if (data && len > 0)
        memcpy((char *)nla + NLA_HDRLEN, data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len);
}

static inline void nl_attr_put_str(struct nlmsghdr *nlh, uint16_t type,
                                    const char *str) {
    nl_attr_put(nlh, type, str, strlen(str) + 1);
}

static inline void nl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type,
                                    uint32_t val) {
    val = htobe32(val);
    nl_attr_put(nlh, type, &val, sizeof(val));
}

static inline void nl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type,
                                    uint64_t val) {
    val = htobe64(val);
    nl_attr_put(nlh, type, &val, sizeof(val));
}

static inline void nl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type,
                                   uint8_t val) {
    nl_attr_put(nlh, type, &val, sizeof(val));
}

/* Nested attribute start/end */
static inline struct nlattr *nl_nest_start(struct nlmsghdr *nlh, uint16_t type) {
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nla->nla_type = type | NLA_F_NESTED;
    nla->nla_len = NLA_HDRLEN;
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;
    return nla;
}

static inline void nl_nest_end(struct nlmsghdr *nlh, struct nlattr *nest) {
    nest->nla_len = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) - (char *)nest;
}

/* ============================================================
 * Batch Operations
 * ============================================================ */

static inline void nft_batch_begin(struct nl_ctx *ctx) {
    ctx->buf_pos = 0;
    struct nlmsghdr *nlh = nl_msg_start(ctx, NFNL_MSG_BATCH_BEGIN, 0);
    struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->res_id = NFNL_SUBSYS_NFTABLES;
    ctx->buf_pos += NLMSG_ALIGN(nlh->nlmsg_len);
}

static inline void nft_batch_end(struct nl_ctx *ctx) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)(ctx->buf + ctx->buf_pos);
    memset(nlh, 0, NLMSG_HDRLEN + sizeof(struct nfgenmsg));
    nlh->nlmsg_type = NFNL_MSG_BATCH_END;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(struct nfgenmsg);
    ctx->buf_pos += NLMSG_ALIGN(nlh->nlmsg_len);
}

static inline int nft_batch_send(struct nl_ctx *ctx) {
    nft_batch_end(ctx);
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    return sendto(ctx->fd, ctx->buf, ctx->buf_pos, 0,
                  (struct sockaddr *)&addr, sizeof(addr));
}

/* Add a message to the current batch */
static inline struct nlmsghdr *nft_batch_msg(struct nl_ctx *ctx,
                                              uint16_t msg_type,
                                              uint16_t flags) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)(ctx->buf + ctx->buf_pos);
    uint16_t type = (NFNL_SUBSYS_NFTABLES << 8) | msg_type;

    memset(nlh, 0, NLMSG_HDRLEN + sizeof(struct nfgenmsg));
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_pid = ctx->portid;
    nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(struct nfgenmsg);

    struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->nfgen_family = NFPROTO_IPV4;
    nfg->version = NFNETLINK_V0;

    return nlh;
}

static inline void nft_batch_advance(struct nl_ctx *ctx, struct nlmsghdr *nlh) {
    ctx->buf_pos += NLMSG_ALIGN(nlh->nlmsg_len);
}

/* ============================================================
 * High-Level nftables Operations
 * ============================================================ */

/* Create table */
static inline void nft_table_create(struct nl_ctx *ctx, const char *name) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWTABLE,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_TABLE_NAME, name);
    nft_batch_advance(ctx, nlh);
}

/* Create table with USERDATA (for spray) */
static inline void nft_table_create_userdata(struct nl_ctx *ctx,
                                              const char *name,
                                              const void *udata,
                                              uint16_t udata_len) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWTABLE,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_TABLE_NAME, name);
    nl_attr_put(nlh, NFTA_TABLE_USERDATA, udata, udata_len);
    nft_batch_advance(ctx, nlh);
}

/* Delete table */
static inline void nft_table_delete(struct nl_ctx *ctx, const char *name) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_DELTABLE, NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_TABLE_NAME, name);
    nft_batch_advance(ctx, nlh);
}

/* Create base chain (hooked into netfilter) */
static inline void nft_chain_create_base(struct nl_ctx *ctx,
                                          const char *table,
                                          const char *name,
                                          uint32_t hooknum,
                                          int32_t priority) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWCHAIN,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_CHAIN_TABLE, table);
    nl_attr_put_str(nlh, NFTA_CHAIN_NAME, name);

    struct nlattr *hook = nl_nest_start(nlh, NFTA_CHAIN_HOOK);
    nl_attr_put_u32(nlh, NFTA_HOOK_HOOKNUM, hooknum);
    priority = htobe32(priority);
    nl_attr_put(nlh, NFTA_HOOK_PRIORITY, &priority, sizeof(priority));
    nl_nest_end(nlh, hook);

    /* Policy: NF_ACCEPT */
    uint32_t policy = htobe32(NF_ACCEPT);
    nl_attr_put(nlh, NFTA_CHAIN_POLICY, &policy, sizeof(policy));

    nl_attr_put_str(nlh, NFTA_CHAIN_TYPE, "filter");
    nft_batch_advance(ctx, nlh);
}

/* Create regular (non-base) chain */
static inline void nft_chain_create(struct nl_ctx *ctx,
                                     const char *table,
                                     const char *name) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWCHAIN,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_CHAIN_TABLE, table);
    nl_attr_put_str(nlh, NFTA_CHAIN_NAME, name);
    nft_batch_advance(ctx, nlh);
}

/* Create set */
static inline void nft_set_create(struct nl_ctx *ctx,
                                   const char *table,
                                   const char *name,
                                   uint32_t key_len,
                                   uint32_t flags,
                                   uint64_t timeout_ms) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWSET,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_SET_TABLE, table);
    nl_attr_put_str(nlh, NFTA_SET_NAME, name);
    nl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, key_len);
    nl_attr_put_u32(nlh, NFTA_SET_FLAGS, flags);
    nl_attr_put_u32(nlh, NFTA_SET_KEY_TYPE, 0); /* unspecified */
    nl_attr_put_u32(nlh, NFTA_SET_ID, 1);

    if (timeout_ms > 0) {
        nl_attr_put_u64(nlh, NFTA_SET_TIMEOUT, timeout_ms);
    }

    nft_batch_advance(ctx, nlh);
}

/* Add set element */
static inline void nft_setelem_add(struct nl_ctx *ctx,
                                    const char *table,
                                    const char *set_name,
                                    const void *key,
                                    uint32_t key_len,
                                    uint64_t timeout_ms) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWSETELEM,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_SET_ELEM_LIST_TABLE, table);
    nl_attr_put_str(nlh, NFTA_SET_ELEM_LIST_SET, set_name);

    struct nlattr *elems = nl_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *elem = nl_nest_start(nlh, NFTA_LIST_ELEM);

    struct nlattr *elem_key = nl_nest_start(nlh, NFTA_SET_ELEM_KEY);
    nl_attr_put(nlh, NFTA_DATA_VALUE, key, key_len);
    nl_nest_end(nlh, elem_key);

    if (timeout_ms > 0) {
        nl_attr_put_u64(nlh, NFTA_SET_ELEM_TIMEOUT, timeout_ms);
    }

    nl_nest_end(nlh, elem);
    nl_nest_end(nlh, elems);
    nft_batch_advance(ctx, nlh);
}

/* Create ct_expect object (common spray target, ~0xcc bytes) */
static inline void nft_obj_create_ct_expect(struct nl_ctx *ctx,
                                             const char *table,
                                             const char *name,
                                             uint16_t l3num,
                                             uint8_t l4proto,
                                             uint16_t dport,
                                             uint32_t timeout,
                                             uint8_t size) {
    struct nlmsghdr *nlh = nft_batch_msg(ctx, NFT_MSG_NEWOBJ,
                                          NLM_F_CREATE | NLM_F_ACK);
    nl_attr_put_str(nlh, NFTA_OBJ_TABLE, table);
    nl_attr_put_str(nlh, NFTA_OBJ_NAME, name);
    nl_attr_put_u32(nlh, NFTA_OBJ_TYPE, 9); /* NFT_OBJECT_CT_EXPECT = 9 */

    struct nlattr *data = nl_nest_start(nlh, NFTA_OBJ_DATA);
    /* ct_expect attributes */
    nl_attr_put(nlh, 1, &l3num, sizeof(l3num));       /* CTA_EXPECT_L3PROTO */
    nl_attr_put_u8(nlh, 2, l4proto);                   /* CTA_EXPECT_L4PROTO */
    dport = htobe16(dport);
    nl_attr_put(nlh, 3, &dport, sizeof(dport));        /* CTA_EXPECT_DPORT */
    nl_attr_put_u32(nlh, 4, timeout);                  /* CTA_EXPECT_TIMEOUT */
    nl_attr_put_u8(nlh, 5, size);                      /* CTA_EXPECT_SIZE */
    nl_nest_end(nlh, data);

    nft_batch_advance(ctx, nlh);
}

/* Cleanup: delete table (cascades to all children) */
static inline void nft_cleanup(struct nl_ctx *ctx, const char *table) {
    nft_batch_begin(ctx);
    nft_table_delete(ctx, table);
    nft_batch_send(ctx);
}

static inline void nft_close(struct nl_ctx *ctx) {
    close(ctx->fd);
}

#endif /* NFT_HELPERS_H */
