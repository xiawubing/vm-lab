/*
 * Traffic Control (TC) Helpers for Kernel Exploitation
 *
 * Netlink-based helpers for creating dummy interfaces,
 * qdiscs, classes, and filters for net/sched exploits.
 *
 * Extracted from kernelCTF net/sched CVEs.
 */

#ifndef TC_HELPERS_H
#define TC_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/pkt_sched.h>

#define TC_BUF_SIZE  4096

struct tc_ctx {
    int fd;
    uint32_t seq;
    char buf[TC_BUF_SIZE];
};

/* ============================================================
 * Netlink Socket Setup
 * ============================================================ */

static inline int tc_init(struct tc_ctx *ctx) {
    ctx->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (ctx->fd < 0) return -1;

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(ctx->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    ctx->seq = 0;
    return 0;
}

static inline int tc_send_recv(struct tc_ctx *ctx, void *msg, int len) {
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (sendto(ctx->fd, msg, len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("tc sendto");
        return -1;
    }

    /* Read ACK */
    char reply[TC_BUF_SIZE];
    int n = recv(ctx->fd, reply, sizeof(reply), 0);
    if (n < 0) {
        perror("tc recv");
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)reply;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0) {
            fprintf(stderr, "tc netlink error: %d\n", err->error);
            return err->error;
        }
    }
    return 0;
}

/* ============================================================
 * Helper: Add Netlink Attribute
 * ============================================================ */

static inline void tc_attr_put(struct nlmsghdr *nlh, uint16_t type,
                                const void *data, uint16_t len) {
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    if (data && len > 0)
        memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static inline void tc_attr_put_str(struct nlmsghdr *nlh, uint16_t type,
                                    const char *str) {
    tc_attr_put(nlh, type, str, strlen(str) + 1);
}

static inline void tc_attr_put_u32(struct nlmsghdr *nlh, uint16_t type,
                                    uint32_t val) {
    tc_attr_put(nlh, type, &val, sizeof(val));
}

/* ============================================================
 * Network Interface Operations
 * ============================================================ */

/* Create dummy network interface */
static inline int tc_if_create(struct tc_ctx *ctx, const char *name,
                                const char *type) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;

    tc_attr_put_str(nlh, IFLA_IFNAME, name);

    /* Nested IFLA_LINKINFO with type */
    struct rtattr *linkinfo = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    linkinfo->rta_type = IFLA_LINKINFO;
    linkinfo->rta_len = RTA_LENGTH(0);
    nlh->nlmsg_len += RTA_ALIGN(linkinfo->rta_len);

    /* IFLA_INFO_KIND inside LINKINFO */
    struct rtattr *kind = (struct rtattr *)((char *)linkinfo + RTA_ALIGN(RTA_HDRLEN));
    kind->rta_type = IFLA_INFO_KIND;
    kind->rta_len = RTA_LENGTH(strlen(type) + 1);
    memcpy(RTA_DATA(kind), type, strlen(type) + 1);

    linkinfo->rta_len = RTA_ALIGN(RTA_HDRLEN) + RTA_ALIGN(kind->rta_len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) - RTA_ALIGN(RTA_LENGTH(0)) + RTA_ALIGN(linkinfo->rta_len);

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* Bring interface up */
static inline int tc_if_up(struct tc_ctx *ctx, const char *name) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = if_nametoindex(name);
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* ============================================================
 * Qdisc Operations
 * ============================================================ */

/* Add root qdisc */
static inline int tc_qdisc_add(struct tc_ctx *ctx, const char *ifname,
                                const char *kind, uint32_t handle) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    struct tcmsg *tcm = (struct tcmsg *)NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(ifname);
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = handle;

    tc_attr_put_str(nlh, TCA_KIND, kind);

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* Add child qdisc under a class */
static inline int tc_qdisc_add_parent(struct tc_ctx *ctx, const char *ifname,
                                       const char *kind, uint32_t parent,
                                       uint32_t handle) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    struct tcmsg *tcm = (struct tcmsg *)NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(ifname);
    tcm->tcm_parent = parent;
    tcm->tcm_handle = handle;

    tc_attr_put_str(nlh, TCA_KIND, kind);

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* Delete qdisc */
static inline int tc_qdisc_del(struct tc_ctx *ctx, const char *ifname,
                                uint32_t handle) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_DELQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    struct tcmsg *tcm = (struct tcmsg *)NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(ifname);
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = handle;

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* ============================================================
 * Class Operations
 * ============================================================ */

/* Add class (generic - caller adds scheduler-specific options) */
static inline struct nlmsghdr *tc_class_start(struct tc_ctx *ctx,
                                               const char *ifname,
                                               const char *kind,
                                               uint32_t parent,
                                               uint32_t classid) {
    memset(ctx->buf, 0, TC_BUF_SIZE);

    struct nlmsghdr *nlh = (struct nlmsghdr *)ctx->buf;
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    struct tcmsg *tcm = (struct tcmsg *)NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(ifname);
    tcm->tcm_parent = parent;
    tcm->tcm_handle = classid;

    tc_attr_put_str(nlh, TCA_KIND, kind);

    return nlh;
}

/* Delete class */
static inline int tc_class_del(struct tc_ctx *ctx, const char *ifname,
                                uint32_t parent, uint32_t classid) {
    char buf[TC_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = RTM_DELTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++ctx->seq;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));

    struct tcmsg *tcm = (struct tcmsg *)NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(ifname);
    tcm->tcm_parent = parent;
    tcm->tcm_handle = classid;

    return tc_send_recv(ctx, buf, nlh->nlmsg_len);
}

/* ============================================================
 * Packet Sending (Trigger)
 * ============================================================ */

/* Send UDP packet to trigger qdisc processing */
static inline int tc_send_packet(const char *ifname, int prio) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    /* Set packet priority to route to specific class */
    if (prio > 0) {
        setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
    }

    /* Bind to interface */
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(12345),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    char data = 'X';
    sendto(sock, &data, 1, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return 0;
}

static inline void tc_close(struct tc_ctx *ctx) {
    close(ctx->fd);
}

#endif /* TC_HELPERS_H */
