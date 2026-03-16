---
name: kernel-nftables-ops
description: nftables/netfilter exploitation helpers including batch operations, table/chain/set/rule/object manipulation via netlink, and common nftables UAF trigger patterns. Use when developing exploits targeting the nftables subsystem.
---

# nftables Exploitation Operations

You are an expert at exploiting the Linux nftables subsystem. This skill covers nftables internals, netlink communication, and exploitation patterns found across 31 kernelCTF CVEs targeting nf_tables.

## nftables Architecture Overview

```
User space:  nft command / exploit
                |
                v (NETLINK_NETFILTER)
Kernel:      nf_tables_api.c
             ├── nft_table (table management)
             ├── nft_chain (chain management, base + binding)
             ├── nft_set (set management: hash, rbtree, pipapo, bitmap)
             │   └── nft_set_elem (set elements with optional timeout)
             ├── nft_rule (rule management, contains expressions)
             │   └── nft_expr (expressions: counter, lookup, payload, etc.)
             └── nft_obj (stateful objects: counter, ct_expect, etc.)
```

## Key Exploitation Concepts

### Transaction Model
nftables uses two-phase transactions:
1. **Prepare phase**: Objects created, added to transaction list
2. **Commit phase**: Changes applied atomically
3. **Abort phase**: Changes rolled back on error

Most vulnerabilities occur when:
- Objects freed in abort path but referenced in commit path
- Garbage collection races with transaction processing
- Reference counting errors during transaction rollback

### Batch Operations
All nftables operations are batched via netlink:
```
NFNL_MSG_BATCH_BEGIN  (seq=0)
NFT_MSG_NEWTABLE      (seq=1)
NFT_MSG_NEWCHAIN      (seq=2)
NFT_MSG_NEWSET        (seq=3)
...
NFNL_MSG_BATCH_END    (seq=N)
```
Entire batch succeeds or fails atomically.

### Common nftables Objects for Exploitation

| Object | Typical Size | Slab Cache | Key Fields | Spray Via |
|--------|-------------|------------|------------|-----------|
| nft_table | variable | kmalloc-256+ | name, USERDATA | NFT_MSG_NEWTABLE + NFTA_TABLE_USERDATA |
| nft_chain | ~200B | kmalloc-256 | name, rules list | NFT_MSG_NEWCHAIN |
| nft_set | variable | kmalloc-256+ | ops, key_size, data_size | NFT_MSG_NEWSET |
| nft_set_elem | variable | depends on set type | key, data, timeout | NFT_MSG_NEWSETELEM |
| nft_rule | variable | kmalloc-* | expressions array | NFT_MSG_NEWRULE |
| nft_expr | embedded | in nft_rule | ops pointer | Expression in rule |
| nft_obj (ct_expect) | ~0xcc | kmalloc-256 | ops, ct_expect data | NFT_MSG_NEWOBJ |

### USERDATA Spray Technique
nft_table with USERDATA is a powerful spray object:
- Fully controlled content
- Variable size (matches any kmalloc cache)
- Allocated via GFP_KERNEL (not _ACCOUNT, so regular kmalloc)
- Can be read back via netlink dump

## Netlink Communication

For implementation, use the templates in [templates/](templates/):
- [templates/nft_netlink.h](templates/nft_netlink.h) — Low-level netlink helpers
- [templates/nft_helpers.h](templates/nft_helpers.h) — nftables operation wrappers

### Socket Setup
```c
int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
bind(nl_fd, (struct sockaddr *)&addr, sizeof(addr));
```

### Message Format
```c
struct nlmsghdr  (16 bytes) - Netlink header
  ├── nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid
  └── struct nfgenmsg (4 bytes) - Netfilter generic header
      ├── nfgen_family (NFPROTO_IPV4/IPV6/INET)
      ├── version (NFNETLINK_V0)
      └── res_id (0)
      └── [Netlink Attributes (NLA)] - Variable
```

## Common Exploitation Patterns

### Pattern A: Set Element Timeout UAF (CVE-2023-4244, CVE-2024-26642, CVE-2024-26925)
```
1. Create table with set (pipapo or rhash type)
2. Add elements with short timeout (e.g., 4 seconds)
3. Elements expire, GC worker fires
4. Race: element freed by GC but still in transaction list
5. Transaction abort/commit uses freed element -> UAF
```

### Pattern B: Chain Reference Count Error (CVE-2023-5197, CVE-2024-26581)
```
1. Create table with chains (base + binding)
2. Add rules referencing binding chain
3. Delete rules in specific order
4. Chain refcount goes to zero but chain still referenced
5. Chain freed, but rule still points to it -> UAF
```

### Pattern C: Expression Evaluation After Free (CVE-2024-27397)
```
1. Create rule with counter expression
2. Trigger rule evaluation (send matching packet)
3. Simultaneously delete the rule
4. Expression ops->eval called on freed expression -> UAF
```

### Pattern D: Set Element Catchall Double-Free (CVE-2023-6111, CVE-2024-1085)
```
1. Create set with catchall element + expiration
2. GC processes catchall, frees it
3. Catchall not removed from set's element list
4. Second GC or manual delete frees same element again -> Double-free
```

### Pattern E: Transaction Abort UAF (CVE-2023-32233, CVE-2023-3390)
```
1. Begin batch with table + chain + rules
2. Include operation that will cause abort (e.g., module autoload)
3. In abort path, object freed but remains in another list
4. Subsequent operation uses freed object -> UAF
```

## Object Relationships

```
nft_table
├── chains: list of nft_chain
│   ├── rules: list of nft_rule
│   │   └── expressions: nft_expr[] (inline array)
│   └── binding chains: referenced by rules via set lookups
├── sets: list of nft_set
│   └── elements: nft_set_elem (stored in set's data structure)
└── objects: list of nft_obj
    └── ct_expect, counter, etc.
```

## Useful nftables Gadgets for Exploitation

### nft_expr->ops Hijack
```c
/* nft_expr has an ops pointer at a known offset.
 * If you can overwrite it with a fake ops structure:
 *   fake_ops->eval = stack_pivot_gadget
 * Then triggering rule evaluation (packet match) calls your gadget.
 *
 * The first argument to eval is: (const struct nft_expr *expr)
 * So rdi points to the expression, which you control.
 * Place ROP chain starting at expr + some_offset.
 */
```

### nft_obj->ops Hijack
```c
/* nft_obj (ct_expect type) has ops at a known offset.
 * If you can corrupt ops to point to fake nft_obj_ops:
 *   fake_ops->eval = code_execution_gadget
 * Trigger via NFT_MSG_GETOBJ or set element lookup that
 * references the object.
 */
```

### nft_table USERDATA as Spray
```c
/* Create table with controlled USERDATA:
 * NFT_MSG_NEWTABLE + NFTA_TABLE_USERDATA attribute
 *
 * The USERDATA is allocated adjacent to the table structure.
 * Size is fully controllable.
 * Content is fully controllable.
 *
 * This is the most reliable nftables spray object because:
 * - Exact size control
 * - Full content control
 * - Same GFP flags as most nftables objects
 * - Can be read back via table dump
 */
```

For complete implementation code, see the [templates/](templates/) directory and the reference material in [reference.md](reference.md).
