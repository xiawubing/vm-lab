# nftables Exploitation Reference

## Netlink Message Types for nftables

| Message Type | Value | Description |
|-------------|-------|-------------|
| NFT_MSG_NEWTABLE | 0 | Create new table |
| NFT_MSG_GETTABLE | 1 | Get table info |
| NFT_MSG_DELTABLE | 2 | Delete table |
| NFT_MSG_NEWCHAIN | 3 | Create new chain |
| NFT_MSG_GETCHAIN | 4 | Get chain info |
| NFT_MSG_DELCHAIN | 5 | Delete chain |
| NFT_MSG_NEWRULE | 6 | Create new rule |
| NFT_MSG_GETRULE | 7 | Get rule info |
| NFT_MSG_DELRULE | 8 | Delete rule |
| NFT_MSG_NEWSET | 9 | Create new set |
| NFT_MSG_GETSET | 10 | Get set info |
| NFT_MSG_DELSET | 11 | Delete set |
| NFT_MSG_NEWSETELEM | 12 | Add set element |
| NFT_MSG_GETSETELEM | 13 | Get set element |
| NFT_MSG_DELSETELEM | 14 | Delete set element |
| NFT_MSG_NEWOBJ | 18 | Create stateful object |
| NFT_MSG_GETOBJ | 19 | Get stateful object |
| NFT_MSG_DELOBJ | 20 | Delete stateful object |
| NFT_MSG_DESTROYTABLE | 26 | Destroy table (no error on miss) |
| NFT_MSG_DESTROYCHAIN | 27 | Destroy chain |
| NFT_MSG_DESTROYRULE | 28 | Destroy rule |
| NFT_MSG_DESTROYSET | 29 | Destroy set |
| NFT_MSG_DESTROYSETELEM | 30 | Destroy set element |
| NFT_MSG_DESTROYOBJ | 31 | Destroy object |

## Set Types

| Type | Backend | Key | Use Case |
|------|---------|-----|----------|
| hash | rhashtable | variable | General purpose, hash lookup |
| rbtree | red-black tree | variable | Range matching, intervals |
| bitmap | bitmap array | up to 65535 | Small integer keys |
| pipapo | packet parsing with offset | variable | Complex multi-field matching |

### Set Flags (NFTA_SET_FLAGS)
- `NFT_SET_ANONYMOUS` (0x1) - Unnamed, bound to rule
- `NFT_SET_CONSTANT` (0x2) - Read-only after creation
- `NFT_SET_INTERVAL` (0x4) - Set contains intervals
- `NFT_SET_MAP` (0x8) - Set maps keys to values
- `NFT_SET_TIMEOUT` (0x10) - Elements have timeouts
- `NFT_SET_EVAL` (0x20) - Set has expressions
- `NFT_SET_OBJECT` (0x40) - Set is linked to objects
- `NFT_SET_CONCAT` (0x80) - Concatenated fields

## Expression Types Commonly Exploited

| Expression | Purpose | Key for Exploitation |
|-----------|---------|---------------------|
| nft_counter | Packet/byte counters | Contains ops pointer (leakable) |
| nft_lookup | Set lookup | References set (binding chain) |
| nft_payload | Packet data extraction | Used in rule matching |
| nft_immediate | Load immediate value | Chain verdict reference |
| nft_dynset | Dynamic set update | Triggers set element allocation |
| nft_ct | Connection tracking | Access ct_expect objects |

## Object Types

| Object Type | Size | Slab | Description |
|------------|------|------|-------------|
| NFT_OBJECT_COUNTER | ~32B | kmalloc-64 | Packet/byte counter |
| NFT_OBJECT_CT_EXPECT | ~0xcc | kmalloc-256 | Connection tracking expectation |
| NFT_OBJECT_CT_HELPER | variable | kmalloc-256+ | CT helper |

### ct_expect Object Structure (Exploitation Target)
```
struct nft_ct_expect_obj {
    /* Embedded ct_expect data */
    u16 l3num;        /* L3 protocol */
    __be16 dport;     /* Destination port */
    u8 l4proto;       /* L4 protocol */
    u8 size;          /* Expected connection size */
    u32 timeout;      /* Expectation timeout */
};
/* Total nft_obj + ct_expect data: ~0xcc bytes -> kmalloc-256 */
```

## Key Kernel Structures

### struct nft_set
```c
struct nft_set {
    struct list_head        list;           /* 0x00: table's set list */
    struct list_head        bindings;       /* 0x10: bound rules */
    struct nft_table        *table;         /* 0x20: owning table */
    possible_net_t          net;            /* 0x28: network namespace */
    char                    *name;          /* 0x30: set name */
    u64                     handle;         /* 0x38: unique handle */
    u32                     ktype;          /* 0x40: key data type */
    u32                     dtype;          /* 0x44: data type */
    u32                     objtype;        /* 0x48: object type */
    u32                     size;           /* 0x4c: max elements */
    u8                      field_len[16];  /* 0x50: field lengths */
    u8                      field_count;    /* 0x60: number of fields */
    u32                     use;            /* reference count */
    atomic_t                nelems;         /* current element count */
    u32                     ndeact;         /* deactivated elements */
    u64                     timeout;        /* default timeout */
    u32                     gc_int;         /* GC interval */
    u16                     policy;         /* set policy */
    u16                     udlen;          /* user data length */
    unsigned char           *udata;         /* user data */
    const struct nft_set_ops *ops;          /* set operations (EXPLOIT TARGET) */
    u16                     flags;          /* set flags */
    u8                      klen;           /* key length */
    u8                      dlen;           /* data length */
    u8                      num_exprs;      /* number of expressions */
    struct nft_expr         *exprs[2];      /* expressions */
    struct list_head        catchall_list;  /* catchall elements */
    /* ... backend-specific data follows ... */
};
```

## Common CVE Trigger Sequences

### Batch for Set Element Timeout UAF
```
BATCH_BEGIN
  NEWTABLE "test" NFPROTO_IPV4
  NEWCHAIN "test" "chain1" (base chain, NF_INET_LOCAL_IN)
  NEWSET "test" "set1" (hash type, NFT_SET_TIMEOUT, timeout=4000ms)
  NEWSETELEM "test" "set1" (key=0x01, timeout=4000ms)
  NEWRULE "test" "chain1" (lookup in "set1")
BATCH_END
// Wait for timeout...
// Element GC fires, races with next batch
BATCH_BEGIN
  DELSETELEM "test" "set1" (key=0x01)  // Double-free with GC
BATCH_END
```

### Batch for Chain Refcount Error
```
BATCH_BEGIN
  NEWTABLE "test" NFPROTO_IPV4
  NEWCHAIN "test" "base" (base chain)
  NEWCHAIN "test" "bind" (binding chain)
  NEWSET "test" "anon_set" (anonymous, references "bind")
  NEWRULE "test" "base" (lookup in "anon_set")
BATCH_END
// Delete in specific order to cause refcount underflow:
BATCH_BEGIN
  DELRULE "test" "base" (handle=X)
  // bind chain refcount decremented but not freed...
  DELCHAIN "test" "bind"
  // Chain freed, but still referenced by set -> UAF
BATCH_END
```

## Required Kernel Configuration

```
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=y (or =m)
CONFIG_NF_TABLES_INET=y
CONFIG_NF_CT_NETLINK=y (for ct_expect objects)
CONFIG_USER_NS=y (for unprivileged CAP_NET_ADMIN)
CONFIG_NET_NS=y (for network namespace)
```

## Required Capabilities
- CAP_NET_ADMIN (obtained via CLONE_NEWUSER + CLONE_NEWNET)
