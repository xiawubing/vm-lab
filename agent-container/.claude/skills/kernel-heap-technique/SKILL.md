---
name: kernel-heap-technique
description: Linux kernel heap exploitation techniques including heap spray, object reclamation, cross-cache attacks, and slab layout manipulation. Use when implementing heap-based kernel exploits or choosing spray objects.
---

# Kernel Heap Exploitation Techniques

You are a kernel heap exploitation expert. Help the user choose and implement the right heap spray, object reclamation, and cross-cache techniques for their kernel exploit.

## Heap Spray Object Selection

When the user needs to spray a specific slab cache, recommend the best object based on:
1. **Target slab cache and size** - Must match the freed object's cache
2. **Control over content** - How much of the sprayed data is attacker-controlled
3. **Stability** - How reliably the object lands in the right slot
4. **Useful fields** - Function pointers, size fields, or list pointers at known offsets
5. **Cleanup** - Whether the object can be safely freed without side effects

## Available Spray Techniques

For each technique, reference the template code in [templates/](templates/) directory.

### 1. msg_msg (IPC Message Queues) — Most Versatile
- **Sizes**: 48-byte header + arbitrary data (kmalloc-64 through kmalloc-4k+)
- **Control**: Full control over data after 48-byte header
- **Spray**: `msgsnd()` to message queue, scales to thousands
- **Leak**: `msgrcv()` with MSG_COPY flag reads without consuming
- **Free**: `msgrcv()` without MSG_COPY consumes and frees
- **Template**: [templates/msg_msg_spray.c](templates/msg_msg_spray.c)

### 2. pipe_buffer — Page-Level Control
- **Size**: Array of 16 `struct pipe_buffer` (each 40 bytes) in kmalloc-640 or page
- **Control**: `pipe_buffer->page`, `pipe_buffer->offset`, `pipe_buffer->ops`
- **Spray**: `pipe()` + `write()` to fill pipe buffers
- **Key fields**: `page` pointer (offset 0), `ops` pointer (offset 0x10)
- **Use case**: Page pointer manipulation, ops pointer hijack
- **Template**: [templates/pipe_buffer_spray.c](templates/pipe_buffer_spray.c)

### 3. user_key_payload (keyctl) — Controlled Read
- **Sizes**: 18-byte header + arbitrary data
- **Control**: Full control over data portion
- **Spray**: `add_key("user", name, data, datalen, keyring)`
- **Leak**: `keyctl_read()` reads the payload back
- **Free**: `keyctl_revoke()` + `keyctl_unlink()`
- **Use case**: When you need both write AND read-back
- **Template**: [templates/user_key_spray.c](templates/user_key_spray.c)

### 4. nftables Objects — Netfilter Context
- **nft_table USERDATA**: Variable size, via NFT_MSG_NEWTABLE with NFTA_TABLE_USERDATA
- **nft_set elements**: Variable key/data size, via NFT_MSG_NEWSETELEM
- **nft_rule + expressions**: Variable, via NFT_MSG_NEWRULE
- **nft_obj (ct_expect)**: ~0xcc bytes (kmalloc-256)
- **Use case**: Already in nftables exploit context, need matching GFP flags
- **Template**: See `kernel-nftables-ops` skill

### 5. Simple xattr — Zero-Fill
- **Sizes**: Variable via setxattr value length
- **Control**: Full control, but ephemeral (freed immediately on error)
- **Spray**: `setxattr("/tmp/x", "user.x", buf, size, XATTR_CREATE)`
- **Use case**: Pre-fill slab with zeros, or brief window allocation
- **Note**: On tmpfs, uses simple_xattr (kmalloc-cg-*)

### 6. AF_PACKET TX_RING — Pointer Arrays
- **Size**: Configurable via PACKET_TX_RING tp_block_size
- **Control**: Ring buffer pointers and metadata
- **Spray**: `socket(AF_PACKET) + setsockopt(PACKET_TX_RING)`
- **Use case**: Large controlled allocations, pointer arrays

### 7. sk_buff (Socket Buffers) — Network Data
- **Sizes**: Variable based on packet size
- **Control**: Packet data content fully controlled
- **Spray**: `sendmsg()` on various socket types (UDP, raw, etc.)
- **Use case**: Network-context sprays matching SKB allocator path

### 8. BPF Objects
- **bpf_prog_aux**: Via BPF_PROG_LOAD
- **BPF ringbuf**: Page-level allocations
- **BPF map values**: Arbitrary size
- **Use case**: BPF-context exploits, JIT spraying

## Cross-Cache Attack Methodology

When the freed object is in a different cache than available spray objects:

### Technique 1: Direct Cross-Cache via RCU
```
1. Spray target cache to fill it up
2. Free target object (enters RCU pending)
3. Wait for RCU grace period (sleep 1-6 seconds)
4. Object's slab page may be returned to page allocator
5. Allocate from different cache to reclaim the page
```

### Technique 2: Cache Transfer via Intermediate
```
1. Free object from cache A (e.g., kmalloc-512)
2. Spray intermediate objects in cache A (e.g., fqdir via CLONE_NEWNET)
3. Intermediate overlaps with freed object
4. Free intermediate -> frees shared sub-object in cache B
5. Reclaim sub-object in cache B with attacker-controlled data
```

### Technique 3: Type Confusion (Same Cache)
```
1. Free object of type X from cache (e.g., drr_class from kmalloc-256)
2. Allocate object of type Y in same cache (e.g., qfq_class from kmalloc-256)
3. Type X operations interpret Y's fields differently
4. Exploit the field misinterpretation
```

### Technique 4: Page Allocator Bypass (Large Objects)
```
1. For objects > PAGE_SIZE, allocator uses page allocator directly
2. Free large object -> pages returned to buddy allocator
3. Spray with page-sized objects (pipe pages, BPF ringbuf)
4. Reclaimed page has attacker-controlled content
```

## Slab Allocator Notes

### SLUB Behavior (default since ~5.x)
- Objects grouped by size classes: 8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192
- Each CPU has per-cpu partial slabs (fast path)
- Objects with GFP_KERNEL_ACCOUNT go to kmalloc-cg-* caches
- CONFIG_RANDOM_KMALLOC_CACHES (6.6+): 16 random cache copies per size

### Mitigations and Bypasses
- **CONFIG_SLAB_FREELIST_HARDENED**: Freelist pointer XOR'd with random value and address
  - Bypass: Don't corrupt freelist; use object content instead
- **CONFIG_RANDOM_KMALLOC_CACHES**: Multiple cache copies for same size
  - Bypass: Type confusion between objects in same physical cache
  - Bypass: Use objects with same kmalloc call site (same random cache)
- **CONFIG_SLAB_FREELIST_RANDOM**: Randomized freelist ordering
  - Impact: Spray more objects to ensure coverage
- **init_on_alloc / init_on_free**: Zero-fills
  - Impact: Can't rely on stale data; must actively reclaim and write

## Implementation Checklist

1. [ ] Identify target slab cache (size + GFP flags)
2. [ ] Choose spray object that matches cache
3. [ ] Determine spray count (typically 0x100-0x10000 objects)
4. [ ] Implement defragmentation: spray to fill partial slabs
5. [ ] Implement targeted allocation: free some spray objects, trigger vuln, reclaim
6. [ ] Verify reclamation: read back sprayed content via leak primitive
7. [ ] Handle cleanup: free spray objects without triggering double-free

For code templates, see the [templates/](templates/) directory.
