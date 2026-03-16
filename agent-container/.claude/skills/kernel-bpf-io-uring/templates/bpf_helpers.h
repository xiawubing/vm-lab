/*
 * BPF Exploitation Helpers
 *
 * Minimal wrappers for BPF syscall operations used in kernel exploits.
 * Extracted from kernelCTF BPF-related CVEs.
 */

#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

/* ============================================================
 * BPF Syscall Wrapper
 * ============================================================ */

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

/* ============================================================
 * Map Operations
 * ============================================================ */

static inline int bpf_create_map(enum bpf_map_type type,
                                  uint32_t key_size,
                                  uint32_t value_size,
                                  uint32_t max_entries) {
    union bpf_attr attr = {
        .map_type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static inline int bpf_create_ringbuf(uint32_t size) {
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_RINGBUF,
        .key_size = 0,
        .value_size = 0,
        .max_entries = size,  /* Must be power of 2, >= PAGE_SIZE */
    };
    return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static inline int bpf_map_update(int fd, const void *key, const void *value,
                                  uint64_t flags) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
        .flags = flags,
    };
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_lookup(int fd, const void *key, void *value) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* ============================================================
 * Program Loading
 * ============================================================ */

static inline int bpf_load_prog(enum bpf_prog_type type,
                                 const struct bpf_insn *insns,
                                 uint32_t insn_cnt,
                                 const char *license) {
    char log_buf[65536] = {};
    union bpf_attr attr = {
        .prog_type = type,
        .insns = (uint64_t)insns,
        .insn_cnt = insn_cnt,
        .license = (uint64_t)license,
        .log_buf = (uint64_t)log_buf,
        .log_size = sizeof(log_buf),
        .log_level = 1,
    };

    int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        fprintf(stderr, "BPF load failed: %s\n", log_buf);
    }
    return fd;
}

/* ============================================================
 * BPF Instruction Macros
 * ============================================================ */

/* These match linux/bpf.h instruction encoding */
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn) { .code = CODE, .dst_reg = DST, \
     .src_reg = SRC, .off = OFF, .imm = IMM })

#define BPF_MOV64_IMM(DST, IMM) \
    BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV64_REG(DST, SRC) \
    BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_LD_MAP_FD(DST, MAP_FD) \
    BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, MAP_FD), \
    BPF_RAW_INSN(0, 0, 0, 0, 0)

#define BPF_CALL_FUNC(FUNC) \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FUNC)

#define BPF_EXIT_INSN() \
    BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    BPF_RAW_INSN(BPF_JMP | OP | BPF_K, DST, 0, OFF, IMM)

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
    BPF_RAW_INSN(BPF_STX | SIZE | BPF_MEM, DST, SRC, OFF, 0)

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
    BPF_RAW_INSN(BPF_LDX | SIZE | BPF_MEM, DST, SRC, OFF, 0)

/* ============================================================
 * Ringbuf Exploitation Helpers
 * ============================================================ */

/*
 * BPF ringbuf memory layout (after mmap):
 *
 * Page 0: Consumer page (read-only for userspace)
 *   - consumer_pos (8 bytes) - userspace reads this
 *
 * Page 1: Producer page (kernel-only)
 *   - producer_pos (8 bytes) - kernel tracks this
 *   - ... other metadata ...
 *
 * Pages 2+: Data pages (ringbuf entries)
 *   - Each entry has 8-byte header:
 *     [31:0]  length
 *     [32]    busy bit (BPF_RINGBUF_BUSY_BIT)
 *     [33]    discard bit (BPF_RINGBUF_DISCARD_BIT)
 *   - Followed by data (rounded up to 8 bytes)
 *   - pg_off tracks allocation position
 */

#define BPF_RINGBUF_BUSY_BIT    (1U << 31)
#define BPF_RINGBUF_DISCARD_BIT (1U << 30)
#define BPF_RINGBUF_HDR_SZ      8

#endif /* BPF_HELPERS_H */
