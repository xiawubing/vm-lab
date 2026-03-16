/*
 * io_uring Exploitation Helpers
 *
 * Minimal wrappers for io_uring syscalls used in kernel exploits.
 * Extracted from kernelCTF io_uring CVEs.
 */

#ifndef IO_URING_HELPERS_H
#define IO_URING_HELPERS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

/* ============================================================
 * io_uring Syscall Wrappers
 * ============================================================ */

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int fd, unsigned to_submit,
                                  unsigned min_complete, unsigned flags) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                   flags, NULL, 0);
}

static inline int io_uring_register(int fd, unsigned opcode,
                                     void *arg, unsigned nr_args) {
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

/* ============================================================
 * io_uring Context Setup
 * ============================================================ */

struct uring_ctx {
    int ring_fd;
    struct io_uring_sqe *sq_ring;
    struct io_uring_cqe *cq_ring;
    uint32_t *sq_tail;
    uint32_t *sq_head;
    uint32_t *cq_tail;
    uint32_t *cq_head;
    uint32_t sq_ring_mask;
    uint32_t cq_ring_mask;
    uint32_t *sq_array;
};

/* Standard io_uring setup */
static inline int uring_init(struct uring_ctx *ctx, unsigned entries) {
    struct io_uring_params params = {};

    ctx->ring_fd = io_uring_setup(entries, &params);
    if (ctx->ring_fd < 0) {
        perror("io_uring_setup");
        return -1;
    }

    /* Map SQ ring */
    size_t sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
    void *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, ctx->ring_fd,
                        IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) return -1;

    ctx->sq_head = sq_ptr + params.sq_off.head;
    ctx->sq_tail = sq_ptr + params.sq_off.tail;
    ctx->sq_ring_mask = *(uint32_t *)(sq_ptr + params.sq_off.ring_mask);
    ctx->sq_array = sq_ptr + params.sq_off.array;

    /* Map SQEs */
    ctx->sq_ring = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                        ctx->ring_fd, IORING_OFF_SQES);
    if (ctx->sq_ring == MAP_FAILED) return -1;

    /* Map CQ ring */
    size_t cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    void *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, ctx->ring_fd,
                        IORING_OFF_CQ_RING);
    if (cq_ptr == MAP_FAILED) return -1;

    ctx->cq_head = cq_ptr + params.cq_off.head;
    ctx->cq_tail = cq_ptr + params.cq_off.tail;
    ctx->cq_ring_mask = *(uint32_t *)(cq_ptr + params.cq_off.ring_mask);
    ctx->cq_ring = cq_ptr + params.cq_off.cqes;

    return 0;
}

/* Submit a NOP SQE (useful for testing / filling ring) */
static inline int uring_submit_nop(struct uring_ctx *ctx) {
    uint32_t tail = *ctx->sq_tail;
    uint32_t idx = tail & ctx->sq_ring_mask;

    struct io_uring_sqe *sqe = &ctx->sq_ring[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_NOP;

    ctx->sq_array[idx] = idx;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);

    return io_uring_enter(ctx->ring_fd, 1, 0, 0);
}

/* Submit a read SQE */
static inline int uring_submit_read(struct uring_ctx *ctx, int fd,
                                     void *buf, size_t len, off_t offset,
                                     uint64_t user_data) {
    uint32_t tail = *ctx->sq_tail;
    uint32_t idx = tail & ctx->sq_ring_mask;

    struct io_uring_sqe *sqe = &ctx->sq_ring[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd = fd;
    sqe->addr = (uint64_t)buf;
    sqe->len = len;
    sqe->off = offset;
    sqe->user_data = user_data;

    ctx->sq_array[idx] = idx;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);

    return io_uring_enter(ctx->ring_fd, 1, 0, 0);
}

/* Wait for and consume a CQE */
static inline int uring_wait_cqe(struct uring_ctx *ctx,
                                  struct io_uring_cqe *out) {
    uint32_t head;

    /* Wait for completion */
    io_uring_enter(ctx->ring_fd, 0, 1, IORING_ENTER_GETEVENTS);

    head = *ctx->cq_head;
    if (head == *ctx->cq_tail) return -1;  /* No completions */

    uint32_t idx = head & ctx->cq_ring_mask;
    *out = ctx->cq_ring[idx];

    /* Advance head */
    __atomic_store_n(ctx->cq_head, head + 1, __ATOMIC_RELEASE);

    return 0;
}

static inline void uring_close(struct uring_ctx *ctx) {
    close(ctx->ring_fd);
}

/* ============================================================
 * Provided Buffer Ring (for CVE-2025-21836, CVE-2025-40364)
 * ============================================================ */

/*
 * io_uring provided buffer rings allow pre-registered buffers
 * that io_uring picks from for read operations.
 *
 * struct io_uring_buf_ring {
 *   union {
 *     struct { uint64_t resv1; uint32_t resv2; uint16_t resv3; uint16_t tail; };
 *     struct io_uring_buf bufs[];
 *   };
 * };
 *
 * struct io_uring_buf {
 *   uint64_t addr;
 *   uint32_t len;
 *   uint16_t bid;
 *   uint16_t resv;
 * };
 */

static inline int uring_register_buf_ring(struct uring_ctx *ctx,
                                           void *ring_addr,
                                           uint32_t nentries,
                                           uint16_t bgid) {
    struct io_uring_buf_reg reg = {
        .ring_addr = (uint64_t)ring_addr,
        .ring_entries = nentries,
        .bgid = bgid,
    };
    return io_uring_register(ctx->ring_fd, IORING_REGISTER_PBUF_RING,
                             &reg, 1);
}

#endif /* IO_URING_HELPERS_H */
