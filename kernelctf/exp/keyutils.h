#ifndef _KEYUTILS_H
#define _KEYUTILS_H
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
typedef int32_t key_serial_t;
#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_REVOKE 3
#define KEYCTL_READ 11
#define KEYCTL_UNLINK 9
static inline key_serial_t add_key(const char *type, const char *description,
    const void *payload, size_t plen, key_serial_t ringid) {
    return (key_serial_t)syscall(__NR_add_key, type, description, payload, plen, ringid);
}
static inline long keyctl_read(key_serial_t key, char *buffer, size_t buflen) {
    return syscall(__NR_keyctl, KEYCTL_READ, key, buffer, buflen);
}
static inline long keyctl_revoke(key_serial_t key) {
    return syscall(__NR_keyctl, KEYCTL_REVOKE, key);
}
static inline long keyctl_unlink(key_serial_t key, key_serial_t ringid) {
    return syscall(__NR_keyctl, KEYCTL_UNLINK, key, ringid);
}
#endif
