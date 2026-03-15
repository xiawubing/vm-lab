/*
 * shell_trap.c — bind-mounted replacement for /bin/sh and /bin/bash.
 *
 * If euid == 0: read and print the flag, then exec the real shell.
 * If euid != 0: transparently exec the real shell.
 *
 * Compiled statically and placed in the 9p-mounted exp/ directory.
 * init.sh bind-mounts it over /bin/sh and /bin/bash before running the exploit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define REAL_SHELL "/tmp/sh.real"

static void try_print_flag(void) {
    static const char *paths[] = {"/tmp/flag", "/flag", "/dev/vdb", NULL};
    char buf[512];
    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            /* strip trailing nulls (from /dev/vdb block device reads) */
            while (n > 0 && buf[n - 1] == '\0') n--;
            buf[n] = '\0';
            printf("%s\n", buf);
            fflush(stdout);
            return;
        }
    }
}

int main(int argc, char *argv[], char *envp[]) {
    if (geteuid() == 0) {
        try_print_flag();
    }
    /* exec the real shell with the same arguments */
    argv[0] = REAL_SHELL;
    execve(REAL_SHELL, argv, envp);
    /* if exec fails, try sh.real directly */
    perror("shell_trap: execve");
    return 127;
}
