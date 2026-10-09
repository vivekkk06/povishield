#define _GNU_SOURCE
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "povishield.h"

int ps_write_file(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n < 0 ? -1 : 0;
}

/* Count syscalls known to libseccomp for this architecture (never hardcoded). */
int ps_total_syscalls(void) {
    int count = 0;
    for (int i = 0; i < 1024; i++) {
        char *n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, i);
        if (n) { count++; free(n); }
    }
    return count;
}

int cmd_info(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "total-syscalls")) {
        printf("%d\n", ps_total_syscalls());
        return 0;
    }
    fprintf(stderr, "usage: povishield info total-syscalls\n");
    return 2;
}
