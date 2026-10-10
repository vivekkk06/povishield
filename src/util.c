#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "povishield.h"

int ps_write_file(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;

    size_t len = strlen(s);
    ssize_t n;
    do {
        n = write(fd, s, len);
    } while (n < 0 && errno == EINTR);

    int saved_errno = errno;
    int close_result = close(fd);

    if (n < 0) {
        errno = saved_errno;
        return -1;
    }
    if ((size_t)n != len) {
        errno = EIO;
        return -1;
    }
    if (close_result < 0) return -1;

    return 0;
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
