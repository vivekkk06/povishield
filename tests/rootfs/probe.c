/* Static test probe used by the root-only runtime and rootfs-isolation tests.
 * Every sub-command prints one machine-readable line per result. Harmless by design. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void report_stat(const char *p) {
    struct stat st;
    if (stat(p, &st) == 0) printf("VISIBLE %s\n", p);
    else printf("HIDDEN %s (%s)\n", p, strerror(errno));
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe CMD [ARGS]\n"); return 2; }
    const char *c = argv[1];

    if (!strcmp(c, "stat")) { for (int i = 2; i < argc; i++) report_stat(argv[i]); return 0; }

    if (!strcmp(c, "id")) {
        char h[256] = "";
        gethostname(h, sizeof h);
        printf("pid=%d uid=%d host=%s\n", getpid(), getuid(), h);
        return 0;
    }

    if (!strcmp(c, "ns")) {
        const char *n[] = { "pid", "mnt", "uts", "ipc", "net" };
        for (int i = 0; i < 5; i++) {
            char p[64], t[128];
            snprintf(p, sizeof p, "/proc/self/ns/%s", n[i]);
            ssize_t l = readlink(p, t, sizeof t - 1);
            if (l < 0) { printf("%s=ERR\n", n[i]); continue; }
            t[l] = 0;
            printf("%s=%s\n", n[i], t);
        }
        return 0;
    }

    if (!strcmp(c, "caps")) {
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        if (!f) { puts("CapEff: ERR"); return 1; }
        while (fgets(line, sizeof line, f)) if (!strncmp(line, "CapEff:", 7)) fputs(line, stdout);
        fclose(f);
        return 0;
    }

    if (!strcmp(c, "mount")) {
        if (mount("none", "/tmp", "tmpfs", 0, NULL) == 0) { puts("MOUNT_OK"); umount("/tmp"); }
        else printf("MOUNT_FAIL %s\n", strerror(errno));
        return 0;
    }

    if (!strcmp(c, "cat") && argc > 2) {
        int fd = open(argv[2], O_RDONLY);
        char b[512]; ssize_t n;
        if (fd < 0) { printf("CAT_FAIL %s\n", strerror(errno)); return 1; }
        while ((n = read(fd, b, sizeof b)) > 0) if (write(1, b, (size_t)n) < 0) break;
        close(fd);
        return 0;
    }

    if (!strcmp(c, "netdev")) {                       /* interface names visible in this network namespace */
        FILE *f = fopen("/proc/net/dev", "r");
        char line[512];
        if (!f) { puts("NETDEV_ERR"); return 1; }
        while (fgets(line, sizeof line, f)) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            *colon = 0;
            char *s = line;
            while (*s == ' ') s++;
            printf("IFACE %s\n", s);
        }
        fclose(f);
        return 0;
    }

    if (!strcmp(c, "marker") && argc > 2) {           /* proves the command really ran */
        int fd = creat(argv[2], 0644);
        if (fd < 0) { printf("MARKER_FAIL %s\n", strerror(errno)); return 1; }
        close(fd);
        puts("MARKER");
        return 0;
    }

    if (!strcmp(c, "busy") && argc > 2) {             /* burn CPU for N wall seconds */
        struct timespec t0, t;
        volatile unsigned long x = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        do {
            for (int i = 0; i < 200000; i++) x += (unsigned long)i;
            clock_gettime(CLOCK_MONOTONIC, &t);
        } while ((t.tv_sec - t0.tv_sec) + (t.tv_nsec - t0.tv_nsec) / 1e9 < atof(argv[2]));
        puts("BUSY_DONE");
        return 0;
    }

    if (!strcmp(c, "alloc") && argc > 2) {            /* touch N MiB */
        size_t n = (size_t)atol(argv[2]) << 20;
        unsigned char *p = malloc(n);
        if (!p) { puts("ALLOC_FAIL"); return 1; }
        volatile unsigned char *vp = (volatile unsigned char *)p;
        for (size_t i = 0; i < n; i += 4096)
            vp[i] = 7;
        if (n > 0)
            vp[n - 1] = 7;
        puts("ALLOC_OK");
        free(p);
        return 0;
    }

    if (!strcmp(c, "forks") && argc > 2) {            /* try to create N sleeping children */
        int want = atoi(argv[2]), ok = 0;
        pid_t *k = calloc((size_t)want, sizeof *k);
        for (int i = 0; i < want; i++) {
            pid_t p = fork();
            if (p == 0) { pause(); _exit(0); }
            if (p < 0) break;
            k[ok++] = p;
        }
        for (int i = 0; i < ok; i++) { kill(k[i], SIGKILL); waitpid(k[i], NULL, 0); }
        printf("FORKED %d\n", ok);
        return 0;
    }

    if (!strcmp(c, "chroot_escape") && argc > 2) {    /* classic chroot break-out, then look for a host path */
        mkdir("esc", 0755);
        if (chroot("esc") != 0) { printf("CHROOT_FAIL %s\n", strerror(errno)); return 0; }
        for (int i = 0; i < 64; i++) if (chdir("..") != 0) break;
        if (chroot(".") != 0) { printf("CHROOT2_FAIL %s\n", strerror(errno)); return 0; }
        puts("CHROOT_DONE");
        report_stat(argv[2]);
        return 0;
    }

    if (!strcmp(c, "tree") && argc > 2) {             /* parent + one sleeping child; child pid goes to a file */
        pid_t p = fork();

        if (p < 0) {
            perror("fork");
            return 1;
        }

        if (p == 0) {
            for (;;)
                pause();
        }

        FILE *f = fopen(argv[2], "w");
        if (!f) {
            kill(p, SIGKILL);
            waitpid(p, NULL, 0);
            perror("pid file");
            return 1;
        }

        fprintf(f, "%ld\n", (long)p);
        if (fclose(f) != 0) {
            kill(p, SIGKILL);
            waitpid(p, NULL, 0);
            perror("pid file");
            return 1;
        }

        printf("TREE_CHILD %ld\n", (long)p);
        fflush(stdout);

        for (;;)
            pause();
    }

    fprintf(stderr, "probe: unknown command %s\n", c);
    return 2;
}
