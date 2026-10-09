#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "povishield.h"

#define STACK_SZ (1024 * 1024)
#define CG_ROOT "/sys/fs/cgroup"

struct cfg {
    const char *rootfs, *profile, *hostname;
    long mem_mb;
    int pids, cpu_pct, audit;
    char **cmd;
    int sync[2];
};

static int setup_rootfs(const char *root) {
    char old[4096];
    snprintf(old, sizeof old, "%s/.old_root", root);
    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) < 0) { perror("bind rootfs"); return -1; }
    mkdir(old, 0700);
    if (syscall(SYS_pivot_root, root, old) < 0) { perror("pivot_root"); return -1; }
    if (chdir("/") < 0) return -1;
    if (umount2("/.old_root", MNT_DETACH) < 0) { perror("umount old root"); return -1; }
    rmdir("/.old_root");
    return 0;
}

static int child_main(void *arg) {
    struct cfg *c = arg;
    char b;
    close(c->sync[1]);
    if (read(c->sync[0], &b, 1) != 1) _exit(125);          /* wait until parent set up the cgroup */
    close(c->sync[0]);

    if (sethostname(c->hostname, strlen(c->hostname)) < 0) perror("sethostname");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) { perror("make / private"); _exit(125); }
    if (c->rootfs && setup_rootfs(c->rootfs) < 0) _exit(125);
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) perror("mount /proc (continuing)");
    if (c->profile && ps_apply_seccomp(c->profile, c->audit) < 0) _exit(126);

    execvp(c->cmd[0], c->cmd);
    perror(c->cmd[0]);
    _exit(127);
}

static void rd(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    buf[0] = 0;
    if (f) { if (fgets(buf, n, f)) buf[strcspn(buf, "\n")] = 0; fclose(f); }
    else snprintf(buf, n, "n/a");
}

int cmd_run(int argc, char **argv) {
    struct cfg c = { .hostname = "povishield" };
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--mem") && i + 1 < argc) c.mem_mb = atol(argv[++i]);
        else if (!strcmp(argv[i], "--pids") && i + 1 < argc) c.pids = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu") && i + 1 < argc) c.cpu_pct = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rootfs") && i + 1 < argc) c.rootfs = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc) c.profile = argv[++i];
        else if (!strcmp(argv[i], "--hostname") && i + 1 < argc) c.hostname = argv[++i];
        else if (!strcmp(argv[i], "--audit")) c.audit = 1;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: povishield run [opts] -- CMD...\n"); return 2; }
    c.cmd = &argv[i];
    if (geteuid() != 0) { fprintf(stderr, "povishield run: needs root (try sudo)\n"); return 1; }
    if (pipe(c.sync) < 0) { perror("pipe"); return 1; }

    char *stack = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap"); return 1; }
    pid_t pid = clone(child_main, stack + STACK_SZ,
                      CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD, &c);
    if (pid < 0) { perror("clone"); return 1; }
    close(c.sync[0]);

    /* ---- cgroup v2 limits ---- */
    char cg[256], path[320], val[64];
    snprintf(cg, sizeof cg, CG_ROOT "/povishield-%d", pid);
    ps_write_file(CG_ROOT "/cgroup.subtree_control", "+memory +pids +cpu");
    if (mkdir(cg, 0755) < 0) { perror("mkdir cgroup (cgroup v2 mounted?)"); }
    else {
        if (c.mem_mb > 0) {
            snprintf(path, sizeof path, "%s/memory.max", cg);
            snprintf(val, sizeof val, "%ld", c.mem_mb * 1024 * 1024);
            ps_write_file(path, val);
            snprintf(path, sizeof path, "%s/memory.swap.max", cg);
            ps_write_file(path, "0");
        }
        if (c.pids > 0) {
            snprintf(path, sizeof path, "%s/pids.max", cg);
            snprintf(val, sizeof val, "%d", c.pids);
            ps_write_file(path, val);
        }
        if (c.cpu_pct > 0) {
            snprintf(path, sizeof path, "%s/cpu.max", cg);
            snprintf(val, sizeof val, "%d 100000", c.cpu_pct * 1000);
            ps_write_file(path, val);
        }
        snprintf(path, sizeof path, "%s/cgroup.procs", cg);
        snprintf(val, sizeof val, "%d", pid);
        ps_write_file(path, val);
    }
    if (write(c.sync[1], "g", 1) != 1) perror("sync");
    close(c.sync[1]);

    int st = 0;
    waitpid(pid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);

    char peak[64], events[128];
    snprintf(path, sizeof path, "%s/memory.peak", cg);
    rd(path, peak, sizeof peak);
    snprintf(path, sizeof path, "%s/memory.events", cg);
    rd(path, events, sizeof events);
    if (getenv("PS_VERBOSE"))
        fprintf(stderr, "[povishield] exit=%d mem.peak=%s\n", code, peak);
    rmdir(cg);
    return code;
}
