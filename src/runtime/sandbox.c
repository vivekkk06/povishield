#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

    if (!root || root[0] != '/') {
        fprintf(stderr, "rootfs must be an absolute path\n");
        return -1;
    }

    int n = snprintf(old, sizeof old, "%s/.old_root", root);
    if (n < 0 || (size_t)n >= sizeof old) {
        fprintf(stderr, "rootfs path is too long\n");
        return -1;
    }

    struct stat st;
    if (stat(root, &st) < 0) {
        perror("stat rootfs");
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "rootfs path is not a directory: %s\n", root);
        return -1;
    }

    if (mkdir(old, 0700) < 0 && errno != EEXIST) {
        perror("create rootfs .old_root");
        return -1;
    }
    if (stat(old, &st) < 0) {
        perror("stat rootfs .old_root");
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "rootfs .old_root is not a directory\n");
        return -1;
    }

    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("bind rootfs");
        return -1;
    }

    if (syscall(SYS_pivot_root, root, old) < 0) {
        int saved_errno = errno;
        if (umount2(root, MNT_DETACH) < 0)
            perror("cleanup bind-mounted rootfs");
        errno = saved_errno;
        perror("pivot_root");
        return -1;
    }

    if (chdir("/") < 0) {
        perror("chdir after pivot_root");
        return -1;
    }
    if (umount2("/.old_root", MNT_DETACH) < 0) {
        perror("umount old root");
        return -1;
    }
    if (rmdir("/.old_root") < 0) {
        perror("remove old root mountpoint");
        return -1;
    }

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
    /* The profile path is host-relative: open it BEFORE pivot_root, then refer to it
     * through /proc/self/fd (proc is mounted below). O_CLOEXEC keeps it out of the target. */
    char prof_path[64];
    const char *profile = c->profile;
    if (c->profile && c->rootfs) {
        int pfd = open(c->profile, O_RDONLY | O_CLOEXEC);
        if (pfd < 0) { perror(c->profile); _exit(126); }
        snprintf(prof_path, sizeof prof_path, "/proc/self/fd/%d", pfd);
        profile = prof_path;
    }
    if (c->rootfs && setup_rootfs(c->rootfs) < 0) _exit(125);
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
        perror("mount /proc");
        if (c->rootfs) _exit(125);
    }
    if (profile && ps_apply_seccomp(profile, c->audit) < 0) _exit(126);

    execvp(c->cmd[0], c->cmd);
    perror(c->cmd[0]);
    _exit(127);
}

static volatile sig_atomic_t run_signal = 0;

static void record_run_signal(int signo) {
    run_signal = signo;
}

static void rd(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    buf[0] = 0;
    if (f) { if (fgets(buf, n, f)) buf[strcspn(buf, "\n")] = 0; fclose(f); }
    else snprintf(buf, n, "n/a");
}

static void rd_memory_events(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(buf, n, "n/a");
        return;
    }

    unsigned long long low = 0, high = 0, max = 0;
    unsigned long long oom = 0, oom_kill = 0, oom_group_kill = 0;
    char line[128];

    while (fgets(line, sizeof(line), f)) {
        char key[64];
        unsigned long long value;

        if (sscanf(line, "%63s %llu", key, &value) != 2)
            continue;

        if (!strcmp(key, "low")) low = value;
        else if (!strcmp(key, "high")) high = value;
        else if (!strcmp(key, "max")) max = value;
        else if (!strcmp(key, "oom")) oom = value;
        else if (!strcmp(key, "oom_kill")) oom_kill = value;
        else if (!strcmp(key, "oom_group_kill")) oom_group_kill = value;
    }

    fclose(f);
    snprintf(buf, n,
        "low %llu high %llu max %llu oom %llu oom_kill %llu oom_group_kill %llu",
        low, high, max, oom, oom_kill, oom_group_kill);
}


static int parse_limit(const char *option, const char *text,
                       long minimum, long maximum, long *result) {
    char *end = NULL;
    long value;

    if (!text || !*text) {
        fprintf(stderr, "povishield run: missing value for %s\n", option);
        return -1;
    }

    errno = 0;
    value = strtol(text, &end, 10);

    if (errno == ERANGE || end == text || *end != '\0' ||
        value < minimum || value > maximum) {
        fprintf(stderr,
                "povishield run: invalid value for %s: '%s' (expected %ld..%ld)\n",
                option, text, minimum, maximum);
        return -1;
    }

    *result = value;
    return 0;
}

/* A just-killed cgroup can stay busy for a few ms while its tasks are torn down. */
static void remove_cgroup(const char *cg) {
    for (int attempt = 0; attempt < 50; attempt++) {
        if (rmdir(cg) == 0 || errno == ENOENT)
            return;
        if (errno != EBUSY)
            break;
        usleep(10000);
    }
    perror("remove cgroup");
}

int cmd_run(int argc, char **argv) {
    struct cfg c = { .hostname = "povishield" };
    int i = 1;

    for (; i < argc; i++) {
        long value;
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("Usage: povishield run [OPTIONS] -- CMD [ARGS...]\n"
                   "  --mem MB          Memory limit in MiB\n"
                   "  --pids COUNT      Process limit\n"
                   "  --cpu PERCENT     CPU quota percentage\n"
                   "  --rootfs PATH     Root filesystem directory\n"
                   "  --profile PATH    Policy profile\n"
                   "  --hostname NAME   Sandbox hostname\n"
                   "  --audit           Enable audit mode\n"
                   "  --help, -h        Show this help\n");
            return 0;
        }


        if (!strcmp(argv[i], "--mem") ||
            !strcmp(argv[i], "--pids") ||
            !strcmp(argv[i], "--cpu")) {
            const char *option = argv[i];

            if (i + 1 >= argc || !strcmp(argv[i + 1], "--")) {
                fprintf(stderr, "povishield run: missing value for %s\n", option);
                return 2;
            }

            long minimum = 1;
            long maximum = !strcmp(option, "--mem") ? 1048576L :
                           !strcmp(option, "--pids") ? 1048576L : 6400L;

            if (parse_limit(option, argv[i + 1], minimum, maximum, &value) < 0)
                return 2;

            i++;
            if (!strcmp(option, "--mem")) c.mem_mb = value;
            else if (!strcmp(option, "--pids")) c.pids = (int)value;
            else c.cpu_pct = (int)value;
        }
        else if (!strcmp(argv[i], "--rootfs") ||
                 !strcmp(argv[i], "--profile") ||
                 !strcmp(argv[i], "--hostname")) {
            const char *option = argv[i];

            if (i + 1 >= argc || !strcmp(argv[i + 1], "--")) {
                fprintf(stderr, "povishield run: missing value for %s\n", option);
                return 2;
            }

            const char *value_text = argv[++i];
            if (!*value_text) {
                fprintf(stderr, "povishield run: empty value for %s\n", option);
                return 2;
            }

            if (!strcmp(option, "--rootfs")) c.rootfs = value_text;
            else if (!strcmp(option, "--profile")) c.profile = value_text;
            else c.hostname = value_text;
        }
        else if (!strcmp(argv[i], "--audit")) c.audit = 1;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: povishield run [opts] -- CMD...\n"); return 2; }
    c.cmd = &argv[i];

    if (c.rootfs) {
        struct stat st;

        if (c.rootfs[0] != '/') {
            fprintf(stderr, "povishield run: --rootfs must be an absolute path\n");
            return 2;
        }
        if (stat(c.rootfs, &st) < 0) {
            perror("povishield run: cannot access rootfs");
            return 2;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "povishield run: --rootfs is not a directory\n");
            return 2;
        }
    }
    if (geteuid() != 0) { fprintf(stderr, "povishield run: needs root (try sudo)\n"); return 1; }
    if (pipe(c.sync) < 0) { perror("pipe"); return 1; }

    char *stack = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) {
        perror("mmap");
        close(c.sync[0]);
        close(c.sync[1]);
        return 1;
    }
    pid_t pid = clone(child_main, stack + STACK_SZ,
                      CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD, &c);
    if (pid < 0) {
        perror("clone");
        close(c.sync[0]);
        close(c.sync[1]);
        munmap(stack, STACK_SZ);
        return 1;
    }
    close(c.sync[0]);

    /* ---- all state is declared up front so every failure can jump to one cleanup path ---- */
    struct sigaction sa = {0}, old_int, old_term;
    int int_installed = 0, term_installed = 0;
    int sync_open = 1;            /* parent's write end of the sync pipe */
    int reaped = 0;               /* child already waited for */
    int cg_created = 0;
    int rc = 1;
    int st = 0, code = 1;
    pid_t waited = -1;
    char cg[256], path[320], val[64], peak[64], events[128];

    sa.sa_handler = record_run_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, &old_int) < 0) {
        perror("install SIGINT handler");
        goto abort_child;
    }
    int_installed = 1;
    if (sigaction(SIGTERM, &sa, &old_term) < 0) {
        perror("install SIGTERM handler");
        goto abort_child;
    }
    term_installed = 1;

    /* ---- cgroup v2 limits: fail closed if requested limits cannot be applied ---- */
    snprintf(cg, sizeof cg, CG_ROOT "/povishield-%d", pid);

    if (c.mem_mb > 0 || c.pids > 0 || c.cpu_pct > 0) {
        if (ps_write_file(CG_ROOT "/cgroup.subtree_control",
                          "+memory +pids +cpu") < 0) {
            perror("enable cgroup controllers");
            goto abort_child;
        }

        if (mkdir(cg, 0755) < 0) {
            perror("mkdir cgroup");
            goto abort_child;
        }
        cg_created = 1;

        if (c.mem_mb > 0) {
            snprintf(path, sizeof path, "%s/memory.max", cg);
            snprintf(val, sizeof val, "%ld", c.mem_mb * 1024 * 1024);
            if (ps_write_file(path, val) < 0) {
                perror("set memory.max");
                goto abort_child;
            }
            snprintf(path, sizeof path, "%s/memory.swap.max", cg);
            if (ps_write_file(path, "0") < 0) {
                perror("set memory.swap.max");
                goto abort_child;
            }
        }

        if (c.pids > 0) {
            snprintf(path, sizeof path, "%s/pids.max", cg);
            snprintf(val, sizeof val, "%d", c.pids);
            if (ps_write_file(path, val) < 0) {
                perror("set pids.max");
                goto abort_child;
            }
        }

        if (c.cpu_pct > 0) {
            snprintf(path, sizeof path, "%s/cpu.max", cg);
            snprintf(val, sizeof val, "%d 100000", c.cpu_pct * 1000);
            if (ps_write_file(path, val) < 0) {
                perror("set cpu.max");
                goto abort_child;
            }
        }

        snprintf(path, sizeof path, "%s/cgroup.procs", cg);
        snprintf(val, sizeof val, "%d", pid);
        if (ps_write_file(path, val) < 0) {
            perror("move child into cgroup");
            goto abort_child;
        }
    }

    if (run_signal)
        goto abort_child;

    /* Release the child only now: every requested limit is in place. */
    if (write(c.sync[1], "g", 1) != 1) {
        perror("release child");
        goto abort_child;
    }
    close(c.sync[1]);
    sync_open = 0;

    for (;;) {
        waited = waitpid(pid, &st, WNOHANG);
        if (waited == pid) { reaped = 1; break; }
        if (waited < 0 && errno != EINTR)
            break;

        if (run_signal) {
            kill(pid, SIGKILL);
            do {
                waited = waitpid(pid, &st, 0);
            } while (waited < 0 && errno == EINTR);
            if (waited == pid) reaped = 1;
            break;
        }

        usleep(10000);
    }

    if (!reaped) {
        perror("waitpid");
        goto abort_child;
    }

    code = WIFEXITED(st) ? WEXITSTATUS(st) :
           (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 1);

    if (cg_created) {
        snprintf(path, sizeof path, "%s/memory.peak", cg);
        rd(path, peak, sizeof peak);
        snprintf(path, sizeof path, "%s/memory.events", cg);
        rd_memory_events(path, events, sizeof events);
    } else {
        snprintf(peak, sizeof peak, "not limited");
        snprintf(events, sizeof events, "not limited");
    }

    if (getenv("PS_VERBOSE"))
        fprintf(stderr, "[povishield] exit=%d mem.peak=%s memory.events=%s\n",
                code, peak, events);

    rc = run_signal ? 128 + run_signal : code;
    goto done;

abort_child:
    /* Setup failed or the wait failed: the child must never run unconfined. */
    if (sync_open) {
        close(c.sync[1]);         /* EOF makes child_main exit before execvp() */
        sync_open = 0;
    }
    if (!reaped) {
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        reaped = 1;
    }
    rc = 1;

done:
    if (sync_open)
        close(c.sync[1]);
    if (cg_created)
        remove_cgroup(cg);
    munmap(stack, STACK_SZ);
    if (term_installed)
        sigaction(SIGTERM, &old_term, NULL);
    if (int_installed)
        sigaction(SIGINT, &old_int, NULL);
    return rc;
}
