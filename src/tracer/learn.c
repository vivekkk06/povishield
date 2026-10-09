#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "povishield.h"

#define MAXNR 1024

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) { if (*s == '"' || *s == '\\') fputc('\\', f); fputc(*s, f); }
    fputc('"', f);
}

#if defined(__x86_64__)
int cmd_learn(int argc, char **argv) {
    const char *out = "profile.json";
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: povishield learn [-o profile.json] -- CMD...\n"); return 2; }
    char **cmd = &argv[i];

    static unsigned char seen[MAXNR];
    pid_t root = fork();
    if (root < 0) { perror("fork"); return 1; }
    if (root == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(cmd[0], cmd);
        perror(cmd[0]);
        _exit(127);
    }

    int st;
    waitpid(root, &st, 0);                     /* SIGTRAP after exec */
    if (WIFEXITED(st)) { fprintf(stderr, "command exited before tracing began\n"); return 127; }
    ptrace(PTRACE_SETOPTIONS, root, 0,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
           PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);
    ptrace(PTRACE_SYSCALL, root, 0, 0);

    int root_status = 0;
    for (;;) {
        pid_t pid = waitpid(-1, &st, __WALL);
        if (pid < 0) { if (errno == EINTR) continue; break; }     /* ECHILD: all done */
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (pid == root) root_status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st), deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {                             /* syscall stop (entry or exit) */
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0 && (long)r.orig_rax >= 0 && (long)r.orig_rax < MAXNR)
                seen[r.orig_rax] = 1;
        } else if (sig != SIGTRAP && sig != SIGSTOP) {
            deliver = sig;                                         /* pass real signals through */
        }
        ptrace(PTRACE_SYSCALL, pid, 0, deliver);
    }

    /* the initial execve happened before tracing started; the enforcer needs it too */
    int ex = seccomp_syscall_resolve_name("execve");
    if (ex >= 0 && ex < MAXNR) seen[ex] = 1;

    FILE *f = fopen(out, "w");
    if (!f) { perror(out); return 1; }
    int count = 0, first = 1;
    for (int n = 0; n < MAXNR; n++) if (seen[n]) count++;
    fprintf(f, "{\n  \"schema\": 1,\n  \"command\": ");
    char joined[1024] = "";
    for (char **c = cmd; *c; c++) { strncat(joined, *c, sizeof joined - strlen(joined) - 2); strncat(joined, " ", sizeof joined - strlen(joined) - 1); }
    json_str(f, joined);
    fprintf(f, ",\n  \"arch\": \"x86_64\",\n  \"count\": %d,\n  \"syscalls\": [", count);
    for (int n = 0; n < MAXNR; n++) {
        if (!seen[n]) continue;
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, n);
        if (!name) continue;
        fprintf(f, "%s\n    ", first ? "" : ",");
        json_str(f, name);
        free(name);
        first = 0;
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    fprintf(stderr, "[povishield] learned %d syscalls -> %s\n", count, out);
    return root_status;
}
#else
int cmd_learn(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "povishield learn: only x86_64 is implemented (see docs/ARCHITECTURE.md roadmap)\n");
    return 1;
}
#endif
