#define _GNU_SOURCE
#include <ctype.h>
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

/* Linux PTRACE_GET_SYSCALL_INFO ABI, defined locally to avoid header conflicts. */
#define PS_PTRACE_GET_SYSCALL_INFO 0x420e
#define PS_SYSCALL_INFO_ENTRY 1
#define PS_SYSCALL_INFO_EXIT 2
struct ps_ptrace_syscall_info {
    unsigned char op;
    unsigned char pad[3];
    unsigned int arch;
    unsigned long long instruction_pointer;
    unsigned long long stack_pointer;
    union {
        struct { unsigned long long nr; unsigned long long args[6]; } entry;
        struct { long long rval; unsigned char is_error; } exit;
        struct { unsigned long long nr; unsigned long long args[6]; unsigned int ret_data; } seccomp;
    } data;
};

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) { if (*s == '"' || *s == '\\') fputc('\\', f); fputc(*s, f); }
    fputc('"', f);
}

/* Returns 0 on success, 1 if the next complete record would exceed the cap,
 * and -1 on formatting or file-write failure. max_bytes == 0 means unlimited. */
static int write_event_record(FILE *events, unsigned long long *seq,
        unsigned long long *written, unsigned long long max_bytes, pid_t pid,
        long long nr, const char *name, int has_return, long long rval) {
    char record[512];
    int n;
    unsigned long long next_seq = *seq + 1;
    if (has_return) {
        n = snprintf(record, sizeof(record),
            "{\"seq\":%llu,\"pid\":%ld,\"phase\":\"exit\",\"syscall_nr\":%lld,\"syscall\":\"%s\",\"return_value\":%lld}\n",
            next_seq, (long)pid, nr, name, rval);
    } else {
        n = snprintf(record, sizeof(record),
            "{\"seq\":%llu,\"pid\":%ld,\"phase\":\"entry\",\"syscall_nr\":%lld,\"syscall\":\"%s\"}\n",
            next_seq, (long)pid, nr, name);
    }
    if (n < 0 || (size_t)n >= sizeof(record)) return -1;
    if (max_bytes && ((unsigned long long)n > max_bytes || *written > max_bytes - (unsigned long long)n)) return 1;
    if (fwrite(record, 1, (size_t)n, events) != (size_t)n || fflush(events) != 0) return -1;
    *seq = next_seq;
    *written += (unsigned long long)n;
    return 0;
}

#if defined(__x86_64__)
int cmd_learn(int argc, char **argv) {
    const char *out = "profile.json";
    const char *events_path = NULL;
    unsigned long long max_event_bytes = 0;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--events") && i + 1 < argc) events_path = argv[++i];
        else if (!strcmp(argv[i], "--max-event-bytes") && i + 1 < argc) {
            const char *arg = argv[++i];
            char *end = NULL;

            /* strtoull() silently accepts "-1", "+5" and leading whitespace,
             * so require the first character to be a plain digit. */
            if (!isdigit((unsigned char)*arg)) {
                fprintf(stderr, "invalid --max-event-bytes value\n");
                return 2;
            }

            errno = 0;
            unsigned long long parsed = strtoull(arg, &end, 10);

            if (errno || end == arg || !end || *end || parsed == 0) {
                fprintf(stderr, "invalid --max-event-bytes value\n");
                return 2;
            }

            max_event_bytes = parsed;
        }
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: povishield learn [-o profile.json] [--events events.jsonl] [--max-event-bytes N] -- CMD...\n"); return 2; }
    char **cmd = &argv[i];

    static unsigned char seen[MAXNR];
    FILE *events = NULL;
    unsigned long long event_seq = 0;
    unsigned long long event_bytes = 0;
    int event_limit_hit = 0;
    int event_write_error = 0;
    int trace_error = 0;
    if (events_path) {
        events = fopen(events_path, "w");
        if (!events) { perror(events_path); return 1; }
        setvbuf(events, NULL, _IOLBF, 0);
    }

    pid_t root = fork();
    if (root < 0) {
        perror("fork");
        if (events) fclose(events);
        return 1;
    }
    if (root == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(cmd[0], cmd);
        perror(cmd[0]);
        _exit(127);
    }

    int st = 0;
    pid_t waited;

    do {
        waited = waitpid(root, &st, 0);                 /* SIGTRAP after exec */
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) {
        perror("waitpid initial trace stop");
        kill(root, SIGKILL);
        while (waitpid(root, NULL, 0) < 0 && errno == EINTR) {}
        if (events && fclose(events) != 0)
            perror(events_path);
        return 1;
    }

    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        fprintf(stderr, "command exited before tracing began\n");
        if (events && fclose(events) != 0)
            perror(events_path);
        return 127;
    }

    if (!WIFSTOPPED(st)) {
        fprintf(stderr, "unexpected initial tracing state\n");
        kill(root, SIGKILL);
        while (waitpid(root, NULL, 0) < 0 && errno == EINTR) {}
        if (events && fclose(events) != 0)
            perror(events_path);
        return 1;
    }

    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;

    if (ptrace(PTRACE_SETOPTIONS, root, 0, options) < 0) {
        perror("ptrace PTRACE_SETOPTIONS");
        kill(root, SIGKILL);
        while (waitpid(root, NULL, 0) < 0 && errno == EINTR) {}
        if (events && fclose(events) != 0)
            perror(events_path);
        return 1;
    }

    if (ptrace(PTRACE_SYSCALL, root, 0, 0) < 0) {
        perror("ptrace initial PTRACE_SYSCALL");
        kill(root, SIGKILL);
        while (waitpid(root, NULL, 0) < 0 && errno == EINTR) {}
        if (events && fclose(events) != 0)
            perror(events_path);
        return 1;
    }

    int root_status = 0;
    for (;;) {
        pid_t pid = waitpid(-1, &st, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;                            /* all tracees gone */
            perror("waitpid");
            trace_error = 1;
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (pid == root) root_status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st), deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {                             /* syscall stop (entry or exit) */
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0) {
                if ((long)r.orig_rax >= 0 && (long)r.orig_rax < MAXNR)
                    seen[r.orig_rax] = 1;
            } else if (errno != ESRCH) {                           /* ESRCH: tracee already died */
                perror("ptrace PTRACE_GETREGS");
                trace_error = 1;
                goto trace_done;
            }

            if (events) {
                struct ps_ptrace_syscall_info info;
                long got = ptrace((enum __ptrace_request)PS_PTRACE_GET_SYSCALL_INFO,
                                  pid, sizeof(info), &info);
                if (got < 0 && errno != ESRCH) {
                    perror("ptrace PTRACE_GET_SYSCALL_INFO (kernel >= 5.3 required)");
                    trace_error = 1;
                    goto trace_done;
                }
                if (got >= 0 && info.op == PS_SYSCALL_INFO_ENTRY) {
                    unsigned long long nr = info.data.entry.nr;
                    char *name = nr < MAXNR
                        ? seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr)
                        : NULL;
                    int wr = write_event_record(events, &event_seq, &event_bytes,
                        max_event_bytes, pid, (long long)nr,
                        name ? name : "unknown", 0, 0);
                    free(name);
                    if (wr == 1) { event_limit_hit = 1; goto trace_done; }
                    if (wr < 0) { event_write_error = 1; goto trace_done; }
                } else if (got >= 0 && info.op == PS_SYSCALL_INFO_EXIT) {
                    long long nr = -1;
                    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0)
                        nr = (long long)r.orig_rax;
                    char *name = (nr >= 0 && nr < MAXNR)
                        ? seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr)
                        : NULL;
                    int wr = write_event_record(events, &event_seq, &event_bytes,
                        max_event_bytes, pid, nr,
                        name ? name : "unknown", 1,
                        (long long)info.data.exit.rval);
                    free(name);
                    if (wr == 1) { event_limit_hit = 1; goto trace_done; }
                    if (wr < 0) { event_write_error = 1; goto trace_done; }
                }
            }
        } else if (sig != SIGTRAP && sig != SIGSTOP) {
            deliver = sig;                                         /* pass real signals through */
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, deliver) < 0 && errno != ESRCH) {
            perror("ptrace PTRACE_SYSCALL");
            trace_error = 1;
            goto trace_done;
        }
    }

trace_done:
    /* Exiting with PTRACE_O_EXITKILL set ensures traced tasks do not outlive the tracer. */
    /* the initial execve happened before tracing started; the enforcer needs it too */
    {
        int ex = seccomp_syscall_resolve_name("execve");
        if (ex >= 0 && ex < MAXNR) seen[ex] = 1;
    }

    if (events) {
        if (fclose(events) != 0) { perror(events_path); return 1; }
        fprintf(stderr, "[povishield] syscall events -> %s (%llu records, %llu bytes)\n",
                events_path, event_seq, event_bytes);
    }
    if (event_write_error) {
        fprintf(stderr, "[povishield] event log write failed\n");
        return 74;
    }
    if (trace_error) {
        fprintf(stderr, "[povishield] tracing failed; profile NOT written (incomplete profiles are unsafe)\n");
        return 1;
    }

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
    {
        int werr = ferror(f);
        if (fclose(f) != 0) werr = 1;
        if (werr) {
            fprintf(stderr, "[povishield] failed writing %s\n", out);
            return 1;
        }
    }
    fprintf(stderr, "[povishield] learned %d syscalls -> %s\n", count, out);
    if (event_limit_hit) {
        fprintf(stderr, "[povishield] event byte limit reached (%llu/%llu bytes); stopped tracing\n",
                event_bytes, max_event_bytes);
        return 75;
    }
    return root_status;
}
#else
int cmd_learn(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "povishield learn: only x86_64 is implemented (see docs/ARCHITECTURE.md roadmap)\n");
    return 1;
}
#endif
