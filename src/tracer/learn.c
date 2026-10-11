#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "povishield.h"

#define MAXNR 1024
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
        struct {
            unsigned long long nr;
            unsigned long long args[6];
        } entry;
        struct {
            long long rval;
            unsigned char is_error;
        } exit;
        struct {
            unsigned long long nr;
            unsigned long long args[6];
            unsigned int ret_data;
        } seccomp;
    } data;
};

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { g_stop = sig; }          /* only sets a flag; the main loop reacts */

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fputc('\\', f); fputc(c, f); }
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

static int write_event_record(FILE *events,
        unsigned long long *seq, unsigned long long *written,
        unsigned long long max_bytes, pid_t pid, long long nr,
        const char *name, int has_return, long long rval) {
    char record[512];
    unsigned long long next_seq = *seq + 1;
    int n;

    if (has_return) {
        n = snprintf(record, sizeof record,
            "{\"seq\":%llu,\"pid\":%ld,\"phase\":\"exit\",\"syscall_nr\":%lld,\"syscall\":\"%s\",\"return_value\":%lld}\n",
            next_seq, (long)pid, nr, name, rval);
    } else {
        n = snprintf(record, sizeof record,
            "{\"seq\":%llu,\"pid\":%ld,\"phase\":\"entry\",\"syscall_nr\":%lld,\"syscall\":\"%s\"}\n",
            next_seq, (long)pid, nr, name);
    }

    if (n < 0 || (size_t)n >= sizeof record) return -1;
    if (max_bytes &&
        ((unsigned long long)n > max_bytes ||
         *written > max_bytes - (unsigned long long)n))
        return 1;
    if (fwrite(record, 1, (size_t)n, events) != (size_t)n ||
        fflush(events) != 0)
        return -1;

    *seq = next_seq;
    *written += (unsigned long long)n;
    return 0;
}

#if defined(__x86_64__)

/* Writes the profile to OUT.tmp.PID then renames it, so a failure never leaves a half-written profile. */
static int write_profile(const char *out, char **cmd, const unsigned char *seen) {
    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp.%d", out, (int)getpid()) >= (int)sizeof tmp) {
        fprintf(stderr, "povishield learn: output path too long\n");
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { perror(out); return -1; }

    int count = 0, first = 1;
    for (int n = 0; n < MAXNR; n++) if (seen[n]) count++;

    fprintf(f, "{\n  \"schema\": 1,\n  \"command\": ");
    char joined[1024];
    size_t used = 0;
    joined[0] = 0;
    for (char **c = cmd; *c; c++) {
        size_t l = strlen(*c);
        if (used + l + 2 >= sizeof joined) break;          /* truncate very long command lines */
        memcpy(joined + used, *c, l);
        used += l;
        joined[used++] = ' ';
        joined[used] = 0;
    }
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

    if (fflush(f) != 0 || ferror(f) || fclose(f) != 0) {
        perror(out);
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, out) != 0) { perror(out); unlink(tmp); return -1; }
    return count;
}

int cmd_learn(int argc, char **argv) {
    const char *out = "profile.json";
    const char *events_path = NULL;
    unsigned long long max_event_bytes = 0;
    int i = 1;

    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            out = argv[++i];
        } else if (!strcmp(argv[i], "--events") && i + 1 < argc) {
            events_path = argv[++i];
        } else if (!strcmp(argv[i], "--max-event-bytes") && i + 1 < argc) {
            const char *arg = argv[++i];
            char *end = NULL;

            if (!arg[0]) {
                fprintf(stderr, "invalid --max-event-bytes value\\n");
                return 2;
            }
            for (const unsigned char *q = (const unsigned char *)arg; *q; q++) {
                if (!isdigit(*q)) {
                    fprintf(stderr, "invalid --max-event-bytes value\\n");
                    return 2;
                }
            }

            errno = 0;
            unsigned long long parsed = strtoull(arg, &end, 10);
            if (errno == ERANGE || end == arg || !end || *end || parsed == 0) {
                fprintf(stderr, "invalid --max-event-bytes value\\n");
                return 2;
            }
            max_event_bytes = parsed;
        } else if (!strcmp(argv[i], "--")) {
            i++;
            break;
        } else {
            break;
        }
    }

    if (i >= argc) {
        fprintf(stderr, "usage: povishield learn [-o profile.json] [--events events.jsonl] [--max-event-bytes N] -- CMD...\\n");
        return 2;
    }

    char **cmd = &argv[i];
    static unsigned char seen[MAXNR];
    FILE *events = NULL;
    unsigned long long event_seq = 0, event_bytes = 0;
    int event_limit_hit = 0, event_write_error = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                              /* no SA_RESTART: waitpid must return EINTR */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    pid_t root = fork();
    if (root < 0) { perror("fork"); return 1; }
    if (root == 0) {
        signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGHUP, SIG_DFL);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("PTRACE_TRACEME"); _exit(126); }
        execvp(cmd[0], cmd);
        perror(cmd[0]);
        _exit(127);
    }

    int st = 0, fatal = 0;
    pid_t w;
    do { w = waitpid(root, &st, 0); } while (w < 0 && errno == EINTR && !g_stop);
    if (w < 0) { perror("waitpid"); kill(root, SIGKILL); return 1; }
    if (!WIFSTOPPED(st)) {                                  /* exec failed or died before the first stop */
        fprintf(stderr, "povishield learn: command did not start (status 0x%x)\n", st);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    if (ptrace(PTRACE_SETOPTIONS, root, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) < 0) {
        perror("PTRACE_SETOPTIONS");
        kill(root, SIGKILL);
        return 1;
    }
    if (events_path) {
        events = fopen(events_path, "w");
        if (!events) {
            perror(events_path);
            kill(root, SIGKILL);
            return 1;
        }
    }

    if (ptrace(PTRACE_SYSCALL, root, 0, 0) < 0) {
        perror("PTRACE_SYSCALL");
        if (events) fclose(events);
        kill(root, SIGKILL);
        return 1;
    }

    int root_status = 0;
    for (;;) {
        if (g_stop) { fatal = 2; break; }
        pid_t pid = waitpid(-1, &st, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;                     /* every traced process has exited */
            perror("waitpid");
            fatal = 1;
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (pid == root) root_status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;

        int sig = WSTOPSIG(st), deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            int have_regs = ptrace(PTRACE_GETREGS, pid, 0, &r) == 0;

            if (have_regs) {
                if ((long)r.orig_rax >= 0 && (long)r.orig_rax < MAXNR)
                    seen[r.orig_rax] = 1;
            } else if (errno != ESRCH) {
                perror("PTRACE_GETREGS");
                fatal = 1;
                break;
            }

            if (events) {
                struct ps_ptrace_syscall_info info;
                long got = ptrace((enum __ptrace_request)PS_PTRACE_GET_SYSCALL_INFO,
                                  pid, sizeof info, &info);
                if (got < 0) {
                    if (errno == ESRCH) continue;
                    perror("PTRACE_GET_SYSCALL_INFO");
                    fatal = 1;
                    break;
                }

                if (info.op == PS_SYSCALL_INFO_ENTRY) {
                    unsigned long long nr = info.data.entry.nr;
                    char *name = nr < MAXNR
                        ? seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr)
                        : NULL;
                    int wr = write_event_record(events, &event_seq, &event_bytes,
                        max_event_bytes, pid, (long long)nr,
                        name ? name : "unknown", 0, 0);
                    free(name);
                    if (wr == 1) { event_limit_hit = 1; break; }
                    if (wr < 0) { event_write_error = 1; break; }
                } else if (info.op == PS_SYSCALL_INFO_EXIT) {
                    long long nr = have_regs ? (long long)r.orig_rax : -1;
                    char *name = (nr >= 0 && nr < MAXNR)
                        ? seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)nr)
                        : NULL;
                    int wr = write_event_record(events, &event_seq, &event_bytes,
                        max_event_bytes, pid, nr, name ? name : "unknown",
                        1, (long long)info.data.exit.rval);
                    free(name);
                    if (wr == 1) { event_limit_hit = 1; break; }
                    if (wr < 0) { event_write_error = 1; break; }
                }
            }
        } else if (sig != SIGTRAP && sig != SIGSTOP) {
            deliver = sig;                                  /* pass real signals through to the program */
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, deliver) < 0 && errno != ESRCH) {
            perror("PTRACE_SYSCALL");
            fatal = 1;
            break;
        }
        if (event_limit_hit || event_write_error) break;
    }

    if (event_limit_hit) kill(root, SIGKILL);

    if (events) {
        if (fclose(events) != 0) {
            perror(events_path);
            event_write_error = 1;
        }
        events = NULL;
        fprintf(stderr, "[povishield] syscall events -> %s (%llu records, %llu bytes)\\n",
                events_path, event_seq, event_bytes);
    }

    if (event_write_error) {
        kill(root, SIGKILL);
        fprintf(stderr, "povishield learn: event log write failed\\n");
        return 74;
    }

    if (fatal) {
        /* PTRACE_O_EXITKILL also kills every remaining tracee when we exit; kill the root now too. */
        kill(root, SIGKILL);
        fprintf(stderr, "povishield learn: aborted%s; no profile written\n",
                fatal == 2 ? " by signal" : " after a tracing error");
        return fatal == 2 ? 128 + (int)g_stop : 1;
    }

    /* the initial execve happened before tracing started; the enforcer needs it too */
    int ex = seccomp_syscall_resolve_name("execve");
    if (ex >= 0 && ex < MAXNR) seen[ex] = 1;

    int count = write_profile(out, cmd, seen);
    if (count < 0) return 1;
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
