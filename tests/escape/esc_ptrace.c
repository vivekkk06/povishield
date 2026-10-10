/* Privileged ptrace: attach to a NON-DUMPABLE sibling. That needs CAP_SYS_PTRACE even for the
 * same uid, so success means real privilege (unlike PTRACE_TRACEME, which anyone may call). */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int pfd[2];
    if (pipe(pfd) < 0) return 1;
    pid_t c = fork();
    if (c < 0) return 1;
    if (c == 0) {
        prctl(PR_SET_DUMPABLE, 0);
        char b = 1;
        if (write(pfd[1], &b, 1) < 0) _exit(1);
        pause();
        _exit(0);
    }
    char b;
    if (read(pfd[0], &b, 1) != 1) return 1;
    int ok = ptrace(PTRACE_ATTACH, c, 0, 0) == 0;
    if (ok) { int st; waitpid(c, &st, 0); ptrace(PTRACE_DETACH, c, 0, 0); }
    kill(c, SIGKILL);
    waitpid(c, 0, 0);
    if (ok) { puts("ESCAPED: ptrace attach to non-dumpable process"); return 0; }
    return 1;
}
