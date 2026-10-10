#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
/* Bounded (200 children): ESCAPED if the pids limit did not stop us. */
int main(void) {
    pid_t kids[200]; int n = 0;
    for (int i = 0; i < 200; i++) {
        pid_t p = fork();
        if (p == 0) { pause(); _exit(0); }
        if (p < 0) break;
        kids[n++] = p;
    }
    for (int i = 0; i < n; i++) {
        kill(kids[i], SIGKILL);
        while (waitpid(kids[i], 0, 0) < 0) {
            if (errno == EINTR) continue;
            break;
        }
    }

    printf("Created %d child processes\n", n);
    if (n >= 150) {
        puts("FAIL: expected the PID limit to stop child creation");
        return 1;
    }

    puts("PASS: PID limit prevented reaching 150 children");
    return 0;
}
