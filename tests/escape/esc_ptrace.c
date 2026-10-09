#include <stdio.h>
#include <sys/ptrace.h>
int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) { puts("ESCAPED: ptrace"); return 0; }
    return 1;
}
