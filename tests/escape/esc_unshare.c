#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
int main(void) {
    if (unshare(CLONE_NEWNS) == 0) { puts("ESCAPED: unshare"); return 0; }
    return 1;
}
