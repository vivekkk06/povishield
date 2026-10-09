#include <stdio.h>
#include <unistd.h>
int main(int c, char **v) {
    if (c < 2) return 1;
    if (chroot(v[1]) == 0) { puts("ESCAPED: chroot"); return 0; }
    return 1;
}
