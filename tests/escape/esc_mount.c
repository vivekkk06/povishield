#include <stdio.h>
#include <sys/mount.h>
int main(int c, char **v) {
    if (c < 2) return 1;
    if (mount("none", v[1], "tmpfs", 0, NULL) == 0) { umount2(v[1], MNT_DETACH); puts("ESCAPED: mount"); return 0; }
    return 1;
}
