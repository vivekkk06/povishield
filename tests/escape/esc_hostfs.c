#include <fcntl.h>
#include <stdio.h>
int main(void) {
    static const char *paths[] = {
        "/proc/1/root/etc/hostname",
        "/proc/1/root/tmp/ps-host-marker",   /* exists only on the host */
        "/tmp/ps-host-marker",
        0 };
    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) { printf("ESCAPED: host fs via %s\n", paths[i]); return 0; }
    }
    return 1;
}
