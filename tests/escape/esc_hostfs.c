#include <fcntl.h>
#include <stdio.h>
int main(void) {
    int fd = open("/proc/1/root/etc/hostname", O_RDONLY);   /* host fs reachable? */
    if (fd >= 0) { puts("ESCAPED: host fs via /proc/1/root"); return 0; }
    return 1;
}
