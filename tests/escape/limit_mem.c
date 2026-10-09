#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Touches 300 MB: ESCAPED if the memory cap did not stop us. */
int main(void) {
    size_t n = 300UL << 20;
    char *p = malloc(n);
    if (!p) return 1;
    memset(p, 1, n);
    puts("ESCAPED: no memory limit");
    return 0;
}
