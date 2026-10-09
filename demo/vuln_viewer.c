/* TOY vulnerable "file viewer" for the demo. Do not deploy.
 * Bug 1: a leftover "diagnostic hook" runs shell commands if the name starts with '!'.
 * Bug 2: path traversal (../) is not filtered. */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s DIR NAME\n", argv[0]); return 2; }
    if (argv[2][0] == '!') return system(argv[2] + 1);
    char path[512];
    snprintf(path, sizeof path, "%s/%s", argv[1], argv[2]);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }
    char buf[256]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}
