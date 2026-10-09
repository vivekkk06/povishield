#include <stdio.h>
#include <string.h>
#include "povishield.h"

static void usage(void) {
    fprintf(stderr,
"PoViShield %s - Intelligent Linux Application Sandboxing and Security Benchmarking Platform\n\n"
"usage:\n"
"  povishield learn   [-o profile.json] -- CMD...      trace CMD, record syscalls\n"
"  povishield enforce -p profile.json [--audit] -- CMD...   run CMD under seccomp policy\n"
"  povishield run     [--mem MB] [--pids N] [--cpu PCT] [--rootfs DIR]\n"
"                     [--profile FILE] [--audit] [--hostname NAME] -- CMD...   (root)\n"
"  povishield info    total-syscalls\n", PS_VERSION);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    const char *c = argv[1];
    if (!strcmp(c, "learn"))   return cmd_learn(argc - 1, argv + 1);
    if (!strcmp(c, "enforce")) return cmd_enforce(argc - 1, argv + 1);
    if (!strcmp(c, "run"))     return cmd_run(argc - 1, argv + 1);
    if (!strcmp(c, "info"))    return cmd_info(argc - 1, argv + 1);
    usage();
    return 2;
}
