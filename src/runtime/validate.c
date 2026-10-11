#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "povishield.h"

/* Strict positive integer in [1, max]; rejects "abc", "-5", "12x", "", overflow. */
static int parse_limit(const char *opt, const char *s, long max) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < 1 || v > max) {
        fprintf(stderr, "povishield run: invalid value '%s' for %s (expected an integer 1..%ld)\n", s, opt, max);
        return -1;
    }
    return 0;
}

/*
 * Fail closed on resource limits: a limit that cannot be parsed must stop the run, never silently become
 * "unlimited". argv[0] is "run". Scanning stops at the first "--" (everything after is the sandboxed command).
 */
int ps_validate_run_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) break;
        long max = 0;
        if (!strcmp(argv[i], "--mem")) max = 1L << 20;          /* MiB */
        else if (!strcmp(argv[i], "--pids")) max = 1048576L;
        else if (!strcmp(argv[i], "--cpu")) max = 6400L;        /* percent of one CPU */
        else continue;
        if (i + 1 >= argc || !strcmp(argv[i + 1], "--")) {
            fprintf(stderr, "povishield run: %s needs a value\n", argv[i]);
            return -1;
        }
        if (parse_limit(argv[i], argv[i + 1], max) < 0) return -1;
        i++;
    }
    return 0;
}
