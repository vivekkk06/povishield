#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "povishield.h"

/* Minimal parser: finds  "syscalls": [ "a", "b", ... ]  in the profile. */
int ps_apply_seccomp(const char *profile, int audit) {
    FILE *f = fopen(profile, "r");
    if (!f) { perror(profile); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc(sz + 1);
    if (!buf || fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); return -1; }
    buf[sz] = 0;
    fclose(f);

    char *p = strstr(buf, "\"syscalls\"");
    if (p) p = strchr(p, '[');
    if (!p) { fprintf(stderr, "povishield: no \"syscalls\" array in %s\n", profile); free(buf); return -1; }

    scmp_filter_ctx ctx = seccomp_init(audit ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS);
    if (!ctx) { free(buf); return -1; }

    int allowed = 0;
    for (p++; *p && *p != ']'; ) {
        if (*p == '"') {
            char *e = strchr(p + 1, '"');
            if (!e) break;
            *e = 0;
            int nr = seccomp_syscall_resolve_name(p + 1);
            if (nr != __NR_SCMP_ERROR) {
                if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) == 0) allowed++;
            } else {
                fprintf(stderr, "povishield: unknown syscall '%s' (skipped)\n", p + 1);
            }
            p = e + 1;
        } else p++;
    }
    free(buf);

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    if (rc < 0) { fprintf(stderr, "povishield: seccomp_load failed: %s\n", strerror(-rc)); return -1; }
    if (getenv("PS_VERBOSE"))
        fprintf(stderr, "[povishield] seccomp active: %d syscalls allowed (%s)\n",
                allowed, audit ? "audit" : "enforce");
    return 0;
}

int cmd_enforce(int argc, char **argv) {
    const char *profile = NULL;
    int audit = 0, i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) profile = argv[++i];
        else if (!strcmp(argv[i], "--audit")) audit = 1;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (!profile || i >= argc) {
        fprintf(stderr, "usage: povishield enforce -p profile.json [--audit] -- CMD...\n");
        return 2;
    }
    if (ps_apply_seccomp(profile, audit) < 0) return 125;
    execvp(argv[i], &argv[i]);
    perror(argv[i]);
    return 127;
}
