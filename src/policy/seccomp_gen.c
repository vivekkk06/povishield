#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "povishield.h"

#define MAX_PROFILE_BYTES (1u << 20)   /* refuse absurdly large profiles */
#define MAX_NAME 64

static void perr(const char *profile, const char *msg) {
    fprintf(stderr, "povishield: invalid profile %s: %s\n", profile, msg);
}

/* Reads the whole file; NULL on any error (caller must treat that as fatal). */
static char *read_profile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    char *buf = NULL;
    long sz = -1;
    if (fseek(f, 0, SEEK_END) == 0) sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > MAX_PROFILE_BYTES || fseek(f, 0, SEEK_SET) != 0) {
        perr(path, "empty, unreadable or larger than 1 MiB");
        goto fail;
    }
    buf = malloc((size_t)sz + 1);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) { perr(path, "read error"); goto fail; }
    buf[sz] = 0;
    if (memchr(buf, 0, (size_t)sz)) { perr(path, "contains NUL bytes"); goto fail; }
    fclose(f);
    return buf;
fail:
    free(buf);
    fclose(f);
    return NULL;
}

/*
 * Fail-closed loader. Accepts only:  ... "syscalls": [ "name", "name", ... ] ...
 * Any malformed token, unknown syscall name, rule-install failure, empty allow-list,
 * or failure to set no_new_privs / load the filter returns -1 and installs NOTHING.
 * (It is still not a general JSON parser: it only has to read profiles our own learner writes.)
 */
int ps_apply_seccomp(const char *profile, int audit) {
    int rc = -1, allowed = 0;
    char *buf = NULL;
    scmp_filter_ctx ctx = NULL;
    const char *p, *s;
    char name[MAX_NAME];
    size_t n;

    buf = read_profile(profile);
    if (!buf) goto out;

    p = strstr(buf, "\"syscalls\"");
    if (p) p = strchr(p, '[');
    if (!p) { perr(profile, "no \"syscalls\" array"); goto out; }
    p++;

    ctx = seccomp_init(audit ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS);
    if (!ctx) { fprintf(stderr, "povishield: seccomp_init failed\n"); goto out; }

    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']') break;
        if (*p != '"') { perr(profile, *p ? "unexpected character in syscalls array" : "unterminated syscalls array"); goto out; }
        s = ++p;
        while (*p && *p != '"') {
            if (*p == '\\' || (unsigned char)*p < 0x20) { perr(profile, "escape or control character in syscall name"); goto out; }
            p++;
        }
        if (*p != '"') { perr(profile, "unterminated string"); goto out; }
        n = (size_t)(p - s);
        if (n == 0 || n >= MAX_NAME) { perr(profile, "empty or overlong syscall name"); goto out; }
        memcpy(name, s, n);
        name[n] = 0;
        p++;

        int nr = seccomp_syscall_resolve_name(name);
        if (nr == __NR_SCMP_ERROR) { fprintf(stderr, "povishield: unknown syscall '%s' in %s\n", name, profile); goto out; }
        int r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
        if (r < 0) { fprintf(stderr, "povishield: cannot allow '%s': %s\n", name, strerror(-r)); goto out; }
        allowed++;
    }
    if (allowed == 0) { perr(profile, "allow-list is empty (would kill every process)"); goto out; }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("PR_SET_NO_NEW_PRIVS"); goto out; }
    int lr = seccomp_load(ctx);
    if (lr < 0) { fprintf(stderr, "povishield: seccomp_load failed: %s\n", strerror(-lr)); goto out; }

    if (getenv("PS_VERBOSE"))
        fprintf(stderr, "[povishield] seccomp active: %d syscalls allowed (%s)\n", allowed, audit ? "audit" : "enforce");
    rc = 0;
out:
    if (ctx) seccomp_release(ctx);
    free(buf);
    return rc;
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
    if (ps_apply_seccomp(profile, audit) < 0) return 125;      /* fail closed: never run unconfined */
    execvp(argv[i], &argv[i]);
    perror(argv[i]);
    return 127;
}
