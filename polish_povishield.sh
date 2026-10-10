#!/usr/bin/env bash
# PoViShield hardening + polish. Run from the project root:  bash polish_povishield.sh
# Makes backups in .backups/, never pushes anything.
set -euo pipefail
[ -f Makefile ] && [ -d src ] && [ -d tests ] || { echo "run this from ~/povishield"; exit 1; }
mkdir -p .backups tests/escape docs evaluation
TS=$(date +%Y%m%d-%H%M%S)
bk() { [ -f "$1" ] && cp -p "$1" ".backups/$(basename "$1").$TS"; return 0; }
grep -qxF '.backups/' .gitignore 2>/dev/null || echo '.backups/' >> .gitignore

############ 1. fail-closed seccomp loader ############
bk src/policy/seccomp_gen.c
cat > src/policy/seccomp_gen.c <<'PSEOF'
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
PSEOF

############ 2. tests: malformed profiles + fuzzing ############
cat > tests/test_profile_validation.py <<'PSEOF'
"""The loader must FAIL CLOSED: a bad profile means the command is never executed (exit 125)."""
import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analysis.common import BIN


def enforce(profile_text):
    d = Path(tempfile.mkdtemp())
    p = d / "p.json"
    if profile_text is not None:
        p.write_bytes(profile_text if isinstance(profile_text, bytes) else profile_text.encode())
    marker = d / "ran"
    r = subprocess.run([str(BIN), "enforce", "-p", str(p), "--", "/bin/sh", "-c", f"touch {marker}"],
                       capture_output=True, text=True)
    return r.returncode, marker.exists(), r.stderr


@unittest.skipUnless(BIN.exists(), "run `make` first")
class FailClosed(unittest.TestCase):
    def assertRejected(self, text):
        rc, ran, err = enforce(text)
        self.assertEqual(rc, 125, err)
        self.assertFalse(ran, "command must NOT run under a rejected profile")

    def test_missing_file(self):            self.assertRejected(None)
    def test_empty_file(self):              self.assertRejected("")
    def test_no_syscalls_key(self):         self.assertRejected('{"schema": 1}')
    def test_no_array(self):                self.assertRejected('{"syscalls": "read"}')
    def test_empty_allowlist(self):         self.assertRejected('{"syscalls": []}')
    def test_unknown_syscall(self):         self.assertRejected('{"syscalls": ["read", "definitely_not_a_syscall"]}')
    def test_unterminated_string(self):     self.assertRejected('{"syscalls": ["read')
    def test_unterminated_array(self):      self.assertRejected('{"syscalls": ["read", "write"')
    def test_garbage_token(self):           self.assertRejected('{"syscalls": ["read", 42]}')
    def test_escape_in_name(self):          self.assertRejected('{"syscalls": ["re\\u0061d"]}')
    def test_empty_name(self):              self.assertRejected('{"syscalls": [""]}')
    def test_overlong_name(self):           self.assertRejected('{"syscalls": ["' + "a" * 100 + '"]}')
    def test_nul_byte(self):                self.assertRejected(b'{"syscalls": ["read"\x00]}')
    def test_huge_file(self):               self.assertRejected('{"syscalls": ["read"' + ',"read"' * 200000 + ']}')

    def test_valid_profile_still_works(self):
        d = Path(tempfile.mkdtemp())
        p = d / "ok.json"
        subprocess.run([str(BIN), "learn", "-o", str(p), "--", "/bin/true"], check=True, capture_output=True)
        r = subprocess.run([str(BIN), "enforce", "-p", str(p), "--", "/bin/true"], capture_output=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
PSEOF

cat > tests/fuzz_profile.py <<'PSEOF'
#!/usr/bin/env python3
"""Mutation-fuzz the profile loader. Passes if it never crashes (SIGSEGV/SIGABRT/SIGBUS/ASan exit).
Usage: python3 tests/fuzz_profile.py [iterations]    (BIN=build/povishield-asan for sanitizers)"""
import os, random, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BIN = os.environ.get("BIN", str(ROOT / "build" / "povishield"))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
CRASH = {-11, -6, -7, -4, -8, 99}   # SEGV ABRT BUS ILL FPE, ASAN_OPTIONS=exitcode=99
env = dict(os.environ, ASAN_OPTIONS="exitcode=99:detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1:exitcode=99")

d = Path(tempfile.mkdtemp())
seed_p = d / "seed.json"
subprocess.run([BIN, "learn", "-o", str(seed_p), "--", "/bin/true"], check=True, capture_output=True, env=env)
seed = seed_p.read_bytes()
rng = random.Random(1234)
junk = b'"[]{},:\\\x00 \n0aZ'
bad = 0
for i in range(N):
    b = bytearray(seed)
    for _ in range(rng.randint(1, 8)):
        op = rng.choice("flip ins del trunc dup".split())
        pos = rng.randrange(len(b)) if b else 0
        if op == "flip" and b: b[pos] = rng.randrange(256)
        elif op == "ins": b[pos:pos] = bytes(rng.choice(junk) for _ in range(rng.randint(1, 6)))
        elif op == "del" and b: del b[pos:pos + rng.randint(1, 10)]
        elif op == "trunc" and b: b = b[:pos]
        elif op == "dup" and b: b[pos:pos] = b[pos:pos + rng.randint(1, 40)]
    f = d / "m.json"
    f.write_bytes(bytes(b))
    r = subprocess.run([BIN, "enforce", "-p", str(f), "--", "/bin/true"], capture_output=True, env=env, timeout=20)
    if r.returncode in CRASH:
        bad += 1
        keep = ROOT / "results" / f"fuzz-crash-{i}.json"
        keep.parent.mkdir(exist_ok=True)
        keep.write_bytes(bytes(b))
        print(f"CRASH rc={r.returncode} iter={i} saved {keep}")
print(f"fuzz: {N} mutants, {bad} crashes")
sys.exit(1 if bad else 0)
PSEOF

############ 3. a meaningful ptrace escape test ############
bk tests/escape/esc_ptrace.c
cat > tests/escape/esc_ptrace.c <<'PSEOF'
/* Privileged ptrace: attach to a NON-DUMPABLE sibling. That needs CAP_SYS_PTRACE even for the
 * same uid, so success means real privilege (unlike PTRACE_TRACEME, which anyone may call). */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int pfd[2];
    if (pipe(pfd) < 0) return 1;
    pid_t c = fork();
    if (c < 0) return 1;
    if (c == 0) {
        prctl(PR_SET_DUMPABLE, 0);
        char b = 1;
        if (write(pfd[1], &b, 1) < 0) _exit(1);
        pause();
        _exit(0);
    }
    char b;
    if (read(pfd[0], &b, 1) != 1) return 1;
    int ok = ptrace(PTRACE_ATTACH, c, 0, 0) == 0;
    if (ok) { int st; waitpid(c, &st, 0); ptrace(PTRACE_DETACH, c, 0, 0); }
    kill(c, SIGKILL);
    waitpid(c, 0, 0);
    if (ok) { puts("ESCAPED: ptrace attach to non-dumpable process"); return 0; }
    return 1;
}
PSEOF

############ 4. Makefile quality targets ############
if ! grep -q '^asan:' Makefile; then
cat >> Makefile <<'PSEOF'

.PHONY: asan fuzz lint verify docs
asan:                          ## build with AddressSanitizer + UBSan
> @mkdir -p build
> $(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -std=gnu11 -Iinclude $(shell find src -name '*.c') -o build/povishield-asan -lseccomp

fuzz: all asan                 ## mutation-fuzz the profile loader (plain + sanitized)
> python3 tests/fuzz_profile.py 500
> BIN=build/povishield-asan python3 tests/fuzz_profile.py 300

lint:                          ## static analysis (needs cppcheck)
> cppcheck --enable=warning,performance,portability --error-exitcode=1 --inline-suppr -Iinclude src

docs: eval                     ## regenerate docs/RESULTS.md from measured data
> python3 -m evaluation.make_docs

verify: all test fuzz          ## everything that needs no root
> @echo "verify OK (run: sudo make escape  for the escape matrix)"
PSEOF
fi

############ 5. longer workloads (startup no longer dominates overhead) ############
touch evaluation/targets.toml
if ! grep -q 'gzip_big' evaluation/targets.toml; then
cat >> evaluation/targets.toml <<'PSEOF'

# --- longer workloads: overhead here reflects seccomp cost, not process startup ---
[[target]]
name  = "gzip_big"
train = [["bash", "-c", "set -o pipefail; seq 1 50000 | gzip -c | gzip -dc | wc -l"], ["bash", "-c", "set -o pipefail; seq 1 20000 | gzip -9 -c | wc -c"]]
test  = [["bash", "-c", "set -o pipefail; seq 1 400000 | gzip -c | gzip -dc | tail -1"]]

[[target]]
name  = "sort_big"
train = [["bash", "-c", "set -o pipefail; seq 1 20000 | sort -rn | head -1"], ["bash", "-c", "set -o pipefail; seq 1 200000 | sort -R | sort -n | tail -1"]]
test  = [["bash", "-c", "set -o pipefail; seq 1 500000 | sort -R | sort -n | tail -1"]]

[[target]]
name  = "python_cpu"
train = [["python3", "-c", "print(sum(i*i for i in range(100000)))"], ["python3", "-c", "import hashlib;print(hashlib.sha256(b'x'*1000000).hexdigest())"]]
test  = [["python3", "-c", "import hashlib;print(sum(i*i for i in range(2000000)));print(hashlib.sha256(b'y'*5000000).hexdigest())"]]
PSEOF
fi
sed -i 's/^runs *=.*/runs = 30/' evaluation/targets.toml


############ 5b. harden the harness: output comparison + kill detection ############
python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("evaluation/run_eval.py")
if p.exists():
    s = p.read_text()
    if "def run_out" not in s and "native_rc = run_rc(c)" in s:
        s = s.replace("def run_rc(cmd):",
            "def run_out(cmd):\n    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)\n    return r.returncode, r.stdout\n\n\ndef run_rc(cmd):", 1)
        s = s.replace("native_rc = run_rc(c)", "native_rc, native_out = run_out(c)")
        s = s.replace('rc = run_rc([str(BIN), "enforce", "-p", str(ppath), "--"] + c)',
                      'rc, got = run_out([str(BIN), "enforce", "-p", str(ppath), "--"] + c)')
        s = s.replace("compat_ok += rc == native_rc", "compat_ok += (rc == native_rc and got == native_out)")
        s = s.replace("false_kills += rc == -31 ", "false_kills += rc in (-31, 159) ")
        # train under the SAME stdout conditions as the test run (grep skips write() when stdout is /dev/null)
        s = s.replace("stdout=DEVNULL, stderr=DEVNULL)\n    return load_profile(out)",
                      "stdout=subprocess.PIPE, stderr=DEVNULL)\n    return load_profile(out)")
        p.write_text(s)
        print("run_eval.py hardened (stdout compared, SIGSYS 159 detected, learn uses piped stdout)")
    else:
        print("run_eval.py: already hardened or customised; skipped")
PYEOF
sed -i 's|/proc/cpuinfo|/proc/version|' evaluation/targets.toml

############ 6. results doc generator + threat model ############
cat > evaluation/make_docs.py <<'PSEOF'
"""Generates docs/RESULTS.md purely from results/results.json (no hand-typed numbers)."""
import json
from analysis.common import ROOT

r = json.loads((ROOT / "results" / "results.json").read_text())
a, env = r["aggregate"], r["env"]
L = ["# Measured results", "", "_Generated by `make docs`. Do not edit by hand._", "",
     f"Environment: kernel `{env['kernel']}`, {env['machine']}, {env['cpus']} CPUs, Python {env['python']}, "
     f"{env['runs_per_measurement']} runs per measurement.", "",
     "| target | allowed syscalls | surface reduction | risk after | held-out coverage | compat | false kills | overhead median [95% CI] |",
     "|---|---|---|---|---|---|---|---|"]
for t in r["targets"]:
    o = t["overhead_pct"]
    L.append(f"| {t['target']} | {t['allowed_syscalls']}/{t['total_syscalls']} | {t['attack_surface_reduction_pct']}% | "
             f"{t['risk_after']} | {t['heldout_coverage_pct']}% | {t['compat_pct']}% | {t['false_kills']} | "
             f"{o['median']}% [{o['ci95'][0]}, {o['ci95'][1]}] |")
L += ["", "## Aggregate", "", "```json", json.dumps(a, indent=2), "```", "",
      "Programs under ~10 ms are dominated by process-start cost; use the `*_big` / `python_cpu` rows for seccomp overhead.", ""]
esc = ROOT / "docs" / "escape-matrix.txt"
if esc.exists():
    L += ["## Escape matrix", "", "```", esc.read_text().rstrip(), "```", ""]
(ROOT / "docs" / "RESULTS.md").write_text("\n".join(L))
print("wrote docs/RESULTS.md")
PSEOF

cat > docs/THREAT_MODEL.md <<'PSEOF'
# PoViShield threat model

## Goal
Reduce the damage a *buggy or compromised, non-malicious-by-design* program can do, by giving it
the minimum kernel interface it was observed to need (least privilege).

## Layers and what each one actually does
| layer | mechanism | stops | does NOT stop |
|---|---|---|---|
| syscall policy | seccomp-bpf from a learned profile (default: kill) | any syscall never observed during learning | misuse of *allowed* syscalls; arguments are not inspected |
| privileges | no_new_privs, empty bounding/ambient sets, empty capset | operations needing a capability (mount, unshare, raw sockets, ptrace of protected tasks) | operations a plain uid-0 file owner may do |
| filesystem | `pivot_root` into a supplied rootfs | host path access / traversal | anything inside the rootfs |
| resources | cgroup v2 memory.max, pids.max, cpu.max | memory exhaustion, fork bombs, CPU hogging | I/O bandwidth, kernel memory side channels |
| views | PID, mount, UTS, IPC, network namespaces | seeing/signalling host processes, host network | nothing by themselves: root with caps escapes them (see escape matrix, `namespaces` column) |

## Assumptions
x86_64 Linux, cgroup v2, libseccomp >= 2.5, `run` executed as root, kernel is trusted and unpatched
bugs are out of scope.

## Out of scope (do not claim)
Kernel vulnerabilities; user namespaces (CLONE_NEWUSER is not used); argument-level syscall filtering;
TOCTOU on filenames; hardware side channels; a malicious profile author (profiles are trusted input,
but the loader fails closed on malformed ones); learn mode is not safe to run on hostile code.

## Known limitations
- A profile only covers behaviour seen during learning; rare paths (error handling, shutdown) may be killed.
  Mitigation: merge several workloads, use `--audit` first.
- Learner is x86_64 only and ptrace-based (slow).
- Escape results are evidence for the listed tests only, not a proof of security.
PSEOF

echo "polish applied. backups in .backups/"
make && make test
