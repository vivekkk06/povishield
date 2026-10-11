#!/usr/bin/env bash
# PoViShield: finish_povishield.sh
# Completes the remaining backlog: hardened learner, strict limit validation, root-only runtime and rootfs
# isolation tests, benchmark rewrite (timing validity), docs, README, CI, dashboard verifier, VM helper.
# Run from the project root:  bash finish_povishield.sh      (never pushes; backups go to .backups/)
set -euo pipefail
[ -f Makefile ] && [ -d src ] && [ -d tests ] && [ -d evaluation ] || { echo "run this from ~/povishield"; exit 1; }
TS=$(date +%Y%m%d-%H%M%S)
mkdir -p .backups src/runtime src/tracer tests/rootfs evaluation scripts docs .github/workflows results
bk() { [ -f "$1" ] && cp -p "$1" ".backups/$(echo "$1" | tr '/' '_').$TS" || true; }
say() { printf '\n>> %s\n' "$*"; }

say "1/9 repository hygiene"
for pat in '.backups/' '.venv/' 'node_modules/' 'frontend/dist/' '.pytest_cache/' '__pycache__/' '*.precheck' '*.bak' '*.bak-*'; do
  grep -qxF "$pat" .gitignore 2>/dev/null || echo "$pat" >> .gitignore
done
if [ -d .git ] && git ls-files --error-unmatch polish_povishield.sh >/dev/null 2>&1; then
  git mv polish_povishield.sh scripts/polish_povishield.sh && echo "moved polish_povishield.sh -> scripts/"
fi

say "2/9 writing files (existing ones are backed up first)"
bk "src/runtime/validate.c"
mkdir -p "$(dirname "src/runtime/validate.c")"
cat > "src/runtime/validate.c" <<'PSEOF_SRC_RUNTIME_VALIDATE_C'
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
        else if (!strcmp(argv[i], "--pids")) max = 4194304L;
        else if (!strcmp(argv[i], "--cpu")) max = 10000L;       /* percent of one CPU */
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
PSEOF_SRC_RUNTIME_VALIDATE_C
bk "tests/helpers.py"
mkdir -p "$(dirname "tests/helpers.py")"
cat > "tests/helpers.py" <<'PSEOF_TESTS_HELPERS_PY'
"""Shared helpers for the test suite."""
import os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analysis.common import BIN  # noqa: E402

IS_ROOT = os.geteuid() == 0
_probe = None


def build_probe():
    """Static probe binary (so it runs inside a minimal rootfs). None if it cannot be built."""
    global _probe
    if _probe is None:
        out = Path(tempfile.mkdtemp(prefix="ps-probe-")) / "probe"
        r = subprocess.run(["gcc", "-static", "-O1", "-Wall", str(ROOT / "tests" / "rootfs" / "probe.c"), "-o", str(out)],
                           capture_output=True)
        _probe = out if r.returncode == 0 else False
    return _probe or None


def run(args, timeout=60, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, **kw)


def run_help_text():
    """Text of `povishield run --help` (used to detect optional features such as --keep-caps)."""
    try:
        r = run([BIN, "run", "--help"], timeout=10)
        return r.stdout + r.stderr
    except Exception:
        return ""


def cgroup_v2_usable():
    cg = Path("/sys/fs/cgroup")
    if not (cg / "cgroup.controllers").exists() or not IS_ROOT:
        return False
    d = cg / f"povishield-selftest-{os.getpid()}"
    try:
        d.mkdir()
        d.rmdir()
        return True
    except OSError:
        return False


def mountinfo_lines():
    return open("/proc/self/mountinfo").read().splitlines()


def leftover_cgroups():
    return sorted(p.name for p in Path("/sys/fs/cgroup").glob("povishield-*") if "selftest" not in p.name)
PSEOF_TESTS_HELPERS_PY
bk "tests/rootfs/probe.c"
mkdir -p "$(dirname "tests/rootfs/probe.c")"
cat > "tests/rootfs/probe.c" <<'PSEOF_TESTS_ROOTFS_PROBE_C'
/* Static test probe used by the root-only runtime and rootfs-isolation tests.
 * Every sub-command prints one machine-readable line per result. Harmless by design. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void report_stat(const char *p) {
    struct stat st;
    if (stat(p, &st) == 0) printf("VISIBLE %s\n", p);
    else printf("HIDDEN %s (%s)\n", p, strerror(errno));
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe CMD [ARGS]\n"); return 2; }
    const char *c = argv[1];

    if (!strcmp(c, "stat")) { for (int i = 2; i < argc; i++) report_stat(argv[i]); return 0; }

    if (!strcmp(c, "id")) {
        char h[256] = "";
        gethostname(h, sizeof h);
        printf("pid=%d uid=%d host=%s\n", getpid(), getuid(), h);
        return 0;
    }

    if (!strcmp(c, "ns")) {
        const char *n[] = { "pid", "mnt", "uts", "ipc", "net" };
        for (int i = 0; i < 5; i++) {
            char p[64], t[128];
            snprintf(p, sizeof p, "/proc/self/ns/%s", n[i]);
            ssize_t l = readlink(p, t, sizeof t - 1);
            if (l < 0) { printf("%s=ERR\n", n[i]); continue; }
            t[l] = 0;
            printf("%s=%s\n", n[i], t);
        }
        return 0;
    }

    if (!strcmp(c, "caps")) {
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        if (!f) { puts("CapEff: ERR"); return 1; }
        while (fgets(line, sizeof line, f)) if (!strncmp(line, "CapEff:", 7)) fputs(line, stdout);
        fclose(f);
        return 0;
    }

    if (!strcmp(c, "mount")) {
        if (mount("none", "/tmp", "tmpfs", 0, NULL) == 0) { puts("MOUNT_OK"); umount("/tmp"); }
        else printf("MOUNT_FAIL %s\n", strerror(errno));
        return 0;
    }

    if (!strcmp(c, "cat") && argc > 2) {
        int fd = open(argv[2], O_RDONLY);
        char b[512]; ssize_t n;
        if (fd < 0) { printf("CAT_FAIL %s\n", strerror(errno)); return 1; }
        while ((n = read(fd, b, sizeof b)) > 0) if (write(1, b, (size_t)n) < 0) break;
        close(fd);
        return 0;
    }

    if (!strcmp(c, "netdev")) {                       /* interface names visible in this network namespace */
        FILE *f = fopen("/proc/net/dev", "r");
        char line[512];
        if (!f) { puts("NETDEV_ERR"); return 1; }
        while (fgets(line, sizeof line, f)) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            *colon = 0;
            char *s = line;
            while (*s == ' ') s++;
            printf("IFACE %s\n", s);
        }
        fclose(f);
        return 0;
    }

    if (!strcmp(c, "marker") && argc > 2) {           /* proves the command really ran */
        int fd = creat(argv[2], 0644);
        if (fd < 0) { printf("MARKER_FAIL %s\n", strerror(errno)); return 1; }
        close(fd);
        puts("MARKER");
        return 0;
    }

    if (!strcmp(c, "busy") && argc > 2) {             /* burn CPU for N wall seconds */
        struct timespec t0, t;
        volatile unsigned long x = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        do {
            for (int i = 0; i < 200000; i++) x += (unsigned long)i;
            clock_gettime(CLOCK_MONOTONIC, &t);
        } while ((t.tv_sec - t0.tv_sec) + (t.tv_nsec - t0.tv_nsec) / 1e9 < atof(argv[2]));
        puts("BUSY_DONE");
        return 0;
    }

    if (!strcmp(c, "alloc") && argc > 2) {            /* touch N MiB */
        size_t n = (size_t)atol(argv[2]) << 20;
        char *p = malloc(n);
        if (!p) { puts("ALLOC_FAIL"); return 1; }
        memset(p, 7, n);
        puts("ALLOC_OK");
        return 0;
    }

    if (!strcmp(c, "forks") && argc > 2) {            /* try to create N sleeping children */
        int want = atoi(argv[2]), ok = 0;
        pid_t *k = calloc((size_t)want, sizeof *k);
        for (int i = 0; i < want; i++) {
            pid_t p = fork();
            if (p == 0) { pause(); _exit(0); }
            if (p < 0) break;
            k[ok++] = p;
        }
        for (int i = 0; i < ok; i++) { kill(k[i], SIGKILL); waitpid(k[i], NULL, 0); }
        printf("FORKED %d\n", ok);
        return 0;
    }

    if (!strcmp(c, "chroot_escape") && argc > 2) {    /* classic chroot break-out, then look for a host path */
        mkdir("esc", 0755);
        if (chroot("esc") != 0) { printf("CHROOT_FAIL %s\n", strerror(errno)); return 0; }
        for (int i = 0; i < 64; i++) if (chdir("..") != 0) break;
        if (chroot(".") != 0) { printf("CHROOT2_FAIL %s\n", strerror(errno)); return 0; }
        puts("CHROOT_DONE");
        report_stat(argv[2]);
        return 0;
    }

    fprintf(stderr, "probe: unknown command %s\n", c);
    return 2;
}
PSEOF_TESTS_ROOTFS_PROBE_C
bk "tests/test_learn_robustness.py"
mkdir -p "$(dirname "tests/test_learn_robustness.py")"
cat > "tests/test_learn_robustness.py" <<'PSEOF_TESTS_TEST_LEARN_ROBUSTNESS_PY'
"""The learner must report failures honestly and never leave junk behind."""
import os, signal, subprocess, sys, tempfile, time, unittest, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import BIN, run
from analysis.common import load_profile


@unittest.skipUnless(BIN.exists(), "run `make` first")
class LearnRobustness(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.out = self.d / "p.json"

    def learn(self, *cmd, out=None):
        return run([BIN, "learn", "-o", out or self.out, "--", *cmd])

    def test_missing_command_writes_nothing(self):
        r = self.learn("/nonexistent/definitely-not-here")
        self.assertEqual(r.returncode, 127)
        self.assertFalse(self.out.exists())

    def test_failing_command_status_is_propagated_and_profile_written(self):
        r = self.learn("false")
        self.assertEqual(r.returncode, 1)
        self.assertIn("execve", load_profile(self.out))

    def test_signal_death_is_reported_as_128_plus_signal(self):
        r = self.learn("sh", "-c", "kill -SEGV $$")
        self.assertEqual(r.returncode, 128 + signal.SIGSEGV)
        self.assertTrue(self.out.exists())

    def test_children_are_traced(self):
        r = self.learn("sh", "-c", "ls / >/dev/null; cat /etc/hostname >/dev/null")
        self.assertEqual(r.returncode, 0, r.stderr)
        s = load_profile(self.out)
        self.assertIn("openat", s)
        self.assertTrue({"clone", "clone3", "fork", "vfork"} & s, "no process-creation syscall seen")

    def test_unwritable_output_is_an_error_and_leaves_no_temp_files(self):
        bad = self.d / "no-such-dir" / "p.json"
        r = self.learn("true", out=bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(list(self.d.glob("*.tmp.*")), [])

    def test_no_temp_file_left_after_success(self):
        self.assertEqual(self.learn("true").returncode, 0)
        self.assertEqual(list(self.d.glob("*.tmp.*")), [])

    def test_missing_dashdash_is_usage_error(self):
        self.assertEqual(run([BIN, "learn", "-o", self.out]).returncode, 2)

    def test_sigterm_aborts_learner_and_kills_the_traced_program(self):
        tag = f"31.{uuid.uuid4().int % 100000}"            # unique argument so we can find the sleeper
        p = subprocess.Popen([str(BIN), "learn", "-o", str(self.out), "--", "sleep", tag],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.8)
        p.send_signal(signal.SIGTERM)
        try:
            rc = p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            self.fail("learner did not exit after SIGTERM")
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertFalse(self.out.exists(), "an aborted run must not write a profile")
        p.stderr.close()
        time.sleep(0.5)
        left = subprocess.run(["pgrep", "-f", f"sleep {tag}"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(left, "", "traced program was left running")


if __name__ == "__main__":
    unittest.main()
PSEOF_TESTS_TEST_LEARN_ROBUSTNESS_PY
bk "tests/test_root_runtime.py"
mkdir -p "$(dirname "tests/test_root_runtime.py")"
cat > "tests/test_root_runtime.py" <<'PSEOF_TESTS_TEST_ROOT_RUNTIME_PY'
"""End-to-end runtime tests for `povishield run`. Need root:  sudo make test-root
Each test asserts a property the sandbox CLAIMS. A failure here is a real gap, not a flaky test.
Cgroup tests are skipped (not faked) where cgroup v2 is unavailable."""
import os, resource, signal, subprocess, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import BIN, IS_ROOT, build_probe, cgroup_v2_usable, leftover_cgroups, mountinfo_lines, run, run_help_text
from analysis.common import load_profile

PROBE = None
HELP = ""


def setUpModule():
    global PROBE, HELP
    if not (IS_ROOT and BIN.exists()):
        return
    PROBE = build_probe()
    HELP = run_help_text()


def kv(text):
    return dict(l.split("=", 1) for l in text.splitlines() if "=" in l)


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class Namespaces(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe (need glibc-static)")

    def test_every_namespace_differs_from_the_host(self):
        inside = kv(run([BIN, "run", "--", PROBE, "ns"]).stdout)
        for ns in ("pid", "mnt", "uts", "ipc", "net"):
            self.assertNotEqual(inside.get(ns), os.readlink(f"/proc/self/ns/{ns}"), f"{ns} namespace is shared with host")

    def test_process_is_pid_1_inside(self):
        self.assertIn("pid=1 ", run([BIN, "run", "--", PROBE, "id"]).stdout)

    def test_hostname_is_private_and_host_is_untouched(self):
        before = os.uname().nodename
        out = run([BIN, "run", "--hostname", "ps-test-box", "--", PROBE, "id"]).stdout
        self.assertIn("host=ps-test-box", out)
        self.assertEqual(os.uname().nodename, before)

    def test_only_loopback_is_visible(self):
        ifaces = {l.split()[1] for l in run([BIN, "run", "--", PROBE, "netdev"]).stdout.splitlines() if l.startswith("IFACE")}
        self.assertEqual(ifaces, {"lo"})

    def test_exit_status_is_propagated(self):
        self.assertEqual(run([BIN, "run", "--", "sh", "-c", "exit 7"]).returncode, 7)


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class Privileges(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe")
        if "--keep-caps" not in HELP:
            self.skipTest("this build has no capability-dropping runtime (--keep-caps absent)")

    def test_default_run_has_no_capabilities(self):
        self.assertIn("0000000000000000", run([BIN, "run", "--", PROBE, "caps"]).stdout)

    def test_keep_caps_baseline_really_has_them(self):
        out = run([BIN, "run", "--keep-caps", "--", PROBE, "caps"]).stdout
        self.assertNotIn("0000000000000000", out)       # control: proves the previous test is meaningful

    def test_mount_is_denied_by_default_and_allowed_with_keep_caps(self):
        self.assertIn("MOUNT_FAIL", run([BIN, "run", "--", PROBE, "mount"]).stdout)
        self.assertIn("MOUNT_OK", run([BIN, "run", "--keep-caps", "--", PROBE, "mount"]).stdout)


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class SeccompInsideRuntime(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe")
        self.d = Path(tempfile.mkdtemp())
        self.prof = self.d / "id.json"                  # learned from `id` only: no mount, no fork
        r = run([BIN, "learn", "-o", self.prof, "--", PROBE, "id"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.extra = ["--keep-caps"] if "--keep-caps" in HELP else []

    def test_allowed_behaviour_still_works(self):
        r = run([BIN, "run", "--profile", self.prof, "--", PROBE, "id"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pid=1", r.stdout)

    def test_unlearned_syscall_kills_the_program(self):
        r = run([BIN, "run", *self.extra, "--profile", self.prof, "--", PROBE, "mount"])
        self.assertEqual(r.returncode, 128 + signal.SIGSYS)
        self.assertNotIn("MOUNT_OK", r.stdout)

    def test_audit_mode_logs_instead_of_killing(self):
        r = run([BIN, "run", *self.extra, "--audit", "--profile", self.prof, "--", PROBE, "mount"])
        self.assertNotEqual(r.returncode, 128 + signal.SIGSYS)
        self.assertRegex(r.stdout, "MOUNT_(OK|FAIL)")


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class FailClosed(unittest.TestCase):
    """If a requested protection cannot be applied the command must NOT run."""

    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe")
        self.d = Path(tempfile.mkdtemp())
        self.marker = self.d / "ran"

    def assertNeverRan(self, *opts):
        r = run([BIN, "run", *opts, "--", PROBE, "marker", self.marker])
        self.assertNotEqual(r.returncode, 0, f"succeeded with {opts}")
        self.assertFalse(self.marker.exists(), f"command ran despite {opts}")

    def test_missing_rootfs(self):            self.assertNeverRan("--rootfs", self.d / "nope")
    def test_rootfs_is_a_file(self):
        f = self.d / "afile"
        f.write_text("x")
        self.assertNeverRan("--rootfs", f)
    def test_missing_profile(self):           self.assertNeverRan("--profile", self.d / "nope.json")
    def test_malformed_profile(self):
        p = self.d / "bad.json"
        p.write_text('{"syscalls": []}')
        self.assertNeverRan("--profile", p)
    def test_non_numeric_memory_limit(self):  self.assertNeverRan("--mem", "abc")
    def test_negative_memory_limit(self):     self.assertNeverRan("--mem", "-5")
    def test_non_numeric_pids_limit(self):    self.assertNeverRan("--pids", "many")
    def test_non_numeric_cpu_limit(self):     self.assertNeverRan("--cpu", "fast")


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class CleanupAndSignals(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe")

    def test_host_mount_table_is_unchanged_after_a_run(self):
        extra = ["--keep-caps"] if "--keep-caps" in HELP else []
        before = mountinfo_lines()
        run([BIN, "run", *extra, "--", PROBE, "mount"])
        self.assertEqual(mountinfo_lines(), before)

    def test_sigterm_to_the_runtime_leaves_no_orphan(self):
        tag = str(40 + (os.getpid() % 1000))
        p = subprocess.Popen([str(BIN), "run", "--", PROBE, "busy", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            self.fail("runtime did not exit after SIGTERM")
        time.sleep(0.7)
        left = subprocess.run(["pgrep", "-f", f"probe busy {tag}"], capture_output=True, text=True).stdout.strip()
        if left:
            subprocess.run(["pkill", "-9", "-f", f"probe busy {tag}"])
        self.assertEqual(left, "", "sandboxed program survived its supervisor")


@unittest.skipUnless(IS_ROOT and cgroup_v2_usable(), "needs root and a writable cgroup v2 hierarchy")
class ResourceLimits(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe")

    def test_memory_limit_kills_a_hog(self):
        r = run([BIN, "run", "--mem", "64", "--", PROBE, "alloc", "400"])
        self.assertNotIn("ALLOC_OK", r.stdout)
        self.assertEqual(r.returncode, 128 + signal.SIGKILL)

    def test_memory_limit_allows_normal_use(self):
        self.assertIn("ALLOC_OK", run([BIN, "run", "--mem", "256", "--", PROBE, "alloc", "20"]).stdout)

    def test_pids_limit_caps_forking(self):
        n = int(run([BIN, "run", "--pids", "16", "--", PROBE, "forks", "64"]).stdout.split()[-1])
        self.assertLessEqual(n, 15)
        self.assertGreater(n, 0)

    def test_without_pids_limit_forking_is_not_capped(self):    # control for the test above
        self.assertEqual(int(run([BIN, "run", "--", PROBE, "forks", "64"]).stdout.split()[-1]), 64)

    def _cpu_seconds(self, *opts):
        p = subprocess.Popen([str(BIN), "run", *opts, "--", PROBE, "busy", "3"], stdout=subprocess.DEVNULL)
        _, _, ru = os.wait4(p.pid, 0)
        return ru.ru_utime + ru.ru_stime

    def test_cpu_limit_throttles(self):
        free = self._cpu_seconds()
        capped = self._cpu_seconds("--cpu", "20")
        self.assertGreater(free, 2.0, "control run did not use a full core")
        self.assertLess(capped, 1.3, f"20% cap still used {capped:.2f}s of CPU in 3s")

    def test_cgroup_is_removed_afterwards(self):
        before = leftover_cgroups()
        run([BIN, "run", "--mem", "64", "--pids", "8", "--", PROBE, "id"])
        self.assertEqual(leftover_cgroups(), before)


if __name__ == "__main__":
    unittest.main()
PSEOF_TESTS_TEST_ROOT_RUNTIME_PY
bk "tests/test_root_rootfs.py"
mkdir -p "$(dirname "tests/test_root_rootfs.py")"
cat > "tests/test_root_rootfs.py" <<'PSEOF_TESTS_TEST_ROOT_ROOTFS_PY'
"""Does --rootfs really hide the host? Needs root:  sudo make test-root
The probe is statically linked and is the ONLY executable inside the rootfs."""
import os, shutil, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import BIN, IS_ROOT, build_probe, cgroup_v2_usable, mountinfo_lines, run, run_help_text

PROBE = None
HELP = ""
ROOTFS = None
HOST_SECRET = None


def setUpModule():
    global PROBE, HELP, ROOTFS, HOST_SECRET
    if not (IS_ROOT and BIN.exists()):
        return
    PROBE = build_probe()
    HELP = run_help_text()
    ROOTFS = Path(tempfile.mkdtemp(prefix="ps-rootfs-"))
    for d in ("tmp", "proc", "dev"):
        (ROOTFS / d).mkdir()
    shutil.copy(PROBE, ROOTFS / "probe")
    (ROOTFS / "inside.txt").write_text("INSIDE-MARKER\n")
    fd, name = tempfile.mkstemp(prefix="host-secret-", dir="/tmp")     # lives on the HOST /tmp only
    os.write(fd, b"HOST-SECRET\n")
    os.close(fd)
    HOST_SECRET = name


def tearDownModule():
    if ROOTFS:
        shutil.rmtree(ROOTFS, ignore_errors=True)
    if HOST_SECRET:
        os.unlink(HOST_SECRET)


def in_rootfs(*args, opts=()):
    return run([BIN, "run", "--rootfs", ROOTFS, *opts, "--", "/probe", *args])


@unittest.skipUnless(IS_ROOT, "needs root: sudo make test-root")
class RootfsIsolation(unittest.TestCase):
    def setUp(self):
        if not PROBE:
            self.skipTest("cannot build static probe (need glibc-static)")

    def test_control_the_rootfs_content_is_visible(self):
        r = in_rootfs("cat", "/inside.txt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("INSIDE-MARKER", r.stdout)

    def test_control_the_secret_exists_on_the_host(self):
        self.assertTrue(os.path.exists(HOST_SECRET))

    def test_host_file_at_the_same_path_is_hidden(self):
        self.assertIn("HIDDEN " + HOST_SECRET, in_rootfs("stat", HOST_SECRET).stdout)

    def test_well_known_host_paths_are_hidden(self):
        out = in_rootfs("stat", "/etc/hostname", "/etc/passwd", "/home", "/root", "/usr", "/var/log").stdout
        self.assertEqual(out.count("HIDDEN"), 6, out)

    def test_dotdot_traversal_cannot_leave_the_root(self):
        out = in_rootfs("stat", "/../../../../etc/hostname", "/tmp/../../../etc/passwd", HOST_SECRET.replace("/tmp/", "/../../tmp/")).stdout
        self.assertEqual(out.count("HIDDEN"), 3, out)

    def test_proc_does_not_lead_back_to_the_host(self):
        paths = [f"/proc/1/root{HOST_SECRET}", f"/proc/self/root{HOST_SECRET}", f"/proc/1/cwd/..{HOST_SECRET}"]
        out = in_rootfs("stat", *paths).stdout
        self.assertEqual(out.count("HIDDEN"), 3, out)

    def test_old_root_mountpoint_is_gone(self):
        self.assertIn("HIDDEN /.old_root", in_rootfs("stat", "/.old_root").stdout)

    def test_privileged_chroot_breakout_does_not_reach_the_host(self):
        if "--keep-caps" not in HELP:
            self.skipTest("no --keep-caps in this build; cannot grant CAP_SYS_CHROOT for the attack")
        r = in_rootfs("chroot_escape", HOST_SECRET, opts=["--keep-caps"])
        self.assertIn("CHROOT_DONE", r.stdout, "the break-out attempt did not run, so this proves nothing")
        self.assertIn("HIDDEN " + HOST_SECRET, r.stdout)

    def test_host_mount_table_is_unchanged_afterwards(self):
        before = mountinfo_lines()
        in_rootfs("id")
        self.assertEqual(mountinfo_lines(), before)

    def test_full_stack_rootfs_plus_seccomp_still_hides_the_host(self):
        prof = Path(tempfile.mkdtemp()) / "stat.json"
        r = run([BIN, "learn", "-o", prof, "--", PROBE, "stat", "/"])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = in_rootfs("stat", HOST_SECRET, "/etc/passwd", opts=["--profile", prof] + (["--pids", "32"] if cgroup_v2_usable() else []))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.count("HIDDEN"), 2, out.stdout)


if __name__ == "__main__":
    unittest.main()
PSEOF_TESTS_TEST_ROOT_ROOTFS_PY
bk "evaluation/run_eval.py"
mkdir -p "$(dirname "evaluation/run_eval.py")"
cat > "evaluation/run_eval.py" <<'PSEOF_EVALUATION_RUN_EVAL_PY'
"""make eval: learn -> generate -> held-out enforce -> benchmark, for every target.

Every number written to results/results.json is computed here. Methodology (docs/BENCHMARKING.md):
  * the policy is trained under the SAME stdout conditions as the test (grep skips write() on /dev/null);
  * compatibility compares exit code AND stdout with the native run;
  * a timing run only counts if the sandboxed run exits exactly like the native one (a killed process is
    fast, which would otherwise show up as a bogus negative overhead);
  * native and sandboxed runs are interleaved (alternating order) after warm-up, so thermal / frequency /
    background-load drift hits both equally; raw samples are saved to results/raw/;
  * short workloads are flagged: below ~20 ms the % overhead measures process start-up, not seccomp.
"""
import fcntl, json, os, platform, random, statistics, subprocess, sys, tempfile, time, tomllib
from pathlib import Path
from analysis.common import BIN, ROOT, load_profile, save_profile, total_syscalls
from analysis.merge import merge_profiles
from analysis.risk import risk_pct

RES = ROOT / "results"
DEVNULL = subprocess.DEVNULL
SHORT_MS = 20.0          # native median below this => overhead % is start-up dominated
WARMUP = 3


def learn(cmd, out):
    subprocess.run([str(BIN), "learn", "-o", str(out), "--"] + cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    if not Path(out).exists():
        raise RuntimeError(f"learn produced no profile for {cmd}")
    return load_profile(out)


def run_out(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    return r.returncode, r.stdout


def timed(cmd):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    return (time.perf_counter() - t) * 1000, r.returncode


def p95(xs):
    return statistics.quantiles(xs, n=20)[18] if len(xs) >= 20 else max(xs)


def bootstrap_ci(nat, box, iters=2000):
    """95% CI of (median(box)/median(nat) - 1) * 100, resampling each series."""
    vals = []
    for _ in range(iters):
        a = statistics.median(random.choices(nat, k=len(nat)))
        b = statistics.median(random.choices(box, k=len(box)))
        vals.append((b / a - 1) * 100)
    vals.sort()
    return vals[int(.025 * iters)], vals[int(.975 * iters) - 1]


def cpu_idle_pct(sample_s=1.5):
    def read():
        f = open("/proc/stat").readline().split()[1:]
        v = list(map(int, f))
        return v[3] + v[4], sum(v)
    i0, t0 = read()
    time.sleep(sample_s)
    i1, t1 = read()
    return round(100.0 * (i1 - i0) / max(t1 - t0, 1), 1)


def environment(runs):
    def sh(c):
        try:
            return subprocess.run(c, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            return ""
    model = ""
    try:
        model = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        pass
    gov = ""
    try:
        gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
    except Exception:
        pass
    return {"kernel": platform.release(), "machine": platform.machine(), "cpus": os.cpu_count(),
            "cpu_model": model, "cpu_governor": gov or "n/a", "python": platform.python_version(),
            "libseccomp": sh(["pkg-config", "--modversion", "libseccomp"]) or "n/a",
            "git_commit": sh(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"]) or "n/a",
            "runs_per_measurement": runs, "warmup_runs": WARMUP,
            "loadavg_start": [round(x, 2) for x in os.getloadavg()], "cpu_idle_pct_start": cpu_idle_pct()}


def benchmark(native_cmd, boxed_cmd, runs, expect_rc):
    nat, box, bad = [], [], 0
    for i in range(WARMUP + runs):
        order = (("n", native_cmd), ("b", boxed_cmd)) if i % 2 == 0 else (("b", boxed_cmd), ("n", native_cmd))
        for kind, cmd in order:
            ms, rc = timed(cmd)
            if i < WARMUP:
                continue
            if kind == "b" and rc != expect_rc:
                bad += 1
            (nat if kind == "n" else box).append(ms)
    return nat, box, bad


def main():
    if not BIN.exists():
        sys.exit("build first: make")
    lock = open("/tmp/povishield-eval.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another evaluation is already running (lock /tmp/povishield-eval.lock). Wait for it to finish.")

    cfg = tomllib.loads((ROOT / "evaluation" / "targets.toml").read_text())
    runs = int(os.environ.get("PS_RUNS", cfg["settings"]["runs"]))
    total = total_syscalls()
    (RES / "profiles").mkdir(parents=True, exist_ok=True)
    (RES / "raw").mkdir(parents=True, exist_ok=True)
    env = environment(runs)
    if env["cpu_idle_pct_start"] < 80:
        print(f"WARNING: machine is only {env['cpu_idle_pct_start']}% idle; timings will be noisy. "
              f"Close other programs and re-run for final numbers.", flush=True)
    tmp = Path(tempfile.mkdtemp())
    out = []

    for t in cfg["target"]:
        name = t["name"]
        print(f"[{name}] learning ...", flush=True)
        train = [learn(c, tmp / f"{name}-train{i}.json") for i, c in enumerate(t["train"])]
        policy = merge_profiles(train)
        ppath = RES / "profiles" / f"{name}.json"
        save_profile(ppath, policy, command=name)

        test_sets = [learn(c, tmp / f"{name}-test{i}.json") for i, c in enumerate(t["test"])]
        test_union = merge_profiles(test_sets)
        coverage = 100.0 * len(test_union & policy) / max(len(test_union), 1)

        compat_ok, false_kills = 0, 0
        for c in t["test"]:
            native_rc, native_out = run_out(c)
            rc, got = run_out([str(BIN), "enforce", "-p", str(ppath), "--"] + c)
            compat_ok += (rc == native_rc and got == native_out)
            false_kills += rc in (-31, 159)                      # SIGSYS
        compat = 100.0 * compat_ok / len(t["test"])

        print(f"[{name}] benchmarking ({runs} interleaved runs) ...", flush=True)
        c0 = t["test"][0]
        boxed = [str(BIN), "enforce", "-p", str(ppath), "--"] + c0
        expect_rc, _ = run_out(c0)
        nat, box, bad = benchmark(c0, boxed, runs, expect_rc)
        (RES / "raw" / f"{name}.json").write_text(json.dumps({"native_ms": nat, "sandboxed_ms": box, "command": c0}))
        med_n, med_b = statistics.median(nat), statistics.median(box)
        valid = bad == 0
        lo, hi = bootstrap_ci(nat, box) if valid else (None, None)
        ov = {"valid": valid, "short_workload": med_n < SHORT_MS, "bad_runs": bad,
              "native_ms_median": round(med_n, 2), "sandboxed_ms_median": round(med_b, 2),
              "added_ms": round(med_b - med_n, 2), "p95_ms": round(p95(box), 2)}
        if valid:
            ov.update({"median": round((med_b / med_n - 1) * 100, 2), "ci95": [round(lo, 2), round(hi, 2)]})
        else:
            ov.update({"median": None, "ci95": None,
                       "note": f"{bad}/{runs} sandboxed timing runs did not exit like the native run (killed?); overhead not reported"})
            print(f"[{name}] WARNING: timing invalid -> {ov['note']}", flush=True)

        out.append({
            "target": name, "allowed_syscalls": len(policy), "total_syscalls": total,
            "attack_surface_reduction_pct": round((1 - len(policy) / total) * 100, 2),
            "risk_before": 100.0, "risk_after": round(risk_pct(policy, total), 2),
            "heldout_coverage_pct": round(coverage, 2), "missing_in_policy": sorted(test_union - policy),
            "compat_pct": round(compat, 2), "false_kills": false_kills, "overhead_pct": ov})

    n = len(out)
    avg = lambda k: round(sum(r[k] for r in out) / n, 2)
    long_ok = [r["overhead_pct"] for r in out if r["overhead_pct"]["valid"] and not r["overhead_pct"]["short_workload"]]
    agg = {"targets": n,
           "avg_attack_surface_reduction_pct": avg("attack_surface_reduction_pct"),
           "avg_risk_after": avg("risk_after"),
           "avg_heldout_coverage_pct": avg("heldout_coverage_pct"),
           "avg_compat_pct": avg("compat_pct"),
           "total_false_kills": sum(r["false_kills"] for r in out),
           "overhead_targets": len(long_ok),
           "avg_median_overhead_pct": round(sum(o["median"] for o in long_ok) / len(long_ok), 2) if long_ok else None,
           "max_median_overhead_pct": max((o["median"] for o in long_ok), default=None),
           "invalid_timing_targets": [r["target"] for r in out if not r["overhead_pct"]["valid"]]}
    env["loadavg_end"] = [round(x, 2) for x in os.getloadavg()]
    (RES / "results.json").write_text(json.dumps({"env": env, "aggregate": agg, "targets": out}, indent=2))

    L = ["# PoViShield evaluation report", "", f"Environment: `{json.dumps(env)}`", "",
         "| target | allowed | surface reduction | risk after | held-out coverage | compat | false kills | native ms | added ms | overhead median [95% CI] |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for r in out:
        o = r["overhead_pct"]
        ovs = (f"{o['median']}% [{o['ci95'][0]}, {o['ci95'][1]}]" + (" (start-up dominated)" if o["short_workload"] else "")) if o["valid"] else "INVALID"
        L.append(f"| {r['target']} | {r['allowed_syscalls']}/{r['total_syscalls']} | {r['attack_surface_reduction_pct']}% | {r['risk_after']} | "
                 f"{r['heldout_coverage_pct']}% | {r['compat_pct']}% | {r['false_kills']} | {o['native_ms_median']} | {o['added_ms']} | {ovs} |")
    L += ["", "## Aggregate", "", "```json", json.dumps(agg, indent=2), "```", "",
          "## Limitations", "- ptrace learning misses rare code paths; merge more workloads.",
          f"- Overhead % is only aggregated over valid timings with native median >= {SHORT_MS:.0f} ms.",
          "- Held-out coverage is computed from a separate learn run of the test workload."]
    (RES / "report.md").write_text("\n".join(L))
    print(json.dumps(agg, indent=2))
    print("wrote results/results.json, results/report.md, results/raw/*.json")


if __name__ == "__main__":
    main()
PSEOF_EVALUATION_RUN_EVAL_PY
bk "evaluation/make_docs.py"
mkdir -p "$(dirname "evaluation/make_docs.py")"
cat > "evaluation/make_docs.py" <<'PSEOF_EVALUATION_MAKE_DOCS_PY'
"""Generates docs/RESULTS.md and refreshes the results block in README.md purely from measured data."""
import json, re
from analysis.common import ROOT

r = json.loads((ROOT / "results" / "results.json").read_text())
a, env = r["aggregate"], r["env"]
L = ["# Measured results", "", "_Generated by `make docs`. Do not edit by hand._", "",
     f"Environment: kernel `{env['kernel']}`, {env['machine']}, {env['cpus']} CPUs ({env.get('cpu_model', '')}), "
     f"governor `{env.get('cpu_governor', 'n/a')}`, Python {env['python']}, libseccomp {env.get('libseccomp', 'n/a')}, "
     f"commit `{env.get('git_commit', 'n/a')}`, {env['runs_per_measurement']} interleaved runs per measurement "
     f"({env.get('warmup_runs', 0)} warm-up discarded). CPU idle at start: {env.get('cpu_idle_pct_start', 'n/a')}%.", "",
     "| target | allowed syscalls | surface reduction | risk after | held-out coverage | compat | false kills | native ms | added ms | overhead median [95% CI] |",
     "|---|---|---|---|---|---|---|---|---|---|"]
for t in r["targets"]:
    o = t["overhead_pct"]
    ovs = (f"{o['median']}% [{o['ci95'][0]}, {o['ci95'][1]}]" + (" *start-up dominated*" if o["short_workload"] else "")) if o["valid"] else "**invalid**"
    L.append(f"| {t['target']} | {t['allowed_syscalls']}/{t['total_syscalls']} | {t['attack_surface_reduction_pct']}% | {t['risk_after']} | "
             f"{t['heldout_coverage_pct']}% | {t['compat_pct']}% | {t['false_kills']} | {o['native_ms_median']} | {o['added_ms']} | {ovs} |")
L += ["", "Overhead % for workloads under ~20 ms measures process start-up, not seccomp; the *added ms* column is the honest figure there.",
      "", "## Aggregate", "", "```json", json.dumps(a, indent=2), "```", ""]
esc = None
for p in (ROOT / "results" / "escape-matrix.txt", ROOT / "docs" / "escape-matrix.txt"):
    if p.exists():
        esc = p.read_text().rstrip()
        break
if esc:
    L += ["## Escape matrix", "", "```", esc, "```", "", "See docs/ESCAPE_ANALYSIS.md for what stops each cell and why.", ""]
(ROOT / "docs" / "RESULTS.md").write_text("\n".join(L))
print("wrote docs/RESULTS.md")

readme = ROOT / "README.md"
if readme.exists():
    s = readme.read_text()
    block = ["<!-- RESULTS:BEGIN (generated by make docs) -->",
             f"Measured on `{env['kernel']}`, {env['cpus']} CPUs, commit `{env.get('git_commit', 'n/a')}`:", "",
             "| metric | value |", "|---|---|",
             f"| programs evaluated | {a['targets']} |",
             f"| attack-surface reduction (avg) | {a['avg_attack_surface_reduction_pct']}% |",
             f"| held-out policy coverage (avg) | {a['avg_heldout_coverage_pct']}% |",
             f"| compatibility (avg) | {a['avg_compat_pct']}% |",
             f"| false kills | {a['total_false_kills']} |"]
    if a.get("avg_median_overhead_pct") is not None:
        block.append(f"| seccomp overhead, long workloads (avg / max) | {a['avg_median_overhead_pct']}% / {a['max_median_overhead_pct']}% |")
    block += ["", "Full table, raw data and methodology: `docs/RESULTS.md`, `results/raw/`, `docs/BENCHMARKING.md`.",
              "<!-- RESULTS:END -->"]
    new = re.sub(r"<!-- RESULTS:BEGIN.*?<!-- RESULTS:END -->", "\n".join(block), s, flags=re.S)
    if new != s:
        readme.write_text(new)
        print("refreshed results block in README.md")
PSEOF_EVALUATION_MAKE_DOCS_PY
bk "evaluation/resume_line.py"
mkdir -p "$(dirname "evaluation/resume_line.py")"
cat > "evaluation/resume_line.py" <<'PSEOF_EVALUATION_RESUME_LINE_PY'
"""Generates the resume bullet FROM measured data. Never edit the numbers by hand."""
import json, re
from analysis.common import ROOT

BLOCKED = {"BLOCKED_SIGSYS", "DENIED", "KILLED_BY_LIMIT", "blocked"}


def matrix():
    """Parse the escape matrix text (docs/escape-matrix.txt) -> {config: [statuses]}."""
    for p in (ROOT / "results" / "escape-matrix.txt", ROOT / "docs" / "escape-matrix.txt"):
        if not p.exists():
            continue
        cols, rows = None, []
        for line in p.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] == "test":
                cols = parts[1:]
            elif parts and cols and re.match(r"(esc_|limit_)", parts[0]):
                rows.append(parts[1:1 + len(cols)])
        if cols and rows:
            return {c: [r[i] for r in rows if len(r) > i] for i, c in enumerate(cols)}
    return {}


def main():
    r = json.loads((ROOT / "results" / "results.json").read_text())["aggregate"]
    bits = [f"Across {r['targets']} real programs: avg attack-surface reduction {r['avg_attack_surface_reduction_pct']}%",
            f"held-out policy coverage {r['avg_heldout_coverage_pct']}%",
            f"compatibility {r['avg_compat_pct']}% ({r['total_false_kills']} false kill(s))"]
    if r.get("avg_median_overhead_pct") is not None:
        bits.append(f"seccomp overhead {r['avg_median_overhead_pct']}% avg (max {r['max_median_overhead_pct']}%) on "
                    f"{r['overhead_targets']} long-running workloads")
    m = matrix()
    col = next((c for c in ("full+rootfs", "full") if c in m), None)
    if col:
        s = m[col]
        blocked = sum(x in BLOCKED for x in s)
        base = m.get("bare")
        tail = f"{blocked}/{len(s)} escape and resource-abuse tests contained by the full sandbox"
        if base:
            tail += f" (vs {sum(x == 'ESCAPED' for x in base)}/{len(base)} succeeding unconfined)"
        bits.append(tail)
    else:
        bits.append("escape matrix not found (run: sudo make escape-full)")
    print(", ".join(bits) + ".")
    if r.get("invalid_timing_targets"):
        print("NOTE: overhead excluded for targets with invalid timing:", ", ".join(r["invalid_timing_targets"]))


if __name__ == "__main__":
    main()
PSEOF_EVALUATION_RESUME_LINE_PY
bk "scripts/audit.sh"
mkdir -p "$(dirname "scripts/audit.sh")"
cat > "scripts/audit.sh" <<'PSEOF_SCRIPTS_AUDIT_SH'
#!/usr/bin/env bash
# Read-only audit of the repository. Output goes to results/audit.txt (and the screen).
cd "$(dirname "$0")/.." || exit 1
mkdir -p results
{
echo "===== GIT ====="; git status --short 2>/dev/null; git log -5 --oneline 2>/dev/null
echo; echo "===== SOURCE TREE ====="
find src include api frontend/src tests evaluation docs scripts -maxdepth 3 -type f \
    ! -path '*/node_modules/*' ! -path '*/__pycache__/*' ! -name '*.bak*' ! -name '*.precheck' 2>/dev/null | sort
echo; echo "===== TODO / FIXME ====="
grep -RInE 'TODO|FIXME|XXX|NOT IMPLEMENTED' src include api frontend/src tests evaluation docs scripts \
    --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude='*.bak*' 2>/dev/null || true
echo; echo "===== UNCHECKED RETURN VALUES IN SECURITY-CRITICAL CALLS (src/runtime) ====="
grep -nE '^\s*(mount|umount2|mkdir|chdir|sethostname|chroot|setns|unshare|prctl|capset|syscall)\(' src/runtime/*.c 2>/dev/null || true
echo; echo "===== SIGNAL / WAIT HANDLING ====="
grep -nE 'waitpid|sigaction|signal\(|SIGTERM|SIGINT|PDEATHSIG|kill\(' src/runtime/*.c src/tracer/*.c 2>/dev/null
echo; echo "===== SANDBOX KEY STEPS ====="
grep -nE 'pivot_root|CLONE_NEW|PR_SET_NO_NEW_PRIVS|PR_CAPBSET_DROP|cgroup|ps_apply_seccomp|--keep-caps' src/runtime/sandbox.c 2>/dev/null
echo; echo "===== API ROUTES ====="
grep -RInE '@(app|router)\.(get|post|put|patch|delete)' api --include='*.py' 2>/dev/null || echo "(none found)"
echo; echo "===== FRONTEND DATA SOURCES (fetch/axios/EventSource/WebSocket) ====="
grep -RInE 'fetch\(|axios|EventSource|WebSocket' frontend/src 2>/dev/null | head -40 || true
} 2>&1 | tee results/audit.txt
PSEOF_SCRIPTS_AUDIT_SH
bk "scripts/verify_dashboard.py"
mkdir -p "$(dirname "scripts/verify_dashboard.py")"
cat > "scripts/verify_dashboard.py" <<'PSEOF_SCRIPTS_VERIFY_DASHBOARD_PY'
#!/usr/bin/env python3
"""Does the dashboard API show REAL data? HTTP 200 is not enough.

 1. discovers every parameterless GET route from the API's /openapi.json
 2. reports status, size and whether the payload is empty
 3. generates a real learn + enforce-kill event with the CLI
 4. re-reads every route and reports which ones changed

Usage: python3 scripts/verify_dashboard.py           (API default http://127.0.0.1:8000, override with API=...)"""
import hashlib, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

API = os.environ.get("API", "http://127.0.0.1:8000").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "povishield"


def get(path):
    try:
        with urllib.request.urlopen(API + path, timeout=8) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                   # connection refused, timeout, ...
        return None, str(e).encode()


def routes():
    st, body = get("/openapi.json")
    if st != 200:
        return None
    paths = json.loads(body).get("paths", {})
    return sorted(p for p, ops in paths.items() if "get" in ops and "{" not in p)


def describe(body):
    try:
        j = json.loads(body)
    except Exception:
        return "non-JSON"
    if j in ([], {}, None, ""):
        return "EMPTY"
    if isinstance(j, list):
        return f"list[{len(j)}]"
    if isinstance(j, dict):
        return f"object({len(j)} keys)"
    return type(j).__name__


def snapshot(rs):
    return {r: (lambda sb: (sb[0], hashlib.sha256(sb[1]).hexdigest(), describe(sb[1])))(get(r)) for r in rs}


def main():
    rs = routes()
    if rs is None:
        print(f"API not reachable at {API} (or no /openapi.json).\nStart it:  .venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000")
        return 2
    print(f"{len(rs)} parameterless GET routes on {API}\n")
    before = snapshot(rs)
    for r, (st, _, d) in before.items():
        print(f"  {st}  {r:<40} {d}")

    print("\ngenerating a real learn + enforce-kill event ...")
    d = Path(tempfile.mkdtemp())
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    if BIN.exists():
        subprocess.run([str(BIN), "learn", "-o", str(results / "dashboard-probe.json"), "--", "/bin/echo", "probe"],
                       capture_output=True)
        subprocess.run([str(BIN), "learn", "-o", str(d / "e.json"), "--", "/bin/echo", "x"], capture_output=True)
        k = subprocess.run([str(BIN), "enforce", "-p", str(d / "e.json"), "--", "/bin/ls", "/"], capture_output=True)
        print(f"  enforce exit status {k.returncode} (-31 or 159 = killed by seccomp)")
    time.sleep(3)
    after = snapshot(rs)
    changed = [r for r in rs if before[r][1] != after[r][1]]
    print()
    if changed:
        print("Routes whose data changed after the events (LIVE):")
        for r in changed:
            print(f"  {r}: {before[r][2]} -> {after[r][2]}")
    else:
        print("VERDICT: no route reflected the new events. The dashboard shows saved/static data only,\n"
              "or reads a different directory than the CLI writes to. Do not describe it as live.")
    empty = [r for r in rs if after[r][2] == "EMPTY"]
    if empty:
        print("\nEmpty routes (not populated):", ", ".join(empty))
    return 0


if __name__ == "__main__":
    sys.exit(main())
PSEOF_SCRIPTS_VERIFY_DASHBOARD_PY
bk "scripts/run_in_vm.sh"
mkdir -p "$(dirname "scripts/run_in_vm.sh")"
cat > "scripts/run_in_vm.sh" <<'PSEOF_SCRIPTS_RUN_IN_VM_SH'
#!/usr/bin/env bash
# Run the full validation inside a DISPOSABLE VM over SSH and fetch the results back.
#   scripts/run_in_vm.sh user@192.168.122.50
# Create the VM with GNOME Boxes or virt-manager (Fedora Server or Ubuntu Server 24.04), enable SSH, snapshot it.
set -euo pipefail
TARGET="${1:?usage: run_in_vm.sh user@vm-address}"
cd "$(dirname "$0")/.."
echo ">> syncing repo to $TARGET"
rsync -az --delete --exclude '.git' --exclude '.venv' --exclude 'node_modules' --exclude 'frontend' \
      --exclude 'build' --exclude 'results' ./ "$TARGET:povishield/"
echo ">> running validation on the VM (needs sudo there)"
ssh -t "$TARGET" 'cd povishield && make deps && make && make test && make fuzz \
  && sudo make test-root | tee /tmp/test-root.txt ; \
  sudo bash tests/escape/make_rootfs.sh >/dev/null 2>&1 || true; \
  sudo env PS_ROOTFS=/tmp/ps-escape-rootfs python3 tests/escape/run_escape.py 2>&1 | tee /tmp/escape-matrix.txt'
mkdir -p results/vm
scp "$TARGET:/tmp/test-root.txt" "$TARGET:/tmp/escape-matrix.txt" results/vm/ || true
echo ">> VM results saved in results/vm/ (compare with your host: diff results/vm/escape-matrix.txt docs/escape-matrix.txt)"
PSEOF_SCRIPTS_RUN_IN_VM_SH
bk "docs/BENCHMARKING.md"
mkdir -p "$(dirname "docs/BENCHMARKING.md")"
cat > "docs/BENCHMARKING.md" <<'PSEOF_DOCS_BENCHMARKING_MD'
# Benchmark methodology

`make eval` is the only source of numbers in the README, `docs/RESULTS.md` and the resume line.

## What is measured
| metric | definition |
|---|---|
| attack-surface reduction | `(1 - allowed / total) x 100`; `total` is read from libseccomp for this architecture |
| risk after | weighted syscall risk of the allowed set, normalised so allow-everything = 100 (weights: `analysis/risk.py`) |
| held-out coverage | share of the test workload's syscalls (learned from a separate run) that the policy allows |
| compatibility | share of held-out workloads whose **exit code and stdout** match the native run |
| false kills | held-out runs killed by SIGSYS (exit -31 or 159 inside shell pipelines) |
| overhead | `median(sandboxed) / median(native) - 1`, bootstrap 95% CI; `added ms` is the absolute difference |

## Rules that keep the numbers honest
1. **Same conditions for training and testing.** Training runs with stdout piped, like the test runs. (GNU grep skips
   `write()` when stdout is `/dev/null`; training that way produced false kills.)
2. **A timing only counts if the run behaved.** If a sandboxed run does not exit like the native run, the whole
   overhead for that target is reported as *invalid*. A killed process is fast; counting it would show a bogus negative overhead.
3. **Interleaved A/B runs** with alternating order and 3 discarded warm-up runs, so frequency scaling and background
   load hit both variants equally.
4. **Short workloads are flagged.** Below ~20 ms the percentage measures process start-up, not seccomp. They are
   excluded from the aggregate overhead; use `added ms` for them.
5. **Environment is recorded**: kernel, CPU model, governor, libseccomp, git commit, load average and CPU idle at start.
   A warning is printed if the machine is under 80% idle.
6. **Raw samples are kept** in `results/raw/<target>.json` so anyone can recompute the statistics.
7. **One evaluation at a time**: a lock file prevents concurrent runs from corrupting each other's timings.

## Reproducing
```bash
make && make test
# close browsers / IDEs, then:
make eval          # PS_RUNS=3 make eval for a 30-second smoke test
make docs && make resume-line
```
PSEOF_DOCS_BENCHMARKING_MD
bk "docs/PROFILE_QUALITY.md"
mkdir -p "$(dirname "docs/PROFILE_QUALITY.md")"
cat > "docs/PROFILE_QUALITY.md" <<'PSEOF_DOCS_PROFILE_QUALITY_MD'
# Profile quality

A learned profile contains the syscalls **observed** while the program ran. It is evidence about those executions,
not a guarantee about future ones.

## Training vs. held-out workloads
Every target in `evaluation/targets.toml` has `train` commands (learned) and `test` commands (never learned).
Held-out coverage and compatibility are measured on the test commands only.

## What went wrong and what was fixed
| finding | cause | fix |
|---|---|---|
| `ls` killed on `readlink` | training listed directories without symlinks | added a symlink-rich training run (`ls -l /`) |
| `grep` killed on first sandboxed run | trained with stdout on `/dev/null`, where grep skips `write()` | train with stdout piped, as in the test |
| shell pipelines hid kills | exit status of a pipeline is that of its last command | `bash -c 'set -o pipefail; ...'`, stdout comparison, and SIGSYS-as-159 detection |

## Practical guidance
- Learn from several workloads and merge (`python3 -m analysis.merge out.json a.json b.json`).
- Run in `--audit` mode first; it logs violations instead of killing.
- Re-learn when the program, its libraries or its inputs change meaningfully.
- Compare versions with `python3 -m analysis.diff old.json new.json`; new high-weight syscalls are highlighted.
PSEOF_DOCS_PROFILE_QUALITY_MD
bk "docs/ESCAPE_ANALYSIS.md"
mkdir -p "$(dirname "docs/ESCAPE_ANALYSIS.md")"
cat > "docs/ESCAPE_ANALYSIS.md" <<'PSEOF_DOCS_ESCAPE_ANALYSIS_MD'
# Escape matrix analysis

Run: `sudo make escape-full` (inside a disposable VM for final results, see `docs/VM_TESTING.md`).
The matrix is saved to `docs/escape-matrix.txt` and embedded in `docs/RESULTS.md`.

## Columns (what each configuration adds)
| column | configuration |
|---|---|
| bare | the test program, unconfined |
| seccomp | `povishield enforce` with a profile learned from a harmless program |
| namespaces | `povishield run --keep-caps` (namespaces only, root keeps all capabilities) |
| full | `run` with cgroup limits, seccomp profile and default capability dropping |
| full+rootfs | `full` plus `--rootfs` (static test binary inside a minimal root) |
| rootfs-only | `run --rootfs` with caps dropped but **no** seccomp profile |

## Statuses
`ESCAPED` means the attempted privileged action **succeeded** in that configuration (the program printed its marker).
It is a statement about that one action, not proof of a full host compromise.
`BLOCKED_SIGSYS`: killed by seccomp. `DENIED`: the call failed (for example `EPERM`, or the path does not exist).
`KILLED_BY_LIMIT`: stopped by a cgroup limit. A missing marker is **not** proof of a block; the runner validates each
configuration with a harmless control program, and every kill was cross-checked in the audit log
(`sudo ausearch -m SECCOMP -i`), which names the syscall that triggered it.

## Reading the cells
| test | what it attempts | unconfined | why the strongest column stops it |
|---|---|---|---|
| esc_mount | mount a tmpfs | ESCAPED | seccomp (`mount` never learned); also capabilities dropped |
| esc_chroot | `chroot()` | ESCAPED | seccomp; also capabilities dropped |
| esc_unshare | `unshare(CLONE_NEWNS)` | ESCAPED | seccomp; also capabilities dropped |
| esc_rawsock | `AF_PACKET` raw socket | ESCAPED | seccomp; also capabilities dropped |
| esc_ptrace | `PTRACE_ATTACH` to a non-dumpable sibling (needs `CAP_SYS_PTRACE`) | ESCAPED | seccomp; capabilities dropped (rootfs-only column shows `DENIED` without seccomp) |
| esc_hostfs | open `/proc/1/root/etc/hostname` | ESCAPED | **only a new root helps**: it stays ESCAPED in every column without `--rootfs` |
| limit_mem | touch 300 MB | ESCAPED | cgroup memory limit (KILLED_BY_LIMIT) |
| limit_pids | create 200 children | ESCAPED | seccomp kills `clone`; the pids cap itself shows in the rootfs-only column |

## Important lessons recorded here
- Namespaces without dropped capabilities blocked **nothing** (8/8 ESCAPED). A root process with capabilities is not contained by them.
- Seccomp from a learned profile does not stop filesystem access (`esc_hostfs`) or memory abuse; those need a root change and cgroups.
- Capability dropping and seccomp are independent layers. `rootfs-only` shows the capability layer working alone;
  `seccomp` shows the syscall layer alone. `tests/test_root_runtime.py` proves the capability layer with a control
  (`--keep-caps` flips the same attempt from denied to allowed).
- An early `full+rootfs` run reported SIGSYS for every test, including the resource-limit ones. The audit log showed the
  profile was too narrow and killed the static binaries at start-up (`openat`, `mmap`, `rt_sigprocmask`). The runner
  now builds a merged profile and the audit log confirms each kill is on the intended syscall.

## Not claimed
Kernel vulnerabilities, user namespaces, argument-level syscall filtering, side channels and the information
`/proc/self/mountinfo` may reveal inside the sandbox are out of scope (see `docs/THREAT_MODEL.md`).
PSEOF_DOCS_ESCAPE_ANALYSIS_MD
bk "docs/VM_TESTING.md"
mkdir -p "$(dirname "docs/VM_TESTING.md")"
cat > "docs/VM_TESTING.md" <<'PSEOF_DOCS_VM_TESTING_MD'
# Validating in a disposable VM

The escape and privileged tests mount filesystems, create namespaces and write cgroups. Run them in a VM you can
discard, not on your daily system.

1. Create a VM (GNOME Boxes or virt-manager). Ubuntu Server 24.04 gives useful cross-distro coverage; Fedora Server also works.
2. Enable SSH, create a user with sudo, and take a snapshot.
3. From the repo: `scripts/run_in_vm.sh user@VM-ADDRESS`
4. Results land in `results/vm/` (`test-root.txt`, `escape-matrix.txt`). Compare with the host:
   `diff results/vm/escape-matrix.txt docs/escape-matrix.txt`
5. Revert the snapshot afterwards.

Record the VM's distro, kernel and cgroup version next to any numbers you publish.
PSEOF_DOCS_VM_TESTING_MD
bk ".github/workflows/ci.yml"
mkdir -p "$(dirname ".github/workflows/ci.yml")"
cat > ".github/workflows/ci.yml" <<'PSEOF__GITHUB_WORKFLOWS_CI_YML'
name: ci
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev python3 cppcheck libc6-dev
      - run: make
      - run: make test
      - run: make lint
      - run: make fuzz
  root-tests:
    runs-on: ubuntu-latest
    continue-on-error: true          # hosted runners restrict namespaces/cgroups; informational
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev python3
      - run: make
      - run: sudo make test-root
  eval-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev python3
      - run: make
      - run: PS_RUNS=3 make eval
      - run: make docs && make resume-line
      - uses: actions/upload-artifact@v4
        with: { name: results, path: "results/\ndocs/RESULTS.md" }
  frontend:
    if: ${{ hashFiles('frontend/package.json') != '' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: cd frontend && npm ci && npm run build
PSEOF__GITHUB_WORKFLOWS_CI_YML
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true
echo "wrote 17 files"
bk README.md
cat > README.md <<'PSEOF_README'
# PoViShield

**Intelligent Linux Application Sandboxing and Security Benchmarking Platform**

PoViShield observes which system calls a program really needs (ptrace), turns that into a least-privilege seccomp-bpf
policy, and runs the program inside namespaces, dropped capabilities, cgroup v2 limits and an optional private root
filesystem. A built-in evaluation harness and escape-test suite *measure* how well that works.

> Status: a research/portfolio prototype, **not** a hardened production container runtime.
> Read `docs/THREAT_MODEL.md` before relying on it.

## Results
<!-- RESULTS:BEGIN (generated by make docs) -->
_Run `make eval && make docs` to fill this in._
<!-- RESULTS:END -->

## Quick start (Fedora or Ubuntu/Debian, x86_64)
```bash
make deps && make
make test                       # unit, CLI, fail-closed and fuzz-adjacent tests (no root)
make verify                     # + fuzzing the profile loader (plain and ASan/UBSan)
sudo make test-root             # runtime, privilege and rootfs-isolation tests
make eval && make docs          # benchmarks -> docs/RESULTS.md
sudo make escape-full           # escape matrix -> docs/escape-matrix.txt
make resume-line                # summary line generated from measured data
```

## Using it
```bash
build/povishield learn   -o app.json -- ./app --typical-args        # observe
python3 -m analysis.merge merged.json run1.json run2.json            # combine workloads
build/povishield enforce -p merged.json -- ./app                     # seccomp only (kills on violation)
build/povishield enforce -p merged.json --audit -- ./app             # log instead of kill
sudo build/povishield run --mem 256 --pids 64 --cpu 50 \
     --rootfs ./rootfs --profile merged.json -- /app                 # full sandbox
python3 -m analysis.risk merged.json                                 # attack-surface score
python3 -m analysis.diff old.json new.json                           # what changed between versions
```
Resource limits are validated strictly: an unparsable `--mem`, `--pids` or `--cpu` stops the run instead of
silently meaning "unlimited". A malformed or empty profile aborts with exit status 125 and never runs the command.

## How it works
| layer | mechanism | source |
|---|---|---|
| learn | `ptrace` follows fork/clone/exec, records syscalls, atomic profile write | `src/tracer/learn.c` |
| policy | libseccomp allow-list, default kill, fail-closed loader | `src/policy/seccomp_gen.c` |
| isolation | PID/mount/UTS/IPC/net namespaces, `pivot_root`, capability dropping | `src/runtime/sandbox.c` |
| limits | cgroup v2 `memory.max`, `pids.max`, `cpu.max` | `src/runtime/sandbox.c` |
| analysis | risk score, profile diff and merge | `analysis/` |
| evidence | benchmarks, escape matrix, fuzzing, root tests | `evaluation/`, `tests/` |

## Documentation
`docs/THREAT_MODEL.md` · `docs/ARCHITECTURE.md` · `docs/BENCHMARKING.md` · `docs/PROFILE_QUALITY.md` ·
`docs/ESCAPE_ANALYSIS.md` · `docs/VM_TESTING.md` · `docs/RESULTS.md` (generated)

## Limitations (summary)
A profile covers only observed behaviour. Seccomp does not inspect syscall arguments or restrict filesystem paths.
Namespaces alone do not contain a root process that keeps its capabilities. Learn mode is x86_64 only and must not be
run on hostile code. Kernel bugs are out of scope. Details in `docs/THREAT_MODEL.md`.

## Dashboard (experimental)
`api/` (FastAPI) and `frontend/` (React + Vite) visualise saved profiles and results. Whether a given view reflects
live sandbox activity is checked, not assumed: `python3 scripts/verify_dashboard.py`.
```bash
.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
cd frontend && npm ci && npm run dev -- --host 127.0.0.1 --port 5175
```
PSEOF_README

say "3/9 hardened learner (only replaces src/tracer/learn.c if it is still the version this project generated)"
if grep -q 'PTRACE_O_EXITKILL' src/tracer/learn.c 2>/dev/null && grep -q 'learned %d syscalls' src/tracer/learn.c 2>/dev/null; then
  bk src/tracer/learn.c
  cat > src/tracer/learn.c <<'PSEOF_LEARN'
#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "povishield.h"

#define MAXNR 1024

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { g_stop = sig; }          /* only sets a flag; the main loop reacts */

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fputc('\\', f); fputc(c, f); }
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

#if defined(__x86_64__)

/* Writes the profile to OUT.tmp.PID then renames it, so a failure never leaves a half-written profile. */
static int write_profile(const char *out, char **cmd, const unsigned char *seen) {
    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp.%d", out, (int)getpid()) >= (int)sizeof tmp) {
        fprintf(stderr, "povishield learn: output path too long\n");
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { perror(out); return -1; }

    int count = 0, first = 1;
    for (int n = 0; n < MAXNR; n++) if (seen[n]) count++;

    fprintf(f, "{\n  \"schema\": 1,\n  \"command\": ");
    char joined[1024];
    size_t used = 0;
    joined[0] = 0;
    for (char **c = cmd; *c; c++) {
        size_t l = strlen(*c);
        if (used + l + 2 >= sizeof joined) break;          /* truncate very long command lines */
        memcpy(joined + used, *c, l);
        used += l;
        joined[used++] = ' ';
        joined[used] = 0;
    }
    json_str(f, joined);
    fprintf(f, ",\n  \"arch\": \"x86_64\",\n  \"count\": %d,\n  \"syscalls\": [", count);
    for (int n = 0; n < MAXNR; n++) {
        if (!seen[n]) continue;
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, n);
        if (!name) continue;
        fprintf(f, "%s\n    ", first ? "" : ",");
        json_str(f, name);
        free(name);
        first = 0;
    }
    fprintf(f, "\n  ]\n}\n");

    if (fflush(f) != 0 || ferror(f) || fclose(f) != 0) {
        perror(out);
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, out) != 0) { perror(out); unlink(tmp); return -1; }
    return count;
}

int cmd_learn(int argc, char **argv) {
    const char *out = "profile.json";
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: povishield learn [-o profile.json] -- CMD...\n"); return 2; }
    char **cmd = &argv[i];

    static unsigned char seen[MAXNR];

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                              /* no SA_RESTART: waitpid must return EINTR */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    pid_t root = fork();
    if (root < 0) { perror("fork"); return 1; }
    if (root == 0) {
        signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGHUP, SIG_DFL);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("PTRACE_TRACEME"); _exit(126); }
        execvp(cmd[0], cmd);
        perror(cmd[0]);
        _exit(127);
    }

    int st = 0, fatal = 0;
    pid_t w;
    do { w = waitpid(root, &st, 0); } while (w < 0 && errno == EINTR && !g_stop);
    if (w < 0) { perror("waitpid"); kill(root, SIGKILL); return 1; }
    if (!WIFSTOPPED(st)) {                                  /* exec failed or died before the first stop */
        fprintf(stderr, "povishield learn: command did not start (status 0x%x)\n", st);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    if (ptrace(PTRACE_SETOPTIONS, root, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) < 0) {
        perror("PTRACE_SETOPTIONS");
        kill(root, SIGKILL);
        return 1;
    }
    if (ptrace(PTRACE_SYSCALL, root, 0, 0) < 0) { perror("PTRACE_SYSCALL"); kill(root, SIGKILL); return 1; }

    int root_status = 0;
    for (;;) {
        if (g_stop) { fatal = 2; break; }
        pid_t pid = waitpid(-1, &st, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;                     /* every traced process has exited */
            perror("waitpid");
            fatal = 1;
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (pid == root) root_status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;

        int sig = WSTOPSIG(st), deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {                      /* syscall stop (entry or exit) */
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0) {
                if ((long)r.orig_rax >= 0 && (long)r.orig_rax < MAXNR) seen[r.orig_rax] = 1;
            } else if (errno != ESRCH) {                    /* ESRCH = it just died; anything else = we are blind */
                perror("PTRACE_GETREGS");
                fatal = 1;
                break;
            }
        } else if (sig != SIGTRAP && sig != SIGSTOP) {
            deliver = sig;                                  /* pass real signals through to the program */
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, deliver) < 0 && errno != ESRCH) {
            perror("PTRACE_SYSCALL");
            fatal = 1;
            break;
        }
    }

    if (fatal) {
        /* PTRACE_O_EXITKILL also kills every remaining tracee when we exit; kill the root now too. */
        kill(root, SIGKILL);
        fprintf(stderr, "povishield learn: aborted%s; no profile written\n",
                fatal == 2 ? " by signal" : " after a tracing error");
        return fatal == 2 ? 128 + (int)g_stop : 1;
    }

    /* the initial execve happened before tracing started; the enforcer needs it too */
    int ex = seccomp_syscall_resolve_name("execve");
    if (ex >= 0 && ex < MAXNR) seen[ex] = 1;

    int count = write_profile(out, cmd, seen);
    if (count < 0) return 1;
    fprintf(stderr, "[povishield] learned %d syscalls -> %s\n", count, out);
    return root_status;
}
#else
int cmd_learn(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "povishield learn: only x86_64 is implemented (see docs/ARCHITECTURE.md roadmap)\n");
    return 1;
}
#endif
PSEOF_LEARN
  echo "learn.c replaced (checked ptrace/waitpid errors, signal-safe abort, atomic profile write)"
else
  echo "NOTE: src/tracer/learn.c has been customised; left untouched. Paste it to me and I will patch it."
fi

say "4/9 wire the strict limit validator into main.c"
python3 - <<'PYEOF2'
import pathlib
h = pathlib.Path("include/povishield.h"); s = h.read_text()
if "ps_validate_run_args" not in s:
    i = s.rfind("#endif")
    s = s[:i] + "int ps_validate_run_args(int argc, char **argv);   /* strict --mem/--pids/--cpu parsing */\n\n" + s[i:]
    h.write_text(s); print("header updated")
m = pathlib.Path("src/main.c"); s = m.read_text()
if "ps_validate_run_args" in s:
    print("main.c already wired")
elif "return cmd_run(argc - 1, argv + 1);" in s:
    s = s.replace("return cmd_run(argc - 1, argv + 1);",
                  "{ if (ps_validate_run_args(argc - 1, argv + 1) != 0) return 2; return cmd_run(argc - 1, argv + 1); }", 1)
    m.write_text(s); print("main.c wired")
else:
    print("WARNING: could not find the cmd_run call in src/main.c. Add before it:  if (ps_validate_run_args(argc-1, argv+1)) return 2;")
PYEOF2

say "5/9 targets.toml: symlink-rich training for ls (fixes the readlink false kill)"
python3 - <<'PYEOF3'
import pathlib
p = pathlib.Path("evaluation/targets.toml"); s = p.read_text()
old = 'train = [["ls", "-la", "/usr"], ["ls", "/etc"]]'
if old in s and '["ls", "-l", "/"]' not in s:
    p.write_text(s.replace(old, 'train = [["ls", "-la", "/usr"], ["ls", "/etc"], ["ls", "-l", "/"]]')); print("ls training extended")
else:
    print("ls target unchanged (already extended or customised)")
PYEOF3
sed -i 's/^runs *=.*/runs = 30/' evaluation/targets.toml

say "6/9 threat model: privileges section"
grep -q '^## Privileges and operational requirements' docs/THREAT_MODEL.md 2>/dev/null || cat >> docs/THREAT_MODEL.md <<'PSEOF_TM'

## Privileges and operational requirements
- `learn` and `enforce` need no privileges; `run` needs root (namespaces, mounts, cgroups).
- cgroup limits need a writable cgroup v2 hierarchy. A limit that is requested but cannot be applied must stop the run;
  `tests/test_root_runtime.py` checks the limits really bite (memory kill, process cap, CPU throttle) and that the cgroup is removed.
- `--rootfs` must contain everything the target needs. Static binaries are simplest. `tests/test_root_rootfs.py` checks that
  host paths, `..` traversal, `/proc/*/root` and a privileged chroot break-out do not reach the host.
- Capabilities are dropped by default. `--keep-caps` exists for baselines and tests only; never use it for untrusted programs.
- Run every privileged test in a disposable VM (`docs/VM_TESTING.md`).
PSEOF_TM

say "7/9 Makefile targets"
if ! grep -q '^test-root:' Makefile; then
cat >> Makefile <<'PSEOF_MK'

.PHONY: test-root escape-full web audit dashboard-check final
test-root: all                 ## privileged runtime + rootfs tests (needs sudo)
> sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_root_*.py' -v

escape-full: all               ## escape matrix incl. rootfs columns -> docs/escape-matrix.txt (needs sudo)
> sudo PS_ROOTFS=/tmp/ps-escape-rootfs bash tests/escape/make_rootfs.sh
> sudo env PS_ROOTFS=/tmp/ps-escape-rootfs PYTHONDONTWRITEBYTECODE=1 python3 tests/escape/run_escape.py 2>&1 | tee results/escape-matrix.txt
> cp results/escape-matrix.txt docs/escape-matrix.txt
> sudo chown -R $$USER:$$USER results docs

web:                           ## frontend production build
> cd frontend && npm ci && npm run build

audit:                         ## read-only repository audit -> results/audit.txt
> bash scripts/audit.sh

dashboard-check:               ## does the API show live data?
> python3 scripts/verify_dashboard.py

final: all                     ## everything, in the right order (quiet machine first, then the noisy tests)
> sudo -v
> $(MAKE) test
> $(MAKE) eval
> $(MAKE) verify
> $(MAKE) test-root
> $(MAKE) escape-full
> $(MAKE) docs
> $(MAKE) resume-line
PSEOF_MK
fi
sed -i 's/^docs: eval/docs:/' Makefile

say "8/9 build and non-privileged tests"
make
if make test > /tmp/povishield-test.log 2>&1; then
  tail -4 /tmp/povishield-test.log
else
  tail -12 /tmp/povishield-test.log
  echo "NOTE: some tests failed (see above). That is information, not a setup error."
fi

say "9/9 done"
cat <<'MSG'

Backups: .backups/    Nothing was pushed.
Next, in this order (each is safe to re-run):
  sudo -v && make final 2>&1 | tee /tmp/final.log     # ~15-25 min, leave the machine alone while it runs
  make audit && make dashboard-check                  # dashboard / API verdict
MSG
