"""End-to-end runtime tests for `povishield run`. Need root:  sudo make test-root
Each test asserts a property the sandbox CLAIMS. A failure here is a real gap, not a flaky test.
Cgroup tests are skipped (not faked) where cgroup v2 is unavailable."""
import os, resource, shutil, signal, subprocess, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import BIN, IS_ROOT, build_probe, cgroup_v2_usable, leftover_cgroups, mountinfo_lines, run, run_help_text
from analysis.common import load_profile

# ---- process-tree helpers (host view; /proc is read directly) -------------------------------------------
def _read_stat(pid):
    """(state, ppid, starttime) of a host pid, or None if it does not exist."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    rest = raw[raw.rindex(")") + 2:].split()          # comm may contain spaces/parentheses: split after the last ')'
    return rest[0], int(rest[1]), int(rest[19])


def _nspids(pid):
    """Pid as seen from each PID namespace, outermost (host) first. [] if unreadable."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("NSpid:"):
                return [int(x) for x in line.split()[1:]]
    except OSError:
        pass
    return []


def _descendants(root):
    children = {}
    for d in os.listdir("/proc"):
        if d.isdigit():
            st = _read_stat(int(d))
            if st:
                children.setdefault(st[1], []).append(int(d))
    found, todo = [], [root]
    while todo:
        for c in children.get(todo.pop(), []):
            found.append(c)
            todo.append(c)
    return found


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
        """SIGTERM to the supervisor must not leave the sandboxed child running.

        `probe tree FILE` forks one sleeping child and writes its pid to FILE. That pid is the number
        INSIDE the sandbox's PID namespace, so it is mapped to the real host pid through NSpid before
        we look at it. A zombie counts as terminated (it only waits to be reaped)."""
        tmp = Path(tempfile.mkdtemp(prefix="ps-tree-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pidfile = tmp / "child.pid"
        tracked = {}                                    # host pid -> starttime of everything we may need to kill

        sup = subprocess.Popen([str(BIN), "run", "--", PROBE, "tree", str(pidfile)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

        def cleanup():                                  # runs on EVERY path: pass, fail or error
            if sup.poll() is None:
                sup.kill()
            try:
                sup.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if sup.stderr:
                sup.stderr.close()
            for pid, start in tracked.items():
                st = _read_stat(pid)
                if st and st[2] == start and st[0] not in ("Z", "X"):   # same process, still alive
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        self.addCleanup(cleanup)

        # 2-3. wait (with a timeout) for the child pid to appear
        ns_child, deadline = None, time.monotonic() + 10
        while time.monotonic() < deadline:
            if sup.poll() is not None:
                self.fail(f"runtime exited before the probe started (rc={sup.returncode}): {sup.stderr.read()}")
            try:
                ns_child = int(pidfile.read_text().strip())
                break
            except (OSError, ValueError):               # not written yet, or caught mid-write
                time.sleep(0.05)
        if ns_child is None:
            self.fail("the probe never wrote the child pid file within 10 s")

        # map the namespace-local pid to the real host pid (only look below OUR supervisor)
        host_child, deadline = None, time.monotonic() + 5
        while host_child is None and time.monotonic() < deadline:
            for pid in _descendants(sup.pid):
                chain = _nspids(pid)
                if chain and chain[-1] == ns_child:
                    host_child = pid
                    break
            else:
                time.sleep(0.05)
        if host_child is None:
            self.fail(f"could not map sandbox pid {ns_child} to a host pid below supervisor {sup.pid}")
        for pid in _descendants(sup.pid):
            st = _read_stat(pid)
            if st:
                tracked[pid] = st[2]
        self.assertIn(host_child, tracked)

        def alive():
            st = _read_stat(host_child)
            return bool(st and st[2] == tracked[host_child] and st[0] not in ("Z", "X"))

        self.assertTrue(alive(), "precondition failed: the child was not running before SIGTERM")

        # 4-5. SIGTERM the supervisor and wait for it to exit
        sup.send_signal(signal.SIGTERM)
        try:
            sup.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("runtime did not exit within 10 s of SIGTERM")

        # 6. the exact child must be gone (short grace period: the kernel tears the namespace down asynchronously)
        deadline = time.monotonic() + 3
        while alive() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(alive(), f"orphan: host pid {host_child} (pid {ns_child} inside the sandbox) "
                                  f"survived its supervisor")


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
        p = subprocess.Popen(
            [str(BIN), "run", *opts, "--", PROBE, "busy", "3"],
            stdout=subprocess.DEVNULL,
        )
        _, status, ru = os.wait4(p.pid, 0)
        # wait4() reaps the child directly, so synchronize Popen's state.
        p.returncode = os.waitstatus_to_exitcode(status)
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
