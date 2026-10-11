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
