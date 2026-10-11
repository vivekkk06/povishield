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
