import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analysis.common import BIN, load_profile


@unittest.skipUnless(BIN.exists(), "run `make` first")
class CLI(unittest.TestCase):
    def test_learn_then_enforce(self):
        p = Path(tempfile.mkdtemp()) / "ls.json"
        subprocess.run([str(BIN), "learn", "-o", str(p), "--", "ls", "/"], check=True, capture_output=True)
        s = load_profile(p)
        self.assertIn("execve", s)
        self.assertNotIn("mount", s)
        ok = subprocess.run([str(BIN), "enforce", "-p", str(p), "--", "ls", "/"], capture_output=True)
        self.assertEqual(ok.returncode, 0)

    def test_enforce_kills_unlearned_syscall(self):
        p = Path(tempfile.mkdtemp()) / "echo.json"
        subprocess.run([str(BIN), "learn", "-o", str(p), "--", "echo", "hi"], check=True, capture_output=True)
        r = subprocess.run([str(BIN), "enforce", "-p", str(p), "--", "ls", "/"], capture_output=True)
        self.assertNotEqual(r.returncode, 0)   # ls needs syscalls echo never used


if __name__ == "__main__":
    unittest.main()
