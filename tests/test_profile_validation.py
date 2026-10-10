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
