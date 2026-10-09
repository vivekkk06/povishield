import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.risk import risk_pct, weight
from analysis.diff import diff
from analysis.merge import merge_profiles


class T(unittest.TestCase):
    def test_weights(self):
        self.assertEqual(weight("ptrace"), 10)
        self.assertEqual(weight("read"), 1)

    def test_risk_monotonic(self):
        small, big = {"read", "write"}, {"read", "write", "mount"}
        self.assertLess(risk_pct(small, 400), risk_pct(big, 400))
        self.assertLessEqual(risk_pct(big, 400), 100)

    def test_diff(self):
        added, removed = diff({"read", "mount"}, {"read", "socket"})
        self.assertEqual(added, ["socket"])
        self.assertEqual(removed, ["mount"])

    def test_merge(self):
        self.assertEqual(merge_profiles([{"a"}, {"b"}, {"a"}]), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
