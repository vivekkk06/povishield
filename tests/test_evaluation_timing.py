import unittest
from unittest.mock import patch

from evaluation import run_eval


class EvaluationTimingTests(unittest.TestCase):
    def run_benchmark(self, boxed_rc=0, boxed_stdout=b"expected"):
        native = ["native"]
        boxed = ["boxed"]

        def fake_timed(cmd):
            if cmd == native:
                return 1.0, 0, b"expected"
            return 1.0, boxed_rc, boxed_stdout

        with patch.object(run_eval, "WARMUP", 0):
            with patch.object(run_eval, "timed", side_effect=fake_timed):
                return run_eval.benchmark(
                    native, boxed, 3, 0, b"expected"
                )

    def test_matching_exit_code_and_stdout_is_valid(self):
        native, boxed, bad = self.run_benchmark()
        self.assertEqual(len(native), 3)
        self.assertEqual(len(boxed), 3)
        self.assertEqual(bad, 0)

    def test_wrong_stdout_marks_runs_invalid(self):
        native, boxed, bad = self.run_benchmark(boxed_stdout=b"wrong")
        self.assertEqual(len(native), 3)
        self.assertEqual(len(boxed), 3)
        self.assertEqual(bad, 3)

    def test_wrong_exit_code_marks_runs_invalid(self):
        _, _, bad = self.run_benchmark(boxed_rc=1)
        self.assertEqual(bad, 3)


if __name__ == "__main__":
    unittest.main()
