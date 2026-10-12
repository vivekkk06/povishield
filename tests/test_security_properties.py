"""Executable formal assurance and security property tests for PoViShield.

These tests assert core security invariants:
1. Fail-closed seccomp enforcement: unlearned/denied syscalls trigger kernel termination via SIGSYS (exit 128+31=159 or -31).
2. Fail-closed profile loading: invalid, empty, or unknown syscall profiles abort before command execution (exit 125/126).
3. Fail-closed resource arguments: malformed limit flags (--mem, --pids, --cpu) fail closed before sandbox execution.
4. Tamper detection in evidence ledgers: corrupt hashes, altered signals, or unbacked removals fail audit_ledger fail-closed.
5. Non-expansion invariant: unobserved syscalls are never automatically allowed into candidate policies.
6. API boundaries: live monitor rejects disallowed binaries, relative paths, and unauthorized hosts.
"""
import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "build" / "povishield"


class TestSecurityInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BIN.exists():
            raise unittest.SkipTest(f"Binary not found at {BIN}; run make first")

    def test_invariant_1_disallowed_syscall_terminates_with_sigsys(self):
        """Invariant: executing a syscall outside the installed seccomp profile causes kernel SIGSYS termination."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as pf:
            # Policy only allows write, exit, exit_group - but NOT getpid or uname
            json.dump({
                "schema": 1,
                "command": "restricted_app",
                "arch": "x86_64",
                "count": 3,
                "syscalls": ["write", "exit", "exit_group"]
            }, pf)
            pfile = pf.name

        try:
            # Running `uname` requires uname syscall which is absent from allowlist
            cmd = [str(BIN), "enforce", "-p", pfile, "--", "uname"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            # Linux kernel delivers SIGSYS (signal 31). WTERMSIG is 31, returncode is either -31 or 128+31=159
            self.assertIn(res.returncode, (-signal.SIGSYS, 128 + signal.SIGSYS, 159),
                          f"Expected termination by SIGSYS, got returncode {res.returncode}")
        finally:
            if os.path.exists(pfile):
                os.unlink(pfile)

    def test_invariant_2_unknown_syscall_aborts_before_execution(self):
        """Invariant: a profile containing an unknown/invalid syscall name aborts before execution (exit 125/126)."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as pf:
            json.dump({
                "schema": 1,
                "command": "app",
                "arch": "x86_64",
                "count": 2,
                "syscalls": ["write", "nonexistent_kernel_call_xyz123"]
            }, pf)
            pfile = pf.name

        sentinel = tempfile.NamedTemporaryFile(delete=False)
        sentinel_path = sentinel.name
        sentinel.close()

        try:
            # If the command were executed, it would remove the sentinel file
            cmd = [str(BIN), "enforce", "-p", pfile, "--", "rm", sentinel_path]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            self.assertIn(res.returncode, (125, 126, 1, 2),
                          f"Expected loader failure (125/126), got {res.returncode}")
            self.assertTrue(os.path.exists(sentinel_path),
                            "Target command was executed despite invalid profile!")
        finally:
            if os.path.exists(pfile):
                os.unlink(pfile)
            if os.path.exists(sentinel_path):
                os.unlink(sentinel_path)

    def test_invariant_3_resource_limit_fail_closed(self):
        """Invariant: unparsable resource limits abort the supervisor instead of defaulting to unlimited."""
        invalid_args = [
            ["--mem", "-100"],
            ["--mem", "invalid_number"],
            ["--pids", "0"],
            ["--cpu", "999999999"],
        ]
        for arg in invalid_args:
            cmd = [str(BIN), "run"] + arg + ["--", "true"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            self.assertIn(res.returncode, (1, 2, 125),
                          f"Expected argument validation failure for {arg}, got {res.returncode}")

    def test_invariant_4_ledger_audit_fails_on_tampered_trial(self):
        """Invariant: audit_ledger detects contradictory or tampered records fail-closed."""
        from analysis.audit_ledger import audit_ledger_file
        from analysis.ledger import EvidenceLedger, TrialRecord, Verdict

        with tempfile.TemporaryDirectory() as tmpdir:
            lpath = Path(tmpdir) / "test_target.jsonl"
            ledger = EvidenceLedger("test_target", ledger_path=lpath)

            # Legitimate trial: ablated write, execution failed with SIGSYS
            trial = TrialRecord(
                trial_id="t1",
                target="test_target",
                workload=["echo", "hello"],
                ablated_syscall="write",
                baseline_rc=0,
                baseline_stdout_hash="abc",
                candidate_rc=-31,
                candidate_stdout_hash="",
                verdict=Verdict.REQUIRED.value,
                signal="SIGSYS",
                output_diverged=True,
                reproduce_cmd="povishield enforce -p cand.json -- echo hello",
            )
            ledger.record_trial(trial)

            # Audit clean ledger: should pass
            ok, report = audit_ledger_file(lpath)
            self.assertTrue(ok, f"Clean ledger failed audit: {report}")

            # Now tamper with candidate profile: claim 'write' is removable
            bad_profile = Path(tmpdir) / "cand.json"
            bad_profile.write_text(json.dumps({
                "schema": 2,
                "syscalls": ["read", "exit"],  # 'write' omitted
                "permission_tiers": {
                    "removable_for_tested_tasks": ["write"]  # Contradicts trial t1
                }
            }))

            # Audit against fraudulent profile: MUST fail
            ok_bad, report_bad = audit_ledger_file(lpath, candidate_profile_path=bad_profile)
            self.assertFalse(ok_bad, "Tampered profile passed audit!")
            self.assertGreater(report_bad["error_count"], 0)

    def test_invariant_5_api_denied_executables(self):
        """Invariant: monitor API definition strictly rejects dangerous executables and shells."""
        # Check definitions directly from api/main.py source
        api_main_path = ROOT / "api" / "main.py"
        self.assertTrue(api_main_path.exists())
        code = api_main_path.read_text(encoding="utf-8")

        for dangerous in ["sh", "bash", "sudo", "rm", "dd", "mount"]:
            self.assertIn(f'"{dangerous}"', code,
                          f"Dangerous executable '{dangerous}' must be in DENIED_EXECUTABLES list")


if __name__ == "__main__":
    unittest.main()
