"""Tests for PoViShield CLI Runner, Policy Evaluation, and Execution Supervisor.

Asserts:
  1. Command argument validation & safety (no shell injection, valid binaries).
  2. Pre-execution policy evaluation (attack surface reduction %, risk calculations).
  3. Fail-closed safety gate: unapproved commands fail closed in approval-required mode.
  4. Permitted sandboxed execution: legitimate commands run cleanly (exit 0).
  5. Kernel seccomp enforcement: unauthorized system calls trigger SIGSYS termination (exit 159 / -31).
  6. Auditable session persistence in results/sessions/ and timeline recording.
  7. Top-level CLI executable wrapper functionality (./povishield).
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
WRAPPER = ROOT / "povishield"

from analysis.runner import (
    evaluate_execution,
    execute_session,
    list_sessions,
    get_session,
    validate_command,
    find_profile_for_target,
    PolicyDecision,
    ExecutionSession,
)


class TestCliRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BIN.exists():
            raise unittest.SkipTest(f"Binary not found at {BIN}; run make first")

    def test_command_validation_safe(self):
        """Resolves valid system binaries to absolute paths without shell execution."""
        resolved, full_cmd = validate_command(["echo", "hello"])
        self.assertTrue(os.path.isabs(resolved))
        self.assertEqual(full_cmd[1], "hello")

    def test_command_validation_rejects_empty(self):
        """Rejects empty command lists or invalid argument types."""
        with self.assertRaises(ValueError):
            validate_command([])
        with self.assertRaises(ValueError):
            validate_command([""])

    def test_command_validation_rejects_nonexistent_binary(self):
        """Rejects non-existent executables fail-closed."""
        with self.assertRaises(FileNotFoundError):
            validate_command(["/usr/bin/this_binary_does_not_exist_xyz_123"])

    def test_pre_execution_policy_evaluation(self):
        """Pre-evaluates policy findings, risk scores, and attack surface reduction."""
        decision = evaluate_execution(["/usr/bin/echo", "hello"], mode="enforce")
        self.assertIsInstance(decision, PolicyDecision)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.action, "PERMIT_WITH_RESTRICTIONS")
        self.assertGreater(decision.allowed_syscalls_count, 0)
        self.assertGreater(decision.attack_surface_reduction_pct, 80.0)
        self.assertLess(decision.risk_after, decision.risk_before)
        self.assertIn("ptrace", decision.withheld_critical_syscalls)
        self.assertIn("mount", decision.withheld_critical_syscalls)

    def test_approval_required_mode_fails_closed_when_unapproved(self):
        """Unapproved commands in approval-required mode fail closed with DENIED / APPROVAL_REQUIRED."""
        # Use an unapproved command
        decision = evaluate_execution(["/usr/bin/cat", "/dev/null"], mode="approval-required")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.action, "APPROVAL_REQUIRED")
        self.assertFalse(decision.approval_verified)
        self.assertIn("requires explicit security approval", decision.rationale)

    def test_approval_required_mode_permits_approved_grep(self):
        """Approved commands in approval-required mode proceed with verified approval."""
        decision = evaluate_execution(["/usr/bin/grep", "root", "/etc/passwd"], mode="approval-required")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.action, "PERMIT_WITH_RESTRICTIONS")
        self.assertTrue(decision.approval_verified)

    def test_execute_permitted_process_exits_zero(self):
        """Permitted execution completes successfully with stdout captured and exit code 0."""
        session = execute_session(
            command=["/usr/bin/echo", "Testing PoViShield Execution"],
            mode="enforce",
            timeout_seconds=5.0,
            record_events=False,
        )
        self.assertEqual(session.status, "completed")
        self.assertEqual(session.exit_code, 0)
        self.assertIn("Testing PoViShield Execution", session.stdout)
        self.assertFalse(session.violation_detected)
        self.assertGreater(len(session.timeline), 2)

        # Verify session is persisted to disk
        disk_sess = get_session(session.id)
        self.assertIsNotNone(disk_sess)
        self.assertEqual(disk_sess["id"], session.id)

    def test_execute_unauthorized_syscall_triggers_kernel_sigsys(self):
        """Disallowed syscall execution outside policy triggers kernel SIGSYS kill."""
        # Execute uname under echo's restrictive profile where uname syscall is absent
        echo_profile = ROOT / "results/profiles/echo.json"
        if not echo_profile.is_file():
            self.skipTest("results/profiles/echo.json not found")

        session = execute_session(
            command=["/usr/bin/uname", "-a"],
            mode="enforce",
            explicit_profile=str(echo_profile),
            timeout_seconds=5.0,
            record_events=False,
        )
        self.assertEqual(session.status, "killed_by_seccomp")
        self.assertIn(session.exit_code, (-signal.SIGSYS, 128 + signal.SIGSYS, 159))
        self.assertTrue(session.violation_detected)
        self.assertIn("SIGSYS", session.violation_detail)

    def test_execute_unapproved_command_fails_closed(self):
        """Executing an unapproved command in approval-required mode terminates before process launch."""
        session = execute_session(
            command=["/usr/bin/cat", "/dev/null"],
            mode="approval-required",
            timeout_seconds=5.0,
        )
        self.assertEqual(session.status, "denied")
        self.assertEqual(session.exit_code, 126)
        self.assertTrue(session.violation_detected)
        self.assertIn("approval", session.violation_detail.lower())

    def test_list_sessions(self):
        """Lists recorded sessions sorted newest first."""
        sessions = list_sessions(limit=5)
        self.assertIsInstance(sessions, list)
        if sessions:
            self.assertTrue(sessions[0]["id"].startswith("run-"))

    def test_wrapper_executable_cli(self):
        """Root ./povishield CLI wrapper supports evaluate and list commands."""
        if not WRAPPER.is_file():
            self.skipTest("./povishield wrapper missing")

        # Test evaluate
        res = subprocess.run(
            [str(WRAPPER), "evaluate", "--", "/usr/bin/echo", "test"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("[DECISION]", res.stdout)

        # Test list
        res = subprocess.run(
            [str(WRAPPER), "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("PoViShield Execution Sessions", res.stdout)


if __name__ == "__main__":
    unittest.main()
