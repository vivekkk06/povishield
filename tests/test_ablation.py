"""Unit and integration tests for counterfactual permission ablation and evidence ledger."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from analysis.ablate import ablate_policy, run_workload
from analysis.common import BIN, ROOT, load_profile, save_profile
from analysis.ledger import EvidenceLedger, TrialRecord
from analysis.verify import verify_policy_candidate


class TestEvidenceLedger(unittest.TestCase):
    def test_ledger_record_and_reload(self):
        with tempfile.TemporaryDirectory() as td:
            lpath = Path(td) / "test.jsonl"
            ledger = EvidenceLedger("test_app", ledger_path=lpath)
            t = TrialRecord(
                trial_id="t1",
                target="test_app",
                workload=["echo", "hi"],
                ablated_syscall="write",
                baseline_rc=0,
                baseline_stdout_hash="abc",
                candidate_rc=-31,
                candidate_stdout_hash="",
                verdict="NECESSARY",
                signal="SIGSYS",
                output_diverged=True,
                reproduce_cmd="povishield enforce ...",
            )
            ledger.record_trial(t)
            self.assertTrue(lpath.exists())

            # Reload ledger
            reloaded = EvidenceLedger("test_app", ledger_path=lpath)
            self.assertEqual(len(reloaded.trials), 1)
            self.assertEqual(reloaded.trials[0].ablated_syscall, "write")
            self.assertEqual(reloaded.trials[0].verdict, "NECESSARY")
            nec = reloaded.get_necessary_syscalls()
            self.assertIn("write", nec)


class TestAblationEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BIN.exists():
            raise unittest.SkipTest("povishield binary not built")

    def test_ablation_identifies_unneeded_permission(self):
        """Injecting an unneeded syscall (e.g. mount, ptrace) must be flagged as REMOVABLE."""
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            # Learn real baseline for a simple command
            cmd = ["cat", "/etc/hostname"]
            prof = tdir / "base.json"
            subprocess.run(
                [str(BIN), "learn", "-o", str(prof), "--"] + cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            real_syscalls = load_profile(prof)
            # Add extraneous unneeded permissions
            noisy_syscalls = real_syscalls | {"mount", "ptrace", "socket"}

            lpath = tdir / "ledger.jsonl"
            ledger = EvidenceLedger("cat_test", ledger_path=lpath)
            res = ablate_policy(
                target="cat_test",
                base_syscalls=noisy_syscalls,
                workloads=[cmd],
                strategy="minimize",
                ledger=ledger,
                verbose=False,
            )

            self.assertIn("mount", res["removable_syscalls"])
            self.assertIn("ptrace", res["removable_syscalls"])
            self.assertIn("socket", res["removable_syscalls"])
            self.assertNotIn("mount", res["final_syscalls"])
            self.assertNotIn("ptrace", res["final_syscalls"])
            self.assertNotIn("socket", res["final_syscalls"])
            # Essential syscalls must be marked necessary
            self.assertIn("read", res["evidence"])
            self.assertEqual(res["evidence"]["read"]["classification"], "experimentally_necessary")

    def test_schema2_backward_compatibility_with_c_enforce(self):
        """Schema 2 profile with evidence metadata must be accepted and enforced by povishield enforce."""
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            cmd = ["cat", "/etc/hostname"]
            prof = tdir / "cat.json"
            subprocess.run(
                [str(BIN), "learn", "-o", str(prof), "--"] + cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            syscalls = load_profile(prof)
            s2_path = tdir / "cat_s2.json"
            save_profile(
                s2_path,
                syscalls,
                command="cat",
                schema=2,
                extra={"evidence": {"read": {"classification": "experimentally_necessary"}}},
            )

            rc, out, _ = run_workload(cmd, profile_path=s2_path)
            self.assertEqual(rc, 0)
            self.assertGreater(len(out), 0)


class TestVerificationGate(unittest.TestCase):
    def test_verify_approves_valid_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            cmd = ["cat", "/etc/hostname"]
            prof = tdir / "cat.json"
            subprocess.run(
                [str(BIN), "learn", "-o", str(prof), "--"] + cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            report = verify_policy_candidate(
                candidate_path=prof,
                active_path=None,
                regression_workloads=[cmd],
                target_name="cat",
            )
            self.assertEqual(report["verdict"], "READY_FOR_APPROVAL")
            self.assertTrue(report["regression"]["passed"])

    def test_verify_rejects_unfamiliar_unbacked_syscalls(self):
        """Never automatically grant unfamiliar permissions: must reject if candidate adds new unbacked syscalls."""
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            cmd = ["cat", "/etc/hostname"]
            active_prof = tdir / "active.json"
            save_profile(active_prof, ["read", "write", "exit_group"], command="cat")

            candidate_prof = tdir / "candidate_unfamiliar.json"
            # Injects 'ptrace' which active did not have and which has no necessity evidence
            save_profile(candidate_prof, ["read", "write", "exit_group", "ptrace"], command="cat")

            report = verify_policy_candidate(
                candidate_path=candidate_prof,
                active_path=active_prof,
                regression_workloads=[cmd],
                target_name="cat",
            )
            self.assertTrue(report["verdict"].startswith("REJECTED_UNAUTHORIZED_NEW_SYSCALLS"))

    def test_permission_tiers_explicitly_distinguished(self):
        """Ablation output must distinguish observed, experimentally_necessary, removable_for_tested_tasks, and not_yet_validated."""
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            cmd = ["cat", "/etc/hostname"]
            prof = tdir / "base.json"
            subprocess.run(
                [str(BIN), "learn", "-o", str(prof), "--"] + cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            real_syscalls = load_profile(prof)
            res = ablate_policy(
                target="cat_tiers",
                base_syscalls=real_syscalls | {"ptrace"},
                workloads=[cmd],
                strategy="minimize",
                ledger=EvidenceLedger("cat_tiers", ledger_path=tdir / "l.jsonl"),
                verbose=False,
            )
            tiers = res["permission_tiers"]
            self.assertIn("observed", tiers)
            self.assertIn("experimentally_necessary", tiers)
            self.assertIn("removable_for_tested_tasks", tiers)
            self.assertIn("not_yet_validated", tiers)
            self.assertIn("ptrace", tiers["removable_for_tested_tasks"])
            self.assertIn("read", tiers["experimentally_necessary"])


from analysis.audit_ledger import audit_ledger_file
from analysis.ledger import Verdict


class TestLedgerAuditor(unittest.TestCase):
    def test_audit_passes_on_valid_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "valid.jsonl"
            ledger = EvidenceLedger("test_valid", ledger_path=lpath)
            t = TrialRecord(
                trial_id="t1",
                target="test_valid",
                workload=["echo", "1"],
                ablated_syscall="write",
                baseline_rc=0,
                baseline_stdout_hash="h1",
                candidate_rc=-31,
                candidate_stdout_hash="",
                verdict=Verdict.REQUIRED.value,
                signal="SIGSYS",
            )
            ledger.record_trial(t)
            passed, report = audit_ledger_file(lpath)
            self.assertTrue(passed)
            self.assertEqual(report["error_count"], 0)
            self.assertEqual(report["experimentally_required_count"], 1)

    def test_audit_fails_on_corrupted_json(self):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "corrupted.jsonl"
            lpath.write_text("{\"trial_id\": \"t1\", NOT VALID JSON\n")
            passed, report = audit_ledger_file(lpath)
            self.assertFalse(passed)
            self.assertGreater(report["error_count"], 0)

    def test_audit_fails_on_contradictory_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "contradictory.jsonl"
            ledger = EvidenceLedger("test_contra", ledger_path=lpath)
            t1 = TrialRecord(
                trial_id="t1",
                target="test_contra",
                workload=["echo", "1"],
                ablated_syscall="write",
                baseline_rc=0,
                baseline_stdout_hash="h1",
                candidate_rc=-31,
                candidate_stdout_hash="",
                verdict=Verdict.REQUIRED.value,
                signal="SIGSYS",
            )
            t2 = TrialRecord(
                trial_id="t2",
                target="test_contra",
                workload=["echo", "1"],
                ablated_syscall="write",
                baseline_rc=0,
                baseline_stdout_hash="h1",
                candidate_rc=0,
                candidate_stdout_hash="h1",
                verdict=Verdict.REMOVABLE.value,
            )
            ledger.record_trial(t1)
            ledger.record_trial(t2)
            passed, report = audit_ledger_file(lpath)
            self.assertFalse(passed)
            self.assertTrue(any("Contradictory evidence" in e for e in report["errors"]))

    def test_audit_fails_when_policy_omits_required_syscall(self):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "ledger.jsonl"
            cand_profile = tdir / "cand.json"
            ledger = EvidenceLedger("test_app", ledger_path=lpath)
            t1 = TrialRecord(
                trial_id="t1",
                target="test_app",
                workload=["cat", "/etc/hostname"],
                ablated_syscall="read",
                baseline_rc=0,
                baseline_stdout_hash="h",
                candidate_rc=-31,
                candidate_stdout_hash="",
                verdict=Verdict.REQUIRED.value,
                signal="SIGSYS",
            )
            ledger.record_trial(t1)
            # Candidate profile mistakenly omits required 'read' syscall
            save_profile(cand_profile, ["write", "close"], command="test_app")
            passed, report = audit_ledger_file(lpath, candidate_profile_path=cand_profile)
            self.assertFalse(passed)
            self.assertTrue(any("Policy defect: Syscall 'read' is experimentally required" in e for e in report["errors"]))

    def test_audit_fails_on_unbacked_removal(self):
        """If candidate profile removes a baseline syscall without positive ledger proof, audit must fail closed."""
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "ledger.jsonl"
            cand_profile = tdir / "cand.json"
            ledger = EvidenceLedger("test_app", ledger_path=lpath)
            t = TrialRecord(
                trial_id="t1",
                target="test_app",
                workload=["echo", "1"],
                ablated_syscall="close",
                baseline_rc=0,
                baseline_stdout_hash="h1",
                candidate_rc=0,
                candidate_stdout_hash="h1",
                verdict=Verdict.REMOVABLE.value,
            )
            ledger.record_trial(t)
            # Candidate profile claims 'read' is removable, but ledger has NO test for 'read'!
            extra = {
                "baseline_syscalls": ["read", "write", "close"],
                "permission_tiers": {
                    "experimentally_necessary": [],
                    "removable_for_tested_tasks": ["read"],  # Claimed removable without proof!
                    "not_yet_validated": [],
                }
            }
            save_profile(cand_profile, ["write", "close"], command="test_app", schema=2, extra=extra)
            passed, report = audit_ledger_file(lpath, candidate_profile_path=cand_profile)
            self.assertFalse(passed)
            self.assertTrue(any("Unbacked removal" in e for e in report["errors"]))


class TestConservativeAblationRules(unittest.TestCase):
    def test_timeout_and_errors_are_retained_not_removed(self):
        """Simulate execution timeout: must assign TIMED_OUT verdict and retain the syscall."""
        from analysis.ablate import test_ablation_trial
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            lpath = tdir / "err_ledger.jsonl"
            ledger = EvidenceLedger("err_target", ledger_path=lpath)
            # When run_workload times out or fails closed, test_ablation_trial must set failed=True
            # and verdict to TIMED_OUT or EXECUTION_ERROR
            intact, trial = test_ablation_trial(
                target="err_target",
                workload=["sleep", "999"],
                ablated_sc="nanosleep",
                base_syscalls={"nanosleep", "exit_group"},
                candidate_syscalls={"exit_group"},
                ref_rc=0,
                ref_out=b"",
                ledger=ledger,
                tmp_dir=tdir,
            )
            # Even if command times out or is killed, intact must be False (conservatively retained)
            self.assertFalse(intact)
            self.assertIn(trial.verdict, (Verdict.REQUIRED.value, Verdict.TIMED_OUT.value, Verdict.POLICY_NOT_APPLIED.value, Verdict.EXECUTION_ERROR.value))


if __name__ == "__main__":
    unittest.main()
