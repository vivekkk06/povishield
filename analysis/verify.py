"""PoViShield Candidate Policy Verification & Safety Gate.

Validates candidate policies before enforcement:
- Runs regression workloads to guarantee legitimate tasks are not broken.
- Runs adversarial / escape checks to ensure disallowed actions are blocked.
- Verifies that retained permissions are backed by evidence in the ledger.
- Enforces an approval requirement before any candidate policy becomes active.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

if __package__ is None or __package__ == "":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import BIN, ROOT, load_profile, load_profile_meta, total_syscalls
    from analysis.ledger import EvidenceLedger
    from analysis.risk import risk_pct, weight
else:
    from .common import BIN, ROOT, load_profile, load_profile_meta, total_syscalls
    from .ledger import EvidenceLedger
    from .risk import risk_pct, weight

SIGSYS_CODES = {-31, 159}


def run_test(cmd: List[str], profile_path: Path, timeout: float = 10.0) -> Dict[str, Any]:
    full_cmd = [str(BIN), "enforce", "-p", str(profile_path), "--"] + cmd
    try:
        r = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "rc": r.returncode,
            "stdout_len": len(r.stdout),
            "killed_by_sigsys": r.returncode in SIGSYS_CODES,
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {"cmd": cmd, "rc": -999, "stdout_len": 0, "killed_by_sigsys": False, "timeout": True}


def verify_policy_candidate(
    candidate_path: Path,
    active_path: Optional[Path],
    regression_workloads: List[List[str]],
    adversarial_workloads: Optional[List[List[str]]] = None,
    target_name: str = "app",
) -> Dict[str, Any]:
    if not candidate_path.exists():
        raise FileNotFoundError(f"Candidate policy not found: {candidate_path}")

    candidate_meta = load_profile_meta(candidate_path)
    candidate_syscalls = set(candidate_meta["syscalls"])
    total_sys = total_syscalls()

    active_syscalls: Set[str] = set()
    if active_path and active_path.exists():
        active_syscalls = load_profile(active_path)

    added = candidate_syscalls - active_syscalls if active_syscalls else set()
    removed = active_syscalls - candidate_syscalls if active_syscalls else set()

    ledger = EvidenceLedger(target_name)
    necessary_map = ledger.get_necessary_syscalls()

    # 1. Regression Verification: all legitimate workloads MUST succeed
    regression_results = []
    regression_passed = True
    for cmd in regression_workloads:
        # Native baseline
        ref = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Candidate enforce
        c_res = run_test(cmd, candidate_path)
        passed = (c_res["rc"] == ref.returncode) and not c_res["killed_by_sigsys"]
        if not passed:
            regression_passed = False
        regression_results.append({
            "cmd": cmd,
            "native_rc": ref.returncode,
            "candidate_rc": c_res["rc"],
            "sigsys": c_res["killed_by_sigsys"],
            "passed": passed,
        })

    # 2. Adversarial / Containment Verification: disallowed actions MUST be blocked
    adversarial_results = []
    adversarial_passed = True
    if adversarial_workloads:
        for cmd in adversarial_workloads:
            a_res = run_test(cmd, candidate_path)
            # An adversarial test is successful if it was killed by SIGSYS or denied
            blocked = a_res["killed_by_sigsys"] or (a_res["rc"] != 0)
            if not blocked:
                adversarial_passed = False
            adversarial_results.append({
                "cmd": cmd,
                "rc": a_res["rc"],
                "blocked": blocked,
                "sigsys": a_res["killed_by_sigsys"],
            })

    # 3. Evidence Audit: check which retained permissions have evidence in ledger
    evidence_backed = {s for s in candidate_syscalls if s in necessary_map or s in candidate_meta.get("evidence", {})}
    unbacked_syscalls = candidate_syscalls - evidence_backed
    unbacked_added = added - evidence_backed

    # 4. Final approval evaluation: never automatically grant new unfamiliar permissions
    if unbacked_added:
        approval_granted = False
        verdict = f"REJECTED_UNAUTHORIZED_NEW_SYSCALLS: {sorted(unbacked_added)}"
    elif not regression_passed:
        approval_granted = False
        verdict = "REJECTED_REGRESSION_FAILURE"
    elif not adversarial_passed:
        approval_granted = False
        verdict = "REJECTED_ADVERSARIAL_LEAK"
    else:
        approval_granted = True
        verdict = "READY_FOR_APPROVAL"

    report = {
        "candidate": str(candidate_path),
        "target": target_name,
        "allowed_count": len(candidate_syscalls),
        "risk_score": round(risk_pct(candidate_syscalls, total_sys), 2),
        "active_comparison": {
            "has_active": bool(active_path and active_path.exists()),
            "added_syscalls": sorted(added),
            "removed_syscalls": sorted(removed),
            "unbacked_added_syscalls": sorted(unbacked_added),
        },
        "regression": {
            "total_tested": len(regression_workloads),
            "passed": regression_passed,
            "details": regression_results,
        },
        "adversarial": {
            "total_tested": len(adversarial_workloads) if adversarial_workloads else 0,
            "contained": adversarial_passed,
            "details": adversarial_results,
        },
        "evidence_audit": {
            "evidence_backed_count": len(evidence_backed),
            "unbacked_count": len(unbacked_syscalls),
            "unbacked_syscalls": sorted(unbacked_syscalls),
        },
        "verdict": verdict,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="PoViShield Policy Verification & Safety Gate")
    parser.add_argument("candidate", help="Path to candidate profile JSON")
    parser.add_argument("--active", help="Path to currently active baseline profile JSON")
    parser.add_argument("--target", default="app", help="Target application name")
    parser.add_argument(
        "--regression",
        action="append",
        required=True,
        help="Regression test command line (can be specified multiple times)",
    )
    parser.add_argument(
        "--adversarial",
        action="append",
        help="Adversarial command line that should be blocked",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Explicitly approve and replace the active policy if verification passes",
    )
    args = parser.parse_args()

    reg_cmds = [shlex.split(c) for c in args.regression]
    adv_cmds = [shlex.split(c) for c in args.adversarial] if args.adversarial else []

    cand_path = Path(args.candidate)
    active_path = Path(args.active) if args.active else None

    report = verify_policy_candidate(
        candidate_path=cand_path,
        active_path=active_path,
        regression_workloads=reg_cmds,
        adversarial_workloads=adv_cmds,
        target_name=args.target,
    )

    print(json.dumps(report, indent=2))
    if report["verdict"] == "READY_FOR_APPROVAL":
        if args.approve:
            if active_path:
                import shutil
                shutil.copyfile(cand_path, active_path)
                appr_file = ROOT / "results" / "approvals.jsonl"
                appr_file.parent.mkdir(parents=True, exist_ok=True)
                now_iso = datetime.now(timezone.utc).isoformat()
                with open(appr_file, "a") as f:
                    f.write(json.dumps({
                        "candidate": str(cand_path),
                        "active": str(active_path),
                        "target": args.target,
                        "timestamp": now_iso,
                        "approved_at": now_iso,
                        "status": "APPROVED",
                    }) + "\n")
                print(f"\n[POLICY REPLACED] Active policy '{active_path}' securely updated with approved candidate.")
            else:
                print("\n[VERDICT: APPROVED] Verified. (Specify --active <path> to replace active file directly).")
            sys.exit(0)
        else:
            print("\n[VERDICT: READY_FOR_APPROVAL] Verification passed. Pass --approve to replace active policy.")
            sys.exit(0)
    else:
        print(f"\n[VERDICT: REJECTED] {report['verdict']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
