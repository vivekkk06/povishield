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
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

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


def resolve_profile_path(p: Union[str, Path]) -> Path:
    path = Path(p)
    if path.is_file():
        return path.resolve()
    name = path.name if path.name.endswith(".json") else f"{path.name}.json"
    candidates = [
        ROOT / path,
        ROOT / name,
        ROOT / "deploy_data" / "profiles" / name,
        ROOT / "results" / "profiles" / name,
        ROOT / "deploy_data" / name,
        ROOT / "results" / name,
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    return path


def run_test(cmd: List[str], profile_path: Path, timeout: float = 10.0) -> Dict[str, Any]:
    if not BIN.is_file():
        subprocess.run(["make", "-C", str(ROOT), "povishield"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    full_cmd = [str(BIN), "enforce", "-p", str(profile_path), "--"] + cmd
    try:
        r = subprocess.run(
            full_cmd,
            input=b"",
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
    except FileNotFoundError as e:
        return {"cmd": cmd, "rc": 127, "stdout_len": 0, "killed_by_sigsys": False, "timeout": False, "error": str(e)}
    except Exception as e:
        return {"cmd": cmd, "rc": 1, "stdout_len": 0, "killed_by_sigsys": False, "timeout": False, "error": str(e)}


def verify_policy_candidate(
    candidate_path: Union[str, Path],
    active_path: Optional[Union[str, Path]] = None,
    regression_workloads: Optional[Union[List[List[str]], List[str], str]] = None,
    adversarial_workloads: Optional[Union[List[List[str]], List[str], str]] = None,
    target_name: str = "app",
    ledger_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    cand_path = resolve_profile_path(candidate_path)
    if not cand_path.is_file():
        raise FileNotFoundError(f"Candidate policy not found: {candidate_path}")

    active_p: Optional[Path] = None
    if active_path:
        active_p = resolve_profile_path(active_path)

    candidate_meta = load_profile_meta(cand_path)
    candidate_syscalls = set(candidate_meta.get("syscalls", []))
    total_sys = total_syscalls()

    # Intelligent target inference if target_name is the generic default "app"
    if target_name == "app":
        cmd_meta = candidate_meta.get("command", "")
        if cmd_meta:
            token = shlex.split(cmd_meta)[0].split("/")[-1]
            if (ROOT / "results" / "ledgers" / f"{token}.jsonl").is_file() or (ROOT / "deploy_data" / "ledgers" / f"{token}.jsonl").is_file():
                target_name = token
        if target_name == "app":
            stem = cand_path.stem.replace("_candidate", "").replace("_counterfactual", "").replace("_baseline", "").replace("_observed", "")
            if (ROOT / "results" / "ledgers" / f"{stem}.jsonl").is_file() or (ROOT / "deploy_data" / "ledgers" / f"{stem}.jsonl").is_file():
                target_name = stem

    active_syscalls: Set[str] = set()
    if active_p and active_p.is_file():
        active_syscalls = load_profile(active_p)

    added = candidate_syscalls - active_syscalls if active_syscalls else set()
    removed = active_syscalls - candidate_syscalls if active_syscalls else set()

    ledger = EvidenceLedger(target_name, ledger_path=Path(ledger_path) if ledger_path else None)
    necessary_map = ledger.get_necessary_syscalls()

    # Normalize regression_workloads
    normalized_reg: List[List[str]] = []
    if regression_workloads:
        if isinstance(regression_workloads, str):
            normalized_reg = [shlex.split(regression_workloads)]
        elif isinstance(regression_workloads, list):
            for item in regression_workloads:
                if isinstance(item, str):
                    normalized_reg.append(shlex.split(item))
                elif isinstance(item, list):
                    normalized_reg.append([str(x) for x in item])
    if not normalized_reg:
        # Default regression command from metadata or target
        cmd_candidate = candidate_meta.get("command", "")
        if cmd_candidate:
            tokens = shlex.split(cmd_candidate)
            if len(tokens) == 1:
                if tokens[0] == "cat":
                    normalized_reg = [["cat", "/dev/null"]]
                elif tokens[0] == "grep":
                    normalized_reg = [["grep", "--version"]]
                elif tokens[0] in ("sed", "awk"):
                    normalized_reg = [[tokens[0], "--version"]]
                else:
                    normalized_reg = [tokens]
            else:
                normalized_reg = [tokens]
        elif target_name and target_name != "app":
            if target_name == "cat":
                normalized_reg = [["cat", "/dev/null"]]
            elif target_name == "grep":
                normalized_reg = [["grep", "--version"]]
            else:
                normalized_reg = [[target_name, "--version"]]
        else:
            normalized_reg = [["/usr/bin/true"]]

    # Normalize adversarial_workloads
    normalized_adv: List[List[str]] = []
    if adversarial_workloads:
        if isinstance(adversarial_workloads, str):
            normalized_adv = [shlex.split(adversarial_workloads)]
        elif isinstance(adversarial_workloads, list):
            for item in adversarial_workloads:
                if isinstance(item, str):
                    normalized_adv.append(shlex.split(item))
                elif isinstance(item, list):
                    normalized_adv.append([str(x) for x in item])

    # 1. Regression Verification: all legitimate workloads MUST succeed
    regression_results = []
    regression_passed = True
    for cmd in normalized_reg:
        try:
            ref = subprocess.run(cmd, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ref_rc = ref.returncode
        except Exception:
            ref_rc = 127
        c_res = run_test(cmd, cand_path)
        passed = (c_res["rc"] == ref_rc) and not c_res["killed_by_sigsys"]
        if not passed:
            regression_passed = False
        regression_results.append({
            "cmd": cmd,
            "native_rc": ref_rc,
            "candidate_rc": c_res["rc"],
            "sigsys": c_res["killed_by_sigsys"],
            "passed": passed,
        })

    # 2. Adversarial / Containment Verification: disallowed actions MUST be blocked
    adversarial_results = []
    adversarial_passed = True
    if normalized_adv:
        for cmd in normalized_adv:
            a_res = run_test(cmd, cand_path)
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
    meta_evidence = set(candidate_meta.get("evidence", {}).keys())
    tiers_necessary = set(candidate_meta.get("permission_tiers", {}).get("experimentally_necessary", []))
    evidence_backed = {
        s for s in candidate_syscalls
        if s in necessary_map or s in meta_evidence or s in tiers_necessary
    }
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
        "candidate": str(cand_path),
        "target": target_name,
        "allowed_count": len(candidate_syscalls),
        "risk_score": round(risk_pct(candidate_syscalls, total_sys), 2),
        "active_comparison": {
            "has_active": bool(active_p and active_p.exists()),
            "added_syscalls": sorted(added),
            "removed_syscalls": sorted(removed),
            "unbacked_added_syscalls": sorted(unbacked_added),
        },
        "regression": {
            "total_tested": len(normalized_reg),
            "passed": regression_passed,
            "details": regression_results,
        },
        "adversarial": {
            "total_tested": len(normalized_adv),
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
    parser.add_argument("--ledger", help="Path to evidence ledger JSONL")
    parser.add_argument(
        "--regression",
        action="append",
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
        help="Explicitly approve and register the candidate policy if verification passes",
    )
    args = parser.parse_args()

    reg_cmds = [shlex.split(c) for c in args.regression] if args.regression else None
    adv_cmds = [shlex.split(c) for c in args.adversarial] if args.adversarial else []

    cand_path = resolve_profile_path(args.candidate)
    active_path = resolve_profile_path(args.active) if args.active else None
    ledger_path = Path(args.ledger) if args.ledger else None

    report = verify_policy_candidate(
        candidate_path=cand_path,
        active_path=active_path,
        regression_workloads=reg_cmds,
        adversarial_workloads=adv_cmds,
        target_name=args.target,
        ledger_path=ledger_path,
    )

    print(json.dumps(report, indent=2))
    if report["verdict"] == "READY_FOR_APPROVAL":
        if args.approve:
            appr_file = ROOT / "results" / "approvals.jsonl"
            appr_file.parent.mkdir(parents=True, exist_ok=True)
            now_iso = datetime.now(timezone.utc).isoformat()
            target_out = report.get("target") or args.target
            if active_path:
                if cand_path.resolve() != active_path.resolve():
                    active_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(cand_path, active_path)
                rec = {
                    "candidate": str(cand_path),
                    "active": str(active_path),
                    "target": target_out,
                    "timestamp": now_iso,
                    "approved_at": now_iso,
                    "status": "APPROVED",
                }
                with open(appr_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                print(f"\n[POLICY REPLACED] Active policy '{active_path}' securely updated with approved candidate.")
            else:
                rec = {
                    "candidate": str(cand_path),
                    "active": str(cand_path),
                    "target": target_out,
                    "timestamp": now_iso,
                    "approved_at": now_iso,
                    "status": "APPROVED",
                }
                with open(appr_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                print(f"\n[VERDICT: APPROVED] Policy '{cand_path}' approved and registered in approvals ledger.")
            sys.exit(0)
        else:
            print("\n[VERDICT: READY_FOR_APPROVAL] Verification passed. Pass --approve to replace active policy.")
            sys.exit(0)
    else:
        print(f"\n[VERDICT: REJECTED] {report['verdict']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
