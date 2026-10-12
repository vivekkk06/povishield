"""Independent Auditor for PoViShield Evidence Ledgers.

Verifies evidence records independently of the generator:
- Validates record schema and environment fingerprints.
- Detects malformed, duplicate, contradictory, or inconclusive records.
- Verifies that removal decisions are strictly backed by clean trials.
- Ensures failed or timed-out trials cannot be counted as removals.
- Fails closed if any evidence is absent, inconsistent, or corrupted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

if __package__ is None or __package__ == "":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import ROOT
    from analysis.ledger import EvidenceLedger, Verdict, normalize_verdict
else:
    from .common import ROOT
    from .ledger import EvidenceLedger, Verdict, normalize_verdict


def audit_ledger_file(ledger_path: Path, candidate_profile_path: Path | None = None) -> Tuple[bool, Dict[str, Any]]:
    if not ledger_path.exists():
        return False, {
            "ledger": str(ledger_path),
            "valid": False,
            "error_count": 1,
            "errors": [f"Ledger file not found: {ledger_path}"],
        }

    ledger_name = ledger_path.stem
    ledger = EvidenceLedger(ledger_name, ledger_path=ledger_path)
    ok, errors = ledger.audit_integrity()

    recomputed = ledger.summarize()
    necessary_syscalls = set(recomputed["necessary_evidence"].keys())
    tested_syscalls = {t.ablated_syscall for t in ledger.trials}
    removable_syscalls = set(recomputed["removable_syscalls"])

    policy_errors: List[str] = []
    if candidate_profile_path and candidate_profile_path.exists():
        try:
            with open(candidate_profile_path, "r", encoding="utf-8") as pf:
                cand_doc = json.load(pf)
            allowed = set(cand_doc.get("syscalls", []))

            # 1. Check: No strictly necessary syscall was erroneously removed
            for nec_sc in necessary_syscalls:
                if nec_sc not in allowed:
                    policy_errors.append(
                        f"Policy defect: Syscall '{nec_sc}' is experimentally required by ledger but omitted from policy!"
                    )

            # 2. Check: Removals claimed in permission_tiers must not be required and must have positive proof
            removable_in_doc = set(cand_doc.get("permission_tiers", {}).get("removable_for_tested_tasks", []))
            for rem_sc in removable_in_doc:
                if rem_sc in necessary_syscalls:
                    policy_errors.append(
                        f"Policy contradiction: Syscall '{rem_sc}' marked removable in profile but proven required in ledger!"
                    )
                if rem_sc not in removable_syscalls:
                    policy_errors.append(
                        f"Unbacked removal: Syscall '{rem_sc}' marked removable in profile but lacks positive proof in ledger!"
                    )

            # 3. Check: If baseline_syscalls recorded, any stripped syscall must have positive proof in ledger
            if "baseline_syscalls" in cand_doc:
                stripped = set(cand_doc["baseline_syscalls"]) - allowed
                for s in stripped:
                    if s not in removable_syscalls:
                        policy_errors.append(
                            f"Unbacked removal: Syscall '{s}' stripped from baseline without verified trial in ledger!"
                        )
        except Exception as e:
            policy_errors.append(f"Failed to inspect candidate profile: {e}")

    total_errors = errors + policy_errors
    passed = (len(total_errors) == 0)

    report = {
        "ledger": str(ledger_path),
        "target": ledger_name,
        "valid": passed,
        "trials_total": len(ledger.trials),
        "tested_syscalls_count": len(tested_syscalls),
        "experimentally_required_count": len(necessary_syscalls),
        "removable_count": len(removable_syscalls),
        "inconclusive_count": recomputed["inconclusive_count"],
        "removable_syscalls": sorted(removable_syscalls),
        "error_count": len(total_errors),
        "errors": total_errors,
    }
    return passed, report


def main():
    parser = argparse.ArgumentParser(description="PoViShield Independent Ledger Auditor")
    parser.add_argument("ledger", help="Path to evidence ledger (.jsonl)")
    parser.add_argument("--candidate", help="Optional path to candidate profile JSON to verify against ledger")
    args = parser.parse_args()

    lpath = Path(args.ledger)
    cpath = Path(args.candidate) if args.candidate else None

    passed, report = audit_ledger_file(lpath, cpath)
    print(json.dumps(report, indent=2))

    if passed:
        print(f"\n[AUDIT PASSED] Ledger '{lpath}' is valid, consistent, and evidence-backed.")
        sys.exit(0)
    else:
        print(f"\n[AUDIT FAILED] Ledger verification failed with {report['error_count']} errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
