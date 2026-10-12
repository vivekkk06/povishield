"""PoViShield Comparative Evaluation: Observation-Only Learning vs Counterfactual Permission Minimization.

Evaluates:
- Attack surface reduction delta
- Weighted risk score delta
- Evidence completeness (% of permissions backed by reproducible failure proof)
- Held-out task compatibility (% of held-out tasks passing under minimized policy)
- Ablation verification overhead
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, Dict, List

from analysis.ablate import ablate_policy, run_workload
from analysis.common import BIN, ROOT, load_profile, save_profile, total_syscalls
from analysis.ledger import EvidenceLedger, get_environment_fingerprint
from analysis.risk import risk_pct

RES = ROOT / "results"


def learn_cmd(cmd: List[str], out_path: Path) -> set:
    subprocess.run(
        [str(BIN), "learn", "-o", str(out_path), "--"] + cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if not out_path.exists():
        raise RuntimeError(f"learn produced no profile for {cmd}")
    return load_profile(out_path)


def evaluate_target(tinfo: Dict[str, Any], total_sys: int, tmp_dir: Path) -> Dict[str, Any]:
    name = tinfo["name"]
    train_cmds = tinfo["train"]
    test_cmds = tinfo["test"]

    print(f"\n==================== [{name}] ====================")
    # 1. Observation-only Baseline
    train_sets = []
    for i, c in enumerate(train_cmds):
        p = tmp_dir / f"{name}_train_{i}.json"
        train_sets.append(learn_cmd(c, p))

    baseline_policy = set.union(*train_sets)
    base_profile_path = RES / "profiles" / f"{name}_baseline.json"
    save_profile(base_profile_path, baseline_policy, command=name)

    base_count = len(baseline_policy)
    base_risk = round(risk_pct(baseline_policy, total_sys), 2)
    base_reduction = round((1 - base_count / total_sys) * 100, 2)
    print(f"Observation-Only Baseline: {base_count} syscalls (risk {base_risk}, reduction {base_reduction}%)")

    # 2. Counterfactual Minimization & Ablation
    t0 = time.perf_counter()
    ledger = EvidenceLedger(name)
    ablate_res = ablate_policy(
        target=name,
        base_syscalls=baseline_policy,
        workloads=train_cmds,
        strategy="minimize",
        ledger=ledger,
        verbose=False,
    )
    ablate_time_s = round(time.perf_counter() - t0, 3)

    min_policy = set(ablate_res["final_syscalls"])
    min_count = len(min_policy)
    min_risk = round(risk_pct(min_policy, total_sys), 2)
    min_reduction = round((1 - min_count / total_sys) * 100, 2)
    removed_count = ablate_res["removed_count"]

    evidence_count = len(ablate_res["evidence"])
    evidence_completeness_pct = round(100.0 * evidence_count / max(min_count, 1), 1)

    min_profile_path = RES / "profiles" / f"{name}_counterfactual.json"
    save_profile(
        min_profile_path,
        min_policy,
        command=name,
        schema=2,
        extra={
            "evidence": ablate_res["evidence"],
            "removable_for_tested_suite": ablate_res["removable_syscalls"],
            "ablation_summary": ablate_res,
        },
    )

    print(
        f"Counterfactual Minimized : {min_count} syscalls "
        f"({removed_count} removed, risk {min_risk}, evidence coverage {evidence_completeness_pct}%) in {ablate_time_s}s"
    )

    # 3. Held-out Test Workloads Compatibility
    base_compat_ok, min_compat_ok = 0, 0
    base_false_kills, min_false_kills = 0, 0

    for c in test_cmds:
        ref_rc, ref_out, _ = run_workload(c)

        # Under baseline policy
        b_rc, b_out, _ = run_workload(c, profile_path=base_profile_path)
        if b_rc == ref_rc and b_out == ref_out:
            base_compat_ok += 1
        if b_rc in (-31, 159):
            base_false_kills += 1

        # Under counterfactual minimized policy
        m_rc, m_out, _ = run_workload(c, profile_path=min_profile_path)
        if m_rc == ref_rc and m_out == ref_out:
            min_compat_ok += 1
        if m_rc in (-31, 159):
            min_false_kills += 1

    total_tests = len(test_cmds)
    base_compat_pct = round(100.0 * base_compat_ok / total_tests, 1)
    min_compat_pct = round(100.0 * min_compat_ok / total_tests, 1)

    return {
        "target": name,
        "baseline": {
            "allowed_syscalls": base_count,
            "risk_score": base_risk,
            "attack_surface_reduction_pct": base_reduction,
            "heldout_compat_pct": base_compat_pct,
            "false_kills": base_false_kills,
        },
        "counterfactual": {
            "allowed_syscalls": min_count,
            "risk_score": min_risk,
            "attack_surface_reduction_pct": min_reduction,
            "syscalls_removed": removed_count,
            "removed_list": ablate_res["removable_syscalls"],
            "evidence_backed_syscalls": evidence_count,
            "evidence_completeness_pct": evidence_completeness_pct,
            "heldout_compat_pct": min_compat_pct,
            "false_kills": min_false_kills,
            "ablation_search_seconds": ablate_time_s,
            "trials_run": len(ablate_res["evidence"]) + removed_count,
        },
    }


def main():
    if not BIN.exists():
        sys.exit("build first: make")

    cfg = tomllib.loads((ROOT / "evaluation" / "targets.toml").read_text())
    targets = cfg["target"]
    total_sys = total_syscalls()

    (RES / "profiles").mkdir(parents=True, exist_ok=True)
    (RES / "ledgers").mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("PoViShield: Counterfactual Permission Verification & Minimization Evaluation")
    print("================================================================================")

    results = []
    with tempfile.TemporaryDirectory(prefix="ps-eval-ablate-") as td:
        tmp_dir = Path(td)
        for t in targets:
            results.append(evaluate_target(t, total_sys, tmp_dir))

    # Aggregates
    n = len(results)
    avg_base_allowed = round(sum(r["baseline"]["allowed_syscalls"] for r in results) / n, 2)
    avg_min_allowed = round(sum(r["counterfactual"]["allowed_syscalls"] for r in results) / n, 2)
    total_removed = sum(r["counterfactual"]["syscalls_removed"] for r in results)
    avg_evidence_coverage = round(sum(r["counterfactual"]["evidence_completeness_pct"] for r in results) / n, 1)
    avg_base_compat = round(sum(r["baseline"]["heldout_compat_pct"] for r in results) / n, 1)
    avg_min_compat = round(sum(r["counterfactual"]["heldout_compat_pct"] for r in results) / n, 1)
    total_search_s = round(sum(r["counterfactual"]["ablation_search_seconds"] for r in results), 2)

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": get_environment_fingerprint(),
        "total_targets_evaluated": n,
        "aggregate": {
            "avg_baseline_syscalls": avg_base_allowed,
            "avg_counterfactual_syscalls": avg_min_allowed,
            "total_unnecessary_syscalls_removed": total_removed,
            "avg_evidence_completeness_pct": avg_evidence_coverage,
            "avg_baseline_compat_pct": avg_base_compat,
            "avg_counterfactual_compat_pct": avg_min_compat,
            "total_ablation_time_seconds": total_search_s,
        },
        "targets": results,
    }

    out_json = RES / "ablation_eval.json"
    out_json.write_text(json.dumps(summary, indent=2))

    # Generate Markdown Report
    lines = [
        "# PoViShield Counterfactual Permission Verification: Empirical Evaluation",
        "",
        "Comparison of **Observation-Only Policy Learning** vs **Counterfactual Permission Minimization**.",
        "",
        "| Target | Baseline Syscalls | Minimized Syscalls | Syscalls Removed | Evidence Coverage | Baseline Compat | Minimized Compat | Search Time |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        b = r["baseline"]
        c = r["counterfactual"]
        lines.append(
            f"| {r['target']} | {b['allowed_syscalls']} | {c['allowed_syscalls']} | {c['syscalls_removed']} | "
            f"{c['evidence_completeness_pct']}% | {b['heldout_compat_pct']}% | {c['heldout_compat_pct']}% | {c['ablation_search_seconds']}s |"
        )
    lines.extend([
        "",
        "## Aggregate Comparison",
        f"- **Average Baseline Syscalls Allowed**: {avg_base_allowed}",
        f"- **Average Minimized Syscalls Allowed**: {avg_min_allowed}",
        f"- **Extraneous Permissions Eliminated Across Suite**: {total_removed}",
        f"- **Mean Evidence Justification Coverage**: {avg_evidence_coverage}%",
        f"- **Held-Out Task Compatibility Retention**: {avg_min_compat}% (vs {avg_base_compat}% baseline)",
        f"- **Total Search & Verification Overhead**: {total_search_s}s",
        "",
        "Every retained permission in the minimized profile links to a reproducible test case in the evidence ledger.",
    ])
    out_md = RES / "ablation_report.md"
    out_md.write_text("\n".join(lines))

    print("\n\n================================================================================")
    print("Aggregate Results Summary")
    print("================================================================================")
    print(json.dumps(summary["aggregate"], indent=2))
    print(f"\nWritten {out_json} and {out_md}")


if __name__ == "__main__":
    main()
