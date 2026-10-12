"""PoViShield Counterfactual Permission Ablation Engine.

Challenges candidate security policies before trusting them:
Systematically withholds permissions (leave-one-out and greedy minimization),
replays legitimate workloads, and records reproducible proof of necessity.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

if __package__ is None or __package__ == "":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import BIN, ROOT, load_profile, load_profile_meta, save_profile, total_syscalls
    from analysis.ledger import EvidenceLedger, TrialRecord, Verdict, get_environment_fingerprint, sha256_bytes, sha256_set
    from analysis.risk import risk_pct
else:
    from .common import BIN, ROOT, load_profile, load_profile_meta, save_profile, total_syscalls
    from .ledger import EvidenceLedger, TrialRecord, Verdict, get_environment_fingerprint, sha256_bytes, sha256_set
    from .risk import risk_pct

SIGSYS_CODES = {-31, 159}


def run_workload(cmd: List[str], profile_path: Optional[Path] = None, timeout: float = 15.0) -> Tuple[int, bytes, bytes]:
    """Runs a workload either natively (if profile_path is None) or under seccomp enforce."""
    full_cmd: List[str]
    if profile_path:
        full_cmd = [str(BIN), "enforce", "-p", str(profile_path), "--"] + cmd
    else:
        full_cmd = list(cmd)

    try:
        r = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -999, b"", b"timeout"
    except Exception as e:
        return -998, b"", str(e).encode()


def test_ablation_trial(
    target: str,
    workload: List[str],
    ablated_sc: str,
    base_syscalls: Set[str],
    candidate_syscalls: Set[str],
    ref_rc: int,
    ref_out: bytes,
    ledger: EvidenceLedger,
    tmp_dir: Path,
) -> Tuple[bool, Optional[TrialRecord]]:
    """Tests if removing ablated_sc breaks the workload.

    Conservative rule: Any timeout, policy-not-applied error, exec failure,
    or divergence causes the permission to be RETAINED (failed = True).
    """
    trial_profile = tmp_dir / f"test_without_{ablated_sc}.json"
    save_profile(trial_profile, candidate_syscalls, command=target)

    cand_rc, cand_out, cand_err = run_workload(workload, profile_path=trial_profile)
    cand_hash = sha256_bytes(cand_out)
    ref_hash = sha256_bytes(ref_out)
    cand_err_hash = sha256_bytes(cand_err)

    is_sigsys = cand_rc in SIGSYS_CODES
    signal_name = "SIGSYS" if is_sigsys else (f"SIGNAL_{abs(cand_rc)}" if cand_rc < 0 and cand_rc != -999 else None)
    output_diverged = (cand_out != ref_out)
    is_timeout = (cand_rc == -999)

    # Classify verdict conservatively
    if is_timeout:
        verdict = Verdict.TIMED_OUT.value
        reason = "Candidate workload execution timed out"
        failed = True
    elif cand_rc == 125:
        verdict = Verdict.POLICY_NOT_APPLIED.value
        reason = "Seccomp profile rejected or PR_SET_NO_NEW_PRIVS failed (exit 125)"
        failed = True
    elif cand_rc in (126, 127):
        verdict = Verdict.EXECUTION_ERROR.value
        reason = f"Execution setup error (exit {cand_rc})"
        failed = True
    elif is_sigsys:
        verdict = Verdict.REQUIRED.value
        reason = "Process killed by kernel SIGSYS (withheld system call invoked)"
        failed = True
    elif cand_rc != ref_rc:
        verdict = Verdict.REQUIRED.value
        reason = f"Exit code diverged: expected {ref_rc}, got {cand_rc}"
        failed = True
    elif output_diverged:
        verdict = Verdict.REQUIRED.value
        reason = "Standard output diverged from baseline"
        failed = True
    else:
        verdict = Verdict.REMOVABLE.value
        reason = "Workload completed cleanly with identical exit status and output"
        failed = False

    repro_cmd = f"{BIN} enforce -p {trial_profile} -- {' '.join(shlex.quote(w) for w in workload)}"
    trial_id = f"{target}_{ablated_sc}_{len(ledger.trials) + 1}"

    trial = TrialRecord(
        trial_id=trial_id,
        target=target,
        workload=workload,
        ablated_syscall=ablated_sc,
        baseline_rc=ref_rc,
        baseline_stdout_hash=ref_hash,
        candidate_rc=cand_rc,
        candidate_stdout_hash=cand_hash,
        verdict=verdict,
        signal=signal_name,
        output_diverged=output_diverged,
        reproduce_cmd=repro_cmd,
        baseline_policy_hash=sha256_set(base_syscalls),
        candidate_policy_hash=sha256_set(candidate_syscalls),
        candidate_stderr_hash=cand_err_hash,
        timeout=is_timeout,
        reason=reason,
    )
    ledger.record_trial(trial)

    return (not failed), trial


def ablate_policy(
    target: str,
    base_syscalls: Set[str],
    workloads: List[List[str]],
    strategy: str = "loo",
    ledger: Optional[EvidenceLedger] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Executes counterfactual permission testing against the workload suite."""
    if not BIN.exists():
        raise RuntimeError(f"PoViShield binary missing at {BIN}; run make first")

    if ledger is None:
        ledger = EvidenceLedger(target)

    # 1. Establish reference baseline for every workload
    baselines: List[Tuple[int, bytes]] = []
    for w in workloads:
        rc, out, _ = run_workload(w)
        baselines.append((rc, out))

    current_policy = set(base_syscalls)
    necessary_evidence: Dict[str, Dict[str, Any]] = {}
    removable_set: Set[str] = set()
    tested_syscalls = sorted(base_syscalls)

    with tempfile.TemporaryDirectory(prefix=f"ps-ablate-{target}-") as td:
        tmp_dir = Path(td)

        if strategy in ("loo", "minimize"):
            for sc in tested_syscalls:
                candidate_set = current_policy - {sc}
                if not candidate_set:
                    # Seccomp cannot enforce an empty allowlist
                    continue

                broken = False
                first_breaker_trial: Optional[TrialRecord] = None

                for w, (ref_rc, ref_out) in zip(workloads, baselines):
                    intact, trial = test_ablation_trial(
                        target, w, sc, current_policy, candidate_set, ref_rc, ref_out, ledger, tmp_dir
                    )
                    if not intact:
                        broken = True
                        first_breaker_trial = trial
                        break

                if broken and first_breaker_trial:
                    necessary_evidence[sc] = {
                        "classification": "experimentally_necessary",
                        "breaking_workload": first_breaker_trial.workload,
                        "exit_code": first_breaker_trial.candidate_rc,
                        "signal": first_breaker_trial.signal,
                        "output_diverged": first_breaker_trial.output_diverged,
                        "reproduce": first_breaker_trial.reproduce_cmd,
                    }
                    if verbose:
                        sig_info = f" ({first_breaker_trial.signal})" if first_breaker_trial.signal else ""
                        print(f"  [NECESSARY] {sc:<18} -> failed on {first_breaker_trial.workload}{sig_info}")
                else:
                    removable_set.add(sc)
                    if verbose:
                        print(f"  [REMOVABLE] {sc:<18} -> safe to remove for tested workloads")
                    if strategy == "minimize":
                        current_policy.remove(sc)

    final_policy = current_policy if strategy == "minimize" else (current_policy - removable_set)
    total_sys = total_syscalls()
    not_yet_validated = sorted(base_syscalls - (set(necessary_evidence.keys()) | removable_set))
    tiers = {
        "observed": sorted(base_syscalls),
        "experimentally_necessary": sorted(necessary_evidence.keys()),
        "removable_for_tested_tasks": sorted(removable_set),
        "not_yet_validated": not_yet_validated,
    }

    result = {
        "schema": 2,
        "target": target,
        "strategy": strategy,
        "baseline_count": len(base_syscalls),
        "minimized_count": len(final_policy),
        "removed_count": len(removable_set),
        "removable_syscalls": sorted(removable_set),
        "final_syscalls": sorted(final_policy),
        "permission_tiers": tiers,
        "evidence": necessary_evidence,
        "risk_before": round(risk_pct(base_syscalls, total_sys), 2),
        "risk_after": round(risk_pct(final_policy, total_sys), 2),
        "trials_recorded": len(ledger.trials),
        "workloads_tested": len(workloads),
        "environment": get_environment_fingerprint(),
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        description="PoViShield Counterfactual Permission Ablation & Policy Verification"
    )
    parser.add_argument("--target", help="Target name from evaluation/targets.toml")
    parser.add_argument("--profile", help="Path to input profile JSON (if not using targets.toml)")
    parser.add_argument(
        "--workload",
        action="append",
        help="Workload command line string (can be specified multiple times)",
    )
    parser.add_argument(
        "--strategy",
        choices=["loo", "minimize"],
        default="minimize",
        help="Ablation strategy: loo (leave-one-out) or minimize (greedy fixed-point)",
    )
    parser.add_argument("-o", "--output", help="Path to save evidence-backed policy (Schema 2 JSON)")
    args = parser.parse_args()

    workloads: List[List[str]] = []
    base_syscalls: Set[str] = set()
    target_name = args.target or "custom"

    if args.profile:
        base_syscalls = load_profile(args.profile)
        if args.workload:
            workloads = [shlex.split(w) for w in args.workload]
        elif args.target:
            cfg_path = ROOT / "evaluation" / "targets.toml"
            cfg = tomllib.loads(cfg_path.read_text())
            matching = [t for t in cfg["target"] if t["name"] == args.target]
            if matching:
                workloads = matching[0]["train"]
        if not workloads:
            sys.exit("Error: Must provide at least one --workload when using --profile")
    elif args.target:
        cfg_path = ROOT / "evaluation" / "targets.toml"
        cfg = tomllib.loads(cfg_path.read_text())
        matching = [t for t in cfg["target"] if t["name"] == args.target]
        if not matching:
            sys.exit(f"Target '{args.target}' not found in {cfg_path}")
        tinfo = matching[0]
        workloads = tinfo["train"]

        prof_file = ROOT / "results" / "profiles" / f"{args.target}.json"
        if prof_file.exists():
            base_syscalls = load_profile(prof_file)
        else:
            # Learn base policy by running learner on training workloads
            print(f"Learning initial baseline for target '{args.target}'...")
            tmp = Path(tempfile.mkdtemp())
            parts = []
            for i, cmd in enumerate(workloads):
                pout = tmp / f"learn_{i}.json"
                subprocess.run(
                    [str(BIN), "learn", "-o", str(pout), "--"] + cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                if not pout.exists():
                    sys.exit(f"Failed to learn profile for {cmd}")
                parts.append(load_profile(pout))
            base_syscalls = set.union(*parts)
    elif args.profile:
        base_syscalls = load_profile(args.profile)
        if args.workload:
            workloads = [shlex.split(w) for w in args.workload]
        else:
            sys.exit("Error: Must provide at least one --workload when using --profile")
    else:
        sys.exit("Error: Specify either --target <name> or --profile <file> --workload '<cmd>'")

    print(f"\n=======================================================")
    print(f"PoViShield Counterfactual Permission Ablation: {target_name}")
    print(f"=======================================================")
    print(f"Baseline allowed syscalls : {len(base_syscalls)}")
    print(f"Workloads in test suite   : {len(workloads)}")
    print(f"Ablation strategy         : {args.strategy}\n")

    res = ablate_policy(target_name, base_syscalls, workloads, strategy=args.strategy, verbose=True)

    print(f"\n---------------- Result Summary ----------------")
    print(f"Initial syscalls  : {res['baseline_count']}")
    print(f"Verified necessary: {len(res['evidence'])}")
    print(f"Removable syscalls: {res['removed_count']} -> {res['removable_syscalls']}")
    print(f"Final syscalls    : {res['minimized_count']}")
    print(f"Risk score        : {res['risk_before']} -> {res['risk_after']}")
    print(f"Evidence trials   : {res['trials_recorded']}")

    out_path = args.output or (ROOT / "results" / "profiles" / f"{target_name}_counterfactual.json")
    save_profile(
        out_path,
        res["final_syscalls"],
        command=target_name,
        schema=2,
        extra={
            "permission_tiers": res["permission_tiers"],
            "evidence": res["evidence"],
            "removable_for_tested_suite": res["removable_syscalls"],
            "ablation_summary": {
                "strategy": res["strategy"],
                "baseline_count": res["baseline_count"],
                "minimized_count": res["minimized_count"],
                "removed_count": res["removed_count"],
                "risk_before": res["risk_before"],
                "risk_after": res["risk_after"],
            },
            "environment": res["environment"],
        },
    )
    print(f"Saved evidence-backed policy (Schema 2) -> {out_path}\n")


if __name__ == "__main__":
    main()
