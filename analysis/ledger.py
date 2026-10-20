"""PoViShield Evidence Ledger: records empirical proof for every permission decision.

Every permission ablation trial records the workload, environment fingerprint,
native reference baseline, and candidate outcome under seccomp enforcement.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

if __package__ is None or __package__ == "":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import ROOT
else:
    from .common import ROOT


class Verdict(str, Enum):
    REQUIRED = "REQUIRED_FOR_TESTED_WORKLOADS"
    REMOVABLE = "REMOVABLE_FOR_TESTED_WORKLOADS"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    TIMED_OUT = "TIMED_OUT"
    POLICY_NOT_APPLIED = "POLICY_NOT_APPLIED"

    # Backward compatibility aliases
    NECESSARY = "NECESSARY"


def normalize_verdict(v: str) -> str:
    if v == "NECESSARY":
        return Verdict.REQUIRED.value
    if v == "REMOVABLE":
        return Verdict.REMOVABLE.value
    return v


def get_git_commit() -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def get_environment_fingerprint() -> Dict[str, Any]:
    return {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os": platform.system(),
        "python": platform.python_version(),
        "git_commit": get_git_commit(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_set(items: Set[str]) -> str:
    canonical = ",".join(sorted(items))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class TrialRecord:
    trial_id: str
    target: str
    workload: List[str]
    ablated_syscall: str
    baseline_rc: int
    baseline_stdout_hash: str
    candidate_rc: int
    candidate_stdout_hash: str
    verdict: str  # Verdict enum string or legacy "NECESSARY"/"REMOVABLE"
    signal: Optional[str] = None
    output_diverged: bool = False
    reproduce_cmd: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    env_fingerprint: Dict[str, Any] = field(default_factory=get_environment_fingerprint)
    schema_version: int = 2
    experiment_id: str = "exp-default"
    workload_str: str = ""
    baseline_policy_hash: str = ""
    candidate_policy_hash: str = ""
    baseline_stderr_hash: str = ""
    candidate_stderr_hash: str = ""
    timeout: bool = False
    reason: str = ""
    tool_version: str = "0.1.0"
    known_limitations: List[str] = field(default_factory=lambda: [
        "Finite workload coverage: removal verified only for tested inputs",
        "SCMP_ACT_KILL_PROCESS fail-stop semantics (no soft error fallbacks)",
    ])

    def __post_init__(self):
        if not self.workload_str and self.workload:
            self.workload_str = " ".join(self.workload)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TrialRecord:
        known_keys = set(cls.__dataclass_fields__.keys())
        filtered = {k: v for k, v in d.items() if k in known_keys}
        return cls(**filtered)


class EvidenceLedger:
    def __init__(self, target: str, ledger_path: Optional[Path] = None):
        self.target = target
        if ledger_path:
            p = Path(ledger_path)
            if not p.is_file():
                if (ROOT / p).is_file():
                    p = ROOT / p
                elif (ROOT / "deploy_data" / "ledgers" / p.name).is_file():
                    p = ROOT / "deploy_data" / "ledgers" / p.name
                elif (ROOT / "results" / "ledgers" / p.name).is_file():
                    p = ROOT / "results" / "ledgers" / p.name
            self.ledger_path = p
        else:
            default_p = ROOT / "results" / "ledgers" / f"{target}.jsonl"
            deploy_p = ROOT / "deploy_data" / "ledgers" / f"{target}.jsonl"
            if not default_p.exists() and deploy_p.exists():
                self.ledger_path = deploy_p
            else:
                self.ledger_path = default_p
        self.trials: List[TrialRecord] = []
        if self.ledger_path.exists():
            self._load()

    def _load(self) -> None:
        self.trials = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if not isinstance(data, dict):
                        continue
                    self.trials.append(TrialRecord.from_dict(data))
                except Exception:
                    # Incomplete or corrupted lines are skipped during load
                    continue

    def record_trial(self, trial: TrialRecord) -> None:
        self.trials.append(trial)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(trial.to_dict()) + "\n")

    def is_required(self, verdict: str) -> bool:
        v = normalize_verdict(verdict)
        return v == Verdict.REQUIRED.value

    def is_removable(self, verdict: str) -> bool:
        v = normalize_verdict(verdict)
        return v == Verdict.REMOVABLE.value

    def get_necessary_syscalls(self) -> Dict[str, TrialRecord]:
        """Returns map of syscall -> first trial record proving it is required."""
        res: Dict[str, TrialRecord] = {}
        for t in self.trials:
            if self.is_required(t.verdict) and t.ablated_syscall not in res:
                res[t.ablated_syscall] = t
        return res

    def get_removable_syscalls(self, tested_syscalls: Set[str]) -> Set[str]:
        """Syscalls tested where ALL trials on tested workloads produced REMOVABLE."""
        nec = set(self.get_necessary_syscalls().keys())
        return tested_syscalls - nec

    def summarize(self) -> Dict[str, Any]:
        nec = self.get_necessary_syscalls()
        tested_syscalls = {t.ablated_syscall for t in self.trials}
        removable = tested_syscalls - set(nec.keys())
        inconclusive_count = sum(1 for t in self.trials if normalize_verdict(t.verdict) in (
            Verdict.INCONCLUSIVE.value, Verdict.EXECUTION_ERROR.value, Verdict.TIMED_OUT.value, Verdict.POLICY_NOT_APPLIED.value
        ))

        return {
            "target": self.target,
            "total_trials": len(self.trials),
            "tested_syscalls_count": len(tested_syscalls),
            "experimentally_necessary_count": len(nec),
            "removable_count": len(removable),
            "inconclusive_count": inconclusive_count,
            "removable_syscalls": sorted(removable),
            "necessary_evidence": {
                sc: {
                    "breaking_workload": t.workload,
                    "signal": t.signal,
                    "rc": t.candidate_rc,
                    "verdict": normalize_verdict(t.verdict),
                    "reason": t.reason or ("Process terminated by SIGSYS" if t.signal == "SIGSYS" else "Exit code / stdout diverged"),
                    "reproduce": t.reproduce_cmd,
                }
                for sc, t in nec.items()
            },
        }

    def audit_integrity(self) -> Tuple[bool, List[str]]:
        """Audits ledger integrity and consistency, failing closed on violations."""
        errors: List[str] = []
        if not self.ledger_path.exists():
            return False, ["Ledger file does not exist"]

        raw_trials: List[Dict[str, Any]] = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if not isinstance(d, dict):
                        errors.append(f"Line {line_no}: record is not a JSON object")
                        continue
                    # Schema check
                    for req in ("trial_id", "target", "workload", "ablated_syscall", "verdict"):
                        if req not in d:
                            errors.append(f"Line {line_no}: missing required field '{req}'")
                    raw_trials.append(d)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_no}: malformed JSON ({e})")

        # Check for contradictory evidence: same workload + ablated syscall having conflicting conclusive verdicts
        verdict_map: Dict[Tuple[str, str], Set[str]] = {}
        for d in raw_trials:
            key = (d.get("ablated_syscall", ""), d.get("workload_str", json.dumps(d.get("workload", []))))
            v = normalize_verdict(d.get("verdict", ""))
            if v in (Verdict.REQUIRED.value, Verdict.REMOVABLE.value):
                verdict_map.setdefault(key, set()).add(v)

        for (sc, wl), v_set in verdict_map.items():
            if len(v_set) > 1:
                errors.append(f"Contradictory evidence for syscall '{sc}' on workload '{wl}': {sorted(v_set)}")

        return (len(errors) == 0), errors
