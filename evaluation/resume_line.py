"""Generates the resume bullet FROM measured data. Never edit the numbers by hand."""
import json, re
from analysis.common import ROOT

BLOCKED = {"BLOCKED_SIGSYS", "DENIED", "KILLED_BY_LIMIT", "blocked"}


def matrix():
    """Parse the escape matrix text (docs/escape-matrix.txt) -> {config: [statuses]}."""
    for p in (ROOT / "results" / "escape-matrix.txt", ROOT / "docs" / "escape-matrix.txt"):
        if not p.exists():
            continue
        cols, rows = None, []
        for line in p.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] == "test":
                cols = parts[1:]
            elif parts and cols and re.match(r"(esc_|limit_)", parts[0]):
                rows.append(parts[1:1 + len(cols)])
        if cols and rows:
            return {c: [r[i] for r in rows if len(r) > i] for i, c in enumerate(cols)}
    return {}


def main():
    r = json.loads((ROOT / "results" / "results.json").read_text())["aggregate"]
    bits = [f"Across {r['targets']} real programs: avg attack-surface reduction {r['avg_attack_surface_reduction_pct']}%",
            f"held-out policy coverage {r['avg_heldout_coverage_pct']}%",
            f"compatibility {r['avg_compat_pct']}% ({r['total_false_kills']} false kill(s))"]
    if r.get("avg_median_overhead_pct") is not None:
        bits.append(f"seccomp overhead {r['avg_median_overhead_pct']}% avg (max {r['max_median_overhead_pct']}%) on "
                    f"{r['overhead_targets']} long-running workloads")
    m = matrix()
    col = next((c for c in ("full+rootfs", "full") if c in m), None)
    if col:
        s = m[col]
        blocked = sum(x in BLOCKED for x in s)
        base = m.get("bare")
        tail = f"{blocked}/{len(s)} escape and resource-abuse tests contained by the full sandbox"
        if base:
            tail += f" (vs {sum(x == 'ESCAPED' for x in base)}/{len(base)} succeeding unconfined)"
        bits.append(tail)
    else:
        bits.append("escape matrix not found (run: sudo make escape-full)")
    print(", ".join(bits) + ".")
    if r.get("invalid_timing_targets"):
        print("NOTE: overhead excluded for targets with invalid timing:", ", ".join(r["invalid_timing_targets"]))


if __name__ == "__main__":
    main()
