"""Generates the resume bullet FROM measured results. Never edit numbers by hand."""
import json
from analysis.common import ROOT

# Long enough that seccomp cost is not hidden by process startup (see targets.toml)
LONG = {"gzip_big", "sort_big", "python_cpu"}

d = json.loads((ROOT / "results" / "results.json").read_text())
r = d["aggregate"]
long_med = [t["overhead_pct"]["median"] for t in d["targets"] if t["target"] in LONG]
line = (f"Across {r['targets']} real programs: avg attack-surface reduction {r['avg_attack_surface_reduction_pct']}%, "
        f"held-out policy coverage {r['avg_heldout_coverage_pct']}%, compatibility {r['avg_compat_pct']}%")
if long_med:
    line += (f", seccomp overhead {min(long_med):+.1f}% to {max(long_med):+.1f}% on long-running workloads "
             f"(short programs are dominated by process startup)")
esc = ROOT / "results" / "escape.json"
if esc.exists():
    e = json.loads(esc.read_text()).get("full")
    if e and e["control_ok"]:
        counts = e.get("counts", {})
        confirmed = counts.get("BLOCKED_SIGSYS", 0)
        line += (
            f", {confirmed}/{e['total']} attempts terminated by seccomp "
            f"(diagnostic escape tests; cgroup-limit kills and denials reported separately)"
        )
print(line + ".")
