"""Generates the resume bullet FROM measured results. Never edit numbers by hand."""
import json
from analysis.common import ROOT

r = json.loads((ROOT / "results" / "results.json").read_text())["aggregate"]
line = (f"Across {r['targets']} real programs: avg attack-surface reduction {r['avg_attack_surface_reduction_pct']}%, "
        f"held-out policy coverage {r['avg_heldout_coverage_pct']}%, compatibility {r['avg_compat_pct']}%, "
        f"median seccomp overhead {r['avg_median_overhead_pct']}%")
esc = ROOT / "results" / "escape.json"
if esc.exists():
    e = json.loads(esc.read_text()).get("full")
    if e and e["control_ok"]:
        line += f", {e['blocked']}/{e['total']} escape attempts blocked"
print(line + ".")
