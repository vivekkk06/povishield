"""Profile diff: which syscalls were added/removed and what that does to risk."""
import argparse, html
if __package__ is None or __package__ == "":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import load_profile, total_syscalls
    from analysis.risk import risk_pct, weight
else:
    from .common import load_profile, total_syscalls
    from .risk import risk_pct, weight

RED, GRN, RST = "\033[31m", "\033[32m", "\033[0m"


def diff(a, b):
    return sorted(b - a), sorted(a - b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--html")
    a = ap.parse_args()
    old, new = load_profile(a.old), load_profile(a.new)
    added, removed = diff(old, new)
    total = total_syscalls()
    d = risk_pct(new, total) - risk_pct(old, total)
    print(f"{a.old}: {len(old)} syscalls   {a.new}: {len(new)} syscalls   risk delta {d:+.2f}")
    for s in added:
        c = RED if weight(s) >= 7 else ""
        print(f"  {c}+ {s} (weight {weight(s)}){RST}")
    for s in removed:
        print(f"  {GRN}- {s}{RST}")
    if a.html:
        rows = "".join(f"<tr><td>+</td><td>{html.escape(s)}</td><td>{weight(s)}</td></tr>" for s in added)
        rows += "".join(f"<tr><td>-</td><td>{html.escape(s)}</td><td>{weight(s)}</td></tr>" for s in removed)
        open(a.html, "w").write(f"<h2>Profile diff</h2><p>risk delta {d:+.2f}</p>"
                                f"<table border=1><tr><th></th><th>syscall</th><th>weight</th></tr>{rows}</table>")


if __name__ == "__main__":
    main()
