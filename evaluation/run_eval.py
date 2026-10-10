"""make eval: learn -> generate -> held-out enforce -> benchmark, for every target.
Every number written to results/results.json is computed here; none is typed by hand."""
import json, os, platform, random, statistics, subprocess, sys, tempfile, time, tomllib
from pathlib import Path
from analysis.common import BIN, ROOT, load_profile, save_profile, total_syscalls
from analysis.merge import merge_profiles
from analysis.risk import risk_pct

RES = ROOT / "results"
DEVNULL = subprocess.DEVNULL


def learn(cmd, out, both_stdout=False):
    """Learn syscalls and fail immediately if tracing or profile loading fails."""
    args = [str(BIN), "learn", "-o", str(out), "--"] + cmd
    first = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if first.returncode != 0:
        raise RuntimeError(
            f"learning failed (exit {first.returncode}) for {cmd!r}: {first.stderr.strip()}"
        )
    prof = load_profile(out)
    if both_stdout:
        second = subprocess.run(args, stdout=DEVNULL, stderr=subprocess.PIPE, text=True)
        if second.returncode != 0:
            raise RuntimeError(
                f"learning with stdout redirected failed (exit {second.returncode}) "
                f"for {cmd!r}: {second.stderr.strip()}"
            )
        prof = merge_profiles([prof, load_profile(out)])
    if not prof:
        raise RuntimeError(f"learner produced an empty syscall profile for {cmd!r}")
    return prof


def run_out(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    return r.returncode, r.stdout


def run_rc(cmd):
    return subprocess.run(cmd, stdout=DEVNULL, stderr=DEVNULL).returncode


def timeit(cmd, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)   # same stdout as learn/compat
        ts.append((time.perf_counter() - t) * 1000)
        if r.returncode in (-31, 159):                                      # SIGSYS: timing a crash is meaningless
            sys.exit("timeit: killed by SIGSYS (policy gap), overhead invalid for: " + " ".join(cmd[:8]))
    return ts


def p95(xs):
    return statistics.quantiles(xs, n=20)[18] if len(xs) >= 20 else max(xs)


def overhead_ci(native, boxed, iters=1000):
    """Bootstrap 95% CI of median overhead (%)."""
    vals = []
    for _ in range(iters):
        a = statistics.median(random.choices(native, k=len(native)))
        b = statistics.median(random.choices(boxed, k=len(boxed)))
        vals.append((b - a) / a * 100)
    vals.sort()
    return vals[int(.025 * iters)], vals[int(.975 * iters)]


def main():
    if not BIN.exists():
        sys.exit("build first: make")
    cfg = tomllib.loads((ROOT / "evaluation" / "targets.toml").read_text())
    runs = int(os.environ.get("PS_RUNS", cfg["settings"]["runs"]))
    total = total_syscalls()
    (RES / "profiles").mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    out = []

    for t in cfg["target"]:
        name = t["name"]
        print(f"[{name}] learning ...", flush=True)
        train = [learn(c, tmp / f"{name}-train{i}.json", both_stdout=True) for i, c in enumerate(t["train"])]
        policy = merge_profiles(train)
        ppath = RES / "profiles" / f"{name}.json"
        save_profile(ppath, policy, command=name)

        test_sets = [learn(c, tmp / f"{name}-test{i}.json") for i, c in enumerate(t["test"])]
        test_union = merge_profiles(test_sets)
        coverage = 100.0 * len(test_union & policy) / max(len(test_union), 1)

        compat_ok, false_kills = 0, 0
        for c in t["test"]:
            native_rc, native_out = run_out(c)
            rc, got = run_out([str(BIN), "enforce", "-p", str(ppath), "--"] + c)
            compat_ok += (rc == native_rc and got == native_out)
            false_kills += rc in (-31, 159)                       # SIGSYS
        compat = 100.0 * compat_ok / len(t["test"])

        c0 = t["test"][0]
        nat = timeit(c0, runs)
        box = timeit([str(BIN), "enforce", "-p", str(ppath), "--"] + c0, runs)
        med_n, med_b = statistics.median(nat), statistics.median(box)
        lo, hi = overhead_ci(nat, box)

        out.append({
            "target": name,
            "allowed_syscalls": len(policy), "total_syscalls": total,
            "attack_surface_reduction_pct": round((1 - len(policy) / total) * 100, 2),
            "risk_before": 100.0, "risk_after": round(risk_pct(policy, total), 2),
            "heldout_coverage_pct": round(coverage, 2),
            "missing_in_policy": sorted(test_union - policy),
            "compat_pct": round(compat, 2), "false_kills": false_kills,
            "overhead_pct": {"median": round((med_b - med_n) / med_n * 100, 2),
                             "ci95": [round(lo, 2), round(hi, 2)],
                             "native_ms_median": round(med_n, 2), "p95_ms": round(p95(box), 2)},
        })

    n = len(out)
    avg = lambda k: round(sum(r[k] for r in out) / n, 2)
    agg = {"targets": n,
           "avg_attack_surface_reduction_pct": avg("attack_surface_reduction_pct"),
           "avg_risk_after": avg("risk_after"),
           "avg_heldout_coverage_pct": avg("heldout_coverage_pct"),
           "avg_compat_pct": avg("compat_pct"),
           "total_false_kills": sum(r["false_kills"] for r in out),
           "avg_median_overhead_pct": round(sum(r["overhead_pct"]["median"] for r in out) / n, 2)}
    env = {"kernel": platform.release(), "machine": platform.machine(), "cpus": os.cpu_count(),
           "python": platform.python_version(), "runs_per_measurement": runs}
    (RES / "results.json").write_text(json.dumps({"env": env, "aggregate": agg, "targets": out}, indent=2))

    lines = ["# PoViShield evaluation report", "", f"Environment: `{env}`", "",
             "| target | allowed | surface reduction | risk after | held-out coverage | compat | false kills | overhead (median, 95% CI) |",
             "|---|---|---|---|---|---|---|---|"]
    for r in out:
        o = r["overhead_pct"]
        lines.append(f"| {r['target']} | {r['allowed_syscalls']}/{r['total_syscalls']} | {r['attack_surface_reduction_pct']}% | "
                     f"{r['risk_after']} | {r['heldout_coverage_pct']}% | {r['compat_pct']}% | {r['false_kills']} | "
                     f"{o['median']}% [{o['ci95'][0]}, {o['ci95'][1]}] |")
    lines += ["", "## Aggregate", "", "```json", json.dumps(agg, indent=2), "```", "",
              "## Limitations", "- ptrace learning misses rare code paths; merge more workloads.",
              "- Timings include process start; short programs inflate percentage overhead.",
              "- Held-out coverage is computed from a separate learn run of the test workload."]
    (RES / "report.md").write_text("\n".join(lines))
    print(json.dumps(agg, indent=2))
    print("wrote results/results.json and results/report.md")


if __name__ == "__main__":
    main()
