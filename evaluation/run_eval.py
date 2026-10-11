"""make eval: learn -> generate -> held-out enforce -> benchmark, for every target.

Every number written to results/results.json is computed here. Methodology (docs/BENCHMARKING.md):
  * the policy is trained under the SAME stdout conditions as the test (grep skips write() on /dev/null);
  * compatibility compares exit code AND stdout with the native run;
  * timing is valid only when every measured sandboxed run matches the native reference exit code AND stdout
    (a killed process or incorrect output must not appear as a fast successful run);
  * native and sandboxed runs are interleaved (alternating order) after warm-up, so thermal / frequency /
    background-load drift hits both equally; raw samples are saved to results/raw/;
  * short workloads are flagged: below ~20 ms the % overhead measures process start-up, not seccomp.
"""
import fcntl, json, os, platform, random, statistics, subprocess, sys, tempfile, time, tomllib
from pathlib import Path
from analysis.common import BIN, ROOT, load_profile, save_profile, total_syscalls
from analysis.merge import merge_profiles
from analysis.risk import risk_pct

RES = ROOT / "results"
DEVNULL = subprocess.DEVNULL
SHORT_MS = 20.0          # native median below this => overhead % is start-up dominated
WARMUP = 3


def learn(cmd, out):
    subprocess.run([str(BIN), "learn", "-o", str(out), "--"] + cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    if not Path(out).exists():
        raise RuntimeError(f"learn produced no profile for {cmd}")
    return load_profile(out)


def run_out(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    return r.returncode, r.stdout


def timed(cmd):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=DEVNULL)
    return (time.perf_counter() - t) * 1000, r.returncode, r.stdout


def p95(xs):
    return statistics.quantiles(xs, n=20)[18] if len(xs) >= 20 else max(xs)


def bootstrap_ci(nat, box, iters=2000):
    """95% CI of (median(box)/median(nat) - 1) * 100, resampling each series."""
    vals = []
    for _ in range(iters):
        a = statistics.median(random.choices(nat, k=len(nat)))
        b = statistics.median(random.choices(box, k=len(box)))
        vals.append((b / a - 1) * 100)
    vals.sort()
    return vals[int(.025 * iters)], vals[int(.975 * iters) - 1]


def cpu_idle_pct(sample_s=1.5):
    def read():
        f = open("/proc/stat").readline().split()[1:]
        v = list(map(int, f))
        return v[3] + v[4], sum(v)
    i0, t0 = read()
    time.sleep(sample_s)
    i1, t1 = read()
    return round(100.0 * (i1 - i0) / max(t1 - t0, 1), 1)


def environment(runs):
    def sh(c):
        try:
            return subprocess.run(c, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            return ""
    model = ""
    try:
        model = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        pass
    gov = ""
    try:
        gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
    except Exception:
        pass
    return {"kernel": platform.release(), "machine": platform.machine(), "cpus": os.cpu_count(),
            "cpu_model": model, "cpu_governor": gov or "n/a", "python": platform.python_version(),
            "libseccomp": sh(["pkg-config", "--modversion", "libseccomp"]) or "n/a",
            "git_commit": sh(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"]) or "n/a",
            "runs_per_measurement": runs, "warmup_runs": WARMUP,
            "loadavg_start": [round(x, 2) for x in os.getloadavg()], "cpu_idle_pct_start": cpu_idle_pct()}


def benchmark(native_cmd, boxed_cmd, runs, expect_rc, expect_out):
    nat, box, bad = [], [], 0
    for i in range(WARMUP + runs):
        order = (("n", native_cmd), ("b", boxed_cmd)) if i % 2 == 0 else (("b", boxed_cmd), ("n", native_cmd))
        for kind, cmd in order:
            ms, rc, stdout = timed(cmd)
            if i < WARMUP:
                continue
            if kind == "b" and (rc != expect_rc or stdout != expect_out):
                bad += 1
            (nat if kind == "n" else box).append(ms)
    return nat, box, bad


def main():
    if not BIN.exists():
        sys.exit("build first: make")
    lock = open("/tmp/povishield-eval.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another evaluation is already running (lock /tmp/povishield-eval.lock). Wait for it to finish.")

    cfg = tomllib.loads((ROOT / "evaluation" / "targets.toml").read_text())
    runs = int(os.environ.get("PS_RUNS", cfg["settings"]["runs"]))
    total = total_syscalls()
    (RES / "profiles").mkdir(parents=True, exist_ok=True)
    (RES / "raw").mkdir(parents=True, exist_ok=True)
    env = environment(runs)
    if env["cpu_idle_pct_start"] < 80:
        print(f"WARNING: machine is only {env['cpu_idle_pct_start']}% idle; timings will be noisy. "
              f"Close other programs and re-run for final numbers.", flush=True)
    tmp = Path(tempfile.mkdtemp())
    out = []

    for t in cfg["target"]:
        name = t["name"]
        print(f"[{name}] learning ...", flush=True)
        train = [learn(c, tmp / f"{name}-train{i}.json") for i, c in enumerate(t["train"])]
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
            false_kills += rc in (-31, 159)                      # SIGSYS
        compat = 100.0 * compat_ok / len(t["test"])

        print(f"[{name}] benchmarking ({runs} interleaved runs) ...", flush=True)
        c0 = t["test"][0]
        boxed = [str(BIN), "enforce", "-p", str(ppath), "--"] + c0
        expect_rc, expect_out = run_out(c0)
        nat, box, bad = benchmark(c0, boxed, runs, expect_rc, expect_out)
        (RES / "raw" / f"{name}.json").write_text(json.dumps({"native_ms": nat, "sandboxed_ms": box, "command": c0}))
        med_n, med_b = statistics.median(nat), statistics.median(box)
        valid = bad == 0
        lo, hi = bootstrap_ci(nat, box) if valid else (None, None)
        ov = {"valid": valid, "short_workload": med_n < SHORT_MS, "bad_runs": bad,
              "native_ms_median": round(med_n, 2), "sandboxed_ms_median": round(med_b, 2),
              "added_ms": round(med_b - med_n, 2), "p95_ms": round(p95(box), 2)}
        if valid:
            ov.update({"median": round((med_b / med_n - 1) * 100, 2), "ci95": [round(lo, 2), round(hi, 2)]})
        else:
            ov.update({"median": None, "ci95": None,
                       "note": f"{bad}/{runs} sandboxed timing runs differed from native exit code or stdout; overhead not reported"})
            print(f"[{name}] WARNING: timing invalid -> {ov['note']}", flush=True)

        out.append({
            "target": name, "allowed_syscalls": len(policy), "total_syscalls": total,
            "attack_surface_reduction_pct": round((1 - len(policy) / total) * 100, 2),
            "risk_before": 100.0, "risk_after": round(risk_pct(policy, total), 2),
            "heldout_coverage_pct": round(coverage, 2), "missing_in_policy": sorted(test_union - policy),
            "compat_pct": round(compat, 2), "false_kills": false_kills, "overhead_pct": ov})

    n = len(out)
    avg = lambda k: round(sum(r[k] for r in out) / n, 2)
    long_ok = [r["overhead_pct"] for r in out if r["overhead_pct"]["valid"] and not r["overhead_pct"]["short_workload"]]
    agg = {"targets": n,
           "avg_attack_surface_reduction_pct": avg("attack_surface_reduction_pct"),
           "avg_risk_after": avg("risk_after"),
           "avg_heldout_coverage_pct": avg("heldout_coverage_pct"),
           "avg_compat_pct": avg("compat_pct"),
           "total_false_kills": sum(r["false_kills"] for r in out),
           "overhead_targets": len(long_ok),
           "avg_median_overhead_pct": round(sum(o["median"] for o in long_ok) / len(long_ok), 2) if long_ok else None,
           "max_median_overhead_pct": max((o["median"] for o in long_ok), default=None),
           "invalid_timing_targets": [r["target"] for r in out if not r["overhead_pct"]["valid"]]}
    env["loadavg_end"] = [round(x, 2) for x in os.getloadavg()]
    (RES / "results.json").write_text(json.dumps({"env": env, "aggregate": agg, "targets": out}, indent=2))

    L = ["# PoViShield evaluation report", "", f"Environment: `{json.dumps(env)}`", "",
         "| target | allowed | surface reduction | risk after | held-out coverage | compat | false kills | native ms | added ms | overhead median [95% CI] |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for r in out:
        o = r["overhead_pct"]
        ovs = (f"{o['median']}% [{o['ci95'][0]}, {o['ci95'][1]}]" + (" (start-up dominated)" if o["short_workload"] else "")) if o["valid"] else "INVALID"
        L.append(f"| {r['target']} | {r['allowed_syscalls']}/{r['total_syscalls']} | {r['attack_surface_reduction_pct']}% | {r['risk_after']} | "
                 f"{r['heldout_coverage_pct']}% | {r['compat_pct']}% | {r['false_kills']} | {o['native_ms_median']} | {o['added_ms']} | {ovs} |")
    L += ["", "## Aggregate", "", "```json", json.dumps(agg, indent=2), "```", "",
          "## Limitations", "- ptrace learning misses rare code paths; merge more workloads.",
          f"- Overhead % is only aggregated over valid timings with native median >= {SHORT_MS:.0f} ms.",
          "- Held-out coverage is computed from a separate learn run of the test workload."]
    (RES / "report.md").write_text("\n".join(L))
    print(json.dumps(agg, indent=2))
    print("wrote results/results.json, results/report.md, results/raw/*.json")


if __name__ == "__main__":
    main()
