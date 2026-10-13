# PoViShield evaluation report

Environment: `{"kernel": "7.2.8-200.fc44.x86_64", "machine": "x86_64", "cpus": 8, "cpu_model": "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz", "cpu_governor": "powersave", "python": "3.14.7", "libseccomp": "2.6.1", "git_commit": "fce0e2e", "runs_per_measurement": 30, "warmup_runs": 3, "loadavg_start": [3.48, 2.23, 1.42], "cpu_idle_pct_start": 50.8, "loadavg_end": [2.5, 2.74, 2.04]}`

| target | allowed | surface reduction | risk after | held-out coverage | compat | false kills | native ms | added ms | overhead median [95% CI] |
|---|---|---|---|---|---|---|---|---|---|
| ls | 32/385 | 91.69% | 5.27 | 100.0% | 100.0% | 0 | 1.49 | 0.68 | 45.32% [21.45, 61.25] (start-up dominated) |
| cat | 20/385 | 94.81% | 3.01 | 100.0% | 100.0% | 0 | 0.61 | 0.62 | 101.66% [68.29, 117.88] (start-up dominated) |
| grep | 23/385 | 94.03% | 3.26 | 100.0% | 100.0% | 0 | 1.24 | 0.57 | 46.11% [29.8, 73.08] (start-up dominated) |
| gzip | 41/385 | 89.35% | 6.02 | 100.0% | 100.0% | 0 | 4.02 | 0.67 | 16.7% [9.41, 23.62] (start-up dominated) |
| sort | 45/385 | 88.31% | 6.61 | 100.0% | 100.0% | 0 | 21.9 | 1.78 | 8.11% [0.92, 14.59] |
| python3 | 36/385 | 90.65% | 4.85 | 100.0% | 100.0% | 0 | 21.5 | 0.76 | 3.53% [-5.17, 14.32] |
| gzip_big | 41/385 | 89.35% | 6.02 | 100.0% | 100.0% | 0 | 115.3 | 9.06 | 7.86% [0.03, 15.68] |
| sort_big | 48/385 | 87.53% | 7.61 | 100.0% | 100.0% | 0 | 6212.23 | 244.9 | 3.94% [-2.39, 10.32] |
| python_cpu | 36/385 | 90.65% | 4.85 | 100.0% | 100.0% | 0 | 154.92 | -1.66 | -1.07% [-9.15, 20.4] |

## Aggregate

```json
{
  "targets": 9,
  "avg_attack_surface_reduction_pct": 90.71,
  "avg_risk_after": 5.28,
  "avg_heldout_coverage_pct": 100.0,
  "avg_compat_pct": 100.0,
  "total_false_kills": 0,
  "overhead_targets": 5,
  "avg_median_overhead_pct": 4.47,
  "max_median_overhead_pct": 8.11,
  "invalid_timing_targets": []
}
```

## Limitations
- ptrace learning misses rare code paths; merge more workloads.
- Overhead % is only aggregated over valid timings with native median >= 20 ms.
- Held-out coverage is computed from a separate learn run of the test workload.