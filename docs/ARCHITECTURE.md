# PoViShield architecture

```
            learn (ptrace)                       analysis/ (Python)
 program ──────────────────► profile.json ─┬──► risk.py   score 0-100
                                           ├──► diff.py   profile vs profile
                                           ├──► merge.py  union of many runs
                                           └──► seccomp_gen.c  ──► enforce / run --profile
 run (clone + namespaces + cgroup v2 + pivot_root) ◄────────────────┘
        │
        ├── dashboard/tui.py   live cgroup stats
        ├── tests/escape/      escape + limit tests x 4-5 configs
        └── evaluation/        make eval -> results.json, report.md, resume line
```

## Profile schema (v1)
```json
{ "schema": 1, "command": "ls -la /", "arch": "x86_64", "count": 30, "syscalls": ["brk", "..."] }
```

## Metrics (all computed by evaluation/run_eval.py)
| metric | formula |
|---|---|
| attack-surface reduction | (1 - allowed / total_native_syscalls) x 100, total from libseccomp |
| risk reduction | weighted risk of allowed set, normalised so allow-all = 100 |
| held-out coverage | |test_syscalls ∩ policy| / |test_syscalls| x 100; test syscalls learned from a workload never used for training |
| compatibility | % of held-out workloads whose enforce exit code equals the native exit code |
| false kills | held-out runs killed by SIGSYS |
| overhead | (median_enforce - median_native) / median_native, bootstrap 95% CI |
| escape block rate | blocked / total, per config, with a control program validating each config |

## Roadmap (not implemented yet, be honest about this on your resume)
- Server targets (nginx, redis) with load generators and throughput deltas
- Static scan of binaries for syscall instructions (union with dynamic profile)
- eBPF learner (lower overhead than ptrace); aarch64 support
- `povishield.toml` loader; argument-level seccomp filtering
- Escape tests inside a real `--rootfs` with static binaries
- Startup latency vs `docker run`; gcov coverage and flake-rate (100x suite) reporting
