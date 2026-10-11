# Benchmark methodology

`make eval` is the only source of numbers in the README, `docs/RESULTS.md` and the resume line.

## What is measured
| metric | definition |
|---|---|
| attack-surface reduction | `(1 - allowed / total) x 100`; `total` is read from libseccomp for this architecture |
| risk after | project-defined heuristic: weighted risk of allowed syscalls, normalised so allow-everything = 100; not a probability of compromise (weights: `analysis/risk.py`) |
| held-out coverage | share of syscalls observed in a separate trace of the configured test workload that the training policy allows; not proof of generalisation to arbitrary unseen behavior |
| compatibility | share of configured held-out workloads whose **exit code and stdout** match the native run; stderr and other side effects are not compared |
| false kills | held-out runs killed by SIGSYS (exit -31 or 159 inside shell pipelines) |
| overhead | `median(sandboxed) / median(native) - 1`, bootstrap 95% CI; `added ms` is the absolute difference |

## Rules that keep the numbers honest
1. **Same conditions for training and testing.** Training runs with stdout piped, like the test runs. (GNU grep skips
   `write()` when stdout is `/dev/null`; training that way produced false kills.)
2. **A timing only counts if the run behaved.** If a sandboxed run does not exit like the native run, the whole
   overhead for that target is reported as *invalid*. A killed process is fast; counting it would show a bogus negative overhead.
3. **Interleaved A/B runs** with alternating order and 3 discarded warm-up runs, so frequency scaling and background
   load hit both variants equally.
4. **Short workloads are flagged.** Below ~20 ms the percentage measures process start-up, not seccomp. They are
   excluded from the aggregate overhead; use `added ms` for them.
5. **Environment is recorded**: kernel, CPU model, governor, libseccomp, git commit, load average and CPU idle at start.
   A warning is printed if the machine is under 80% idle.
6. **Raw samples are kept** in `results/raw/<target>.json` so anyone can recompute the statistics.
7. **One evaluation at a time**: a lock file prevents concurrent runs from corrupting each other's timings.

## Interpretation and limitations

- The syscall-count reduction measures how many syscall numbers are excluded from
  the generated allowlist. It is not a direct measurement of exploitability.
- The risk-after score is a heuristic defined by this project. Its weights are
  assumptions, not empirically calibrated probabilities of compromise.
- Held-out coverage measures syscall coverage on the configured test traces.
  Different commands and inputs provide useful variation, but this finite suite
  does not establish coverage of arbitrary future execution paths.
- A benchmark target is marked invalid if any measured sandboxed run has an exit code or stdout that differs from the native reference. A mismatch invalidates the target's overhead estimate rather than being treated as a fast successful run.
- Compatibility compares exit status and stdout only. It does not establish
  full behavioral equivalence, and zero false kills applies only to the tested
  runs and the evaluator's SIGSYS detection rules.
- The overhead aggregate includes only valid workloads whose native median is
  at least 20 ms. Reported estimates are machine- and workload-specific; confidence
  intervals that include zero do not establish a measurable overhead difference.
- Escape-matrix results apply only to the listed test cases and configurations.
  They do not prove that the sandbox is unescapable.

## Reproducing
```bash
make && make test
# close browsers / IDEs, then:
make eval          # PS_RUNS=3 make eval for a 30-second smoke test
make docs && make resume-line
```
