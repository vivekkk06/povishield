# PoViShield
**Intelligent Linux Application Sandboxing and Security Benchmarking Platform**

Run a program, let PoViShield *learn* the syscalls it really needs (ptrace), generate a
least-privilege seccomp-bpf policy, enforce it inside namespaces + cgroups v2, and
*measure* everything (attack surface, held-out coverage, compatibility, overhead, escape tests).

## Quick start (Ubuntu/Debian, use a throwaway VM)
```bash
make deps && make
make test                                   # unit tests
make eval                                   # benchmarks  -> results/report.md
sudo make escape                            # escape matrix -> results/escape.json
make resume-line                            # bullet generated from measured data
bash demo/run_demo.sh                       # attack demo

build/povishield learn -o ls.json -- ls -la /
build/povishield enforce -p ls.json -- ls -la /
sudo build/povishield run --mem 128 --pids 32 --profile ls.json -- ls /
sudo python3 dashboard/tui.py               # second terminal
```
Layout: see `docs/ARCHITECTURE.md`. Requires Linux x86_64, kernel >= 5.x with cgroup v2, libseccomp.
